//! Ordered hedged connections through a candidate set of upstream proxies.

use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::Mutex;
use tokio::task::JoinSet;

use crate::connect::connect_proxy::{connect_proxy_on, TlsConnector};
use crate::connect::AnyUpstream;
use crate::error::ConnectError;
use crate::pool::ProxyPool;
use crate::types::ProxyConfig;

#[cfg(test)]
#[path = "hedged_tests.rs"]
mod tests;

/// Options controlling candidate launch and handshake duration.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct HedgeOptions {
    /// Delay before launching another candidate while no handshake is active.
    /// A delay too large for the monotonic clock behaves as "never hedge".
    pub hedge_delay: Duration,
    /// Timeout for each proxy-protocol handshake.
    pub handshake_timeout: Duration,
}

impl Default for HedgeOptions {
    fn default() -> Self {
        Self {
            hedge_delay: Duration::from_secs(2),
            handshake_timeout: Duration::from_secs(10),
        }
    }
}

impl HedgeOptions {
    /// Set the delay before launching another candidate.
    #[must_use]
    pub fn with_hedge_delay(mut self, delay: Duration) -> Self {
        self.hedge_delay = delay;
        self
    }

    /// Set the timeout for each proxy-protocol handshake.
    #[must_use]
    pub fn with_handshake_timeout(mut self, timeout: Duration) -> Self {
        self.handshake_timeout = timeout;
        self
    }
}

/// Completion category for a launched candidate.
#[derive(Debug)]
#[non_exhaustive]
pub enum AttemptOutcome {
    /// This attempt established the returned connection.
    Won,
    /// This attempt succeeded after another attempt won; the late stream is
    /// dropped instead of returned.
    LateSuccess,
    /// TCP acquisition completed after the winner; its acquired socket is
    /// closed without sending a proxy handshake.
    Lost,
    /// TCP acquisition or proxy handshake failed.
    Failed(ConnectError),
}

/// Completion details for one launched candidate.
#[derive(Debug)]
#[non_exhaustive]
pub struct AttemptReport {
    /// Candidate's zero-based position in the input slice.
    pub index: usize,
    /// Candidate proxy configuration.
    pub proxy: Arc<ProxyConfig>,
    /// Time from launch through completion.
    pub elapsed: Duration,
    /// Candidate's final outcome.
    pub outcome: AttemptOutcome,
    /// Whether another candidate had already won at settlement.
    pub after_win: bool,
}

/// Established upstream stream and the winning candidate's index.
pub struct Hedged {
    /// Stream connected to the requested target.
    pub stream: AnyUpstream,
    /// Winner's zero-based position in the candidate slice.
    pub winner: usize,
}

impl fmt::Debug for Hedged {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Hedged")
            .field("winner", &self.winner)
            .finish_non_exhaustive()
    }
}

/// Summary returned when no candidate establishes a connection.
#[derive(Debug)]
pub struct HedgeError {
    /// Number of candidates launched.
    pub attempts: usize,
    /// Last completed connection error, if any.
    pub last: Option<ConnectError>,
}

impl fmt::Display for HedgeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("all upstream connection attempts failed")
    }
}
impl std::error::Error for HedgeError {}

#[derive(Default)]
struct RaceState {
    won: AtomicBool,
    /// Exclusive handshake admission: locked by the one attempt talking to
    /// its upstream, so a TCP-ready sibling waits instead of sending a
    /// second CONNECT to the target.
    handshake_slot: Mutex<()>,
}

struct Finished {
    index: usize,
    result: Result<AnyUpstream, AttemptFailure>,
    elapsed: Duration,
}

#[derive(Debug)]
enum AttemptFailure {
    Lost,
    Failed(ConnectError),
}

async fn attempt(
    race: &RaceState,
    proxy: &ProxyConfig,
    target_addr: &str,
    pool: &ProxyPool,
    timeout: Duration,
    tls_connector: Option<Arc<TlsConnector>>,
) -> Result<AnyUpstream, AttemptFailure> {
    let stream = pool.acquire(proxy).await.map_err(AttemptFailure::Failed)?;
    if race.won.load(Ordering::Acquire) {
        return Err(AttemptFailure::Lost);
    }
    // Exclusive handshake admission: a TCP-ready sibling waits here with its
    // socket and sends nothing until the slot is its own.
    let _slot = race.handshake_slot.lock().await;
    // The holder publishes its win before freeing the slot, so a waiter that
    // acquires it after a success observes `won` and never handshakes.
    if race.won.load(Ordering::Acquire) {
        return Err(AttemptFailure::Lost);
    }
    let result = connect_proxy_on(
        stream,
        target_addr,
        proxy,
        timeout,
        tls_connector.as_deref(),
    )
    .await;
    if result.is_ok() {
        // Publish before dropping the slot so the next waiter sees the win.
        race.won.store(true, Ordering::Release);
    }
    drop(_slot);
    result.map_err(AttemptFailure::Failed)
}

fn report(
    callback: &dyn Fn(&AttemptReport),
    proxies: &[Arc<ProxyConfig>],
    finished: Finished,
    after_win: bool,
) {
    let outcome = match finished.result {
        Ok(stream) if after_win => {
            drop(stream);
            AttemptOutcome::LateSuccess
        }
        Ok(_) => AttemptOutcome::Won,
        Err(AttemptFailure::Lost) => AttemptOutcome::Lost,
        Err(AttemptFailure::Failed(error)) => AttemptOutcome::Failed(error),
    };
    callback(&AttemptReport {
        index: finished.index,
        proxy: proxies[finished.index].clone(),
        elapsed: finished.elapsed,
        outcome,
        after_win,
    });
}

async fn drain(
    mut running: JoinSet<Finished>,
    proxies: Vec<Arc<ProxyConfig>>,
    callback: Arc<dyn Fn(&AttemptReport) + Send + Sync>,
) {
    let proxies = Arc::new(proxies);
    while let Some(joined) = running.join_next().await {
        if let Ok(finished) = joined {
            report(callback.as_ref(), &proxies, finished, true);
        }
    }
}

/// Next hedge-tick deadline. `None` arms no timer: a delay too large for the
/// monotonic clock behaves as "never hedge" instead of panicking on overflow.
fn hedge_deadline(opts: &HedgeOptions, pending_len: usize) -> Option<tokio::time::Instant> {
    if opts.hedge_delay.is_zero() || pending_len == 0 {
        return None;
    }
    tokio::time::Instant::now().checked_add(opts.hedge_delay)
}

/// Connect through candidates in input order. Zero delay selects sequential
/// operation; otherwise another candidate launches after each delay only while
/// no handshake is active. The next launches immediately when all active
/// attempts fail.
///
/// Handshake admission is exclusive: a launched attempt that reaches its
/// upstream while another attempt is talking to it waits with its acquired
/// socket and sends nothing. If the holder succeeds, the waiter is reported
/// `Lost` and closes its socket; only a failed holder lets the waiter start
/// its own handshake, so the target never sees duplicate CONNECTs. A
/// `hedge_delay` too large for the monotonic clock (e.g. `Duration::MAX`)
/// arms no hedge timer and behaves as "never hedge".
///
/// Every normally completed launched attempt is reported exactly once. The
/// winner and failures observed before it have `after_win == false`; the
/// detached drain reports remaining results with `after_win == true`. A
/// callback panic unwinds the caller and may prevent later callbacks.
/// Unlaunched candidates produce no reports. Dropping this future before a
/// winner cancels its coordinator and aborts its `JoinSet`; after a winner the
/// drain is detached and continues independently.
///
/// # Errors
///
/// Returns neutral [`HedgeError`] when no candidate establishes a tunnel. It
/// records the number launched and the last completed connection error. Empty
/// input returns zero attempts and no last error.
pub async fn connect_hedged<F>(
    candidates: &[Arc<ProxyConfig>],
    target_addr: &str,
    pool: &Arc<ProxyPool>,
    tls_connector: Option<&TlsConnector>,
    opts: &HedgeOptions,
    on_attempt: F,
) -> Result<Hedged, HedgeError>
where
    F: Fn(&AttemptReport) + Send + Sync + 'static,
{
    if candidates.is_empty() {
        return Err(HedgeError {
            attempts: 0,
            last: None,
        });
    }
    let race = Arc::new(RaceState::default());
    let callback: Arc<dyn Fn(&AttemptReport) + Send + Sync> = Arc::new(on_attempt);
    let target = target_addr.to_owned();
    let pool = Arc::clone(pool);
    #[cfg(feature = "tls")]
    let tls = tls_connector.cloned().map(Arc::new);
    #[cfg(not(feature = "tls"))]
    let tls = {
        let _ = tls_connector;
        None
    };
    let mut pending = candidates.iter().cloned().enumerate();
    let mut running = JoinSet::new();
    let mut launched = Vec::<Arc<ProxyConfig>>::new();
    let mut last = None;
    // Some(deadline) arms the hedge timer; `None` arms nothing.
    let mut hedge_at = None;

    loop {
        if running.is_empty() {
            let Some((index, proxy)) = pending.next() else {
                return Err(HedgeError {
                    attempts: launched.len(),
                    last,
                });
            };
            launch(
                &mut running,
                &mut launched,
                index,
                proxy,
                race.clone(),
                target.clone(),
                pool.clone(),
                opts.handshake_timeout,
                tls.clone(),
            );
            hedge_at = hedge_deadline(opts, pending.len());
        }
        tokio::select! {
            joined = running.join_next() => {
                let Some(Ok(finished)) = joined else { continue };
                match finished.result {
                    Ok(stream) => {
                        let winner = finished.index;
                        race.won.store(true, Ordering::Release);
                        callback(&AttemptReport { index: winner, proxy: launched[winner].clone(), elapsed: finished.elapsed, outcome: AttemptOutcome::Won, after_win: false });
                        if !running.is_empty() {
                            tokio::spawn(drain(running, launched, callback.clone()));
                        }
                        return Ok(Hedged { stream, winner });
                    }
                    Err(AttemptFailure::Failed(error)) => {
                        let report = AttemptReport { index: finished.index, proxy: launched[finished.index].clone(), elapsed: finished.elapsed, outcome: AttemptOutcome::Failed(error), after_win: false };
                        callback(&report);
                        let AttemptReport { outcome: AttemptOutcome::Failed(error), .. } = report else { unreachable!() };
                        last = Some(error);
                    }
                    Err(AttemptFailure::Lost) => callback(&AttemptReport { index: finished.index, proxy: launched[finished.index].clone(), elapsed: finished.elapsed, outcome: AttemptOutcome::Lost, after_win: false }),
                }
            }
            _ = async {
                match hedge_at {
                    Some(at) => tokio::time::sleep_until(at).await,
                    None => std::future::pending().await,
                }
            }, if !opts.hedge_delay.is_zero() && pending.len() > 0 => {
                hedge_at = hedge_deadline(opts, pending.len());
                // A tick does not launch beside a handshaking attempt.
                let slot_busy = race.handshake_slot.try_lock().is_err();
                if !slot_busy {
                    if let Some((index, proxy)) = pending.next() {
                        launch(&mut running, &mut launched, index, proxy, race.clone(), target.clone(), pool.clone(), opts.handshake_timeout, tls.clone());
                    }
                }
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn launch(
    running: &mut JoinSet<Finished>,
    launched: &mut Vec<Arc<ProxyConfig>>,
    index: usize,
    proxy: Arc<ProxyConfig>,
    race: Arc<RaceState>,
    target: String,
    pool: Arc<ProxyPool>,
    timeout: Duration,
    tls: Option<Arc<TlsConnector>>,
) {
    launched.push(proxy.clone());
    running.spawn(async move {
        let started = Instant::now();
        let result = attempt(&race, &proxy, &target, &pool, timeout, tls).await;
        Finished {
            index,
            result,
            elapsed: started.elapsed(),
        }
    });
}
