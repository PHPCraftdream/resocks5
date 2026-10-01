//! ## Lifecycle
//!
//! - At startup `spawn_refill_for(proxy)` launches one task per unique
//!   `(host, port)` upstream (creation is atomic — concurrent callers
//!   race through a single `DashMap::entry`, so exactly one task per
//!   key exists). Each task keeps its own queue topped up to
//!   `spare_per_proxy`.
//! - On `checkout`, we pop one socket. If its age exceeds
//!   `max_session_age_sec` (defends against silent idle-disconnects on
//!   the proxy side), or a non-blocking probe shows the peer already
//!   closed or broke the socket while it sat in the queue, we discard
//!   it and pop the next. The refill task notices the queue is below
//!   target and reconnects. Draining the queue this way lets
//!   `acquire` fall through to a fresh connect, so a dead spare never
//!   becomes the caller's hard failure while the upstream is still
//!   reachable.
//! - On a checkout that finds the queue empty (or all stale), the
//!   caller falls back to a fresh `TcpStream::connect`. The pool is a
//!   best-effort accelerator, never a hard dependency.
//! - `forget(proxy)` tears down one endpoint eagerly: it removes the
//!   `(host, port)` entry from the spare map (dropping its queued
//!   spares) and from the cap map, and aborts that endpoint's refill
//!   task. Without it, endpoints only disappear when the pool drops.
//!   Endpoints therefore live until `forget` or the pool's drop.
//! - Dropping the pool aborts its refill tasks — no task outlives the
//!   pool it serves.
//!
//! ## Per-upstream concurrent-connection cap
//!
//! A `Semaphore` is kept per `(host, port)`. Pre-warmed spares take
//! their permit BEFORE connecting, so `max_per_upstream` bounds REAL
//! live TCP connections (spares + active) per upstream, and on
//! `acquire` the spare's already-held permit travels with the
//! connection instead of a second one being reserved. A fresh
//! fallback `connect` first takes one permit. The permit is held
//! inside the returned `UpstreamStream` and released when that stream
//! is dropped. The cap
//! defends the upstream provider's per-account / per-IP connection
//! limit — without it a burst of client requests opens hundreds of
//! sockets in parallel, the provider blocks our IP or account, and
//! every subsequent SOCKS5 handshake times out for the duration of
//! their cool-down (observed symptom: 10-second handshake timeouts on
//! every direct attempt, while via-Tor still works because each Tor
//! circuit sources from a different exit IP).
//!
//! `forget` removes a whole endpoint: permits already
//! handed out keep their own `Arc<Semaphore>` clone and release
//! normally when their connection drops, but a later acquire for the
//! same endpoint creates a FRESH semaphore (a fresh cap budget) —
//! outstanding permits no longer count against the new one.
//!
//! Gate-tunneled connections additionally hold a socket-less permit
//! for the inner proxy (see `reserve_permit`), so direct traffic and
//! gate-routed traffic draw on the same cap.

use std::io;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crossbeam_queue::ArrayQueue;
use dashmap::DashMap;
use tokio::net::TcpStream;
use tokio::sync::{Notify, OwnedSemaphorePermit, Semaphore};
use tokio::time::{sleep, timeout};

use crate::connect::tcp_dial::tcp_dial;
use crate::error::ConnectError;
use crate::pool::PoolConfig;
use crate::types::ProxyConfig;

mod error;
mod stream;

pub use error::AtCapacity;
pub use stream::UpstreamStream;

#[cfg(test)]
mod tests;

/// One pre-warmed TCP socket plus its creation timestamp (used to
/// reject stale entries on `checkout`) and the per-upstream cap
/// permit it was granted before connecting — carrying the permit in
/// the struct is what makes spares count against
/// `max_per_upstream`, and lets the permit travel with the
/// connection on `acquire` instead of being re-reserved.
struct PreWarmed {
    stream: TcpStream,
    created_at: Instant,
    permit: OwnedSemaphorePermit,
}

/// Per-proxy state: the queue itself plus a `Notify` used by the
/// refill task to react instantly when a slot frees up.
struct ProxySpares {
    queue: ArrayQueue<PreWarmed>,
    /// `notify_one` on every successful pop so the refill task wakes
    /// immediately and reconnects rather than discovering the empty
    /// slot on its next periodic timer.
    notify: Notify,
}

/// `(host, port)` key — auth differences live above the TCP layer
/// and don't affect socket reuse, and the per-account/per-IP quota
/// that the semaphore defends is keyed the same way.
type ProxyKey = (String, u16);

/// `host:port` for log messages — upstream credentials (both user
/// and password) are intentionally NOT included, since the username
/// half of a SOCKS5 cred is itself sensitive enough to keep out of
/// log files, shell scrollback, and shipped diagnostics.
pub(crate) fn upstream_endpoint(proxy: &ProxyConfig) -> String {
    format!("{}:{}", proxy.host, proxy.port)
}

/// Non-blocking liveness probe for a queued spare.
///
/// A spare is worthless when the upstream already closed it — the
/// upstream's own idle/greeting timeout can fire well before our
/// `max_session_age_sec` — because the next handshake on such a socket
/// fails on its first read or write. `try_read` never blocks and never
/// waits: `Ok(0)` means the peer's FIN has already arrived, an error
/// means the socket is broken (RST or worse), and `WouldBlock` means
/// the connection is alive with nothing pending. Data already queued
/// (`Ok(n > 0)`) also disqualifies the spare: sockets enter the queue
/// before any handshake bytes are written, so any pending byte is
/// unexpected and a consumed byte cannot be put back — the socket
/// cannot serve a clean handshake either way.
///
/// This only narrows the race window; a FIN arriving after the probe
/// and before first use is still seen by the caller. That residual
/// race is inherent to pre-connect pools — the probe removes the
/// common case of a socket that died long ago.
fn spare_is_dead(stream: &TcpStream) -> bool {
    let mut probe = [0u8; 1];
    match stream.try_read(&mut probe) {
        Err(e) if e.kind() == io::ErrorKind::WouldBlock => false,
        // EOF (peer closed), socket error, or unexpected pending data.
        _ => true,
    }
}

/// Pre-connect TCP pool plus a per-upstream concurrency cap.
///
/// See the module docs for the full lifecycle. Construct with
/// [`ProxyPool::new`]; `connect_timeout` and the per-upstream cap are fixed
/// for the pool's lifetime, while the [`PoolConfig`] fields (master switch,
/// spares, max age) are read via [`enabled`](ProxyPool::enabled).
pub struct ProxyPool {
    config: PoolConfig,
    /// Maximum time to wait for a TCP `connect` to an upstream. Without
    /// this cap a dead proxy stalls callers for the full kernel SYN
    /// timeout (tens of seconds on Linux). Applied to both the
    /// fallback connect in `acquire` and the background refill loop.
    connect_timeout: Duration,
    /// Hard cap on concurrent in-flight TCP connections per upstream
    /// `(host, port)`. Enforced via `upstream_caps`.
    max_per_upstream: usize,
    pools: DashMap<ProxyKey, Arc<ProxySpares>>,
    /// Per-upstream semaphores. Lazily created on first `acquire` for
    /// each `(host, port)` and kept alive (cheap — one tiny Semaphore
    /// per upstream forever) so concurrent acquires share the same
    /// permit pool.
    upstream_caps: DashMap<ProxyKey, Arc<Semaphore>>,
    /// Background refill tasks, one per `(host, port)`, keyed by the
    /// same endpoint key as `pools` so `forget` can abort a single
    /// endpoint's task — otherwise a forgotten endpoint would keep
    /// opening sockets forever. `Drop` aborts all of them. A `std`
    /// Mutex suffices: the guard is only ever held synchronously,
    /// never across an await.
    refill_tasks:
        std::sync::Mutex<std::collections::HashMap<ProxyKey, tokio::task::JoinHandle<()>>>,
}

impl ProxyPool {
    /// Create a new pool.
    ///
    /// `connect_timeout` bounds every TCP `connect` (both the fallback in
    /// [`acquire`](ProxyPool::acquire) and the background refill loop).
    /// `max_per_upstream` caps concurrent live connections per `(host, port)`;
    /// `0` is clamped up to `1` (a zero-permit pool would brick every acquire).
    pub fn new(config: PoolConfig, connect_timeout: Duration, max_per_upstream: usize) -> Self {
        // Tokio's Semaphore requires at least one permit; treat `0`
        // configuration as "1" to avoid hard-bricking the pool.
        let max_per_upstream = max_per_upstream.max(1);
        Self {
            config,
            connect_timeout,
            max_per_upstream,
            pools: DashMap::new(),
            upstream_caps: DashMap::new(),
            refill_tasks: std::sync::Mutex::new(std::collections::HashMap::new()),
        }
    }

    /// Abort every refill task this pool spawned. Called on drop so
    /// a discarded pool stops opening sockets in the background.
    /// `abort()` is sync and non-blocking; cancellation drops the
    /// task's in-flight permit/stream locals at its await point. The
    /// lock is recovered from poisoning rather than panicking — Drop
    /// must never panic.
    fn abort_refill_tasks(&self) {
        let mut tasks = self
            .refill_tasks
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for (_, handle) in tasks.drain() {
            handle.abort();
        }
    }

    /// Convenience for `establish_connection` / `use_gate` to skip the
    /// pool path entirely when disabled.
    pub fn enabled(&self) -> bool {
        self.config.enabled
    }

    /// Get-or-create the semaphore that caps concurrent live
    /// connections to this `(host, port)`. First-acquire for a new
    /// upstream allocates the Semaphore inline.
    fn upstream_semaphore(&self, host: &str, port: u16) -> Arc<Semaphore> {
        let key = (host.to_string(), port);
        if let Some(s) = self.upstream_caps.get(&key) {
            return s.value().clone();
        }
        // Race-safe insert: another caller may have populated the
        // entry between our get() and entry().or_insert_with(). DashMap
        // serialises the entry, so whichever lands first wins and the
        // other reads it back.
        self.upstream_caps
            .entry(key)
            .or_insert_with(|| Arc::new(Semaphore::new(self.max_per_upstream)))
            .value()
            .clone()
    }

    /// Take one slot from `(host, port)`'s concurrency-cap semaphore
    /// without opening a TCP connection. If idle spares hold every slot,
    /// discard one spare and transfer its permit to the active tunnel.
    /// The single choke point through which every path
    /// accounts a node of a tunnel against `max_per_upstream`:
    /// `acquire` calls it for the socket it opens, and the gate path
    /// (`establish_connection::use_gate`) calls it for the inner proxy
    /// of a chain — that tunnel holds a live connection to the proxy
    /// through the gate, so it must consume the same cap as a direct
    /// connection even though no dedicated socket exists for it.
    ///
    /// Fails fast with an [`AtCapacity`] error when the cap is hit;
    /// never waits. The caller MUST keep the returned permit alive for
    /// as long as the connection it accounts is alive —
    /// [`UpstreamStream::attach_permit`] is the intended way for
    /// tunneled hops.
    ///
    /// # Errors
    ///
    /// Returns [`ConnectError::AtCapacity`] when the endpoint's cap is
    /// already fully consumed by live connections and no spare's permit
    /// can be reclaimed.
    pub fn reserve_permit(
        &self,
        proxy: &ProxyConfig,
    ) -> Result<OwnedSemaphorePermit, ConnectError> {
        let sem = self.upstream_semaphore(&proxy.host, proxy.port);
        if let Ok(permit) = sem.clone().try_acquire_owned() {
            return Ok(permit);
        }
        if let Some(spares) = self.pools.get(&(proxy.host.clone(), proxy.port)) {
            if let Some(spare) = spares.queue.pop() {
                let PreWarmed { stream, permit, .. } = spare;
                drop(stream);
                spares.notify.notify_one();
                return Ok(permit);
            }
        }
        // A concurrent checkout may have released an expired spare's slot.
        sem.try_acquire_owned().map_err(|_| {
            ConnectError::AtCapacity(AtCapacity {
                host: proxy.host.clone(),
                port: proxy.port,
            })
        })
    }

    /// "Give me a TCP socket to this proxy, fast if you can" — the
    /// standard entry point used by every connect path.
    ///
    /// Two-step acquisition:
    /// 1. Pop a pre-warmed socket. Its already-held cap permit
    ///    travels with the connection — no second reserve (that
    ///    would silently over-tighten the cap). This succeeds even
    ///    when the semaphore is empty, which is correct: the spare
    ///    genuinely holds a real socket + permit.
    /// 2. No spare available: take one permit from the per-upstream
    ///    semaphore (fail fast with `AtCapacity` when the cap is
    ///    hit) and open a fresh `TcpStream::connect` under
    ///    `connect_timeout`.
    ///
    /// Returns `UpstreamStream` so the permit lives exactly as long as
    /// the socket and the slot is released on drop.
    ///
    /// # Errors
    ///
    /// Returns [`ConnectError::AtCapacity`] when the cap is hit, and
    /// [`ConnectError::Io`] / [`ConnectError::Timeout`]
    /// (`TimeoutKind::PoolConnect`) when the fresh TCP connect fails.
    pub async fn acquire(&self, proxy: &ProxyConfig) -> Result<UpstreamStream, ConnectError> {
        // Step 1: pre-warmed socket — its permit comes with it.
        if let Some(pw) = self.checkout_prewarmed(proxy) {
            return Ok(UpstreamStream {
                stream: pw.stream,
                _permit: Some(pw.permit),
                extra_permits: Vec::new(),
            });
        }

        // Step 2: fresh connect under the cap.
        let permit = self.reserve_permit(proxy)?;
        let stream = tcp_dial(proxy, self.connect_timeout).await?;
        Ok(UpstreamStream {
            stream,
            _permit: Some(permit),
            extra_permits: Vec::new(),
        })
    }

    /// Try to take a pre-warmed socket (with its bundled cap permit)
    /// for the given proxy. Returns `None` when the pool is disabled,
    /// no entry exists yet, the queue is empty, every entry has aged
    /// out, or every entry fails the liveness probe (the peer already
    /// closed or broke the socket while it sat in the queue).
    fn checkout_prewarmed(&self, proxy: &ProxyConfig) -> Option<PreWarmed> {
        if !self.config.enabled {
            return None;
        }
        let key = (proxy.host.clone(), proxy.port);
        let spares = self.pools.get(&key)?.value().clone();
        let max_age = Duration::from_secs(self.config.max_session_age_sec);
        let now = Instant::now();
        // Drop stale or already-dead entries lazily on checkout. Each
        // pop notifies the refill task so it can replenish whatever we
        // drained; draining the whole queue hands `acquire` its fresh-
        // connect fallback instead of a dead socket.
        loop {
            let Some(pw) = spares.queue.pop() else {
                spares.notify.notify_one();
                return None;
            };
            spares.notify.notify_one();
            if now.saturating_duration_since(pw.created_at) <= max_age && !spare_is_dead(&pw.stream)
            {
                return Some(pw);
            }
            // stale or dead — drop (releasing its socket and cap
            // permit) and try the next.
        }
    }

    /// Take a pre-warmed socket for the given proxy WITH its bundled
    /// cap permit: the returned [`UpstreamStream`] holds the permit
    /// until it is dropped, exactly like the pre-warmed branch of
    /// [`acquire`](ProxyPool::acquire), so the live connection keeps
    /// counting against `max_per_upstream` for as long as the caller
    /// keeps it. This is the default — the unguarded variant is an
    /// escape hatch.
    pub fn checkout(&self, proxy: &ProxyConfig) -> Option<UpstreamStream> {
        self.checkout_prewarmed(proxy).map(|pw| UpstreamStream {
            stream: pw.stream,
            _permit: Some(pw.permit),
            extra_permits: Vec::new(),
        })
    }

    /// Like [`checkout`](ProxyPool::checkout) but returns the bare
    /// [`TcpStream`], deliberately releasing the cap permit at the
    /// call: the returned socket is NOT counted against
    /// `max_per_upstream` while it lives, so it is possible to exceed
    /// the per-upstream cap with this API. Escape hatch only, for
    /// callers that do their own accounting.
    pub fn checkout_unguarded(&self, proxy: &ProxyConfig) -> Option<TcpStream> {
        self.checkout_prewarmed(proxy).map(|pw| pw.stream)
    }

    /// Forget one endpoint: remove its spare queue (dropping the
    /// queued spares), its per-upstream cap semaphore, and abort its
    /// refill task. Idempotent — an unknown `(host, port)` is a no-op.
    ///
    /// Tradeoff: permits already handed out for this endpoint keep
    /// their own `Arc<Semaphore>` clone and release normally when
    /// their connections drop; but the cap map entry is gone, so the
    /// next acquire for the same endpoint creates a FRESH semaphore
    /// with a full budget — outstanding old permits no longer count
    /// against it, and the two generations do not share accounting.
    ///
    /// Endpoints otherwise live until `forget` or until the pool
    /// drops; there is no automatic shrinking.
    pub fn forget(&self, proxy: &ProxyConfig) {
        let key = (proxy.host.clone(), proxy.port);
        self.pools.remove(&key);
        self.upstream_caps.remove(&key);
        if let Some(handle) = self
            .refill_tasks
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&key)
        {
            handle.abort();
        }
    }

    /// Launch a long-lived refill task for `proxy`. Idempotent: if a
    /// task is already running for the same `(host, port)`, this is a
    /// no-op. Creation is atomic — concurrent callers race through a
    /// single `DashMap::entry`, so exactly one constructs the
    /// `ProxySpares` and spawns; at most one refill task per
    /// `(host, port)` exists for the pool's lifetime. The task handle
    /// is retained and aborted when the pool drops.
    pub fn spawn_refill_for(&self, proxy: Arc<ProxyConfig>) {
        if !self.config.enabled {
            return;
        }
        let key = (proxy.host.clone(), proxy.port);
        let target = self
            .config
            .spare_per_proxy
            .max(1)
            .min(self.max_per_upstream);
        let max_age = Duration::from_secs(self.config.max_session_age_sec);
        // Race-safe get-or-create: DashMap serialises the entry, so
        // whichever caller lands first constructs the ProxySpares and
        // spawns the refill task; losers read the same Arc back and
        // return. No await inside the closure — it's a sync fn.
        let mut won_race = false;
        let spares = self
            .pools
            .entry(key.clone())
            .or_insert_with(|| {
                won_race = true;
                Arc::new(ProxySpares {
                    queue: ArrayQueue::new(target),
                    notify: Notify::new(),
                })
            })
            .value()
            .clone();
        if !won_race {
            return; // Already running for this proxy.
        }

        // The refill loop:
        // - top up to `target` while space available
        // - on connect failure, exponential backoff (capped at 10s) so
        //   a dead proxy doesn't burn CPU
        // - then wait either for a `notify` (slot freed by checkout)
        //   or for `max_age` (time to proactively recycle stale)
        let connect_timeout = self.connect_timeout;
        // Cap semaphore captured at spawn time: every pre-warmed
        // socket reserves a permit BEFORE connecting, so spares +
        // active together never exceed `max_per_upstream`.
        let sem = self.upstream_semaphore(&proxy.host, proxy.port);
        let handle = tokio::spawn(async move {
            let mut backoff = Duration::from_millis(100);
            loop {
                while spares.queue.len() < target {
                    // Reserve a cap slot first; when the cap is full
                    // there is no point opening a socket we must not
                    // keep — back off and retry.
                    let Ok(permit) = sem.clone().try_acquire_owned() else {
                        sleep(backoff).await;
                        backoff = (backoff * 2).min(Duration::from_secs(10));
                        continue;
                    };
                    match timeout(
                        connect_timeout,
                        TcpStream::connect((proxy.host.as_str(), proxy.port)),
                    )
                    .await
                    {
                        Ok(Ok(stream)) => {
                            let pw = PreWarmed {
                                stream,
                                created_at: Instant::now(),
                                permit,
                            };
                            // Best-effort push: queue may have filled
                            // up while we were connecting (concurrent
                            // refill iteration succeeded first), in
                            // which case we drop this socket — and
                            // with it the cap permit.
                            let _ = spares.queue.push(pw);
                            backoff = Duration::from_millis(100);
                        }
                        // Both kinds of failure (connect error or
                        // timeout) feed the same exponential backoff
                        // so a dead proxy doesn't burn CPU on retries.
                        // Release the reserved slot first — a dead or
                        // slow proxy must not pin cap slots while it
                        // backs off.
                        Ok(Err(_)) | Err(_) => {
                            drop(permit);
                            sleep(backoff).await;
                            backoff = (backoff * 2).min(Duration::from_secs(10));
                        }
                    }
                }
                // Queue full. Wait for either a checkout (notify) or
                // the max-age deadline (then we recycle whatever sits
                // in the queue at that point).
                tokio::select! {
                    _ = spares.notify.notified() => {}
                    _ = sleep(max_age) => {
                        // Drain everything older than max_age. A simple
                        // pop-and-rebuild — small target so the cost
                        // is microseconds.
                        let now = Instant::now();
                        let mut keepers: Vec<PreWarmed> = Vec::new();
                        while let Some(pw) = spares.queue.pop() {
                            if now.saturating_duration_since(pw.created_at) <= max_age {
                                keepers.push(pw);
                            }
                        }
                        for pw in keepers {
                            let _ = spares.queue.push(pw);
                        }
                    }
                }
            }
        });
        self.refill_tasks
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(key, handle);
    }
    /// Introspection for tests: `(pools has key, caps has key,
    /// refill task running)` for this endpoint.
    #[cfg(test)]
    fn endpoint_state(&self, proxy: &ProxyConfig) -> (bool, bool, bool) {
        let key = (proxy.host.clone(), proxy.port);
        (
            self.pools.contains_key(&key),
            self.upstream_caps.contains_key(&key),
            self.refill_tasks
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .contains_key(&key),
        )
    }
}

impl Drop for ProxyPool {
    fn drop(&mut self) {
        self.abort_refill_tasks();
    }
}
