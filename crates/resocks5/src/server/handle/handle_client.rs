use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use anyhow::anyhow;
use regex::RegexSet;
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use tokio::time::{timeout, Instant};

use tokio_rustls::TlsConnector;

use crate::auth::AuthState;
use crate::config::{NetworkConfig, TlsFragmentConfig};
use crate::http_proxy::handle_http_client;
use crate::logger::Logger;
use crate::server::handle_socks5_client;
use resocks5_net::pool::ProxyPool;
use resocks5_net::rotator::ProxyRotator;

/// Time still left in the shared client-protocol budget at `deadline`.
///
/// The budget is ONE absolute deadline anchored when the connection is
/// accepted (see `handle_client`); every client-facing stage — the
/// protocol detection, the SOCKS5/HTTP handshake, and the
/// recovery peek — spends only its remainder, never a fresh
/// full-length timer. After the deadline has passed this returns
/// `Duration::ZERO`, which makes the stage's `timeout` fire
/// immediately instead of silently granting a new budget.
pub(crate) fn remaining_client_budget(deadline: Instant) -> Duration {
    deadline.saturating_duration_since(Instant::now())
}

/// Run one client-facing stage under the remainder of the shared
/// accept-anchored budget, refusing to enter the stage at all once the
/// deadline has passed.
///
/// A bare `timeout(Duration::ZERO, op)` is not such a guard: Tokio's
/// `Timeout::poll` polls the wrapped future FIRST and only consults the
/// timer when that poll returns `Pending`, so an already-Ready
/// operation completes normally even with a zero budget — and a
/// Pending first poll may already have performed side effects (a
/// buffered read, a response write, an auth check whose
/// `spawn_blocking` claim outlives cancellation). This helper checks
/// the remainder BEFORE the first poll: with an expired deadline it
/// returns `Err(Duration::ZERO)` without polling `op` even once. On a
/// live budget the stage runs under `timeout` exactly like the bare
/// form it replaces; the `Err(Duration)` payload — the budget as of
/// stage entry, `Duration::ZERO` in the already-expired case — lets
/// callers keep their stage-specific "…timed out with only Ns left…"
/// messages.
///
/// cancel-safety: on `Err(Duration::ZERO)` the stage was never polled;
/// on a live-budget exhaustion the stage is dropped mid-flight, the
/// same cancellation contract as the bare `timeout` form.
pub(crate) async fn run_phase_in_client_budget<F, T>(
    deadline: Instant,
    op: F,
) -> Result<anyhow::Result<T>, Duration>
where
    F: Future<Output = anyhow::Result<T>>,
{
    let budget = remaining_client_budget(deadline);
    if budget.is_zero() {
        return Err(budget);
    }
    match timeout(budget, op).await {
        Ok(result) => Ok(result),
        Err(_) => Err(budget),
    }
}

/// Parse/authenticate once under the listener-supplied accept deadline, then route egress.
///
/// cancel-safe: NO — owns the client stream and closes it on failure/cancellation;
/// admitted authentication persistence may finish after its waiter is dropped.
#[allow(clippy::too_many_arguments)]
pub async fn handle_client(
    mut client_stream: TcpStream,
    auth: &Arc<AuthState>,
    gate_rotator: &Option<Arc<ProxyRotator>>,
    v6_rotator: &Option<Arc<ProxyRotator>>,
    v4_rotator: &Option<Arc<ProxyRotator>>,
    logger: &Arc<Logger>,
    banned: &Arc<RegexSet>,
    pool: &Arc<ProxyPool>,
    frag: &Arc<TlsFragmentConfig>,
    network: &Arc<NetworkConfig>,
    tls_connector: Option<&TlsConnector>,
    direct_limiter: &Arc<Semaphore>,
    client_deadline: Instant,
) -> anyhow::Result<()> {
    #[cfg(test)]
    stage_probe::emit("client_handler_started");
    let options = resocks5_net::server::ServerOptions::new(
        client_deadline,
        auth.allow_anonymous,
        !auth.is_empty(),
    );
    let auth_state = auth.clone();
    let req = resocks5_net::server::accept(
        &mut client_stream,
        &options,
        move |credentials| async move {
            auth_state
                .verify_async(credentials.username(), credentials.password())
                .await
        },
    )
    .await?;
    match req.protocol() {
        resocks5_net::server::Protocol::Socks5 => {
            handle_socks5_client(
                client_stream,
                req,
                auth,
                gate_rotator,
                v6_rotator,
                v4_rotator,
                logger,
                banned,
                pool,
                frag,
                network,
                tls_connector,
                direct_limiter,
                client_deadline,
            )
            .await
        }
        resocks5_net::server::Protocol::Http => {
            handle_http_client(
                client_stream,
                req,
                auth,
                gate_rotator,
                v6_rotator,
                v4_rotator,
                logger,
                banned,
                pool,
                frag,
                network,
                tls_connector,
                direct_limiter,
                client_deadline,
            )
            .await
        }
        other => Err(anyhow!("unsupported inbound protocol: {other:?}")),
    }
}

/// Test-only observation seam for the paused-clock deadline tests in
/// [`tests`]: a process-global sink reports only `client_handler_started`,
/// immediately before the handler spends the listener-supplied deadline.
/// It does not report deadline anchoring or protocol routing. Compiles
/// to nothing outside `#[cfg(test)]` builds. Global, but per-instance
/// safe: each test installs its OWN channel (overwriting any stale sink)
/// while holding the test module's `STAGE_PROBE_SLOT` mutex, so no two
/// sink-using tests can interleave.
#[cfg(test)]
pub(crate) mod stage_probe {
    use std::sync::{Mutex, MutexGuard, PoisonError};

    use tokio::sync::mpsc::UnboundedSender;

    static SINK: Mutex<Option<UnboundedSender<&'static str>>> = Mutex::new(None);

    fn sink() -> MutexGuard<'static, Option<UnboundedSender<&'static str>>> {
        SINK.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Replace the current sink with `tx`; a previous test's undelivered
    /// events stay in that test's own receiver and are dropped with it.
    pub(crate) fn install(tx: UnboundedSender<&'static str>) {
        *sink() = Some(tx);
    }

    /// Detach the sink; later `emit`s are silently dropped.
    pub(crate) fn remove() {
        *sink() = None;
    }

    /// Never blocks and never fails: drops the event when no sink is
    /// installed (an unbounded send only buffers).
    pub(crate) fn emit(stage: &'static str) {
        if let Some(tx) = sink().as_ref() {
            let _ = tx.send(stage);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::task::{Context, Poll};
    use std::time::Duration;

    use tokio::io::AsyncWriteExt;
    use tokio::net::{TcpListener, TcpStream};
    use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver};
    use tokio::sync::Semaphore;

    use super::*;
    use crate::config::{NetworkConfig, TlsFragmentConfig};
    use resocks5_net::rotator::ProxyRotator;

    fn test_auth() -> Arc<crate::auth::AuthState> {
        Arc::new(
            crate::auth::AuthState::build(
                &crate::config::AuthConfig {
                    allow_anonymous: true,
                },
                &crate::config::UsersConfig { users: Vec::new() },
                "unused",
            )
            .unwrap(),
        )
    }

    fn test_logger() -> Arc<crate::logger::Logger> {
        let (tx, _rx) = tokio::sync::mpsc::channel::<crate::logger::ELog>(64);
        Arc::new(crate::logger::Logger::new(
            tx,
            crate::logger::LogConfig::default(),
        ))
    }

    /// Serializes the two tests that use the process-global
    /// [`stage_probe`](super::stage_probe) sink: cargo runs one file's
    /// tests on parallel OS threads by default, and the sink is global.
    /// A tokio (async) mutex because the guard is held across `.await`s.
    static STAGE_PROBE_SLOT: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    /// Event-driven replacement for the old fixed-iteration
    /// `anchor_first_poll` settle loop: block the TEST task until the
    /// handler has really reached the expected stage, spinning on
    /// `try_recv` + `yield_now` + a real 1 ms `thread::sleep`. Neither
    /// await in this loop is a timer, so the ready queue is never empty
    /// and the paused virtual clock cannot auto-advance while we settle;
    /// the loop runs until the EXACT expected event arrives — or, to
    /// convert a hang into a loud failure, until a generous 10 s
    /// REAL-time deadline expires (real `std::time::Instant`: the tokio
    /// clock is paused in these tests).
    async fn wait_for_stage_event(
        rx: &mut UnboundedReceiver<&'static str>,
        expected: &'static str,
    ) {
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        loop {
            match rx.try_recv() {
                Ok(stage) if stage == expected => return,
                Ok(_) => {} // an earlier stage event; keep waiting
                Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => {
                    panic!("stage-probe channel closed before seeing {expected:?}")
                }
                Err(tokio::sync::mpsc::error::TryRecvError::Empty) => {}
            }
            tokio::task::yield_now().await;
            std::thread::sleep(Duration::from_millis(1));
            assert!(
                std::time::Instant::now() < deadline,
                "timed out waiting 10 s (real time) for the {expected:?} stage event"
            );
        }
    }

    /// Write `data` to `stream` without ever awaiting a plain
    /// `write_all` future: spin on `try_write` with `yield_now` + a real
    /// 1 ms sleep. Awaiting the plain future can park the runtime with
    /// "no ready work" while real bytes are still in flight, and
    /// paused-clock auto-advance would then jump to the next virtual
    /// timer before the peer even observes the write — the exact R6-07
    /// flake. This loop keeps the ready queue non-empty, structurally
    /// preventing that park.
    async fn park_free_write_all(stream: &TcpStream, mut data: &[u8]) {
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while !data.is_empty() {
            match stream.try_write(data) {
                Ok(0) => panic!("try_write reported 0 bytes written"),
                Ok(n) => data = &data[n..],
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    tokio::task::yield_now().await;
                    std::thread::sleep(Duration::from_millis(1));
                }
                Err(e) => panic!("park-free write failed: {e}"),
            }
            assert!(
                std::time::Instant::now() < deadline,
                "park-free write did not complete within 10 s (real time)"
            );
        }
    }

    /// Read exactly `buf.len()` bytes from `stream` without ever
    /// awaiting a plain `read_exact` future; same park-free spin as
    /// [`park_free_write_all`]. Loopback may deliver partial reads, so
    /// this accumulates into `buf` like `read_exact` does.
    async fn park_free_read_exact(stream: &TcpStream, mut buf: &mut [u8]) {
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while !buf.is_empty() {
            match stream.try_read(buf) {
                Ok(0) => panic!("unexpected EOF during park-free read"),
                Ok(n) => buf = &mut buf[n..],
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    tokio::task::yield_now().await;
                    std::thread::sleep(Duration::from_millis(1));
                }
                Err(e) => panic!("park-free read failed: {e}"),
            }
            assert!(
                std::time::Instant::now() < deadline,
                "park-free read did not complete within 10 s (real time)"
            );
        }
    }

    /// R5-02 regression: a first byte that arrives just before the end of
    /// the client-protocol budget must not buy the SOCKS5 handshake a
    /// fresh full-length budget. The dispatcher's peek consumes the first
    /// 90% of a 1 s budget; the subsequently stalled handshake has only
    /// the remaining ~100 ms and must time out at the accept-anchored
    /// deadline (~1 s of virtual time), not at 1.9 s.
    #[tokio::test(start_paused = true)]
    async fn slow_first_byte_does_not_buy_a_fresh_handshake_budget() {
        let _probe_slot = STAGE_PROBE_SLOT.lock().await;
        let (stage_tx, mut stage_rx) = unbounded_channel();
        stage_probe::install(stage_tx);
        let auth = test_auth();
        let logger = test_logger();
        let banned = Arc::new(regex::RegexSet::empty());
        let pool = Arc::new(resocks5_net::pool::ProxyPool::new(
            Default::default(),
            Duration::from_secs(2),
            4,
        ));
        let network = Arc::new(NetworkConfig {
            client_protocol_timeout_sec: 1,
            handshake_timeout_sec: 2,
            ..Default::default()
        });
        let frag = Arc::new(TlsFragmentConfig::default());
        let direct_limiter = Arc::new(Semaphore::new(8));
        let no_rotator: Option<Arc<ProxyRotator>> = None;

        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        let mut client = TcpStream::connect(addr).await.unwrap();
        let server = l.accept().await.unwrap().0;

        let client_deadline =
            Instant::now() + Duration::from_secs(network.client_protocol_timeout_sec);
        let task = tokio::spawn(async move {
            handle_client(
                server,
                &auth,
                &no_rotator,
                &no_rotator,
                &no_rotator,
                &logger,
                &banned,
                &pool,
                &frag,
                &network,
                None,
                &direct_limiter,
                client_deadline,
            )
            .await
        });

        // Wait until the handler begins spending the supplied deadline.
        // advance does not poll newly spawned tasks.
        wait_for_stage_event(&mut stage_rx, "client_handler_started").await;

        let t0 = tokio::time::Instant::now();
        // Eat 90% of the budget in protocol detection: the first byte only
        // arrives when ~100 ms of the 1 s budget is left.
        tokio::time::advance(Duration::from_millis(900)).await;
        client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        // Observe the method reply on the wire before allowing virtual time
        // to auto-advance: this proves parsing began, without a parser seam.
        let mut method = [0; 2];
        park_free_read_exact(&client, &mut method).await;
        assert_eq!(method, [5, 0]);
        // Method selection completed; CONNECT now stalls with only ~100ms left.

        let result = tokio::time::timeout(Duration::from_secs(30), task)
            .await
            .expect("handler must terminate at the shared deadline")
            .unwrap();
        let elapsed = t0.elapsed();
        let err = result.expect_err("the stalled handshake must fail");
        assert!(matches!(
            err.downcast_ref::<resocks5_net::server::ServerError>(),
            Some(resocks5_net::server::ServerError::Deadline)
        ));
        assert!(
            elapsed >= Duration::from_millis(900),
            "the peek must have consumed ~900 ms first, elapsed {elapsed:?}"
        );
        assert!(
            elapsed <= Duration::from_millis(1200),
            "handshake must inherit only the remaining ~100 ms of the shared budget, not a fresh 1 s (elapsed {elapsed:?})"
        );

        stage_probe::remove();
    }

    /// R5-02 regression: time consumed before recovery must shrink the
    /// recovery budget. After 1.5 s of a 2 s budget is spent on peek +
    /// SOCKS5 handshake, a client that goes silent must hit the recovery
    /// peek timeout at the accept-anchored deadline (~2 s of virtual
    /// time), not receive a fresh 2 s recovery budget (~3.5 s).
    #[tokio::test(start_paused = true)]
    async fn time_spent_before_recovery_shrinks_the_recovery_budget() {
        let _probe_slot = STAGE_PROBE_SLOT.lock().await;
        let (stage_tx, mut stage_rx) = unbounded_channel();
        stage_probe::install(stage_tx);
        let auth = test_auth();
        let logger = test_logger();
        let banned = Arc::new(regex::RegexSet::empty());
        let pool = Arc::new(resocks5_net::pool::ProxyPool::new(
            Default::default(),
            Duration::from_secs(2),
            4,
        ));
        let network = Arc::new(NetworkConfig {
            client_protocol_timeout_sec: 2,
            handshake_timeout_sec: 2,
            ..Default::default()
        });
        let frag = Arc::new(TlsFragmentConfig::default());
        let direct_limiter = Arc::new(Semaphore::new(8));
        let no_rotator: Option<Arc<ProxyRotator>> = None;

        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        let client = TcpStream::connect(addr).await.unwrap();
        let server = l.accept().await.unwrap().0;

        let client_deadline =
            Instant::now() + Duration::from_secs(network.client_protocol_timeout_sec);
        let task = tokio::spawn(async move {
            handle_client(
                server,
                &auth,
                &no_rotator,
                &no_rotator,
                &no_rotator,
                &logger,
                &banned,
                &pool,
                &frag,
                &network,
                None,
                &direct_limiter,
                client_deadline,
            )
            .await
        });

        // Wait until the handler begins spending the supplied deadline.
        // advance does not poll newly spawned tasks.
        wait_for_stage_event(&mut stage_rx, "client_handler_started").await;

        let t0 = tokio::time::Instant::now();
        tokio::time::advance(Duration::from_millis(1500)).await;

        // Complete the whole SOCKS5 handshake instantly (real loopback I/O,
        // no virtual time passes): greeting, anonymous method selection,
        // CONNECT to a bare IPv4 — the recovery branch replies success
        // early and starts the recovery peek with ~500 ms left. (No
        // upstream rotator is configured, so the speculative upstream dial
        // fails immediately and peek_recovery simply keeps waiting for the
        // client.) All of this exchange is park-free
        // (`park_free_write_all`/`park_free_read_exact`): the runtime never
        // finds an empty ready queue while real bytes are in flight, so
        // paused-clock auto-advance cannot race ahead of actual delivery
        // mid-handshake.
        park_free_write_all(&client, &[0x05, 0x01, 0x00]).await;
        let mut method = [0u8; 2];
        park_free_read_exact(&client, &mut method).await;
        assert_eq!(method, [0x05, 0x00]);
        park_free_write_all(
            &client,
            &[0x05, 0x01, 0x00, 0x01, 203, 0, 113, 9, 0x01, 0xBB],
        )
        .await;
        let mut success = [0u8; 10];
        park_free_read_exact(&client, &mut success).await;
        assert_eq!([success[0], success[1]], [0x05, 0x00]);

        // Now the client goes silent: the recovery peek gets only the
        // remaining ~500 ms. A fresh budget would instead hold the
        // client-facing slot until ~3.5 s of virtual time.
        let result = tokio::time::timeout(Duration::from_secs(30), task)
            .await
            .expect("handler must terminate at the shared deadline")
            .unwrap();
        let elapsed = t0.elapsed();
        let error = result.expect_err("the stalled recovery must fail");
        assert!(matches!(
            error.downcast_ref::<resocks5_net::server::ServerError>(),
            Some(resocks5_net::server::ServerError::Deadline)
        ));
        assert!(
            elapsed >= Duration::from_millis(1500),
            "peek + handshake must have consumed ~1.5 s first, elapsed {elapsed:?}"
        );
        assert!(
            elapsed <= Duration::from_millis(2600),
            "recovery must inherit only the remaining ~500 ms of the shared budget, not a fresh 2 s (elapsed {elapsed:?})"
        );

        stage_probe::remove();
    }

    /// R5-02 regression: once the accept-anchored deadline has passed the
    /// remaining budget is ZERO, and a stage wrapped in a ZERO timeout
    /// fails immediately as a timeout instead of hanging or getting a new
    /// budget.
    ///
    /// NOTE: this test alone does NOT distinguish "the stage was started
    /// but stayed pending" from "the stage was never started" — Tokio's
    /// `timeout(ZERO, op)` polls `op` once before the timer fires. The
    /// R6-03 tests below (poll-counting Ready/Pending phases) pin the
    /// never-started property on `run_phase_in_client_budget`.
    #[tokio::test(start_paused = true)]
    async fn expired_deadline_fails_the_next_stage_immediately() {
        let deadline = tokio::time::Instant::now();
        tokio::time::advance(Duration::from_millis(1)).await;
        let budget = remaining_client_budget(deadline);
        assert_eq!(budget, Duration::ZERO);
        let res: Result<(), tokio::time::error::Elapsed> =
            tokio::time::timeout(budget, std::future::pending::<()>()).await;
        assert!(res.is_err(), "a ZERO budget must time out immediately");
    }

    // ── R6-03: the expired-deadline guard must precede the first poll ──

    /// Poll-counting phase that completes on its first poll.
    struct ReadyPhase {
        polls: Arc<AtomicUsize>,
    }

    impl Future for ReadyPhase {
        type Output = anyhow::Result<()>;

        fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
            self.polls.fetch_add(1, Ordering::SeqCst);
            Poll::Ready(Ok(()))
        }
    }

    /// Poll-counting phase that stays Pending forever and never
    /// registers a waker (same style as `std::future::pending()`). Only
    /// ever passed to the guard with an expired deadline, where the
    /// guard must reject before polling.
    struct PendingPhase {
        polls: Arc<AtomicUsize>,
    }

    impl Future for PendingPhase {
        type Output = anyhow::Result<()>;

        fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
            self.polls.fetch_add(1, Ordering::SeqCst);
            Poll::Pending
        }
    }

    /// R6-03: an expired deadline must not start a phase at all — not
    /// even one poll — even when the phase would complete immediately.
    #[tokio::test(start_paused = true)]
    async fn expired_deadline_never_polls_an_already_ready_phase() {
        let deadline = tokio::time::Instant::now();
        tokio::time::advance(Duration::from_millis(1)).await;
        let polls = Arc::new(AtomicUsize::new(0));
        let res = run_phase_in_client_budget(
            deadline,
            ReadyPhase {
                polls: polls.clone(),
            },
        )
        .await;
        assert_eq!(
            res.unwrap_err(),
            Duration::ZERO,
            "an expired deadline must be rejected with a ZERO budget"
        );
        assert_eq!(
            polls.load(Ordering::SeqCst),
            0,
            "a Ready phase must not be polled even once past the deadline"
        );
    }

    /// R6-03: same property for a Pending phase — the counter must stay
    /// at zero, proving the guard fired before the first poll. (The
    /// ZERO-budget-times-out test above cannot tell this apart:
    /// `timeout(ZERO, pending)` also returns immediately, but only
    /// AFTER having polled the future once.)
    #[tokio::test(start_paused = true)]
    async fn expired_deadline_never_polls_a_pending_phase() {
        let deadline = tokio::time::Instant::now();
        tokio::time::advance(Duration::from_millis(1)).await;
        let polls = Arc::new(AtomicUsize::new(0));
        let res = run_phase_in_client_budget(
            deadline,
            PendingPhase {
                polls: polls.clone(),
            },
        )
        .await;
        assert_eq!(
            res.unwrap_err(),
            Duration::ZERO,
            "an expired deadline must be rejected with a ZERO budget"
        );
        assert_eq!(
            polls.load(Ordering::SeqCst),
            0,
            "a Pending phase must not be polled even once past the deadline"
        );
    }

    /// R6-03: a live budget must still run the phase exactly once and
    /// forward its result — the guard only rejects expired deadlines.
    #[tokio::test(start_paused = true)]
    async fn non_expired_deadline_runs_a_ready_phase_exactly_once() {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        let polls = Arc::new(AtomicUsize::new(0));
        let res = run_phase_in_client_budget(
            deadline,
            ReadyPhase {
                polls: polls.clone(),
            },
        )
        .await;
        res.expect("a live deadline must run the phase")
            .expect("the ready phase must succeed");
        assert_eq!(polls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn anonymous_http_never_uses_empty_username_direct_privilege() {
        let auth = Arc::new(
            AuthState::build(
                &crate::config::AuthConfig {
                    allow_anonymous: true,
                },
                &crate::config::UsersConfig {
                    users: vec![crate::config::User {
                        name: String::new(),
                        hash: "init".into(),
                        is_enabled: true,
                        direct: true,
                    }],
                },
                "unused-empty-user",
            )
            .unwrap(),
        );
        assert!(
            auth.is_direct(""),
            "regression requires a privileged empty-name account"
        );
        let logger = test_logger();
        let banned = Arc::new(regex::RegexSet::new(["^blocked[.]invalid:443$"]).unwrap());
        let pool = Arc::new(ProxyPool::new(
            Default::default(),
            Duration::from_secs(1),
            1,
        ));
        let frag = Arc::new(TlsFragmentConfig::default());
        let network = Arc::new(NetworkConfig::default());
        // If anonymous identity is incorrectly replaced with "", the direct cap
        // branch sends 503 before checking the ban. Correct pool policy sends 403.
        let direct_limiter = Arc::new(Semaphore::new(0));
        let no_rotator = None;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let host = async {
            let (stream, _) = listener.accept().await.unwrap();
            let deadline = Instant::now() + Duration::from_secs(5);
            let error = handle_client(
                stream,
                &auth,
                &no_rotator,
                &no_rotator,
                &no_rotator,
                &logger,
                &banned,
                &pool,
                &frag,
                &network,
                None,
                &direct_limiter,
                deadline,
            )
            .await
            .expect_err("banned anonymous target must fail");
            assert!(error.to_string().contains("Banned target address"));
            assert_eq!(direct_limiter.available_permits(), 0);
        };
        let peer = async {
            let mut socket = TcpStream::connect(address).await.unwrap();
            socket
                .write_all(b"CONNECT blocked.invalid:443 HTTP/1.1\r\n\r\n")
                .await
                .unwrap();
            let mut response = Vec::new();
            tokio::io::AsyncReadExt::read_to_end(&mut socket, &mut response)
                .await
                .unwrap();
            assert_eq!(
                response,
                b"HTTP/1.1 403 Forbidden\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"
            );
        };
        timeout(Duration::from_secs(8), async {
            tokio::join!(host, peer);
        })
        .await
        .unwrap();
    }
}
