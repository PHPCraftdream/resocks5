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
/// protocol-detection peek, the SOCKS5/HTTP handshake, and the
/// recovery peek — spends only its remainder, never a fresh
/// full-length timer. After the deadline has passed this returns
/// `Duration::ZERO`, which makes the stage's `timeout` fire
/// immediately instead of silently granting a new budget.
pub(crate) fn remaining_client_budget(deadline: Instant) -> Duration {
    deadline.saturating_duration_since(Instant::now())
}

/// Single accept-loop dispatcher: peeks the first byte without
/// consuming it and routes the client to the SOCKS5 or HTTP CONNECT
/// handler. This is what lets one listening port serve both protocols
/// transparently — SOCKS5 always opens with `0x05` (greeting version),
/// HTTP always opens with an ASCII method letter, so a single byte is
/// enough to tell them apart with zero ambiguity. It computes the
/// accept-anchored client-protocol deadline and threads it down into
/// the selected protocol handler.
#[allow(clippy::too_many_arguments)]
pub async fn handle_client(
    client_stream: TcpStream,
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
) -> anyhow::Result<()> {
    // Slowloris guard on protocol-detection: a client that completes
    // TCP connect but never sends the first byte would otherwise
    // freeze this task indefinitely (until TCP keepalive eventually
    // kills the socket, ~60-90 s). We bound it explicitly so the
    // global `max_concurrent_clients` slot is freed promptly. It is
    // the first slice of the single accept-anchored
    // `client_protocol_timeout_sec` deadline; whatever it leaves is
    // all the selected protocol handler gets.
    //
    // The client-protocol budget starts ONCE, here — as close to the
    // accept in run_server's loop as the dispatcher interface allows —
    // and every downstream client-facing stage (peek, SOCKS5/HTTP
    // handshake, recovery) draws from this single absolute deadline.
    let client_deadline = Instant::now() + Duration::from_secs(network.client_protocol_timeout_sec);
    let peek_budget = remaining_client_budget(client_deadline);
    let mut peek_buf = [0u8; 1];
    let n = match timeout(peek_budget, client_stream.peek(&mut peek_buf)).await {
        Ok(res) => res?,
        Err(_) => {
            return Err(anyhow!(
                "client did not send any byte within the remaining {}s of the client-protocol budget — protocol-detect timeout",
                peek_budget.as_secs()
            ));
        }
    };
    if n == 0 {
        return Err(anyhow!("client closed before sending any data"));
    }
    match peek_buf[0] {
        0x05 => {
            handle_socks5_client(
                client_stream,
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
        b if b.is_ascii_alphabetic() => {
            handle_http_client(
                client_stream,
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
        other => Err(anyhow!(
            "unrecognised first byte {:#04x} — neither SOCKS5 (0x05) nor an HTTP method",
            other
        )),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};
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

    /// Give a freshly spawned task's first poll every real-scheduler
    /// opportunity to happen before the paused virtual clock is
    /// advanced. A single `sleep(1ms).await` can resolve via the
    /// paused-clock auto-advance before the executor actually gets
    /// around to polling the new task, under heavy real scheduler
    /// pressure (observed in practice under simultaneous multi-crate
    /// compilation/linking) — the freshly spawned task would then
    /// anchor its deadline against an already-advanced virtual time,
    /// silently invalidating this test's tight elapsed-time bounds.
    /// Repeated real yields + a real sleep make that overwhelmingly
    /// unlikely; same defensive pattern as `quiesce()` in
    /// `proxy_pool.rs`'s tests for the same class of paused-clock /
    /// real-scheduler interaction.
    async fn anchor_first_poll() {
        for _ in 0..50 {
            tokio::task::yield_now().await;
            std::thread::sleep(Duration::from_millis(1));
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
            )
            .await
        });

        // Let the freshly spawned handler run to its first poll so its
        // accept-anchored deadline is really anchored at accept time;
        // tokio auto-advance does not poll newly spawned tasks during
        // `advance`.
        anchor_first_poll().await;

        let t0 = tokio::time::Instant::now();
        // Eat 90% of the budget in protocol detection: the first byte only
        // arrives when ~100 ms of the 1 s budget is left.
        tokio::time::advance(Duration::from_millis(900)).await;
        client.write_all(&[0x05]).await.unwrap();
        // A real SOCKS5 greeting continues with NMETHODS + methods; the
        // client now stays silent. Under the shared deadline the handshake
        // stage gets only ~100 ms; a fresh per-stage budget would let it
        // stall until t=1.9 s.

        let result = tokio::time::timeout(Duration::from_secs(30), task)
            .await
            .expect("handler must terminate at the shared deadline")
            .unwrap();
        let elapsed = t0.elapsed();
        let err = result.expect_err("the stalled handshake must fail");
        assert!(
            err.to_string().contains("handshake timed out"),
            "must fail in the handshake stage, got: {err}"
        );
        assert!(
            elapsed >= Duration::from_millis(900),
            "the peek must have consumed ~900 ms first, elapsed {elapsed:?}"
        );
        assert!(
            elapsed <= Duration::from_millis(1200),
            "handshake must inherit only the remaining ~100 ms of the shared budget, not a fresh 1 s (elapsed {elapsed:?})"
        );
    }

    /// R5-02 regression: time consumed before recovery must shrink the
    /// recovery budget. After 1.5 s of a 2 s budget is spent on peek +
    /// SOCKS5 handshake, a client that goes silent must hit the recovery
    /// peek timeout at the accept-anchored deadline (~2 s of virtual
    /// time), not receive a fresh 2 s recovery budget (~3.5 s).
    #[tokio::test(start_paused = true)]
    async fn time_spent_before_recovery_shrinks_the_recovery_budget() {
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
        let mut client = TcpStream::connect(addr).await.unwrap();
        let server = l.accept().await.unwrap().0;

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
            )
            .await
        });

        // Let the freshly spawned handler run to its first poll so its
        // accept-anchored deadline is really anchored at accept time;
        // tokio auto-advance does not poll newly spawned tasks during
        // `advance`.
        anchor_first_poll().await;

        let t0 = tokio::time::Instant::now();
        tokio::time::advance(Duration::from_millis(1500)).await;

        // Complete the whole SOCKS5 handshake instantly (real loopback I/O,
        // no virtual time passes): greeting, anonymous method selection,
        // CONNECT to a bare IPv4 — the recovery branch replies success
        // early and starts the recovery peek with ~500 ms left. (No
        // upstream rotator is configured, so the speculative upstream dial
        // fails immediately and peek_recovery simply keeps waiting for the
        // client.)
        client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut method = [0u8; 2];
        client.read_exact(&mut method).await.unwrap();
        assert_eq!(method, [0x05, 0x00]);
        client
            .write_all(&[0x05, 0x01, 0x00, 0x01, 203, 0, 113, 9, 0x01, 0xBB])
            .await
            .unwrap();
        let mut success = [0u8; 10];
        client.read_exact(&mut success).await.unwrap();
        assert_eq!([success[0], success[1]], [0x05, 0x00]);

        // Now the client goes silent: the recovery peek gets only the
        // remaining ~500 ms. A fresh budget would instead hold the
        // client-facing slot until ~3.5 s of virtual time.
        let result = tokio::time::timeout(Duration::from_secs(30), task)
            .await
            .expect("handler must terminate at the shared deadline")
            .unwrap();
        let elapsed = t0.elapsed();
        let err = result.expect_err("the stalled recovery must fail");
        assert!(
            err.to_string().contains("recovery peek timeout"),
            "must fail in the recovery stage, got: {err}"
        );
        assert!(
            elapsed >= Duration::from_millis(1500),
            "peek + handshake must have consumed ~1.5 s first, elapsed {elapsed:?}"
        );
        assert!(
            elapsed <= Duration::from_millis(2600),
            "recovery must inherit only the remaining ~500 ms of the shared budget, not a fresh 2 s (elapsed {elapsed:?})"
        );
    }

    /// R5-02 regression: once the accept-anchored deadline has passed the
    /// remaining budget is ZERO, and a stage wrapped in a ZERO timeout
    /// fails immediately as a timeout instead of hanging or getting a new
    /// budget.
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
}
