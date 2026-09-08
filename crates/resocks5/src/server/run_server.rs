use std::sync::Arc;
use std::time::Duration;

use regex::RegexSet;
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;

use tokio_rustls::TlsConnector;

use crate::auth::AuthState;
use crate::config::{NetworkConfig, TlsFragmentConfig};
use crate::logger::Logger;
use crate::server::handle_client;
use resocks5_net::connect::tcp_keepalive::set_keepalive;
use resocks5_net::pool::ProxyPool;
use resocks5_net::rotator::ProxyRotator;

/// Grace period for in-flight tunnels to finish after Ctrl+C before
/// the runtime is torn down. Long enough that an open browser request
/// in the middle of streaming gets its EOF; short enough not to make
/// shutdown feel hung.
const SHUTDOWN_DRAIN_SEC: u64 = 30;

#[allow(clippy::too_many_arguments)]
pub async fn run_server(
    auth: Arc<AuthState>,
    gate_rotator: Option<Arc<ProxyRotator>>,
    v6_rotator: Option<Arc<ProxyRotator>>,
    v4_rotator: Option<Arc<ProxyRotator>>,
    local_addr: &str,
    logger: &Arc<Logger>,
    banned: Arc<RegexSet>,
    pool: Arc<ProxyPool>,
    frag: Arc<TlsFragmentConfig>,
    network: Arc<NetworkConfig>,
    tls_connector: Option<Arc<TlsConnector>>,
) -> anyhow::Result<()> {
    let listener = TcpListener::bind(local_addr).await?;
    let local_addr_for_log = local_addr.to_string();
    logger.lifecycle(move || {
        format!(
            "Server started on {} (SOCKS5 + HTTP CONNECT auto-detected per connection)",
            local_addr_for_log
        )
    });
    let users_n = auth.users_count();
    let allow_anon = auth.allow_anonymous;
    logger.lifecycle(move || match (users_n == 0, allow_anon) {
        (true, true) => "Auth: anonymous-only (no users configured)".into(),
        (true, false) => "Auth: REJECT-ALL (allow_anonymous=false and no users configured) \
                          — every client will be rejected; either set allow_anonymous=true \
                          or add a user"
            .into(),
        (false, true) => format!(
            "Auth: optional ({} user(s) configured, anonymous also allowed)",
            users_n
        ),
        (false, false) => format!(
            "Auth: required ({} user(s) configured, anonymous disallowed)",
            users_n
        ),
    });

    let max_clients = network.max_concurrent_clients;
    let limiter = Arc::new(Semaphore::new(max_clients));
    {
        let cap = max_clients;
        logger.lifecycle(move || {
            format!(
                "Concurrency: max {} simultaneous client tunnels (excess rejected)",
                cap
            )
        });
    }

    let max_direct = network.max_concurrent_direct;
    let direct_limiter = Arc::new(Semaphore::new(max_direct));
    {
        let cap = max_direct;
        logger.lifecycle(move || {
            format!(
                "Direct cap: max {} simultaneous bypass tunnels (excess rejected after auth)",
                cap
            )
        });
    }

    // Active per-connection tasks. JoinSet lets us drain them on
    // shutdown without polling — `join_next().await` resolves as each
    // task finishes.
    let mut tasks: JoinSet<()> = JoinSet::new();

    loop {
        // Drop already-finished tasks from the set every loop iteration
        // so it doesn't grow unboundedly with completed handlers. (The
        // permit-via-Semaphore enforces the live cap, but this keeps
        // memory tight.)
        while let Some(res) = tasks.try_join_next() {
            report_finished_task(logger, res);
        }

        tokio::select! {
            // Bias accept toward listening rather than to the shutdown
            // signal so a steady stream of clients can't starve the
            // Ctrl+C check — `select!` does that round-robin by default.
            res = listener.accept() => {
                let (client_stream, _) = match res {
                    Ok(pair) => pair,
                    Err(e) => {
                        // Transient accept errors (EMFILE, kernel hiccup,
                        // peer that connected and instantly RST'd) must
                        // NOT take down the server. Log and keep serving.
                        // Brief sleep prevents a tight busy-loop on
                        // persistent failures (e.g. global FD exhaustion).
                        logger.connection_error(
                            || format!("accept() failed: {} — continuing", e),
                        );
                        tokio::time::sleep(Duration::from_millis(100)).await;
                        continue;
                    }
                };

                // TCP_NODELAY on the accepted client — SOCKS5/HTTP
                // handshake is ~5 tiny writes; Nagle would add ~40 ms
                // each. Free latency win.
                let _ = client_stream.set_nodelay(true);
                // Keepalive on client side too, so the kernel handles
                // dead clients without our application-layer code
                // having to detect it.
                let _ = set_keepalive(&client_stream, network.tcp_keepalive_sec);

                // Non-blocking permit acquisition: at capacity we drop
                // the new connection immediately rather than queueing,
                // which would translate the load spike into latency.
                let permit = match limiter.clone().try_acquire_owned() {
                    Ok(p) => p,
                    Err(_) => {
                        logger.connection_error(|| {
                            format!(
                                "Concurrent client cap reached ({}) — \
                                 dropping new connection",
                                max_clients
                            )
                        });
                        drop(client_stream);
                        continue;
                    }
                };

                let auth_clone = auth.clone();
                let v6_rotator_clone = v6_rotator.clone();
                let gate_rotator_clone = gate_rotator.clone();
                let v4_rotator_clone = v4_rotator.clone();
                let logger_clone = logger.clone();
                let banned_clone = banned.clone();
                let pool_clone = pool.clone();
                let frag_clone = frag.clone();
                let network_clone = network.clone();
                let tls_clone = tls_connector.clone();
                let direct_limiter_clone = direct_limiter.clone();
                tasks.spawn(async move {
                    let _permit = permit;
                    if let Err(e) = handle_client(
                        client_stream,
                        &auth_clone,
                        &gate_rotator_clone,
                        &v6_rotator_clone,
                        &v4_rotator_clone,
                        &logger_clone,
                        &banned_clone,
                        &pool_clone,
                        &frag_clone,
                        &network_clone,
                        tls_clone.as_deref(),
                        &direct_limiter_clone,
                    )
                    .await
                    {
                        logger_clone.connection_error(
                            || format!("Error handling connection: {}", e),
                        );
                    }
                });
            }

            _ = tokio::signal::ctrl_c() => {
                logger.lifecycle(|| {
                    format!(
                        "Received Ctrl+C — closing listener, draining \
                         {} active tunnel(s) (up to {} s)…",
                        tasks.len(),
                        SHUTDOWN_DRAIN_SEC
                    )
                });
                break;
            }
        }
    }

    // Close the listener immediately so no new client can sneak in.
    drop(listener);

    // Drain active handlers with a deadline. After it expires whatever
    // is still running gets aborted by the runtime when this function
    // returns (the JoinSet drops, all its tasks are cancelled).
    let drain = async {
        while let Some(res) = tasks.join_next().await {
            report_finished_task(logger, res);
        }
    };
    let _ = tokio::time::timeout(Duration::from_secs(SHUTDOWN_DRAIN_SEC), drain).await;
    logger.lifecycle(|| "Shutdown complete.".to_string());
    Ok(())
}

/// Inspect one finished connection-handler task instead of discarding
/// its `Result`. A panic in `handle_client` unwinds past the handler's
/// own `connection_error` logging, so this `JoinError` is the only
/// trace it leaves. Cancellation is deliberately silent: it is the
/// expected outcome of the drain-timeout path dropping the `JoinSet`,
/// and nothing aborts individual tasks before that point.
fn report_finished_task(logger: &Logger, res: Result<(), tokio::task::JoinError>) {
    match res {
        Ok(()) => {}
        Err(e) if e.is_cancelled() => {}
        Err(e) => logger.connection_error(|| format!("connection handler task panicked: {e}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::logger::{ELog, LogConfig};
    use tokio::sync::mpsc;

    fn panic_reporting_logger() -> (Arc<Logger>, mpsc::Receiver<ELog>) {
        let (tx, rx) = mpsc::channel::<ELog>(4);
        let cfg = LogConfig {
            connection_errors: true,
            ..Default::default()
        };
        (Arc::new(Logger::new(tx, cfg)), rx)
    }

    /// A panicked handler must be observable as `Some(Err(e))` with
    /// `is_panic() == true` and produce a visible log line — it used to
    /// vanish because the accept-loop cleanup discarded every result
    /// (review R25).
    #[tokio::test]
    async fn panicking_task_surfaces_as_join_error_and_log_line() {
        let (logger, mut rx) = panic_reporting_logger();

        let mut tasks: JoinSet<()> = JoinSet::new();
        tasks.spawn(async {
            panic!("simulated handler panic");
        });

        // Accept-loop shape: poll without blocking until the task is
        // joinable. Bounded so a regression can't spin forever.
        let mut finished = None;
        for _ in 0..100 {
            match tasks.try_join_next() {
                Some(res) => {
                    finished = Some(res);
                    break;
                }
                None => tokio::task::yield_now().await,
            }
        }
        let res = finished.expect("panicked task must become joinable");
        assert!(res.is_err());
        assert!(
            res.as_ref().unwrap_err().is_panic(),
            "JoinError must be reported as a panic"
        );

        report_finished_task(&logger, res);
        let msg = match rx.recv().await {
            Some(ELog::Error(m)) => m,
            _ => panic!("expected a connection_error for the panicked handler"),
        };
        assert!(
            msg.contains("panicked") && msg.contains("simulated handler panic"),
            "panic report must name the panic, got: {msg}"
        );
    }

    /// Drain-loop shape: `join_next().await` resolves with the panic and
    /// the fixed loop routes it to the logger. Cancellation — the
    /// expected drain-timeout abort outcome — must stay unlogged.
    #[tokio::test]
    async fn drain_loop_reports_panic_but_stays_silent_on_cancellation() {
        let (logger, mut rx) = panic_reporting_logger();

        let mut tasks: JoinSet<()> = JoinSet::new();
        tasks.spawn(async {
            panic!("drain-side panic");
        });
        while let Some(res) = tasks.join_next().await {
            report_finished_task(&logger, res);
        }
        let msg = match rx.recv().await {
            Some(ELog::Error(m)) => m,
            _ => panic!("expected a connection_error for the panicked handler"),
        };
        assert!(msg.contains("drain-side panic"), "got: {msg}");

        // A real cancelled JoinError: abort a sleeping task mid-flight.
        let mut tasks: JoinSet<()> = JoinSet::new();
        let handle = tasks.spawn(async {
            tokio::time::sleep(Duration::from_secs(30)).await;
        });
        handle.abort();
        let res = tasks
            .join_next()
            .await
            .expect("aborted task must yield a result");
        assert!(res.as_ref().unwrap_err().is_cancelled());
        report_finished_task(&logger, res);
        assert!(
            rx.try_recv().is_err(),
            "cancellation must not be logged (expected on drain-timeout abort)"
        );
    }
}
