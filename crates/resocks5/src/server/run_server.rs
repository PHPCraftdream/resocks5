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
        while tasks.try_join_next().is_some() {}

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
    let drain = async { while tasks.join_next().await.is_some() {} };
    let _ = tokio::time::timeout(Duration::from_secs(SHUTDOWN_DRAIN_SEC), drain).await;
    logger.lifecycle(|| "Shutdown complete.".to_string());
    Ok(())
}
