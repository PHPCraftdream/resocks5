use std::sync::Arc;

use regex::RegexSet;
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use tokio::time::Instant;

use tokio_rustls::TlsConnector;

use crate::auth::AuthState;
use crate::config::{NetworkConfig, TlsFragmentConfig};
use crate::logger::Logger;
use crate::server;
use resocks5_net::connect::tcp_keepalive::set_keepalive;
use resocks5_net::pool::ProxyPool;
use resocks5_net::rotator::ProxyRotator;
use resocks5_net::server::{IncomingRequest, Reply};

use super::recover::recover_and_tunnel;

#[allow(clippy::too_many_arguments)]
pub async fn handle_socks5_client(
    mut client_stream: TcpStream,
    mut req: IncomingRequest,
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
    let pipeline = req.take_pipeline();
    let target_addr = req.target();
    let client_user = req.username();

    // If the authenticated user has direct=true, bypass the pool and
    // connect straight to the target. Anonymous clients NEVER take the
    // direct path.
    let is_direct = client_user.is_some_and(|user| auth.is_direct(user));

    // Acquire a direct-limiter permit when taking the bypass path.
    // Held until this function returns so it covers the full tunnel
    // lifetime. `None` for the pool path.
    let _direct_permit = if is_direct {
        let user_owned = client_user.expect("is_direct implies a named user");
        match direct_limiter.clone().try_acquire_owned() {
            Ok(p) => Some(p),
            Err(_) => {
                let target_addr_c = target_addr.to_owned();
                let user_c = user_owned.to_string();
                let cap = network.max_concurrent_direct;
                logger.connection_error(move || {
                    format!(
                        "Direct cap reached ({}) — dropping client={} target={}",
                        cap, user_c, target_addr_c
                    )
                });
                let _ = req.reply(&mut client_stream, Reply::Overloaded).await;
                return Ok(());
            }
        }
    } else {
        None
    };

    // ── SNI/Host recovery ───────────────────────────────────────────
    // Pool-routed clients only (never direct). When the CONNECT target
    // is a bare IPv4 literal and recovery is enabled, we recover the
    // intended hostname from the client's first record (TLS SNI / HTTP
    // Host) and address the upstream by that domain. See
    // `recover_host_from_payload` in NetworkConfig for the rationale.
    if !is_direct && network.recover_host_from_payload {
        if let Some(port) = ipv4_literal_port(target_addr) {
            return recover_and_tunnel(
                client_stream,
                &req,
                target_addr,
                port,
                gate_rotator,
                v6_rotator,
                v4_rotator,
                logger,
                banned,
                pool,
                frag,
                network,
                client_user,
                tls_connector,
                client_deadline,
            )
            .await;
        }
    }

    let proxy_stream = if is_direct {
        let user_owned = client_user.expect("is_direct implies a named user");
        match crate::server::establish_direct(target_addr, banned, logger, network, user_owned)
            .await
        {
            Ok(s) => s,
            Err(e) => {
                let rep = if banned.is_match(target_addr) {
                    Reply::Forbidden
                } else {
                    Reply::UpstreamUnavailable
                };
                let _ = req.reply(&mut client_stream, rep).await;
                return Err(e);
            }
        }
    } else {
        match server::establish_connection(
            target_addr,
            gate_rotator,
            v6_rotator,
            v4_rotator,
            logger,
            banned,
            pool,
            network,
            client_user,
            tls_connector,
        )
        .await
        {
            Ok(s) => s,
            Err(e) => {
                let rep = if banned.is_match(target_addr) {
                    Reply::Forbidden
                } else {
                    Reply::UpstreamUnavailable
                };
                let _ = req.reply(&mut client_stream, rep).await;
                return Err(e);
            }
        }
    };

    req.reply(&mut client_stream, Reply::Established).await?;

    // ── Phase 3: forwarding ─────────────────────────────────────────
    // Aggressive keepalive on both legs of the tunnel so kernels on
    // either side notice a dead peer and tear the socket down instead
    // of leaving us with a half-open zombie that consumes a slot in
    // the upstream proxy's per-account connection table.
    let _ = set_keepalive(&client_stream, network.tcp_keepalive_sec);
    if let Some(tcp) = proxy_stream.as_tcp() {
        let _ = set_keepalive(tcp, network.tcp_keepalive_sec);
    }

    if frag.enabled {
        proxy_stream.set_nodelay(true)?;
    }
    server::forward_tunnel(
        client_stream,
        proxy_stream,
        pipeline,
        frag,
        network,
        Some(server::TunnelLabel {
            logger,
            target: target_addr,
            client: client_user,
        }),
    )
    .await
}

/// If `target` is `IPv4:port`, return the port substring; otherwise
/// `None`. Recovery only applies to bare IPv4 literals — domains
/// already carry the name we want, and IPv6 literals are left on the
/// standard path (Proxifier-style front-ends emit IPv4 in practice).
fn ipv4_literal_port(target: &str) -> Option<&str> {
    let (host, port) = target.rsplit_once(':')?;
    if host.parse::<std::net::Ipv4Addr>().is_ok() {
        Some(port)
    } else {
        None
    }
}
