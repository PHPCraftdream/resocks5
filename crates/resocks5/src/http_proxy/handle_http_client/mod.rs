use std::sync::Arc;

use anyhow::Result;
use regex::RegexSet;
use tokio::net::TcpStream;
use tokio::time::Instant;

use tokio_rustls::TlsConnector;

use crate::config::{NetworkConfig, TlsFragmentConfig};
use crate::logger::Logger;
use crate::server;
use resocks5_net::chain::GateLevels;
use resocks5_net::connect::tcp_keepalive::set_keepalive;
use resocks5_net::pool::ProxyPool;
use resocks5_net::rotator::ProxyRotator;
use resocks5_net::server::{IncomingRequest, Reply};
mod recovery;
#[cfg(test)]
mod recovery_halfclose_tests;
#[cfg(test)]
mod tests;
use recovery::{ipv4_literal_port, recover_and_tunnel_http};

#[allow(clippy::too_many_arguments)]
pub async fn handle_http_client(
    mut client_stream: TcpStream,
    mut req: IncomingRequest,
    gate_rotator: &Arc<GateLevels>,
    v6_rotator: &Option<Arc<ProxyRotator>>,
    v4_rotator: &Option<Arc<ProxyRotator>>,
    logger: &Arc<Logger>,
    banned: &Arc<RegexSet>,
    pool: &Arc<ProxyPool>,
    frag: &Arc<TlsFragmentConfig>,
    network: &Arc<NetworkConfig>,
    tls_connector: Option<&TlsConnector>,
    client_deadline: Instant,
) -> Result<()> {
    let pipeline = req.take_pipeline();
    let target_addr = req.target();
    // Over HTTP the SDK serves anonymous clients only (a Proxy-Authorization
    // header is a 407, see `http_requests_accepted_by_the_app_never_carry_an_identity`),
    // so there is no account here and no direct-routing privilege: HTTP always
    // goes through the pool.
    let client_user = req.username();

    // ── SNI/Host recovery ───────────────────────────────────────────
    // When the CONNECT target is a bare IPv4 literal and recovery is
    // enabled, recover the intended hostname from the client's first
    // record (pipelined ClientHello, or the first read) and address the
    // upstream by that domain. See `recover_host_from_payload` in
    // NetworkConfig.
    if network.recover_host_from_payload {
        if let Some(port) = ipv4_literal_port(target_addr) {
            return recover_and_tunnel_http(
                client_stream,
                &req,
                target_addr,
                port,
                pipeline,
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

    let proxy_stream = match server::establish_connection(
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
            let resp = if banned.is_match(target_addr) {
                Reply::Forbidden
            } else {
                Reply::UpstreamUnavailable
            };
            let _ = req.reply(&mut client_stream, resp).await;
            return Err(e);
        }
    };

    req.reply(&mut client_stream, Reply::Established).await?;

    // ── Phase 3: forwarding ─────────────────────────────────────────
    // Aggressive keepalive on both legs — same rationale as in the
    // SOCKS5 handler: kernels will tear down half-open zombies on
    // their own so we don't accumulate them in the upstream proxy's
    // per-account connection table.
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
