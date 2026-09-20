use std::sync::Arc;

use anyhow::{anyhow, Result};
use regex::RegexSet;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::time::Instant;

use tokio_rustls::TlsConnector;

use crate::config::{NetworkConfig, TlsFragmentConfig};
use crate::logger::Logger;
use crate::server;
use crate::server::handle_client::run_phase_in_client_budget;
use crate::server::recovery::{peek_recovery, RecoveryPeek};
use resocks5_net::connect::tcp_keepalive::set_keepalive;
use resocks5_net::connect::{parse_http_host, parse_sni};
use resocks5_net::pool::ProxyPool;
use resocks5_net::rotator::ProxyRotator;

/// If `target` is `IPv4:port`, return the port substring; otherwise
/// `None`. Recovery applies only to bare IPv4 literals (domains already
/// carry the name; IPv6 literals stay on the standard path).
pub(super) fn ipv4_literal_port(target: &str) -> Option<&str> {
    let (host, port) = target.rsplit_once(':')?;
    if host.parse::<std::net::Ipv4Addr>().is_ok() {
        Some(port)
    } else {
        None
    }
}

/// HTTP CONNECT recovery path: target is a bare IPv4 and recovery is on.
///
/// Mirror of the SOCKS5 `recover_and_tunnel`: reply `200 Connection
/// Established` early so the client emits its first record, then
/// accumulate that record across reads (TCP segmentation routinely
/// splits a ClientHello, and a pipelined fast-open hello can itself be
/// truncated) until TLS SNI / HTTP `Host` recovery can decide, the
/// probes rule the record out, or the 16 KiB cap is hit — all under
/// the remainder of the accept-anchored client-protocol deadline
/// threaded down from the dispatcher. Open the upstream by that domain
/// (falling back to the IP), forward the buffered record, then tunnel.
///
/// A client still silent after the ~1 s grace (`CLIENT_FIRST_GRACE`) is
/// unlikely to be TLS/HTTP (those speak within an RTT): the upstream —
/// dialed by the original IP, nothing recovered yet — then gets one
/// chance to greet first. A server-speaks-first protocol (SSH, SMTP,
/// FTP) does, and we fall back to plain forwarding by IP; otherwise we
/// keep waiting for the client as before.
#[allow(clippy::too_many_arguments)]
pub(super) async fn recover_and_tunnel_http(
    mut client_stream: TcpStream,
    target: &str,
    port: &str,
    pipelined: Vec<u8>,
    gate_rotator: &Option<Arc<ProxyRotator>>,
    v6_rotator: &Option<Arc<ProxyRotator>>,
    v4_rotator: &Option<Arc<ProxyRotator>>,
    logger: &Arc<Logger>,
    banned: &Arc<RegexSet>,
    pool: &Arc<ProxyPool>,
    frag: &Arc<TlsFragmentConfig>,
    network: &Arc<NetworkConfig>,
    client_user: Option<&str>,
    tls_connector: Option<&TlsConnector>,
    client_deadline: Instant,
) -> Result<()> {
    let ctag = match client_user {
        Some(u) => format!(" [client={}]", u),
        None => " [client=anon]".to_string(),
    };

    // (R7-01) The WHOLE initial recovery phase — the early 200 reply
    // AND the payload peek — sits behind the expired-deadline guard.
    // With a decidable payload already pipelined past CONNECT, a bare
    // `timeout` still polls the peek once before consulting the timer:
    // the 200 would go out and the upstream dial would start even
    // though the client-protocol budget is already dead.
    // `run_phase_in_client_budget` checks the budget BEFORE the first
    // poll.
    let peeked = match run_phase_in_client_budget(
        client_deadline,
        async {
            // Early 200 so the client sends its first application
            // record.
            client_stream
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .await?;
            Ok::<_, anyhow::Error>(
                peek_recovery(
                    &mut client_stream,
                    pipelined,
                    server::establish_connection(
                        target,
                        gate_rotator,
                        v6_rotator,
                        v4_rotator,
                        logger,
                        banned,
                        pool,
                        network,
                        client_user,
                        tls_connector,
                    ),
                )
                .await?,
            )
        },
    )
    .await
    {
        Ok(Ok(peeked)) => peeked,
        Ok(Err(e)) => return Err(e),
        Err(budget) => {
            return Err(anyhow!(
                "client sent no payload within the remaining {}s of the client-protocol budget ? recovery peek timeout{}",
                budget.as_secs(),
                ctag,
            ))
        }
    };

    let buf = match peeked {
        RecoveryPeek::ClientClosed => return Ok(()), // client closed before sending
        RecoveryPeek::ServerFirst(upstream, banner) => {
            // Server-speaks-first protocol: skip recovery entirely (an
            // empty client read carries no host to recover), relay the
            // greeting and tunnel by IP.
            logger.attempt(|| {
                format!(
                    "Client silent; upstream {} greeted first — forwarding by IP without recovery{}",
                    target, ctag
                )
            });
            client_stream.write_all(&banner).await?;
            let _ = set_keepalive(&client_stream, network.tcp_keepalive_sec);
            if let Some(tcp) = upstream.as_tcp() {
                let _ = set_keepalive(tcp, network.tcp_keepalive_sec);
            }
            if frag.enabled {
                upstream.set_nodelay(true)?;
            }
            return server::forward_tunnel(client_stream, upstream, Vec::new(), frag, network)
                .await;
        }
        RecoveryPeek::Client(prefix) => prefix,
    };

    let effective_target = match parse_sni(&buf).or_else(|| parse_http_host(&buf)) {
        Some(host) => {
            let t = format!("{}:{}", host, port);
            logger.cache_write(|| {
                format!(
                    "Recovered host {} from payload for IP {}{}",
                    t, target, ctag
                )
            });
            t
        }
        None => {
            logger.attempt(|| {
                format!(
                    "No host recoverable from payload for {} — using IP{}",
                    target, ctag
                )
            });
            target.to_string()
        }
    };

    // We have already sent `200`, so an upstream failure here cannot be
    // reported as an HTTP error — log and drop.
    let proxy_stream = match server::establish_connection(
        &effective_target,
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
            logger.connection_error(|| {
                format!(
                    "Recovery upstream failed for {}: {}{}",
                    effective_target, e, ctag
                )
            });
            return Err(e);
        }
    };

    let _ = set_keepalive(&client_stream, network.tcp_keepalive_sec);
    if let Some(tcp) = proxy_stream.as_tcp() {
        let _ = set_keepalive(tcp, network.tcp_keepalive_sec);
    }

    if frag.enabled {
        proxy_stream.set_nodelay(true)?;
    }
    server::forward_tunnel(client_stream, proxy_stream, buf, frag, network).await
}
