use std::sync::Arc;

use anyhow::anyhow;
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

/// Recovery path: the client asked for a bare IPv4 and recovery is on.
///
/// We send the SOCKS5 success reply *early* so the client emits its
/// first application record, then recover the intended hostname from
/// it (TLS SNI or HTTP `Host`) and open the upstream addressed by that
/// domain — falling back to the original IP when nothing is recovered.
/// The prefix is *accumulated* across reads (TCP segmentation routinely
/// splits a ClientHello, and a single read would see only a truncated
/// prefix) until the parsers decide, the probes rule the record out, or
/// the 16 KiB cap is hit — all under the remainder of the
/// accept-anchored client-protocol deadline threaded down from the
/// dispatcher, so the peeked record is forwarded (fragmented if
/// configured) before the bidirectional tunnel starts and no client
/// bytes are lost.
///
/// A client still silent after a ~1 s grace (`CLIENT_FIRST_GRACE`) is
/// unlikely to be TLS/HTTP (those speak within an RTT): we then give
/// the upstream — dialed by the original IP, nothing recovered yet —
/// one chance to greet first. A server-speaks-first protocol (SSH,
/// SMTP, FTP) does, and we fall back to plain forwarding by IP;
/// otherwise we keep waiting for the client as before.
#[allow(clippy::too_many_arguments)]
pub(super) async fn recover_and_tunnel(
    mut client_stream: TcpStream,
    target_addr: &str,
    port: &str,
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
) -> anyhow::Result<()> {
    let ctag = match client_user {
        Some(u) => format!(" [client={}]", u),
        None => " [client=anon]".to_string(),
    };

    // (R7-01) The WHOLE initial recovery phase — the early SOCKS5
    // success reply AND the payload peek — sits behind the
    // expired-deadline guard. With a decidable payload already
    // buffered, a bare `timeout` still polls the peek once before
    // consulting the timer: the early reply would go out and the
    // upstream dial would start even though the client-protocol budget
    // is already dead. `run_phase_in_client_budget` checks the budget
    // BEFORE the first poll.
    let peeked = match run_phase_in_client_budget(
        client_deadline,
        async {
            // Early SOCKS5 success reply — required so the client
            // sends its ClientHello / HTTP request, which carries the
            // name we need.
            client_stream
                .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await?;
            // Peek under the client-protocol deadline (slowloris
            // guard: a client that completes CONNECT but never speaks
            // must not pin the slot). The grace window inside
            // distinguishes a slow client-first protocol from a
            // server-speaks-first one.
            Ok::<_, anyhow::Error>(
                peek_recovery(
                    &mut client_stream,
                    Vec::new(),
                    server::establish_connection(
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
                    target_addr, ctag
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

    // Recover the intended host: TLS SNI first, then HTTP Host.
    let effective_target = match parse_sni(&buf).or_else(|| parse_http_host(&buf)) {
        Some(host) => {
            let t = format!("{}:{}", host, port);
            logger.cache_write(|| {
                format!(
                    "Recovered host {} from payload for IP {}{}",
                    t, target_addr, ctag
                )
            });
            t
        }
        None => {
            logger.attempt(|| {
                format!(
                    "No host recoverable from payload for {} — using IP{}",
                    target_addr, ctag
                )
            });
            target_addr.to_string()
        }
    };

    // Open the upstream by the recovered domain. We have already sent
    // the SOCKS5 success reply, so a failure here cannot be reported as
    // a SOCKS error — we log it and drop the tunnel (the client's TLS
    // handshake / HTTP request simply fails and is retried).
    let proxy_stream = match crate::server::establish_connection(
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
