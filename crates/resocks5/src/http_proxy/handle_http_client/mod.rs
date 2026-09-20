use std::sync::Arc;

use anyhow::{anyhow, Result};
use regex::RegexSet;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use tokio::time::Instant;

use tokio_rustls::TlsConnector;

use crate::auth::AuthState;
use crate::config::{NetworkConfig, TlsFragmentConfig};
use crate::logger::Logger;
use crate::server;
use crate::server::handle_client::run_phase_in_client_budget;
use resocks5_net::connect::tcp_keepalive::set_keepalive;
use resocks5_net::pool::ProxyPool;
use resocks5_net::rotator::ProxyRotator;
mod byte_lines;
mod parse_connect;
mod recovery;
#[cfg(test)]
mod tests;
#[cfg(test)]
pub(crate) use byte_lines::ByteLines;
use parse_connect::parse_http_connect;
#[cfg(test)]
pub(crate) use parse_connect::ConnectRequest;
use recovery::{ipv4_literal_port, recover_and_tunnel_http};

/// Maximum size of the request line + headers section. 16 KiB matches
/// what mainstream servers (nginx, Apache) use for client request
/// headers — enough for any sane Proxy-Authorization plus typical
/// browser header bloat, small enough that a hostile client cannot
/// exhaust memory by streaming an unterminated header.
const MAX_HEADER_BYTES: usize = 16 * 1024;

const RESP_407: &[u8] = b"HTTP/1.1 407 Proxy Authentication Required\r\n\
                          Proxy-Authenticate: Basic realm=\"resocks5\", charset=\"UTF-8\"\r\n\
                          Connection: close\r\n\
                          Content-Length: 0\r\n\r\n";

const RESP_400: &[u8] = b"HTTP/1.1 400 Bad Request\r\n\
                          Connection: close\r\n\
                          Content-Length: 0\r\n\r\n";

const RESP_403: &[u8] = b"HTTP/1.1 403 Forbidden\r\n\
                          Connection: close\r\n\
                          Content-Length: 0\r\n\r\n";

const RESP_502: &[u8] = b"HTTP/1.1 502 Bad Gateway\r\n\
                          Connection: close\r\n\
                          Content-Length: 0\r\n\r\n";

const RESP_503: &[u8] = b"HTTP/1.1 503 Service Unavailable\r\n\
                          Connection: close\r\n\
                          Content-Length: 0\r\n\r\n";

const RESP_501: &[u8] = b"HTTP/1.1 501 Not Implemented\r\n\
                          Connection: close\r\n\
                          Content-Length: 0\r\n\r\n";

const RESP_413: &[u8] = b"HTTP/1.1 431 Request Header Fields Too Large\r\n\
                          Connection: close\r\n\
                          Content-Length: 0\r\n\r\n";

#[allow(clippy::too_many_arguments)]
pub async fn handle_http_client(
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
) -> Result<()> {
    // ── Phase 1: HTTP CONNECT request + auth ────────────────────────
    // Bounded by the remainder of the accept-anchored client-protocol
    // deadline handed down by the dispatcher, so a slow drip of header
    // bytes can't pin the handler indefinitely.
    // The dispatcher already spent part of the accept-anchored budget
    // on protocol detection; only the remainder is ours to spend.
    let req = match run_phase_in_client_budget(
        client_deadline,
        parse_http_connect(&mut client_stream, auth),
    )
    .await
    {
        Ok(Ok(r)) => r,
        Ok(Err(e)) => return Err(e),
        Err(budget) => {
            return Err(anyhow!(
                "client HTTP CONNECT timed out with only {}s left of the client-protocol budget",
                budget.as_secs()
            ));
        }
    };

    // ── Phase 2: upstream connect (no client-protocol timeout) ──────
    // If the authenticated user has direct=true, bypass the pool and
    // connect straight to the target. Anonymous clients NEVER take the
    // direct path.
    let is_direct = auth.is_direct(req.client_user.as_deref().unwrap_or(""));

    // Acquire a direct-limiter permit when taking the bypass path.
    // Held until this function returns so it covers the full tunnel
    // lifetime. `None` for the pool path.
    let _direct_permit = if is_direct {
        let user_owned = req
            .client_user
            .as_deref()
            .expect("is_direct implies a named user");
        match direct_limiter.clone().try_acquire_owned() {
            Ok(p) => Some(p),
            Err(_) => {
                let target_c = req.target.clone();
                let user_c = user_owned.to_string();
                let cap = network.max_concurrent_direct;
                logger.connection_error(move || {
                    format!(
                        "Direct cap reached ({}) — dropping client={} target={}",
                        cap, user_c, target_c
                    )
                });
                let _ = client_stream.write_all(RESP_503).await;
                return Ok(());
            }
        }
    } else {
        None
    };

    // ── SNI/Host recovery ───────────────────────────────────────────
    // Pool-routed clients only. When the CONNECT target is a bare IPv4
    // literal and recovery is enabled, recover the intended hostname
    // from the client's first record (pipelined ClientHello, or the
    // first read) and address the upstream by that domain. See
    // `recover_host_from_payload` in NetworkConfig.
    if !is_direct && network.recover_host_from_payload {
        if let Some(port) = ipv4_literal_port(&req.target) {
            return recover_and_tunnel_http(
                client_stream,
                &req.target,
                port,
                req.pipelined,
                gate_rotator,
                v6_rotator,
                v4_rotator,
                logger,
                banned,
                pool,
                frag,
                network,
                req.client_user.as_deref(),
                tls_connector,
                client_deadline,
            )
            .await;
        }
    }

    let proxy_stream = if is_direct {
        let user_owned = req
            .client_user
            .as_deref()
            .expect("is_direct implies a named user");
        match crate::server::establish_direct(&req.target, banned, logger, network, user_owned)
            .await
        {
            Ok(s) => s,
            Err(e) => {
                let resp = if banned.is_match(&req.target) {
                    RESP_403
                } else {
                    RESP_502
                };
                let _ = client_stream.write_all(resp).await;
                return Err(e);
            }
        }
    } else {
        match server::establish_connection(
            &req.target,
            gate_rotator,
            v6_rotator,
            v4_rotator,
            logger,
            banned,
            pool,
            network,
            req.client_user.as_deref(),
            tls_connector,
        )
        .await
        {
            Ok(s) => s,
            Err(e) => {
                let resp = if banned.is_match(&req.target) {
                    RESP_403
                } else {
                    RESP_502
                };
                let _ = client_stream.write_all(resp).await;
                return Err(e);
            }
        }
    };

    client_stream
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await?;

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
    server::forward_tunnel(client_stream, proxy_stream, req.pipelined, frag, network).await
}
