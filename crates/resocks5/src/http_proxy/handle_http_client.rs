use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Result};
use base64::{engine::general_purpose, Engine as _};
use regex::RegexSet;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use tokio::time::timeout;

use tokio_rustls::TlsConnector;

use crate::auth::AuthState;
use crate::config::{NetworkConfig, TlsFragmentConfig};
use crate::logger::Logger;
use crate::server;
use resocks5_net::connect::tcp_keepalive::set_keepalive;
use resocks5_net::connect::tunnel::tunnel_with_timeouts;
use resocks5_net::connect::{parse_http_host, parse_sni, send_possibly_fragmented};
use resocks5_net::pool::ProxyPool;
use resocks5_net::rotator::ProxyRotator;

/// Maximum size of the request line + headers section. 16 KiB matches
/// what mainstream servers (nginx, Apache) use for client request
/// headers — enough for any sane Proxy-Authorization plus typical
/// browser header bloat, small enough that a hostile client cannot
/// exhaust memory by streaming an unterminated header.
const MAX_HEADER_BYTES: usize = 16 * 1024;

const RESP_407: &[u8] = b"HTTP/1.1 407 Proxy Authentication Required\r\n\
                          Proxy-Authenticate: Basic realm=\"resocks5\"\r\n\
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

/// Parsed result of the HTTP CONNECT handshake phase.
struct ConnectRequest {
    target: String,
    /// Any bytes the client pipelined past `\r\n\r\n` — typically a
    /// fast-open TLS ClientHello. Empty in the normal case.
    pipelined: Vec<u8>,
    /// Authenticated client username from `Proxy-Authorization: Basic`
    /// (`None` for anonymous CONNECT). Propagated into every log line
    /// for this request so we can tell WHICH client triggered which
    /// upstream failure.
    client_user: Option<String>,
}

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
) -> Result<()> {
    let protocol_dur = Duration::from_secs(network.client_protocol_timeout_sec);

    // ── Phase 1: HTTP CONNECT request + auth ────────────────────────
    // Bounded by the client-protocol deadline so a slow drip of header
    // bytes can't pin the handler indefinitely.
    let req = match timeout(protocol_dur, parse_http_connect(&mut client_stream, auth)).await {
        Ok(Ok(r)) => r,
        Ok(Err(e)) => return Err(e),
        Err(_) => {
            return Err(anyhow!(
                "client HTTP CONNECT timed out after {}s",
                protocol_dur.as_secs()
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
            )
            .await;
        }
    }

    let mut proxy_stream = if is_direct {
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
        if !req.pipelined.is_empty() {
            // Fast-open path: TLS ClientHello arrived pipelined with
            // the CONNECT request — fragment it before bidir copy.
            send_possibly_fragmented(&mut proxy_stream, &req.pipelined, &frag.to_spec()).await?;
        } else {
            // Normal path: read the first application chunk from the
            // client (typically TLS ClientHello) and fragment it.
            // 16 KiB buffer covers oversized ClientHello records with
            // ECH / post-quantum extensions.
            let mut buf = vec![0u8; 16 * 1024];
            match client_stream.read(&mut buf).await? {
                0 => return Ok(()),
                n => {
                    send_possibly_fragmented(&mut proxy_stream, &buf[..n], &frag.to_spec()).await?
                }
            }
        }
    } else if !req.pipelined.is_empty() {
        proxy_stream.write_all(&req.pipelined).await?;
    }

    // `tunnel_with_timeouts` is a half-close-aware bidirectional
    // copy with two safety nets: an idle deadline (sends FIN on both
    // halves when no bytes flow either direction for
    // `tunnel_idle_timeout_sec`) and a hard lifetime cap.
    let idle = idle_duration(network.tunnel_idle_timeout_sec);
    let lifetime = Duration::from_secs(network.tunnel_max_lifetime_sec);
    let _ = tunnel_with_timeouts(client_stream, proxy_stream, idle, lifetime).await;
    Ok(())
}

/// `0` means "no idle check"; we still need a finite Duration to feed
/// `tokio::time::sleep`. A century is well within Tokio's safe range
/// and effectively never fires.
fn idle_duration(secs: u64) -> Duration {
    if secs == 0 {
        Duration::from_secs(60 * 60 * 24 * 365 * 100)
    } else {
        Duration::from_secs(secs)
    }
}

/// If `target` is `IPv4:port`, return the port substring; otherwise
/// `None`. Recovery applies only to bare IPv4 literals (domains already
/// carry the name; IPv6 literals stay on the standard path).
fn ipv4_literal_port(target: &str) -> Option<&str> {
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
/// Established` early so the client emits its first record, recover the
/// hostname from the pipelined ClientHello (or the first read) via TLS
/// SNI / HTTP `Host`, open the upstream by that domain (falling back to
/// the IP), forward the buffered record, then tunnel.
#[allow(clippy::too_many_arguments)]
async fn recover_and_tunnel_http(
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
) -> Result<()> {
    let ctag = match client_user {
        Some(u) => format!(" [client={}]", u),
        None => " [client=anon]".to_string(),
    };

    // Early 200 so the client sends its first application record.
    client_stream
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await?;

    // First record: prefer a pipelined ClientHello, else read one under
    // the client-protocol deadline.
    let buf: Vec<u8> = if !pipelined.is_empty() {
        pipelined
    } else {
        let protocol_dur = Duration::from_secs(network.client_protocol_timeout_sec);
        let mut b = vec![0u8; 16 * 1024];
        let n = match timeout(protocol_dur, client_stream.read(&mut b)).await {
            Ok(Ok(0)) => return Ok(()),
            Ok(Ok(n)) => n,
            Ok(Err(e)) => return Err(e.into()),
            Err(_) => {
                return Err(anyhow!(
                    "client sent no payload within {}s — recovery peek timeout{}",
                    protocol_dur.as_secs(),
                    ctag
                ));
            }
        };
        b.truncate(n);
        b
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
    let mut proxy_stream = match server::establish_connection(
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
        send_possibly_fragmented(&mut proxy_stream, &buf, &frag.to_spec()).await?;
    } else {
        proxy_stream.write_all(&buf).await?;
    }

    let idle = idle_duration(network.tunnel_idle_timeout_sec);
    let lifetime = Duration::from_secs(network.tunnel_max_lifetime_sec);
    let _ = tunnel_with_timeouts(client_stream, proxy_stream, idle, lifetime).await;
    Ok(())
}

/// Read the HTTP CONNECT request line + headers until `\r\n\r\n`,
/// validate the method, run RFC 7617 Basic auth against `auth`. Any
/// bytes after `\r\n\r\n` are returned as `pipelined` for the
/// fast-open TLS ClientHello case. On failure the appropriate HTTP
/// response is written to the client before the error is returned.
async fn parse_http_connect(
    client_stream: &mut TcpStream,
    auth: &Arc<AuthState>,
) -> Result<ConnectRequest> {
    // Drain bytes until \r\n\r\n. Any bytes that arrive past the header
    // boundary belong to the tunneled payload — we hand them to the
    // upstream after the 200 reply, so a client that pipelines a TLS
    // ClientHello immediately after CONNECT (rare but legal) doesn't
    // lose its handshake bytes.
    let mut buf = Vec::with_capacity(2048);
    let mut tmp = [0u8; 1024];
    let header_end = loop {
        let n = client_stream.read(&mut tmp).await?;
        if n == 0 {
            return Err(anyhow!("client closed before sending HTTP request line"));
        }
        buf.extend_from_slice(&tmp[..n]);
        if let Some(pos) = find_double_crlf(&buf) {
            break pos + 4;
        }
        if buf.len() > MAX_HEADER_BYTES {
            let _ = client_stream.write_all(RESP_413).await;
            return Err(anyhow!("HTTP headers exceeded {} bytes", MAX_HEADER_BYTES));
        }
    };
    let pipelined = buf.split_off(header_end);
    let header_section = std::str::from_utf8(&buf[..header_end - 4])
        .map_err(|_| anyhow!("non-UTF-8 bytes in HTTP request line/headers"))?;

    let mut lines = header_section.split("\r\n");
    let request_line = lines.next().unwrap_or("");
    let mut parts = request_line.splitn(3, ' ');
    let method = parts.next().unwrap_or("");
    let target = parts.next().unwrap_or("");
    let version = parts.next().unwrap_or("");

    if method.is_empty() || target.is_empty() || !version.starts_with("HTTP/") {
        let _ = client_stream.write_all(RESP_400).await;
        return Err(anyhow!("malformed HTTP request line: {:?}", request_line));
    }
    if method != "CONNECT" {
        let _ = client_stream.write_all(RESP_501).await;
        return Err(anyhow!(
            "only CONNECT is supported, client sent {:?}",
            method
        ));
    }
    if !target.contains(':') {
        let _ = client_stream.write_all(RESP_400).await;
        return Err(anyhow!("CONNECT target lacks :port — {:?}", target));
    }

    // Find Proxy-Authorization (case-insensitive header name).
    let mut proxy_auth_value: Option<&str> = None;
    for line in lines {
        if line.is_empty() {
            continue;
        }
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if name.trim().eq_ignore_ascii_case("proxy-authorization") {
            proxy_auth_value = Some(value.trim());
            break;
        }
    }

    // Auth policy mirrors the SOCKS5 dispatcher in
    // proxy_tools::handle_socks5_client:
    //
    //   users empty | allow_anonymous | client behaviour
    //   ------------|-----------------|-----------------
    //   yes         | true            | accepted, no creds checked
    //   yes         | false           | always 407 (REJECT-ALL)
    //   no          | true            | creds verified if present, else accepted
    //   no          | false           | creds required and verified
    let server_supports_auth = !auth.is_empty();
    let server_supports_anon = auth.allow_anonymous;

    let mut client_user: Option<String> = None;

    match proxy_auth_value {
        Some(value) => {
            let creds_b64 = match split_basic_token(value) {
                Some(s) => s,
                None => {
                    let _ = client_stream.write_all(RESP_407).await;
                    return Err(anyhow!(
                        "unsupported Proxy-Authorization scheme: {:?}",
                        value
                    ));
                }
            };
            let decoded = match general_purpose::STANDARD.decode(creds_b64) {
                Ok(b) => b,
                Err(_) => {
                    let _ = client_stream.write_all(RESP_407).await;
                    return Err(anyhow!("Proxy-Authorization base64 decode failed"));
                }
            };
            let s = match std::str::from_utf8(&decoded) {
                Ok(s) => s,
                Err(_) => {
                    let _ = client_stream.write_all(RESP_407).await;
                    return Err(anyhow!("Proxy-Authorization not valid UTF-8"));
                }
            };
            let Some((user, password)) = s.split_once(':') else {
                let _ = client_stream.write_all(RESP_407).await;
                return Err(anyhow!("Proxy-Authorization missing ':'"));
            };
            if !server_supports_auth {
                let _ = client_stream.write_all(RESP_407).await;
                return Err(anyhow!(
                    "client sent Proxy-Authorization but server has no users configured"
                ));
            }
            if !auth.verify(user, password) {
                let _ = client_stream.write_all(RESP_407).await;
                return Err(anyhow!("HTTP auth failed for user {:?}", user));
            }
            client_user = Some(user.to_string());
        }
        None => {
            if !server_supports_anon {
                let _ = client_stream.write_all(RESP_407).await;
                return Err(anyhow!(
                    "anonymous HTTP CONNECT not allowed (allow_anonymous=false)"
                ));
            }
        }
    }

    Ok(ConnectRequest {
        target: target.to_string(),
        pipelined,
        client_user,
    })
}

fn find_double_crlf(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

fn split_basic_token(value: &str) -> Option<&str> {
    let mut it = value.splitn(2, ' ');
    let scheme = it.next()?;
    let token = it.next()?.trim();
    if scheme.eq_ignore_ascii_case("Basic") {
        Some(token)
    } else {
        None
    }
}
