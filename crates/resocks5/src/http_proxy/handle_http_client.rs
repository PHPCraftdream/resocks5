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
use crate::server::recovery::{peek_recovery, RecoveryPeek};
use resocks5_net::connect::tcp_keepalive::set_keepalive;
use resocks5_net::connect::{parse_http_host, parse_sni, HostPort};
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
/// Established` early so the client emits its first record, then
/// accumulate that record across reads (TCP segmentation routinely
/// splits a ClientHello, and a pipelined fast-open hello can itself be
/// truncated) until TLS SNI / HTTP `Host` recovery can decide, the
/// probes rule the record out, or the 16 KiB cap is hit — all under the
/// existing client-protocol deadline. Open the upstream by that domain
/// (falling back to the IP), forward the buffered record, then tunnel.
///
/// A client still silent after the ~1 s grace (`CLIENT_FIRST_GRACE`) is
/// unlikely to be TLS/HTTP (those speak within an RTT): the upstream —
/// dialed by the original IP, nothing recovered yet — then gets one
/// chance to greet first. A server-speaks-first protocol (SSH, SMTP,
/// FTP) does, and we fall back to plain forwarding by IP; otherwise we
/// keep waiting for the client as before.
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

    let protocol_dur = Duration::from_secs(network.client_protocol_timeout_sec);
    let peeked = match timeout(
        protocol_dur,
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
        ),
    )
    .await
    {
        Ok(result) => result?,
        Err(_) => {
            return Err(anyhow!(
                "client sent no payload within {}s ? recovery peek timeout{}",
                protocol_dur.as_secs(),
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
        let scan_from = buf.len().saturating_sub(3);
        buf.extend_from_slice(&tmp[..n]);
        if let Some(pos) = find_double_crlf(&buf[scan_from..]) {
            let end = scan_from + pos + 4;
            if end > MAX_HEADER_BYTES {
                let _ = client_stream.write_all(RESP_413).await;
                return Err(anyhow!("HTTP headers exceeded {} bytes", MAX_HEADER_BYTES));
            }
            break end;
        }
        if buf.len() > MAX_HEADER_BYTES {
            let _ = client_stream.write_all(RESP_413).await;
            return Err(anyhow!("HTTP headers exceeded {} bytes", MAX_HEADER_BYTES));
        }
    };
    let pipelined = buf.split_off(header_end);
    // Byte-wise header parsing: obs-text bytes (0x80..=0xFF) are legal
    // in field values (RFC 9110 §5.5) and this proxy ignores fields it
    // doesn't use, so the block as a whole must NOT be required to be
    // UTF-8. Only the request line and the fields actually read below
    // are validated.
    let mut lines: Vec<&[u8]> = Vec::new();
    let mut rest = &buf[..header_end - 4];
    while let Some(pos) = rest.windows(2).position(|w| w == b"\r\n") {
        lines.push(&rest[..pos]);
        rest = &rest[pos + 2..];
    }
    lines.push(rest);

    let request_line = match std::str::from_utf8(lines[0]) {
        Ok(s) => s,
        Err(_) => {
            let _ = client_stream.write_all(RESP_400).await;
            return Err(anyhow!("non-UTF-8 bytes in HTTP request line"));
        }
    };
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
    // Validate the authority with the same grammar the upstream applies
    // (HostPort::parse) BEFORE any pool acquire / dial: a bad port is a
    // client error (RFC 9110 §9.3.6) and must cost a 400 here — never a
    // wasted upstream attempt or a rotator rating penalty.
    if HostPort::parse(target).is_none() {
        let _ = client_stream.write_all(RESP_400).await;
        return Err(anyhow!(
            "CONNECT target is not a valid host:port authority — {:?}",
            target
        ));
    }

    // Find Proxy-Authorization (case-insensitive header name). The scan
    // works on raw bytes; only THIS field's value must be UTF-8 (it is
    // decoded further below) — opaque bytes in any other header are
    // skipped without affecting the parse.
    let mut proxy_auth_value: Option<&str> = None;
    for &line in lines.iter().skip(1) {
        if line.is_empty() {
            continue;
        }
        let Some(colon) = line.iter().position(|&b| b == b':') else {
            continue;
        };
        let (name, value) = (&line[..colon], &line[colon + 1..]);
        if !name
            .trim_ascii()
            .eq_ignore_ascii_case(b"proxy-authorization")
        {
            continue;
        }
        let Ok(value) = std::str::from_utf8(value.trim_ascii()) else {
            let _ = client_stream.write_all(RESP_407).await;
            return Err(anyhow!("Proxy-Authorization header is not valid UTF-8"));
        };
        proxy_auth_value = Some(value);
        break;
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
                    return Err(anyhow!("unsupported Proxy-Authorization scheme"));
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
            if !auth.verify_async(user, password).await {
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

#[cfg(test)]
mod tests {
    use super::*;

    async fn parse_request(request: &[u8]) -> (Result<ConnectRequest>, Vec<u8>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = async {
            let (mut stream, _) = listener.accept().await.unwrap();
            let auth = Arc::new(
                AuthState::build(
                    &crate::config::AuthConfig {
                        allow_anonymous: true,
                    },
                    &crate::config::UsersConfig { users: Vec::new() },
                    "unused-users.ktav",
                )
                .unwrap(),
            );
            parse_http_connect(&mut stream, &auth).await
        };
        let client = async {
            let mut stream = TcpStream::connect(address).await.unwrap();
            stream.write_all(request).await.unwrap();
            stream.shutdown().await.unwrap();
            let mut response = Vec::new();
            stream.read_to_end(&mut response).await.unwrap();
            response
        };
        tokio::time::timeout(Duration::from_secs(5), async {
            tokio::join!(server, client)
        })
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn unsupported_auth_does_not_expose_credentials() {
        let (result, response) = parse_request(b"CONNECT example.com:443 HTTP/1.1\r\nProxy-Authorization: Bearer private-token\r\n\r\n").await;
        let error = result
            .err()
            .expect("unsupported auth must fail")
            .to_string();
        assert!(!error.contains("private-token"));
        assert!(response.starts_with(b"HTTP/1.1 407 "));
    }

    #[tokio::test]
    async fn header_limit_includes_the_terminating_delimiter() {
        let mut request = b"CONNECT example.com:443 HTTP/1.1\r\nX-Pad: ".to_vec();
        request.resize(MAX_HEADER_BYTES - 4, b'a');
        request.extend_from_slice(b"\r\n\r\n");
        assert!(parse_request(&request).await.0.is_ok());
        request.insert(MAX_HEADER_BYTES - 4, b'a');
        let (result, response) = parse_request(&request).await;
        assert!(result.is_err());
        assert!(response.starts_with(b"HTTP/1.1 431 "));
    }

    #[tokio::test]
    async fn invalid_connect_port_is_rejected_with_400_without_dialing() {
        // parse_http_connect is called directly — no pool, rotator, or
        // upstream exists in this test, so a 400 here provably happens
        // before any upstream attempt or rating change.
        for target in [
            "example.com:notaport",
            "example.com:",
            "example.com:99999",
            "example.com:65536",
            "example.com:-1",
            ":443",
            "[::1]",
        ] {
            let request = format!("CONNECT {target} HTTP/1.1\r\nHost: example.com\r\n\r\n");
            let (result, response) = parse_request(request.as_bytes()).await;
            let error = result
                .err()
                .unwrap_or_else(|| panic!("target {target:?} must be rejected"));
            assert!(
                !error.to_string().contains("upstream"),
                "target {target:?} must not be classified as an upstream failure: {error}"
            );
            assert!(
                response.starts_with(b"HTTP/1.1 400 "),
                "target {target:?} must get 400, got {response:?}"
            );
        }
    }

    #[tokio::test]
    async fn valid_connect_authorities_still_parse() {
        for target in [
            "example.com:443",
            "1.2.3.4:443",
            "[2001:db8::1]:443",
            "2001:db8::1:443",
        ] {
            let request = format!("CONNECT {target} HTTP/1.1\r\nHost: example.com\r\n\r\n");
            let (result, _) = parse_request(request.as_bytes()).await;
            assert!(result.is_ok(), "target {target:?} must still parse");
        }
    }

    #[tokio::test]
    async fn opaque_byte_in_unused_header_does_not_break_connect() {
        // obs-text 0xE9 inside a header the proxy never reads (RFC 9110
        // §5.5) must not fail the parse of an otherwise-valid CONNECT.
        let request =
            b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com\r\nX-Opaque: \xE9\r\n\r\n"
                .to_vec();
        let (result, response) = parse_request(&request).await;
        let req = result.expect("obs-text in an unused header must not fail the parse");
        assert_eq!(req.target, "example.com:443");
        assert!(
            response.is_empty(),
            "no error response expected on success, got {response:?}"
        );
    }

    #[tokio::test]
    async fn non_utf8_proxy_authorization_value_is_rejected_with_407() {
        let (result, response) = parse_request(
            b"CONNECT example.com:443 HTTP/1.1\r\nProxy-Authorization: Basic \xE9\r\n\r\n",
        )
        .await;
        assert!(result.is_err());
        assert!(response.starts_with(b"HTTP/1.1 407 "));
    }

    #[tokio::test]
    async fn non_utf8_request_line_is_rejected_with_400() {
        let (result, response) =
            parse_request(b"CONNECT ex\xE9ample.com:443 HTTP/1.1\r\nHost: example.com\r\n\r\n")
                .await;
        assert!(result.is_err());
        assert!(response.starts_with(b"HTTP/1.1 400 "));
    }

    // ── Recovery-path tests ─────────────────────────────────────────
    //
    // Mirror of the SOCKS5 recovery tests: exercise
    // `recover_and_tunnel_http` end-to-end against a minimal no-auth
    // SOCKS5 stub upstream, observing which target the upstream was
    // asked for (recovered host vs. bare IP) and what bytes flowed.

    use std::net::SocketAddr;
    use std::sync::Mutex;

    use tokio::net::TcpListener;

    fn test_logger() -> Arc<crate::logger::Logger> {
        let (tx, _rx) = tokio::sync::mpsc::channel::<crate::logger::ELog>(64);
        Arc::new(crate::logger::Logger::new(
            tx,
            crate::logger::LogConfig::default(),
        ))
    }

    /// Minimal no-auth SOCKS5 stub. After CONNECT succeeds it writes
    /// `banner` to the tunnel (if non-empty), then records everything the
    /// client sends. The log starts with the requested target ("host:port").
    async fn spawn_socks5_stub(banner: &'static [u8]) -> (SocketAddr, Arc<Mutex<Vec<String>>>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let log: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let log2 = log.clone();
        tokio::spawn(async move {
            while let Ok((sock, _)) = listener.accept().await {
                let log = log2.clone();
                tokio::spawn(async move {
                    let _ = serve_stub_client(sock, log, banner).await;
                });
            }
        });
        (addr, log)
    }

    async fn serve_stub_client(
        mut sock: tokio::net::TcpStream,
        log: Arc<Mutex<Vec<String>>>,
        banner: &'static [u8],
    ) -> Option<()> {
        let mut greet = [0u8; 2];
        sock.read_exact(&mut greet).await.ok()?;
        let mut methods = vec![0u8; greet[1] as usize];
        sock.read_exact(&mut methods).await.ok()?;
        sock.write_all(&[0x05, 0x00]).await.ok()?;
        let mut head = [0u8; 4];
        sock.read_exact(&mut head).await.ok()?;
        let host = match head[3] {
            0x01 => {
                let mut o = [0u8; 4];
                sock.read_exact(&mut o).await.ok()?;
                std::net::Ipv4Addr::from(o).to_string()
            }
            0x03 => {
                let mut l = [0u8; 1];
                sock.read_exact(&mut l).await.ok()?;
                let mut d = vec![0u8; l[0] as usize];
                sock.read_exact(&mut d).await.ok()?;
                String::from_utf8(d).ok()?
            }
            _ => return None,
        };
        let mut pt = [0u8; 2];
        sock.read_exact(&mut pt).await.ok()?;
        log.lock()
            .unwrap()
            .push(format!("{}:{}", host, u16::from_be_bytes(pt)));
        sock.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .await
            .ok()?;
        if !banner.is_empty() {
            sock.write_all(banner).await.ok()?;
        }
        let mut b = [0u8; 512];
        loop {
            match sock.read(&mut b).await {
                Ok(0) | Err(_) => break,
                Ok(n) => log
                    .lock()
                    .unwrap()
                    .push(String::from_utf8_lossy(&b[..n]).into_owned()),
            }
        }
        Some(())
    }

    fn socks5_upstream_config(addr: SocketAddr) -> resocks5_net::types::ProxyConfig {
        resocks5_net::types::ProxyConfig {
            protocol: resocks5_net::types::ProxyProtocol::Socks5,
            ip: resocks5_net::types::IP::V4,
            host: "127.0.0.1".to_string(),
            port: addr.port(),
            user: None,
            password: None,
            is_gate: false,
            gate: None,
        }
    }

    /// Build a minimal but well-formed TLS ClientHello carrying a single
    /// SNI host_name extension. (Duplicated from the private helper in
    /// `resocks5-net/src/connect/recover_host.rs` — it is not exported.)
    fn client_hello_with_sni(host: &str) -> Vec<u8> {
        let host_bytes = host.as_bytes();
        let mut sni_ext = Vec::new();
        let entry_len = 1 + 2 + host_bytes.len();
        sni_ext.extend_from_slice(&(entry_len as u16).to_be_bytes());
        sni_ext.push(0x00); // name_type = host_name
        sni_ext.extend_from_slice(&(host_bytes.len() as u16).to_be_bytes());
        sni_ext.extend_from_slice(host_bytes);

        let mut exts = Vec::new();
        exts.extend_from_slice(&0x0000u16.to_be_bytes());
        exts.extend_from_slice(&(sni_ext.len() as u16).to_be_bytes());
        exts.extend_from_slice(&sni_ext);

        let mut ch = Vec::new();
        ch.extend_from_slice(&[0x03, 0x03]); // client_version TLS1.2
        ch.extend_from_slice(&[0xAB; 32]); // random
        ch.push(0x00); // session_id length 0
        ch.extend_from_slice(&0x0002u16.to_be_bytes()); // cipher_suites len
        ch.extend_from_slice(&[0x13, 0x01]); // one cipher suite
        ch.push(0x01); // compression_methods len
        ch.push(0x00); // null compression
        ch.extend_from_slice(&(exts.len() as u16).to_be_bytes());
        ch.extend_from_slice(&exts);

        let mut hs = Vec::new();
        hs.push(0x01);
        let l = ch.len();
        hs.push((l >> 16) as u8);
        hs.push((l >> 8) as u8);
        hs.push(l as u8);
        hs.extend_from_slice(&ch);

        let mut rec = Vec::new();
        rec.push(0x16);
        rec.extend_from_slice(&[0x03, 0x01]);
        rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        rec.extend_from_slice(&hs);
        rec
    }

    #[tokio::test]
    async fn recovery_recovers_sni_from_truncated_pipelined_hello() {
        let (up_addr, up_log) = spawn_socks5_stub(b"").await;
        let v4 = Some(Arc::new(ProxyRotator::new(vec![socks5_upstream_config(
            up_addr,
        )])));
        let logger = test_logger();
        let banned = Arc::new(regex::RegexSet::empty());
        let pool = Arc::new(resocks5_net::pool::ProxyPool::new(
            Default::default(),
            Duration::from_secs(2),
            4,
        ));
        let network = Arc::new(NetworkConfig {
            client_protocol_timeout_sec: 5,
            handshake_timeout_sec: 2,
            ..Default::default()
        });
        let frag = Arc::new(TlsFragmentConfig::default());
        let gate: Option<Arc<ProxyRotator>> = None;
        let v6: Option<Arc<ProxyRotator>> = None;

        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let caddr = l.local_addr().unwrap();
        let mut client = TcpStream::connect(caddr).await.unwrap();
        let server = l.accept().await.unwrap().0;

        // First 5 bytes of the hello ride along pipelined; the 200 reply
        // is sent first, then the rest arrives in a separate segment.
        let hello = client_hello_with_sni("recovered.example");
        let rest = hello[5..].to_vec();
        let task = tokio::spawn(async move {
            recover_and_tunnel_http(
                server,
                "203.0.113.9:443",
                "443",
                hello[..5].to_vec(), // truncated pipelined prefix
                &gate,
                &v6,
                &v4,
                &logger,
                &banned,
                &pool,
                &frag,
                &network,
                None,
                None,
            )
            .await
        });

        let mut reply = [0u8; b"HTTP/1.1 200 Connection Established\r\n\r\n".len()];
        client.read_exact(&mut reply).await.unwrap();
        assert!(reply.starts_with(b"HTTP/1.1 200 "));

        tokio::time::sleep(Duration::from_millis(150)).await;
        client.write_all(&rest).await.unwrap();
        drop(client);

        tokio::time::timeout(Duration::from_secs(8), task)
            .await
            .expect("recovery must not stall")
            .unwrap()
            .expect("recovery succeeds");
        let targets = up_log.lock().unwrap().clone();
        assert!(
            targets.iter().any(|t| t == "recovered.example:443"),
            "SNI must be recovered from the truncated pipelined hello, targets: {targets:?}"
        );
        assert!(
            !targets.iter().any(|t| t == "203.0.113.9:443"),
            "the IP must not be dialed when SNI was recovered, targets: {targets:?}"
        );
    }

    #[tokio::test]
    async fn recovery_recovers_http_host_across_segmented_reads() {
        let (up_addr, up_log) = spawn_socks5_stub(b"").await;
        let v4 = Some(Arc::new(ProxyRotator::new(vec![socks5_upstream_config(
            up_addr,
        )])));
        let logger = test_logger();
        let banned = Arc::new(regex::RegexSet::empty());
        let pool = Arc::new(resocks5_net::pool::ProxyPool::new(
            Default::default(),
            Duration::from_secs(2),
            4,
        ));
        let network = Arc::new(NetworkConfig {
            client_protocol_timeout_sec: 5,
            handshake_timeout_sec: 2,
            ..Default::default()
        });
        let frag = Arc::new(TlsFragmentConfig::default());
        let gate: Option<Arc<ProxyRotator>> = None;
        let v6: Option<Arc<ProxyRotator>> = None;

        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let caddr = l.local_addr().unwrap();
        let mut client = TcpStream::connect(caddr).await.unwrap();
        let server = l.accept().await.unwrap().0;

        let task = tokio::spawn(async move {
            recover_and_tunnel_http(
                server,
                "203.0.113.9:80",
                "80",
                Vec::new(),
                &gate,
                &v6,
                &v4,
                &logger,
                &banned,
                &pool,
                &frag,
                &network,
                None,
                None,
            )
            .await
        });

        let mut reply = [0u8; b"HTTP/1.1 200 Connection Established\r\n\r\n".len()];
        client.read_exact(&mut reply).await.unwrap();
        assert!(reply.starts_with(b"HTTP/1.1 200 "));

        // The request line + Host header split across two writes, with
        // real time in between so one read cannot see both.
        client.write_all(b"POST / HTTP/1.1\r\nHo").await.unwrap();
        tokio::time::sleep(Duration::from_millis(150)).await;
        client
            .write_all(b"st: recovered.example\r\nContent-Length: 0\r\n\r\n")
            .await
            .unwrap();
        drop(client);

        tokio::time::timeout(Duration::from_secs(8), task)
            .await
            .expect("recovery must not stall")
            .unwrap()
            .expect("recovery succeeds");
        let targets = up_log.lock().unwrap().clone();
        assert!(
            targets.iter().any(|t| t == "recovered.example:80"),
            "HTTP Host must be recovered across segmented reads, targets: {targets:?}"
        );
        assert!(
            !targets.iter().any(|t| t == "203.0.113.9:80"),
            "the IP must not be dialed when the Host was recovered, targets: {targets:?}"
        );
    }

    #[tokio::test]
    async fn server_first_upstream_banner_is_relayed_without_recovery() {
        let (up_addr, up_log) = spawn_socks5_stub(b"SSH-2.0-stub\r\n").await;
        let v4 = Some(Arc::new(ProxyRotator::new(vec![socks5_upstream_config(
            up_addr,
        )])));
        let logger = test_logger();
        let banned = Arc::new(regex::RegexSet::empty());
        let pool = Arc::new(resocks5_net::pool::ProxyPool::new(
            Default::default(),
            Duration::from_secs(2),
            4,
        ));
        let network = Arc::new(NetworkConfig {
            client_protocol_timeout_sec: 5,
            handshake_timeout_sec: 2,
            ..Default::default()
        });
        let frag = Arc::new(TlsFragmentConfig::default());
        let gate: Option<Arc<ProxyRotator>> = None;
        let v6: Option<Arc<ProxyRotator>> = None;

        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let caddr = l.local_addr().unwrap();
        let mut client = TcpStream::connect(caddr).await.unwrap();
        let server = l.accept().await.unwrap().0;

        let task = tokio::spawn(async move {
            recover_and_tunnel_http(
                server,
                "203.0.113.9:22",
                "22",
                Vec::new(),
                &gate,
                &v6,
                &v4,
                &logger,
                &banned,
                &pool,
                &frag,
                &network,
                None,
                None,
            )
            .await
        });

        // Read the early 200 reply, then stay silent — the client of an
        // SSH server waits for the banner.
        let mut reply = [0u8; b"HTTP/1.1 200 Connection Established\r\n\r\n".len()];
        client.read_exact(&mut reply).await.unwrap();

        let mut banner = [0u8; 14];
        tokio::time::timeout(Duration::from_secs(4), client.read_exact(&mut banner))
            .await
            .expect("banner must arrive without the full protocol timeout")
            .unwrap();
        assert_eq!(&banner, b"SSH-2.0-stub\r\n");

        client.write_all(b"CLIENT-RESP").await.unwrap();
        drop(client);

        tokio::time::timeout(Duration::from_secs(8), task)
            .await
            .expect("server-first path must not stall")
            .unwrap()
            .expect("server-first tunnel succeeds");
        let targets = up_log.lock().unwrap().clone();
        assert!(
            targets.iter().any(|t| t == "203.0.113.9:22"),
            "the upstream must be dialed by the original IP, targets: {targets:?}"
        );
        assert!(
            targets.iter().any(|t| t == "CLIENT-RESP"),
            "client traffic must flow after the banner, targets: {targets:?}"
        );
        assert_eq!(
            targets.first().map(String::as_str),
            Some("203.0.113.9:22"),
            "no recovery may happen for a server-speaks-first protocol, targets: {targets:?}"
        );
    }

    #[tokio::test]
    async fn undecidable_pipelined_payload_falls_back_to_ip_promptly() {
        let (up_addr, up_log) = spawn_socks5_stub(b"").await;
        let v4 = Some(Arc::new(ProxyRotator::new(vec![socks5_upstream_config(
            up_addr,
        )])));
        let logger = test_logger();
        let banned = Arc::new(regex::RegexSet::empty());
        let pool = Arc::new(resocks5_net::pool::ProxyPool::new(
            Default::default(),
            Duration::from_secs(2),
            4,
        ));
        let network = Arc::new(NetworkConfig {
            client_protocol_timeout_sec: 5,
            handshake_timeout_sec: 2,
            ..Default::default()
        });
        let frag = Arc::new(TlsFragmentConfig::default());
        let gate: Option<Arc<ProxyRotator>> = None;
        let v6: Option<Arc<ProxyRotator>> = None;

        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let caddr = l.local_addr().unwrap();
        let mut client = TcpStream::connect(caddr).await.unwrap();
        let server = l.accept().await.unwrap().0;

        let task = tokio::spawn(async move {
            recover_and_tunnel_http(
                server,
                "203.0.113.9:443",
                "443",
                b"\x00\x01\x02".to_vec(),
                &gate,
                &v6,
                &v4,
                &logger,
                &banned,
                &pool,
                &frag,
                &network,
                None,
                None,
            )
            .await
        });

        let mut reply = [0u8; b"HTTP/1.1 200 Connection Established\r\n\r\n".len()];
        client.read_exact(&mut reply).await.unwrap();
        drop(client);

        tokio::time::timeout(Duration::from_secs(8), task)
            .await
            .expect("undecidable payload must not stall recovery")
            .unwrap()
            .expect("fallback-to-IP tunnel succeeds");
        let targets = up_log.lock().unwrap().clone();
        assert!(
            targets.iter().any(|t| t == "203.0.113.9:443"),
            "the IP must be dialed when no host is recoverable, targets: {targets:?}"
        );
        assert_eq!(
            targets.first().map(String::as_str),
            Some("203.0.113.9:443"),
            "the CONNECT target must be the only dialed host, targets: {targets:?}"
        );
    }
}
