use std::sync::Arc;

use anyhow::{anyhow, Result};
use base64::{engine::general_purpose, Engine as _};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::auth::AuthState;
use resocks5_net::connect::HostPort;

use super::byte_lines::{find_double_crlf, ByteLines};
use super::{MAX_HEADER_BYTES, RESP_400, RESP_407, RESP_413, RESP_501};

/// Parsed result of the HTTP CONNECT handshake phase.
pub(crate) struct ConnectRequest {
    pub(crate) target: String,
    /// Any bytes the client pipelined past `\r\n\r\n` — typically a
    /// fast-open TLS ClientHello. Empty in the normal case.
    pub(crate) pipelined: Vec<u8>,
    /// Authenticated client username from `Proxy-Authorization: Basic`
    /// (`None` for anonymous CONNECT). Propagated into every log line
    /// for this request so we can tell WHICH client triggered which
    /// upstream failure.
    pub(crate) client_user: Option<String>,
}

/// Read the HTTP CONNECT request line + headers until `\r\n\r\n`,
/// validate the method, run RFC 7617 Basic auth against `auth`. Any
/// bytes after `\r\n\r\n` are returned as `pipelined` for the
/// fast-open TLS ClientHello case. On failure the appropriate HTTP
/// response is written to the client before the error is returned.
pub(super) async fn parse_http_connect(
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
    let mut lines = ByteLines {
        rest: &buf[..header_end - 4],
    };

    let request_line = match lines.next() {
        // An empty header block yields no line at all; the empty string
        // then fails the request-line check below exactly like the old
        // collect-then-index parser's empty first line did.
        None => "",
        Some(line) => match std::str::from_utf8(line) {
            Ok(s) => s,
            Err(_) => {
                let _ = client_stream.write_all(RESP_400).await;
                return Err(anyhow!("non-UTF-8 bytes in HTTP request line"));
            }
        },
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
    // The upstream HTTP client (write_connect_request in
    // resocks5-net/src/connect/connect_http_proxy.rs) rejects any target
    // byte that is ASCII control or whitespace. Reject it here instead,
    // BEFORE any pool acquire / dial: such a target is a client error
    // (RFC 9110 §9.3.6) and must cost a 400 — never a wasted upstream
    // attempt booked against a healthy proxy's rating.
    if target
        .bytes()
        .any(|b| b.is_ascii_control() || b.is_ascii_whitespace())
    {
        let _ = client_stream.write_all(RESP_400).await;
        return Err(anyhow!(
            "CONNECT target contains control or whitespace bytes — {:?}",
            target
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
    for line in lines {
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
