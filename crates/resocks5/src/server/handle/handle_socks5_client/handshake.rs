use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

use anyhow::anyhow;
use resocks5_net::connect::HostPort;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::auth::AuthState;

/// Read greeting → method-selection → (optional) RFC 1929 auth →
/// CONNECT request from the client. Returns `(target_addr,
/// authenticated_username)` on success; the username is `None` for
/// the anonymous-method path.
pub(super) async fn socks5_handshake(
    client_stream: &mut TcpStream,
    auth: &Arc<AuthState>,
) -> anyhow::Result<(String, Option<String>)> {
    let mut greeting = [0u8; 2];
    client_stream.read_exact(&mut greeting).await?;
    if greeting[0] != 0x05 {
        return Err(anyhow!(
            "Invalid SOCKS version from client: {:02x}",
            greeting[0]
        ));
    }
    let nmethods = greeting[1] as usize;
    let mut methods = vec![0u8; nmethods];
    client_stream.read_exact(&mut methods).await?;

    // Method-selection matrix:
    //
    //   users empty | allow_anonymous | server advertises
    //   ------------|-----------------|----------------------
    //   yes         | true            | 0x00 (anonymous)
    //   yes         | false           | nothing → reject all
    //   no          | true            | 0x00 + 0x02
    //   no          | false           | 0x02 only
    //
    // We pick the method we both support, preferring 0x02 over 0x00
    // when both are on the table — so a client that *can* identify
    // itself does, instead of being silently treated as anonymous.
    let server_supports_auth = !auth.is_empty();
    let server_supports_anon = auth.allow_anonymous;

    let chosen: u8 = if server_supports_auth && methods.contains(&0x02) {
        0x02
    } else if server_supports_anon && methods.contains(&0x00) {
        0x00
    } else {
        client_stream.write_all(&[0x05, 0xff]).await?;
        return Err(anyhow!(
            "No mutually supported SOCKS5 auth method (server: anonymous={}, user/pass={}; \
             client offered {} method(s))",
            server_supports_anon,
            server_supports_auth,
            methods.len()
        ));
    };

    client_stream.write_all(&[0x05, chosen]).await?;

    let mut authed_user: Option<String> = None;

    if chosen == 0x02 {
        // RFC 1929 sub-negotiation:
        //   VER=0x01  ULEN  UNAME...  PLEN  PASSWD...
        let mut auth_hdr = [0u8; 2];
        client_stream.read_exact(&mut auth_hdr).await?;
        if auth_hdr[0] != 0x01 {
            return Err(anyhow!(
                "Invalid auth subnegotiation version: {:02x}",
                auth_hdr[0]
            ));
        }
        let ulen = auth_hdr[1] as usize;
        // RFC 1929 §2: ULEN and PLEN are 1..=255 — a zero length is a
        // malformed frame, rejected before any credential processing.
        if ulen == 0 {
            let _ = client_stream.write_all(&[0x01, 0x01]).await;
            return Err(anyhow!(
                "Zero-length username in auth subnegotiation (RFC 1929 requires 1-255 bytes)"
            ));
        }
        let mut uname = vec![0u8; ulen];
        client_stream.read_exact(&mut uname).await?;
        let mut plen_buf = [0u8; 1];
        client_stream.read_exact(&mut plen_buf).await?;
        let plen = plen_buf[0] as usize;
        if plen == 0 {
            let _ = client_stream.write_all(&[0x01, 0x01]).await;
            return Err(anyhow!(
                "Zero-length password in auth subnegotiation (RFC 1929 requires 1-255 bytes)"
            ));
        }
        let mut pword = vec![0u8; plen];
        client_stream.read_exact(&mut pword).await?;

        let uname_str = match std::str::from_utf8(&uname) {
            Ok(s) => s,
            Err(_) => {
                let _ = client_stream.write_all(&[0x01, 0x01]).await;
                return Err(anyhow!("Invalid UTF-8 in username"));
            }
        };
        let pword_str = match std::str::from_utf8(&pword) {
            Ok(s) => s,
            Err(_) => {
                let _ = client_stream.write_all(&[0x01, 0x01]).await;
                return Err(anyhow!("Invalid UTF-8 in password"));
            }
        };

        if !auth.verify_async(uname_str, pword_str).await {
            // Generic "auth failed" reply — same code for unknown user,
            // disabled user, and bad password, so the client can't
            // distinguish causes.
            let _ = client_stream.write_all(&[0x01, 0x01]).await;
            return Err(anyhow!("Auth failed for user '{}'", uname_str));
        }

        // RFC 1929 success: VER=0x01, STATUS=0x00.
        client_stream.write_all(&[0x01, 0x00]).await?;
        authed_user = Some(uname_str.to_string());
    }

    let mut req_hdr = [0u8; 4];
    client_stream.read_exact(&mut req_hdr).await?;
    if req_hdr[0] != 0x05 {
        return Err(anyhow!("Invalid version in CONNECT request"));
    }
    if req_hdr[1] != 0x01 {
        return Err(anyhow!("Only CONNECT commands are supported"));
    }
    let target_addr = match req_hdr[3] {
        0x01 => {
            let mut ip_bytes = [0u8; 4];
            let mut port_bytes = [0u8; 2];
            client_stream.read_exact(&mut ip_bytes).await?;
            client_stream.read_exact(&mut port_bytes).await?;
            format!(
                "{}:{}",
                Ipv4Addr::from(ip_bytes),
                u16::from_be_bytes(port_bytes)
            )
        }
        0x03 => {
            let mut len_buf = [0u8; 1];
            client_stream.read_exact(&mut len_buf).await?;
            let mut domain_buf = vec![0u8; len_buf[0] as usize];
            let mut port_bytes = [0u8; 2];
            client_stream.read_exact(&mut domain_buf).await?;
            client_stream.read_exact(&mut port_bytes).await?;
            let domain = String::from_utf8(domain_buf)?;
            let target = format!("{}:{}", domain, u16::from_be_bytes(port_bytes));
            // Validate DOMAINNAME BEFORE any pool acquire / dial: an
            // empty domain, one carrying control/whitespace bytes, or
            // a name the upstream HostPort grammar rejects is a client
            // error — it must cost a client-facing SOCKS5 failure
            // reply here, never a wasted upstream attempt booked
            // against a healthy proxy's rating. (R8-03; mirrors the
            // HTTP CONNECT input validation.)
            if domain.is_empty()
                || domain
                    .bytes()
                    .any(|b| b.is_ascii_control() || b.is_ascii_whitespace())
                || HostPort::parse(&target).is_none()
            {
                let _ = client_stream
                    .write_all(&[0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                    .await;
                return Err(anyhow!(
                    "Invalid DOMAINNAME in CONNECT request: {:?}",
                    domain
                ));
            }
            target
        }
        0x04 => {
            let mut ip_bytes = [0u8; 16];
            let mut port_bytes = [0u8; 2];
            client_stream.read_exact(&mut ip_bytes).await?;
            client_stream.read_exact(&mut port_bytes).await?;
            format!(
                "[{}]:{}",
                Ipv6Addr::from(ip_bytes),
                u16::from_be_bytes(port_bytes)
            )
        }
        _ => return Err(anyhow!("Unknown ATYP: {:02x}", req_hdr[3])),
    };

    Ok((target_addr, authed_user))
}
