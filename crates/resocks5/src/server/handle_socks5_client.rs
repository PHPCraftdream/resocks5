use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::Duration;

use anyhow::anyhow;
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
use resocks5_net::connect::send_possibly_fragmented;
use resocks5_net::connect::tcp_keepalive::set_keepalive;
use resocks5_net::connect::tunnel::tunnel_with_timeouts;
use resocks5_net::pool::ProxyPool;
use resocks5_net::rotator::ProxyRotator;

#[allow(clippy::too_many_arguments)]
pub async fn handle_socks5_client(
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
) -> anyhow::Result<()> {
    let protocol_dur = Duration::from_secs(network.client_protocol_timeout_sec);

    // ── Phase 1: client-side SOCKS5 handshake ───────────────────────
    // Greeting + method selection + (optional) RFC 1929 auth + CONNECT
    // request, all under a single deadline. Slowloris-style clients
    // that hold the TCP open but never finish the protocol exit here
    // instead of pinning the task indefinitely.
    let (target_addr, client_user) =
        match timeout(protocol_dur, socks5_handshake(&mut client_stream, auth)).await {
            Ok(Ok(pair)) => pair,
            Ok(Err(e)) => return Err(e),
            Err(_) => {
                return Err(anyhow!(
                    "client SOCKS5 handshake timed out after {}s",
                    protocol_dur.as_secs()
                ));
            }
        };

    // ── Phase 2: upstream connect (no client-protocol timeout) ──────
    // If the authenticated user has direct=true, bypass the pool and
    // connect straight to the target. Anonymous clients NEVER take the
    // direct path.
    let is_direct = client_user
        .as_deref()
        .map(|u| auth.is_direct(u))
        .unwrap_or(false);

    // Acquire a direct-limiter permit when taking the bypass path.
    // Held until this function returns so it covers the full tunnel
    // lifetime. `None` for the pool path.
    let _direct_permit = if is_direct {
        let user_owned = client_user
            .as_deref()
            .expect("is_direct implies a named user");
        match direct_limiter.clone().try_acquire_owned() {
            Ok(p) => Some(p),
            Err(_) => {
                let target_addr_c = target_addr.clone();
                let user_c = user_owned.to_string();
                let cap = network.max_concurrent_direct;
                logger.connection_error(move || {
                    format!(
                        "Direct cap reached ({}) — dropping client={} target={}",
                        cap, user_c, target_addr_c
                    )
                });
                let _ = client_stream
                    .write_all(&[0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                    .await;
                return Ok(());
            }
        }
    } else {
        None
    };

    let mut proxy_stream = if is_direct {
        let user_owned = client_user
            .as_deref()
            .expect("is_direct implies a named user");
        match crate::server::establish_direct(&target_addr, banned, logger, network, user_owned)
            .await
        {
            Ok(s) => s,
            Err(e) => {
                let rep = if banned.is_match(&target_addr) {
                    0x02
                } else {
                    0x04
                };
                let _ = client_stream
                    .write_all(&[0x05, rep, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                    .await;
                return Err(e);
            }
        }
    } else {
        match server::establish_connection(
            &target_addr,
            gate_rotator,
            v6_rotator,
            v4_rotator,
            logger,
            banned,
            pool,
            network,
            client_user.as_deref(),
            tls_connector,
        )
        .await
        {
            Ok(s) => s,
            Err(e) => {
                let rep = if banned.is_match(&target_addr) {
                    0x02
                } else {
                    0x04
                };
                let _ = client_stream
                    .write_all(&[0x05, rep, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                    .await;
                return Err(e);
            }
        }
    };

    client_stream
        .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await?;

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
        // Read up to 16 KiB so the entire TLS ClientHello (including
        // bulky extensions like ECH and post-quantum key shares) is in
        // hand before we split. Fragmenting only the first 4 KiB
        // would leak the SNI in the unfragmented remainder.
        let mut buf = vec![0u8; 16 * 1024];
        match client_stream.read(&mut buf).await? {
            0 => return Ok(()),
            n => send_possibly_fragmented(&mut proxy_stream, &buf[..n], &frag.to_spec()).await?,
        }
    }

    // `tunnel_with_timeouts` is a half-close-aware bidirectional
    // copy with two safety nets: an idle deadline (sends FIN on both
    // halves when no bytes flow either direction for
    // `tunnel_idle_timeout_sec`) and a hard lifetime cap. Replaces
    // `tokio::io::copy_bidirectional`, which had no activity tracking.
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

/// Read greeting → method-selection → (optional) RFC 1929 auth →
/// CONNECT request from the client. Returns `(target_addr,
/// authenticated_username)` on success; the username is `None` for
/// the anonymous-method path.
async fn socks5_handshake(
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
        let mut uname = vec![0u8; ulen];
        client_stream.read_exact(&mut uname).await?;
        let mut plen_buf = [0u8; 1];
        client_stream.read_exact(&mut plen_buf).await?;
        let plen = plen_buf[0] as usize;
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

        if !auth.verify(uname_str, pword_str) {
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
            format!(
                "{}:{}",
                String::from_utf8(domain_buf)?,
                u16::from_be_bytes(port_bytes)
            )
        }
        0x04 => {
            let mut ip_bytes = [0u8; 16];
            let mut port_bytes = [0u8; 2];
            client_stream.read_exact(&mut ip_bytes).await?;
            client_stream.read_exact(&mut port_bytes).await?;
            format!(
                "{}:{}",
                Ipv6Addr::from(ip_bytes),
                u16::from_be_bytes(port_bytes)
            )
        }
        _ => return Err(anyhow!("Unknown ATYP: {:02x}", req_hdr[3])),
    };

    Ok((target_addr, authed_user))
}
