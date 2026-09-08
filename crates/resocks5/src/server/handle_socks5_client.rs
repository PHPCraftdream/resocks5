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
use resocks5_net::connect::tcp_keepalive::set_keepalive;
use resocks5_net::connect::{parse_http_host, parse_sni};
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

    // ── SNI/Host recovery ───────────────────────────────────────────
    // Pool-routed clients only (never direct). When the CONNECT target
    // is a bare IPv4 literal and recovery is enabled, we recover the
    // intended hostname from the client's first record (TLS SNI / HTTP
    // Host) and address the upstream by that domain. See
    // `recover_host_from_payload` in NetworkConfig for the rationale.
    if !is_direct && network.recover_host_from_payload {
        if let Some(port) = ipv4_literal_port(&target_addr) {
            return recover_and_tunnel(
                client_stream,
                &target_addr,
                port,
                gate_rotator,
                v6_rotator,
                v4_rotator,
                logger,
                banned,
                pool,
                frag,
                network,
                client_user.as_deref(),
                tls_connector,
            )
            .await;
        }
    }

    let proxy_stream = if is_direct {
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
    }
    server::forward_tunnel(client_stream, proxy_stream, Vec::new(), frag, network).await
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

/// Recovery path: the client asked for a bare IPv4 and recovery is on.
///
/// We send the SOCKS5 success reply *early* so the client emits its
/// first application record, peek it to recover the intended hostname
/// (TLS SNI or HTTP `Host`), then open the upstream addressed by that
/// domain — falling back to the original IP when nothing is recovered.
/// The peeked record is forwarded (fragmented if configured) before the
/// bidirectional tunnel starts, so no client bytes are lost.
#[allow(clippy::too_many_arguments)]
async fn recover_and_tunnel(
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
) -> anyhow::Result<()> {
    let ctag = match client_user {
        Some(u) => format!(" [client={}]", u),
        None => " [client=anon]".to_string(),
    };

    // Early SOCKS5 success reply — required so the client sends its
    // ClientHello / HTTP request, which carries the name we need.
    client_stream
        .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await?;

    // Read the first application record under the client-protocol
    // deadline (slowloris guard: a client that completes CONNECT but
    // never speaks must not pin the slot).
    let protocol_dur = Duration::from_secs(network.client_protocol_timeout_sec);
    let mut buf = vec![0u8; 16 * 1024];
    let n = match timeout(protocol_dur, client_stream.read(&mut buf)).await {
        Ok(Ok(0)) => return Ok(()), // client closed before sending
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
    buf.truncate(n);

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
