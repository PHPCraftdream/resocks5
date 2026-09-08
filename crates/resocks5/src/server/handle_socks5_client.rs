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
use crate::server::recovery::{peek_recovery, RecoveryPeek};
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
/// first application record, then recover the intended hostname from
/// it (TLS SNI or HTTP `Host`) and open the upstream addressed by that
/// domain — falling back to the original IP when nothing is recovered.
/// The prefix is *accumulated* across reads (TCP segmentation routinely
/// splits a ClientHello, and a single read would see only a truncated
/// prefix) until the parsers decide, the probes rule the record out, or
/// the 16 KiB cap is hit — all under the existing client-protocol
/// deadline, so the peeked record is forwarded (fragmented if
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

    // Peek under the client-protocol deadline (slowloris guard: a
    // client that completes CONNECT but never speaks must not pin the
    // slot). The grace window inside distinguishes a slow client-first
    // protocol from a server-speaks-first one.
    let protocol_dur = Duration::from_secs(network.client_protocol_timeout_sec);
    let peeked = match timeout(
        protocol_dur,
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
                "[{}]:{}",
                Ipv6Addr::from(ip_bytes),
                u16::from_be_bytes(port_bytes)
            )
        }
        _ => return Err(anyhow!("Unknown ATYP: {:02x}", req_hdr[3])),
    };

    Ok((target_addr, authed_user))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    use super::socks5_handshake;

    #[tokio::test]
    async fn recovery_limit_preserves_the_unread_tail() {
        let mut seed = b"GET / HTTP/1.1\r\nX-Pad: ".to_vec();
        seed.resize(16 * 1024 - 1, b'a');
        let (mut client, mut reader) = tokio::io::duplex(128);
        client
            .write_all(b"a\r\nHost: example.com\r\n\r\nbody")
            .await
            .unwrap();
        client.shutdown().await.unwrap();
        let prefix = crate::server::recovery::read_recovery_prefix(&mut reader, seed)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(prefix.len(), 16 * 1024);
        let mut tail = Vec::new();
        reader.read_to_end(&mut tail).await.unwrap();
        assert_eq!(tail, b"\r\nHost: example.com\r\n\r\nbody");
    }

    fn test_auth() -> Arc<crate::auth::AuthState> {
        Arc::new(
            crate::auth::AuthState::build(
                &crate::config::AuthConfig {
                    allow_anonymous: true,
                },
                &crate::config::UsersConfig { users: Vec::new() },
                "unused",
            )
            .unwrap(),
        )
    }

    /// Server side of the handshake test: accept one connection, run
    /// `socks5_handshake` on it, and return `(target_addr, authed_user)`.
    async fn serve_one(
        listener: TcpListener,
        auth: Arc<crate::auth::AuthState>,
    ) -> anyhow::Result<(String, Option<String>)> {
        let (mut server, _) = listener.accept().await?;
        socks5_handshake(&mut server, &auth).await
    }

    #[tokio::test]
    async fn ipv6_target_is_bracketed() {
        let auth = test_auth();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(serve_one(listener, auth));

        let mut client = TcpStream::connect(addr).await.unwrap();
        client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut method = [0u8; 2];
        client.read_exact(&mut method).await.unwrap();
        assert_eq!(method, [0x05, 0x00]);
        client
            .write_all(&[
                0x05, 0x01, 0x00, 0x04, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0x01, 0xBB,
            ])
            .await
            .unwrap();

        let (target_addr, authed_user) = tokio::time::timeout(Duration::from_secs(5), async {
            (server.await.unwrap().unwrap(), ())
        })
        .await
        .expect("timed out")
        .0;
        assert_eq!(target_addr, "[::1]:443");
        assert_eq!(authed_user, None);
    }

    #[tokio::test]
    async fn ipv4_target_unchanged() {
        let auth = test_auth();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(serve_one(listener, auth));

        let mut client = TcpStream::connect(addr).await.unwrap();
        client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut method = [0u8; 2];
        client.read_exact(&mut method).await.unwrap();
        client
            .write_all(&[0x05, 0x01, 0x00, 0x01, 1, 2, 3, 4, 0x01, 0xBB])
            .await
            .unwrap();

        let (target_addr, _) = tokio::time::timeout(Duration::from_secs(5), async {
            (server.await.unwrap().unwrap(), ())
        })
        .await
        .expect("timed out")
        .0;
        assert_eq!(target_addr, "1.2.3.4:443");
    }

    #[tokio::test]
    async fn domain_target_unchanged() {
        let auth = test_auth();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(serve_one(listener, auth));

        let mut client = TcpStream::connect(addr).await.unwrap();
        client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut method = [0u8; 2];
        client.read_exact(&mut method).await.unwrap();
        client
            .write_all(&[0x05, 0x01, 0x00, 0x03, 11])
            .await
            .unwrap();
        client.write_all(b"example.com").await.unwrap();
        client.write_all(&[0x01, 0xBB]).await.unwrap();

        let (target_addr, _) = tokio::time::timeout(Duration::from_secs(5), async {
            (server.await.unwrap().unwrap(), ())
        })
        .await
        .expect("timed out")
        .0;
        assert_eq!(target_addr, "example.com:443");
    }

    // ── Recovery-path tests ─────────────────────────────────────────
    //
    // These exercise `recover_and_tunnel` end-to-end against a minimal
    // no-auth SOCKS5 stub upstream, so the tests observe which target
    // the upstream was asked for (recovered host vs. bare IP) and what
    // bytes flowed through the tunnel.

    use std::net::SocketAddr;
    use std::sync::Mutex;

    use super::recover_and_tunnel;
    use crate::config::{NetworkConfig, TlsFragmentConfig};
    use resocks5_net::rotator::ProxyRotator;

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
    async fn recovery_recovers_sni_across_segmented_reads() {
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

        let hello = client_hello_with_sni("recovered.example");
        let task = tokio::spawn(async move {
            recover_and_tunnel(
                server,
                "203.0.113.9:443",
                "443",
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

        // Early SOCKS5 success reply.
        let mut success = [0u8; 10];
        client.read_exact(&mut success).await.unwrap();
        assert_eq!([success[0], success[1]], [0x05, 0x00]);

        // Split the ClientHello: 5 bytes first (record header only — the
        // exact prefix the old single-read flow misclassified), the rest
        // after real time has passed so one read cannot see both writes.
        client.write_all(&hello[..5]).await.unwrap();
        tokio::time::sleep(Duration::from_millis(150)).await;
        client.write_all(&hello[5..]).await.unwrap();

        // Close the client so the forwarding phase sees EOF and the
        // task terminates instead of tunneling forever.
        drop(client);

        tokio::time::timeout(Duration::from_secs(8), task)
            .await
            .expect("recovery must not stall")
            .unwrap()
            .expect("recovery succeeds");
        let targets = up_log.lock().unwrap().clone();
        assert!(
            targets.iter().any(|t| t == "recovered.example:443"),
            "SNI must be recovered despite segmentation, targets: {targets:?}"
        );
        assert!(
            !targets.iter().any(|t| t == "203.0.113.9:443"),
            "the IP must not be dialed when SNI was recovered, targets: {targets:?}"
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
            recover_and_tunnel(
                server,
                "203.0.113.9:22",
                "22",
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

        // Read the early success, then stay silent — the client of an SSH
        // server waits for the banner.
        let mut success = [0u8; 10];
        client.read_exact(&mut success).await.unwrap();

        // The banner must arrive via the speculative upstream connection —
        // long before client_protocol_timeout_sec (5s here).
        let mut banner = [0u8; 14];
        tokio::time::timeout(Duration::from_secs(4), client.read_exact(&mut banner))
            .await
            .expect("banner must arrive without the full protocol timeout")
            .unwrap();
        assert_eq!(&banner, b"SSH-2.0-stub\r\n");

        // The tunnel must be live in BOTH directions afterwards.
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
    async fn undecidable_client_payload_falls_back_to_ip_promptly() {
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
            recover_and_tunnel(
                server,
                "203.0.113.9:443",
                "443",
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

        let mut success = [0u8; 10];
        client.read_exact(&mut success).await.unwrap();
        // Neither a TLS record nor an HTTP request: both probes must
        // call this "definitively absent" immediately.
        client.write_all(b"\x00\x01\x02").await.unwrap();
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

    #[tokio::test]
    async fn client_closed_before_payload_ends_cleanly() {
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
            recover_and_tunnel(
                server,
                "203.0.113.9:443",
                "443",
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

        let mut success = [0u8; 10];
        client.read_exact(&mut success).await.unwrap();
        // The EOF lands during the grace read, so no upstream is ever
        // dialed; the observable contract is a clean Ok(()) and an
        // untouched stub.
        drop(client);

        let result = tokio::time::timeout(Duration::from_secs(8), task)
            .await
            .expect("client-close path must not stall")
            .unwrap();
        assert!(result.is_ok(), "expected Ok(()), got: {result:?}");
        let targets = up_log.lock().unwrap().clone();
        assert!(
            targets.is_empty(),
            "no upstream may be dialed when the client closed first, targets: {targets:?}"
        );
    }
}
