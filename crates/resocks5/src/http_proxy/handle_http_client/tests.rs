use super::*;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

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
    resocks5_net::types::ProxyConfig::socks5("127.0.0.1", addr.port())
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
    let client_deadline =
        tokio::time::Instant::now() + Duration::from_secs(network.client_protocol_timeout_sec);
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
        let req = recovery_request().await;
        recover_and_tunnel_http(
            server,
            &req,
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
            client_deadline,
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
    let client_deadline =
        tokio::time::Instant::now() + Duration::from_secs(network.client_protocol_timeout_sec);
    let frag = Arc::new(TlsFragmentConfig::default());
    let gate: Option<Arc<ProxyRotator>> = None;
    let v6: Option<Arc<ProxyRotator>> = None;

    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let caddr = l.local_addr().unwrap();
    let mut client = TcpStream::connect(caddr).await.unwrap();
    let server = l.accept().await.unwrap().0;

    let task = tokio::spawn(async move {
        let req = recovery_request().await;
        recover_and_tunnel_http(
            server,
            &req,
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
            client_deadline,
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
    let client_deadline =
        tokio::time::Instant::now() + Duration::from_secs(network.client_protocol_timeout_sec);
    let frag = Arc::new(TlsFragmentConfig::default());
    let gate: Option<Arc<ProxyRotator>> = None;
    let v6: Option<Arc<ProxyRotator>> = None;

    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let caddr = l.local_addr().unwrap();
    let mut client = TcpStream::connect(caddr).await.unwrap();
    let server = l.accept().await.unwrap().0;

    let task = tokio::spawn(async move {
        let req = recovery_request().await;
        recover_and_tunnel_http(
            server,
            &req,
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
            client_deadline,
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
    let client_deadline =
        tokio::time::Instant::now() + Duration::from_secs(network.client_protocol_timeout_sec);
    let frag = Arc::new(TlsFragmentConfig::default());
    let gate: Option<Arc<ProxyRotator>> = None;
    let v6: Option<Arc<ProxyRotator>> = None;

    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let caddr = l.local_addr().unwrap();
    let mut client = TcpStream::connect(caddr).await.unwrap();
    let server = l.accept().await.unwrap().0;

    let task = tokio::spawn(async move {
        let req = recovery_request().await;
        recover_and_tunnel_http(
            server,
            &req,
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
            client_deadline,
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

// ── R7-01: an expired deadline must not start recovery ──────────

#[tokio::test]
async fn expired_deadline_with_pipelined_payload_never_starts_recovery() {
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
    // Already in the past: the client-protocol budget is exhausted
    // before recovery is even entered.
    let client_deadline = tokio::time::Instant::now() - Duration::from_secs(1);
    let frag = Arc::new(TlsFragmentConfig::default());
    let gate: Option<Arc<ProxyRotator>> = None;
    let v6: Option<Arc<ProxyRotator>> = None;

    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let caddr = l.local_addr().unwrap();
    let mut client = TcpStream::connect(caddr).await.unwrap();
    let server = l.accept().await.unwrap().0;

    // A decidable payload rides along pipelined past CONNECT — the
    // recovery probes would decide on the very first poll (the
    // exact shortcut a bare `timeout` used to take before
    // consulting an already-expired timer).
    let hello = client_hello_with_sni("pipelined.example");

    let task = tokio::spawn(async move {
        let req = recovery_request().await;
        recover_and_tunnel_http(
            server,
            &req,
            "203.0.113.9:443",
            "443",
            hello,
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
            client_deadline,
        )
        .await
    });

    let result = tokio::time::timeout(Duration::from_secs(8), task)
        .await
        .expect("expired deadline must not stall recovery")
        .unwrap();
    assert!(result.is_err(), "expected Err, got: {result:?}");

    // The 200 must never have gone out: the client sees a bare
    // EOF, zero bytes. (A close can surface as RST on some
    // platforms; any other error is a real failure.)
    let mut received = Vec::new();
    let eof = tokio::time::timeout(Duration::from_secs(5), client.read_to_end(&mut received))
        .await
        .expect("client must see EOF promptly");
    if let Err(err) = eof {
        assert_eq!(
            err.kind(),
            std::io::ErrorKind::ConnectionReset,
            "client must see EOF promptly, got: {err}"
        );
    }
    assert!(
        received.is_empty(),
        "no byte may reach the client once the deadline is expired, got {received:?}"
    );

    // A healthy upstream was reachable, yet must never be dialed.
    let targets = up_log.lock().unwrap().clone();
    assert!(
        targets.is_empty(),
        "no upstream may be dialed on an expired deadline, targets: {targets:?}"
    );
}

#[tokio::test]
async fn handle_client_hands_partial_http_pipeline_to_recovery_losslessly() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream_listener.local_addr().unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let auth = Arc::new(
            AuthState::build(
                &crate::config::AuthConfig {
                    allow_anonymous: true,
                },
                &crate::config::UsersConfig { users: Vec::new() },
                "unused-handoff",
            )
            .unwrap(),
        );
        let v4 = Some(Arc::new(ProxyRotator::new(vec![socks5_upstream_config(
            upstream_addr,
        )])));
        let no_rotator = None;
        let logger = test_logger();
        let banned = Arc::new(regex::RegexSet::empty());
        let pool = Arc::new(ProxyPool::new(
            Default::default(),
            Duration::from_secs(2),
            4,
        ));
        let frag = Arc::new(TlsFragmentConfig::default());
        let network = Arc::new(NetworkConfig {
            client_protocol_timeout_sec: 5,
            handshake_timeout_sec: 2,
            ..Default::default()
        });
        let direct_limiter = Arc::new(tokio::sync::Semaphore::new(1));
        let hello = client_hello_with_sni("handoff.example");
        let expected = hello.clone();
        let mut request = b"CONNECT 203.0.113.9:443 HTTP/1.1\r\n\r\n".to_vec();
        request.extend_from_slice(&hello[..5]);
        assert!(request.len() < 1024);
        let (frame_sent_tx, frame_sent_rx) = tokio::sync::oneshot::channel();
        let (upstream_seen_tx, upstream_seen_rx) = tokio::sync::oneshot::channel();
        let upstream = async {
            let (mut socket, _) = upstream_listener.accept().await.unwrap();
            let mut greeting = [0; 2];
            socket.read_exact(&mut greeting).await.unwrap();
            assert_eq!(greeting[0], 5);
            let mut methods = vec![0; usize::from(greeting[1])];
            socket.read_exact(&mut methods).await.unwrap();
            assert!(methods.contains(&0));
            socket.write_all(&[5, 0]).await.unwrap();
            let mut header = [0; 4];
            socket.read_exact(&mut header).await.unwrap();
            assert_eq!(header, [5, 1, 0, 3]);
            let len = socket.read_u8().await.unwrap();
            let mut domain = vec![0; usize::from(len)];
            socket.read_exact(&mut domain).await.unwrap();
            assert_eq!(domain, b"handoff.example");
            assert_eq!(socket.read_u16().await.unwrap(), 443);
            socket
                .write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0])
                .await
                .unwrap();
            let mut payload = Vec::new();
            socket.read_to_end(&mut payload).await.unwrap();
            assert_eq!(
                payload, expected,
                "prefix must be forwarded exactly once before segmented remainder"
            );
            socket.shutdown().await.unwrap();
            upstream_seen_tx.send(()).unwrap();
        };
        let host = async {
            let (socket, _) = listener.accept().await.unwrap();
            let deadline =
                Instant::now() + Duration::from_secs(network.client_protocol_timeout_sec);
            frame_sent_rx.await.unwrap();
            // Do not poll the parser until the entire header and partial hello
            // share the receive queue. Peek preserves every byte; the outer
            // timeout bounds this yield-only loop without timing sleeps.
            let mut queued = vec![0; request.len()];
            loop {
                let n = socket.peek(&mut queued).await.unwrap();
                assert_ne!(n, 0, "peer closed before queuing the pipeline");
                if n == request.len() {
                    assert_eq!(queued, request);
                    break;
                }
                tokio::task::yield_now().await;
            }
            crate::server::handle_client(
                socket,
                &auth,
                &no_rotator,
                &no_rotator,
                &v4,
                &logger,
                &banned,
                &pool,
                &frag,
                &network,
                None,
                &direct_limiter,
                &None,
                deadline,
            )
            .await
            .unwrap();
        };
        let peer = async {
            let mut socket = TcpStream::connect(address).await.unwrap();
            socket.write_all(&request).await.unwrap();
            frame_sent_tx.send(()).unwrap();
            let expected_reply = b"HTTP/1.1 200 Connection Established\r\n\r\n";
            let mut reply = vec![0; expected_reply.len()];
            socket.read_exact(&mut reply).await.unwrap();
            assert_eq!(reply, expected_reply);
            // The reply synchronizes the first segment before the remaining hello.
            socket.write_all(&hello[5..]).await.unwrap();
            socket.shutdown().await.unwrap();
            let mut extra = Vec::new();
            socket.read_to_end(&mut extra).await.unwrap();
            assert!(
                extra.is_empty(),
                "no second protocol reply after early success"
            );
            upstream_seen_rx.await.unwrap();
        };
        tokio::join!(upstream, host, peer);
    })
    .await
    .expect("finite application handoff");
}

#[tokio::test(start_paused = true)]
async fn delayed_handle_client_rejects_expired_accept_deadline_without_consumption() {
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let path = std::env::temp_dir().join(format!(
        "resocks5-delayed-init-{}-{}.ktav",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    assert!(!path.exists());
    let auth = Arc::new(
        AuthState::build(
            &crate::config::AuthConfig {
                allow_anonymous: false,
            },
            &crate::config::UsersConfig {
                users: vec![crate::config::User {
                    name: "bob".into(),
                    hash: "init".into(),
                    is_enabled: true,
                    direct: false,
                    allowed_clients: None,
                }],
            },
            path.to_string_lossy().into_owned(),
        )
        .unwrap(),
    );
    let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let v4 = Some(Arc::new(ProxyRotator::new(vec![socks5_upstream_config(
        upstream_listener.local_addr().unwrap(),
    )])));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut peer = TcpStream::connect(listener.local_addr().unwrap())
        .await
        .unwrap();
    let (socket, _) = listener.accept().await.unwrap();
    let deadline = Instant::now() + Duration::from_secs(1);
    // Duplicate the accepted OS socket solely in this test. Both handles see the
    // same receive queue; keeping an observer alive proves the handler did not read.
    let original = socket.into_std().unwrap();
    let observer = original.try_clone().unwrap();
    let socket = TcpStream::from_std(original).unwrap();
    let mut observer = TcpStream::from_std(observer).unwrap();
    let frame = b"CONNECT 203.0.113.9:443 HTTP/1.1\r\nProxy-Authorization: Basic Ym9iOnB3\r\n\r\n";
    peer.write_all(frame).await.unwrap();
    let mut first = [0; 1];
    observer.peek(&mut first).await.unwrap();
    assert_eq!(first, [b'C']);
    // Deliberately defer entry, without a sleep or a production observation seam.
    tokio::time::advance(Duration::from_secs(2)).await;
    // Real sockets below: a paused clock auto-advances whenever the runtime is
    // idle, so a late kernel event (FIN delivery on macOS) would trip the
    // timeouts. The deadline is already expired; wall-clock time is enough.
    tokio::time::resume();
    let logger = test_logger();
    let banned = Arc::new(regex::RegexSet::empty());
    let pool = Arc::new(ProxyPool::new(
        Default::default(),
        Duration::from_secs(1),
        1,
    ));
    let frag = Arc::new(TlsFragmentConfig::default());
    let network = Arc::new(NetworkConfig::default());
    let direct_limiter = Arc::new(tokio::sync::Semaphore::new(1));
    let no_rotator = None;
    let error = crate::server::handle_client(
        socket,
        &auth,
        &no_rotator,
        &no_rotator,
        &v4,
        &logger,
        &banned,
        &pool,
        &frag,
        &network,
        None,
        &direct_limiter,
        &None,
        deadline,
    )
    .await
    .expect_err("expired accept deadline");
    assert!(matches!(
        error.downcast_ref::<resocks5_net::server::ServerError>(),
        Some(resocks5_net::server::ServerError::Deadline)
    ));
    let mut untouched = vec![0; frame.len()];
    tokio::time::timeout(Duration::from_secs(5), observer.read_exact(&mut untouched))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(untouched, frame);
    assert!(
        !path.exists(),
        "expired handler must not claim/persist credentials"
    );
    let upstream = upstream_listener.into_std().unwrap();
    assert!(
        matches!(upstream.accept(), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock)
    );
    drop(observer);
    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), peer.read_to_end(&mut response))
        .await
        .unwrap()
        .unwrap();
    assert!(
        response.is_empty(),
        "expired handler must send no protocol reply"
    );
}

/// Parse a real request to obtain the recovery reply capability.
async fn recovery_request() -> IncomingRequest {
    let (mut peer, mut stream) = tokio::io::duplex(128);
    peer.write_all(b"CONNECT 203.0.113.9:443 HTTP/1.1\r\n\r\n")
        .await
        .unwrap();
    resocks5_net::server::accept(
        &mut stream,
        &resocks5_net::server::ServerOptions::new(
            tokio::time::Instant::now() + Duration::from_secs(5),
            true,
            false,
        ),
        |_| async { false },
    )
    .await
    .unwrap()
}
