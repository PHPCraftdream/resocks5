use super::*;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

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
    let (result, response) = parse_request(
        b"CONNECT example.com:443 HTTP/1.1\r\nProxy-Authorization: Bearer private-token\r\n\r\n",
    )
    .await;
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
async fn control_bytes_in_connect_target_are_rejected_with_400_without_dialing() {
    // parse_http_connect is called directly — no pool, rotator, or
    // upstream exists in this test, so a 400 here provably happens
    // before any upstream attempt or rating change.
    for target in [
        "exa\x00mple.com:443", // NUL
        "exa\x01mple.com:443", // SOH
        "exa\x7Fmple.com:443", // DEL
        "exa\nmple.com:443",   // smuggled lone LF
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
        b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com\r\nX-Opaque: \xE9\r\n\r\n".to_vec();
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
        parse_request(b"CONNECT ex\xE9ample.com:443 HTTP/1.1\r\nHost: example.com\r\n\r\n").await;
    assert!(result.is_err());
    assert!(response.starts_with(b"HTTP/1.1 400 "));
}

#[test]
fn byte_lines_yields_the_old_collect_semantics_without_the_table() {
    fn old_lines(mut rest: &[u8]) -> Vec<&[u8]> {
        let mut lines = Vec::new();
        while let Some(pos) = rest.windows(2).position(|w| w == b"\r\n") {
            lines.push(&rest[..pos]);
            rest = &rest[pos + 2..];
        }
        lines.push(rest);
        lines
    }

    let buffers: [&[u8]; 6] = [
        b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com",
        b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com\r\n",
        b"\r\nFAST-OPEN-CLIENTHELLO",
        b"single line without terminator",
        b"",
        b"first\r\n\r\nthird",
    ];
    for buf in buffers {
        let mut expected = old_lines(buf);
        // The ONLY difference from the old collect: an empty block
        // and a CRLF-terminated block yield no trailing empty line
        // (the old loop pushed one; downstream skipped/rejected it
        // either way).
        if expected.last().is_some_and(|last| last.is_empty()) {
            expected.pop();
        }
        assert_eq!(
            ByteLines { rest: buf }.collect::<Vec<&[u8]>>(),
            expected,
            "byte-lines mismatch for buffer {buf:?}"
        );
    }
}

#[tokio::test]
async fn thousands_of_header_lines_are_still_fully_scanned() {
    // ~4000 short filler headers fit under the 16 KiB header limit;
    // Proxy-Authorization is the LAST line, so the scan must reach
    // the end of the block without materializing a line table.
    let mut request = b"CONNECT example.com:443 HTTP/1.1\r\n".to_vec();
    request.extend_from_slice(&b"X:\r\n".repeat(4000));

    let mut with_auth = request.clone();
    with_auth.extend_from_slice(b"Proxy-Authorization: Basic dXNlcjpwYXNz\r\n\r\n");
    let (result, response) = parse_request(&with_auth).await;
    assert!(
        result.is_err(),
        "creds with no users configured must be rejected: {response:?}"
    );
    assert!(
        response.starts_with(b"HTTP/1.1 407 "),
        "Proxy-Authorization on the last line must still be found, got {response:?}"
    );

    request.extend_from_slice(b"\r\n");
    let (result, response) = parse_request(&request).await;
    let req = result.expect("filler headers alone must parse");
    assert_eq!(req.target, "example.com:443");
    assert!(
        response.is_empty(),
        "no error response expected on success, got {response:?}"
    );
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
        recover_and_tunnel_http(
            server,
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

// ── R8-08: the Basic challenge declares its credential charset ──

#[tokio::test]
async fn proxy_auth_challenge_declares_utf8_charset() {
    // A 407-triggering request (unsupported auth scheme): the
    // credential decoder hard-requires UTF-8, so the challenge must
    // say so (RFC 7617 §2.1 — charset after realm).
    let (_, response) = parse_request(
        b"CONNECT example.com:443 HTTP/1.1\r\nProxy-Authorization: Bearer token\r\n\r\n",
    )
    .await;
    assert!(response.starts_with(b"HTTP/1.1 407 "));
    let text = String::from_utf8_lossy(&response);
    assert!(
        text.contains("Proxy-Authenticate: Basic realm=\"resocks5\", charset=\"UTF-8\""),
        "the 407 challenge must declare charset=UTF-8, got: {text:?}"
    );
}
