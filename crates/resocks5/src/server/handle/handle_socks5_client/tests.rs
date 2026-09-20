use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use super::handshake::socks5_handshake;

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

// ── RFC 1929 zero-length-field tests (R5-07) ────────────────────

fn init_user(name: &str) -> crate::config::User {
    crate::config::User {
        name: name.to_string(),
        // Mirrors state.rs's INIT_HASH ("init") first-login sentinel.
        hash: "init".to_string(),
        is_enabled: true,
        direct: false,
    }
}

fn unique_users_path() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let i = COUNTER.fetch_add(1, Ordering::Relaxed);
    let path = std::env::temp_dir()
        .join(format!(
            "resocks5_test_socks5_users_{}_{}.ktav",
            std::process::id(),
            i,
        ))
        .to_string_lossy()
        .into_owned();
    let _ = std::fs::remove_file(&path);
    path
}

fn auth_state_with_users(
    users: Vec<crate::config::User>,
    path: &str,
) -> Arc<crate::auth::AuthState> {
    Arc::new(
        crate::auth::AuthState::build(
            &crate::config::AuthConfig {
                allow_anonymous: false,
            },
            &crate::config::UsersConfig { users },
            path,
        )
        .unwrap(),
    )
}

async fn zero_length_field_rejected_then_valid_claim(auth_frame: &[u8]) {
    let path = unique_users_path();
    let auth = auth_state_with_users(vec![init_user("bob")], &path);

    // First connection: the malformed auth frame must fail the
    // handshake without touching the claim machinery.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(serve_one(listener, auth.clone()));

    let mut client = TcpStream::connect(addr).await.unwrap();
    client.write_all(&[0x05, 0x01, 0x02]).await.unwrap();
    let mut method = [0u8; 2];
    client.read_exact(&mut method).await.unwrap();
    assert_eq!(method, [0x05, 0x02]);
    client.write_all(auth_frame).await.unwrap();

    let mut reply = [0u8; 2];
    client.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply, [0x01, 0x01]);
    drop(client);

    let result = tokio::time::timeout(Duration::from_secs(5), server)
        .await
        .expect("timed out")
        .unwrap();
    assert!(
        result.is_err(),
        "malformed frame must fail the handshake: {result:?}"
    );
    assert!(!std::path::Path::new(&path).exists());

    // Second connection: a valid claim still succeeds and persists.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(serve_one(listener, auth));

    let mut client = TcpStream::connect(addr).await.unwrap();
    client.write_all(&[0x05, 0x01, 0x02]).await.unwrap();
    let mut method = [0u8; 2];
    client.read_exact(&mut method).await.unwrap();
    assert_eq!(method, [0x05, 0x02]);

    let mut frame = vec![0x01, 0x03, b'b', b'o', b'b', 0x07];
    frame.extend_from_slice(b"real-pw");
    client.write_all(&frame).await.unwrap();
    let mut reply = [0u8; 2];
    client.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply, [0x01, 0x00]);

    client
        .write_all(&[0x05, 0x01, 0x00, 0x01, 1, 2, 3, 4, 0x01, 0xBB])
        .await
        .unwrap();
    let (target_addr, authed_user) = tokio::time::timeout(Duration::from_secs(5), async {
        server.await.unwrap().unwrap()
    })
    .await
    .expect("timed out");
    assert_eq!(target_addr, "1.2.3.4:443");
    assert_eq!(authed_user.as_deref(), Some("bob"));

    let loaded: crate::config::UsersConfig = ktav::from_file(&path).unwrap();
    let bob = loaded.users.iter().find(|u| u.name == "bob").unwrap();
    assert_ne!(bob.hash, "init");
    assert!(bob.hash.starts_with("$argon2id$"));
    let _ = std::fs::remove_file(&path);
}

#[tokio::test]
async fn zero_length_username_frame_rejected_and_init_stays_unclaimed() {
    zero_length_field_rejected_then_valid_claim(&[0x01, 0x00]).await;
}

#[tokio::test]
async fn zero_length_password_frame_rejected_and_init_stays_unclaimed() {
    zero_length_field_rejected_then_valid_claim(&[0x01, 0x03, b'b', b'o', b'b', 0x00]).await;
}

async fn short_password_claims_via_socks5(password: &[u8]) {
    let path = unique_users_path();
    let auth = auth_state_with_users(vec![init_user("bob")], &path);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(serve_one(listener, auth));

    let mut client = TcpStream::connect(addr).await.unwrap();
    client.write_all(&[0x05, 0x01, 0x02]).await.unwrap();
    let mut method = [0u8; 2];
    client.read_exact(&mut method).await.unwrap();
    assert_eq!(method, [0x05, 0x02]);

    let mut frame = vec![0x01, 0x03, b'b', b'o', b'b', password.len() as u8];
    frame.extend_from_slice(password);
    client.write_all(&frame).await.unwrap();
    let mut reply = [0u8; 2];
    client.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply, [0x01, 0x00]);

    client
        .write_all(&[0x05, 0x01, 0x00, 0x01, 1, 2, 3, 4, 0x01, 0xBB])
        .await
        .unwrap();
    let (target_addr, authed_user) = tokio::time::timeout(Duration::from_secs(5), async {
        server.await.unwrap().unwrap()
    })
    .await
    .expect("timed out");
    assert_eq!(target_addr, "1.2.3.4:443");
    assert_eq!(authed_user.as_deref(), Some("bob"));

    let loaded: crate::config::UsersConfig = ktav::from_file(&path).unwrap();
    let bob = loaded.users.iter().find(|u| u.name == "bob").unwrap();
    assert_ne!(bob.hash, "init");
    assert!(bob.hash.starts_with("$argon2id$"));

    let fresh = crate::auth::AuthState::build(
        &crate::config::AuthConfig {
            allow_anonymous: false,
        },
        &loaded,
        path.clone(),
    )
    .unwrap();
    assert!(fresh.verify("bob", std::str::from_utf8(password).unwrap()));
    assert!(!fresh.verify("bob", "y"));
    let _ = std::fs::remove_file(&path);
}

#[tokio::test]
async fn one_byte_password_claims_via_socks5_and_persists() {
    short_password_claims_via_socks5(b"x").await;
}

#[tokio::test]
async fn password_255_bytes_claims_via_socks5_and_persists() {
    short_password_claims_via_socks5(&vec![b'a'; 255]).await;
}

// ── Recovery-path tests ─────────────────────────────────────────
//
// These exercise `recover_and_tunnel` end-to-end against a minimal
// no-auth SOCKS5 stub upstream, so the tests observe which target
// the upstream was asked for (recovered host vs. bare IP) and what
// bytes flowed through the tunnel.

use std::net::SocketAddr;
use std::sync::Mutex;

use super::recover::recover_and_tunnel;
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
    let client_deadline =
        tokio::time::Instant::now() + Duration::from_secs(network.client_protocol_timeout_sec);
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
            client_deadline,
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
            client_deadline,
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
            client_deadline,
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
            client_deadline,
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

// ── R7-01: an expired deadline must not start recovery ──────────

#[tokio::test]
async fn expired_deadline_with_buffered_payload_never_starts_recovery() {
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

    // A decidable payload is already sitting in the kernel receive
    // buffer before recovery is entered — a full HTTP request whose
    // Host header the recovery probes would decide on the very
    // first poll (the exact shortcut a bare `timeout` used to
    // take before consulting an already-expired timer).
    client
        .write_all(b"GET / HTTP/1.1\r\nHost: buffered.example\r\n\r\n")
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(150)).await;

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
            client_deadline,
        )
        .await
    });

    let result = tokio::time::timeout(Duration::from_secs(8), task)
        .await
        .expect("expired deadline must not stall recovery")
        .unwrap();
    assert!(result.is_err(), "expected Err, got: {result:?}");

    // The early success reply must never have gone out: the client
    // sees a bare EOF, zero bytes. (A close with the payload still
    // unread can also surface as an RST — ConnectionReset — which
    // proves the same thing; any other error is a real failure.)
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

// ── R8-03: DOMAINNAME validation happens before any dial ────────

/// Drive `socks5_handshake` directly — no pool, rotator, or
/// upstream exists in this test beyond the handshake itself, so a
/// rejection here provably happens before any upstream attempt or
/// rating change. Asserts the client-facing SOCKS5 failure reply
/// and that the error text is input validation, not an upstream
/// failure.
async fn connect_domain_expect_rejection(domain: &[u8], port: [u8; 2]) {
    let auth = test_auth();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(serve_one(listener, auth));

    let mut client = TcpStream::connect(addr).await.unwrap();
    client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    let mut method = [0u8; 2];
    client.read_exact(&mut method).await.unwrap();
    assert_eq!(method, [0x05, 0x00]);

    let mut req = vec![0x05, 0x01, 0x00, 0x03, domain.len() as u8];
    req.extend_from_slice(domain);
    req.extend_from_slice(&port);
    client.write_all(&req).await.unwrap();

    // rep=0x04 (host unreachable), BND.ADDR 0.0.0.0, BND.PORT 0.
    let mut reply = [0u8; 10];
    client.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply, [0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0]);

    let result = tokio::time::timeout(Duration::from_secs(5), server)
        .await
        .expect("timed out")
        .unwrap();
    let error = result.expect_err("handshake must reject the domain");
    assert!(
        !error.to_string().contains("upstream"),
        "rejection must be input validation, not an upstream failure: {error}"
    );
}

#[tokio::test]
async fn zero_length_domain_connect_is_rejected_with_client_error() {
    connect_domain_expect_rejection(b"", [0x01, 0xBB]).await;
}

#[tokio::test]
async fn nul_byte_domain_connect_is_rejected_with_client_error() {
    connect_domain_expect_rejection(b"exa\x00mple.com", [0x01, 0xBB]).await;
}

#[tokio::test]
async fn colon_in_domain_connect_is_rejected_with_client_error() {
    connect_domain_expect_rejection(b"exa:mple.com", [0x01, 0xBB]).await;
}
