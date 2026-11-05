// R3-I end-to-end, HTTP CONNECT mirror: a client that only
// `shutdown(write)`s after the early 200 reply still receives the
// server-first greeting — the recovery peek must not turn the
// write-half-close into a full session close.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use super::recovery::recover_and_tunnel_http;
use super::tests::{recovery_request, socks5_upstream_config, spawn_socks5_stub, test_logger};
use crate::config::{NetworkConfig, TlsFragmentConfig};
use resocks5_net::chain::GateLevels;
use resocks5_net::rotator::ProxyRotator;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const REPLY: &[u8] = b"HTTP/1.1 200 Connection Established\r\n\r\n";
const BANNER: &[u8] = b"banner-after-eof";

/// Minimal no-auth SOCKS5 stub that answers CONNECT and then waits for
/// EOF on its tunnel-read side — the propagated client FIN — before
/// sending `banner` and closing. The log records the CONNECT target
/// and a `target-eof` marker when the FIN arrived.
async fn spawn_stub_banner_after_eof(
    banner: &'static [u8],
) -> (SocketAddr, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let log: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let log2 = log.clone();
    tokio::spawn(async move {
        while let Ok((sock, _)) = listener.accept().await {
            let log = log2.clone();
            tokio::spawn(async move {
                let _ = serve_stub_after_eof(sock, log, banner).await;
            });
        }
    });
    (addr, log)
}

async fn serve_stub_after_eof(
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
    // The tunnel is up: wait for the propagated FIN, mark it, then
    // greet and close.
    let mut b = [0u8; 512];
    loop {
        match sock.read(&mut b).await {
            Ok(0) => break,
            Err(_) => return None,
            Ok(_) => {}
        }
    }
    log.lock().unwrap().push("target-eof".to_string());
    sock.write_all(banner).await.ok()?;
    sock.shutdown().await.ok()?;
    Some(())
}

/// After the early 200 the client does `shutdown(write)` and keeps
/// reading: the IP fallback must be dialed, the FIN must reach the
/// target, and the target's greeting must be relayed completely.
/// Mutation: empty EOF => ClientClosed => return (the client never
/// sees the banner).
#[tokio::test]
async fn half_closed_client_still_receives_the_server_first_banner() {
    let (up_addr, up_log) = spawn_stub_banner_after_eof(BANNER).await;
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
    let gate = Arc::new(GateLevels::default());
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

    // Early 200, then only a write-half-close: the client keeps
    // reading and waits for the greeting.
    let mut reply = [0u8; REPLY.len()];
    client.read_exact(&mut reply).await.unwrap();
    assert!(reply.starts_with(b"HTTP/1.1 200 "));
    client.shutdown().await.unwrap();

    let mut banner = [0u8; BANNER.len()];
    tokio::time::timeout(Duration::from_secs(10), client.read_exact(&mut banner))
        .await
        .expect("the greeting must reach a half-closed client")
        .unwrap();
    assert_eq!(banner.as_slice(), BANNER);
    // Nothing else is relayed; the session ends with a clean EOF.
    let mut tail = Vec::new();
    tokio::time::timeout(Duration::from_secs(10), client.read_to_end(&mut tail))
        .await
        .expect("the session must end with EOF after the greeting")
        .unwrap();
    assert!(tail.is_empty());

    tokio::time::timeout(Duration::from_secs(10), task)
        .await
        .expect("a half-closed session must not stall")
        .unwrap()
        .expect("the half-closed session succeeds");
    let targets = up_log.lock().unwrap().clone();
    assert_eq!(
        targets.first().map(String::as_str),
        Some("203.0.113.9:443"),
        "the IP fallback must be dialed, targets: {targets:?}"
    );
    assert!(
        targets.iter().any(|t| t == "target-eof"),
        "the propagated FIN must reach the target, targets: {targets:?}"
    );
}

/// Contract edge: a client that RESETS (close with the 200 still
/// unread) still ends the session with an error, promptly — the reset
/// must not be mapped onto the half-close path, where the peek would
/// keep waiting on the fallback until the protocol deadline (~5 s
/// here).
#[tokio::test]
async fn client_reset_still_ends_the_session_promptly() {
    let (up_addr, _up_log) = spawn_socks5_stub(b"").await;
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
    let gate = Arc::new(GateLevels::default());
    let v6: Option<Arc<ProxyRotator>> = None;

    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let caddr = l.local_addr().unwrap();
    let client = TcpStream::connect(caddr).await.unwrap();
    let server = l.accept().await.unwrap().0;

    let task = tokio::spawn(async move {
        let req = recovery_request().await;
        recover_and_tunnel_http(
            server,
            &req,
            "203.0.113.9:443",
            "443",
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

    // Close with the 200 still unread: the kernel sends a RST instead
    // of a FIN.
    drop(client);

    let started = std::time::Instant::now();
    let result = tokio::time::timeout(Duration::from_secs(4), task)
        .await
        .expect("a reset must end the peek promptly, not run to the deadline")
        .unwrap();
    assert!(
        result.is_err(),
        "a reset client must end the session with an error: {result:?}"
    );
    assert!(
        started.elapsed() < Duration::from_secs(3),
        "the reset must abort immediately: {:?}",
        started.elapsed()
    );
}

/// Control: the half-close keeps the session only while something can
/// be relayed. With the IP fallback unreachable (refused connect), the
/// peek returns `ClientClosed` and the handler still ends cleanly —
/// the pre-R3-I outcome — with the client seeing a prompt EOF and
/// nothing else.
#[tokio::test]
async fn half_closed_client_with_unreachable_upstream_ends_cleanly() {
    let dead = {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        listener.local_addr().unwrap()
    }; // listener dropped: connect refused
    let v4 = Some(Arc::new(ProxyRotator::new(vec![socks5_upstream_config(
        dead,
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
    let gate = Arc::new(GateLevels::default());
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

    let mut reply = [0u8; REPLY.len()];
    client.read_exact(&mut reply).await.unwrap();
    assert!(reply.starts_with(b"HTTP/1.1 200 "));
    client.shutdown().await.unwrap();

    let result = tokio::time::timeout(Duration::from_secs(10), task)
        .await
        .expect("an unreachable fallback must not stall the session")
        .unwrap();
    assert!(result.is_ok(), "expected Ok(()), got: {result:?}");
    let mut tail = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), client.read_to_end(&mut tail))
        .await
        .expect("the client must see EOF promptly")
        .unwrap();
    assert!(tail.is_empty(), "nothing may be relayed: {tail:?}");
}
