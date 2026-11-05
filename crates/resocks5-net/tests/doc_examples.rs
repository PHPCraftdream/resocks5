//! The rustdoc examples, as ordinary tests. Doctests are disabled in this
//! crate (`doctest = false`); every example shown in the docs runs here
//! against a local SOCKS5 stub instead of a live upstream.

use std::time::Duration;

use resocks5_net::connect::{
    connect_proxy_once, dial, dial_chain_over, parse_proxy_str, DialOptions,
};
use resocks5_net::progress::FlushProgress;
use resocks5_net::types::{ProxyConfig, ProxyProtocol};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// No-auth SOCKS5 stub for one connection: accepts CONNECT, writes `ok`.
async fn socks5_stub() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(async move {
        let (mut s, _) = l.accept().await.unwrap();
        let mut greeting = [0u8; 3];
        s.read_exact(&mut greeting).await.unwrap();
        s.write_all(&[0x05, 0x00]).await.unwrap();
        let mut head = [0u8; 4];
        s.read_exact(&mut head).await.unwrap();
        let rest = match head[3] {
            0x01 => 6,
            0x04 => 18,
            _ => s.read_u8().await.unwrap() as usize + 2,
        };
        let mut tail = vec![0u8; rest];
        s.read_exact(&mut tail).await.unwrap();
        s.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0, b'o', b'k'])
            .await
            .unwrap();
        let _ = s.read(&mut [0u8; 1]).await;
    });
    port
}

async fn read_ok(mut stream: impl tokio::io::AsyncRead + Unpin) {
    let mut buf = [0u8; 2];
    stream.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"ok");
}

/// `connect::dial` example.
#[tokio::test]
async fn dial_example() {
    let port = socks5_stub().await;
    let proxy = parse_proxy_str(&format!("127.0.0.1:{port}"), ProxyProtocol::Socks5)
        .expect("valid proxy line");
    let opts = DialOptions::new().with_total_timeout(Duration::from_secs(15));
    let stream = dial(&proxy, "example.com", 80, &opts, None).await.unwrap();
    read_ok(stream).await;
}

/// `connect::dial_chain_over` example: two SOCKS5 nodes served by one stub
/// that answers a handshake per layer, the last one followed by `ok`.
#[tokio::test]
async fn dial_chain_over_example() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        let (mut s, _) = listener.accept().await.unwrap();
        for _ in 0..2 {
            let mut greeting = [0u8; 3];
            s.read_exact(&mut greeting).await.unwrap();
            s.write_all(&[0x05, 0x00]).await.unwrap();
            let mut head = [0u8; 4];
            s.read_exact(&mut head).await.unwrap();
            let rest = match head[3] {
                0x01 => 6,
                0x04 => 18,
                _ => s.read_u8().await.unwrap() as usize + 2,
            };
            let mut tail = vec![0u8; rest];
            s.read_exact(&mut tail).await.unwrap();
            s.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await
                .unwrap();
        }
        s.write_all(b"ok").await.unwrap();
        let _ = s.read(&mut [0u8; 1]).await;
    });

    let proxy =
        ProxyConfig::socks5("exit.example", 1080).with_gate(ProxyConfig::socks5("127.0.0.1", port));
    let outer = proxy.outermost();
    let base = TcpStream::connect((outer.host.as_str(), outer.port))
        .await
        .unwrap();
    let opts = DialOptions::new()
        .with_handshake_timeout(Duration::from_secs(10))
        .with_total_timeout(Duration::from_secs(15));
    let stream = dial_chain_over(base, &proxy, "example.com", 80, &opts, None)
        .await
        .unwrap();
    read_ok(stream).await;
}

/// README "Inbound options" example: validate a config, accept with the opt-in
/// options, take the retained credentials, read the pipeline through `Prefixed`.
#[tokio::test]
async fn inbound_options_example() {
    use resocks5_net::server::{accept, ServerOptions};

    let proxy = ProxyConfig::socks5("198.51.100.7", 1080)
        .try_with_auth("user", "pass")
        .unwrap();
    proxy.validate().unwrap();

    // CONNECT with Basic auth and an over-read payload in the same write.
    let basic = {
        use base64::Engine as _;
        base64::engine::general_purpose::STANDARD.encode("user:pass")
    };
    let request = format!(
        "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\nProxy-Authorization: Basic {basic}\r\n\r\nEARLY"
    );
    let (mut peer, mut client) = tokio::io::duplex(4096);
    peer.write_all(request.as_bytes()).await.unwrap();
    peer.write_all(b"LATER").await.unwrap();
    drop(peer);

    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    let options = ServerOptions::new(deadline, false, true)
        .retain_credentials(true)
        .raw_credentials(true)
        .strict_http(true);
    let mut req = accept(&mut client, &options, |c| async move {
        c.username() == "user" && c.password() == "pass"
    })
    .await
    .unwrap();
    assert_eq!(req.target(), "example.com:443");
    let credentials = req.take_credentials().expect("credentials retained");
    assert_eq!(credentials.username_bytes(), b"user");
    assert_eq!(credentials.password_bytes(), b"pass");
    assert!(credentials.is_utf8());

    let mut stream = req.into_prefixed(client);
    let mut rest = Vec::new();
    stream.read_to_end(&mut rest).await.unwrap();
    assert_eq!(rest, b"EARLYLATER");
}

/// `connect::connect_proxy_once` example.
#[tokio::test]
async fn connect_proxy_once_example() {
    let port = socks5_stub().await;
    let proxy = parse_proxy_str(&format!("127.0.0.1:{port}"), ProxyProtocol::Socks5)
        .expect("valid proxy line");
    let stream = connect_proxy_once(
        "example.com:80",
        &proxy,
        Duration::from_secs(10),
        Duration::from_secs(10),
        None,
    )
    .await
    .unwrap();
    read_ok(stream).await;
}

/// `connect::make_tls_connector_with_provider` example. The
/// process-global `make_tls_connector` example is covered by
/// `crypto_provider_contract.rs`, which owns that global state.
#[cfg(feature = "tls")]
#[test]
fn make_tls_connector_with_provider_example() {
    let _connector = resocks5_net::connect::make_tls_connector_with_provider(std::sync::Arc::new(
        rustls::crypto::ring::default_provider(),
    ));
}

/// `progress::FlushProgress` example: outside any bounded helper's scope,
/// reporting is a silent no-op. The custom-wrapper part of that example
/// is exercised end to end by `custom_progress.rs`.
#[test]
fn flush_progress_report_outside_a_scope_is_a_no_op() {
    let sink = FlushProgress::new();
    FlushProgress::report_confirmed(64);
    assert_eq!(sink.total(), 0);
}
