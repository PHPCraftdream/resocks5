//! The rustdoc examples, as ordinary tests. Doctests are disabled in this
//! crate (`doctest = false`); every example shown in the docs runs here
//! against a local SOCKS5 stub instead of a live upstream.

use std::time::Duration;

use resocks5_net::connect::{connect_proxy_once, dial, parse_proxy_str, DialOptions};
use resocks5_net::progress::FlushProgress;
use resocks5_net::types::ProxyProtocol;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

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
