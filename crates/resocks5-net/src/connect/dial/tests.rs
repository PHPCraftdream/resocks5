use std::error::Error as _;
use std::net::Ipv6Addr;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

use super::*;

use crate::error::ProtocolViolation;

const GUARD: Duration = Duration::from_secs(10);

async fn bind() -> (TcpListener, u16) {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    (l, port)
}

/// SOCKS5 stub; returns the captured CONNECT request (head + addr + port).
fn socks5_stub(l: TcpListener, ver: u8, rep: u8) -> JoinHandle<Vec<u8>> {
    tokio::spawn(async move {
        let (mut s, _) = l.accept().await.unwrap();
        let mut greeting = [0u8; 3];
        s.read_exact(&mut greeting).await.unwrap();
        assert_eq!(greeting, [0x05, 0x01, 0x00]);
        s.write_all(&[0x05, 0x00]).await.unwrap();
        let mut req = vec![0u8; 4];
        s.read_exact(&mut req).await.unwrap();
        let rest = match req[3] {
            0x01 => 6,
            0x04 => 18,
            0x03 => {
                let len = s.read_u8().await.unwrap();
                req.push(len);
                len as usize + 2
            }
            other => panic!("ATYP {other}"),
        };
        let mut tail = vec![0u8; rest];
        s.read_exact(&mut tail).await.unwrap();
        req.extend_from_slice(&tail);
        s.write_all(&[ver, rep, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .await
            .unwrap();
        if ver == 0x05 && rep == 0 {
            s.write_all(b"ok").await.unwrap();
        }
        // Hold until the client goes away.
        let _ = s.read(&mut [0u8; 1]).await;
        req
    })
}

/// HTTP stub; returns the captured request head.
fn http_stub(l: TcpListener, response: &'static [u8]) -> JoinHandle<Vec<u8>> {
    tokio::spawn(async move {
        let (mut s, _) = l.accept().await.unwrap();
        let mut req = Vec::new();
        while !req.ends_with(b"\r\n\r\n") {
            req.push(s.read_u8().await.unwrap());
        }
        s.write_all(response).await.unwrap();
        let _ = s.read(&mut [0u8; 1]).await;
        req
    })
}

/// Accepts and never replies.
fn silent_stub(l: TcpListener) -> JoinHandle<()> {
    tokio::spawn(async move {
        let (_s, _) = l.accept().await.unwrap();
        std::future::pending::<()>().await;
    })
}

fn opts() -> DialOptions {
    DialOptions::new()
        .with_connect_timeout(Duration::from_secs(5))
        .with_handshake_timeout(Duration::from_secs(5))
}

async fn dial_guarded(
    proxy: &ProxyConfig,
    host: &str,
    port: u16,
    opts: &DialOptions,
) -> Result<AnyUpstream, ConnectError> {
    timeout(GUARD, dial(proxy, host, port, opts, None))
        .await
        .expect("test guard")
}

async fn dial_err(proxy: &ProxyConfig, host: &str, port: u16, opts: &DialOptions) -> ConnectError {
    match dial_guarded(proxy, host, port, opts).await {
        Ok(_) => panic!("dial must fail"),
        Err(e) => e,
    }
}

async fn dial_plain_guarded(
    proxy: &ProxyConfig,
    host: &str,
    port: u16,
    opts: &DialOptions,
) -> Result<AnyUpstream, ConnectError> {
    timeout(GUARD, dial_plain(proxy, host, port, opts))
        .await
        .expect("test guard")
}

async fn expect_ok_payload(mut up: AnyUpstream) {
    let mut buf = [0u8; 2];
    up.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"ok");
}

#[test]
fn options_defaults_and_builders() {
    let d = DialOptions::default();
    assert_eq!(d.connect_timeout, Duration::from_secs(10));
    assert_eq!(d.handshake_timeout, Duration::from_secs(10));
    assert_eq!(d.total_timeout, None);
    let o = DialOptions::new()
        .with_connect_timeout(Duration::from_secs(1))
        .with_handshake_timeout(Duration::from_secs(2))
        .with_total_timeout(Duration::from_secs(3));
    assert_eq!(o.connect_timeout, Duration::from_secs(1));
    assert_eq!(o.handshake_timeout, Duration::from_secs(2));
    assert_eq!(o.total_timeout, Some(Duration::from_secs(3)));
    assert!(!d.nodelay);
    assert_eq!(d.keepalive, None);
    assert_eq!(d.keepalive_interval, None);
    let o = o
        .with_nodelay(true)
        .with_keepalive(Duration::from_secs(30))
        .with_keepalive_interval(Duration::from_secs(5));
    assert!(o.nodelay);
    assert_eq!(o.keepalive, Some(Duration::from_secs(30)));
    assert_eq!(o.keepalive_interval, Some(Duration::from_secs(5)));
}

#[tokio::test]
async fn socks5_domain() {
    let (l, port) = bind().await;
    let stub = socks5_stub(l, 0x05, 0);
    let proxy = ProxyConfig::socks5("127.0.0.1", port);
    let up = dial_guarded(&proxy, "example.com", 443, &opts())
        .await
        .unwrap();
    assert!(matches!(up, AnyUpstream::Plain(_)));
    expect_ok_payload(up).await;
    let req = stub.await.unwrap();
    assert_eq!(&req[..5], &[0x05, 0x01, 0x00, 0x03, 11]);
    assert_eq!(&req[5..16], b"example.com");
    assert_eq!(&req[16..], &443u16.to_be_bytes());
}

#[tokio::test]
async fn socks5_ipv4() {
    let (l, port) = bind().await;
    let stub = socks5_stub(l, 0x05, 0);
    let proxy = ProxyConfig::socks5("127.0.0.1", port);
    let up = dial_guarded(&proxy, "1.2.3.4", 80, &opts()).await.unwrap();
    expect_ok_payload(up).await;
    assert_eq!(
        stub.await.unwrap(),
        [0x05, 0x01, 0x00, 0x01, 1, 2, 3, 4, 0, 80]
    );
}

#[tokio::test]
async fn socks5_bracketed_ipv6() {
    let (l, port) = bind().await;
    let stub = socks5_stub(l, 0x05, 0);
    let proxy = ProxyConfig::socks5("127.0.0.1", port);
    let up = dial_guarded(&proxy, "[::1]", 443, &opts()).await.unwrap();
    expect_ok_payload(up).await;
    let req = stub.await.unwrap();
    assert_eq!(&req[..4], &[0x05, 0x01, 0x00, 0x04]);
    assert_eq!(&req[4..20], &Ipv6Addr::LOCALHOST.octets());
    assert_eq!(&req[20..], &443u16.to_be_bytes());
}

#[tokio::test]
async fn socks5_bare_password_is_refused_before_any_connection() {
    let (l, port) = bind().await;
    let proxy = ProxyConfig::socks5("127.0.0.1", port).with_auth("u", "p");
    let err = dial_err(&proxy, "1.2.3.4", 80, &opts()).await;
    assert!(
        matches!(err, ConnectError::CleartextCredentialsRefused),
        "{err:?}"
    );
    // The upstream was never contacted.
    let accepted = tokio::time::timeout(std::time::Duration::from_millis(100), l.accept()).await;
    assert!(accepted.is_err());
}

/// Dial skips validation entirely: a config with only a username set is
/// invalid per `validate_node`, yet dials anonymously (no auth in greeting).
#[tokio::test]
async fn socks5_half_credentials_dial_anonymously() {
    let (l, port) = bind().await;
    let stub = socks5_stub(l, 0x05, 0);
    let mut proxy = ProxyConfig::socks5("127.0.0.1", port);
    proxy.user = Some("only-user".to_string());
    assert_eq!(
        proxy.validate_node(),
        Err(crate::types::ProxyConfigError::IncompleteCredentials)
    );
    let up = dial_guarded(&proxy, "1.2.3.4", 80, &opts()).await.unwrap();
    expect_ok_payload(up).await;
    stub.await.unwrap();
}

#[tokio::test]
async fn socks5_rep_nonzero_is_proxy_rejected() {
    let (l, port) = bind().await;
    let _stub = socks5_stub(l, 0x05, 0x05);
    let proxy = ProxyConfig::socks5("127.0.0.1", port);
    let err = dial_err(&proxy, "1.2.3.4", 80, &opts()).await;
    assert!(
        matches!(
            err,
            ConnectError::ProxyRejected {
                protocol: ProxyProtocol::Socks5,
                code: Some(5),
                ..
            }
        ),
        "{err:?}"
    );
}

#[tokio::test]
async fn socks5_bad_version_is_protocol() {
    let (l, port) = bind().await;
    let _stub = socks5_stub(l, 0x04, 0);
    let proxy = ProxyConfig::socks5("127.0.0.1", port);
    let err = dial_err(&proxy, "1.2.3.4", 80, &opts()).await;
    assert!(
        matches!(
            err,
            ConnectError::Protocol(ProtocolViolation::Socks5BadVersion { got: 4 })
        ),
        "{err:?}"
    );
    assert_eq!(err.to_string(), "[SOCKS5] Invalid proxy response version");
}

#[tokio::test]
async fn socks5_peer_close_is_io_with_source() {
    let (l, port) = bind().await;
    tokio::spawn(async move {
        let (mut s, _) = l.accept().await.unwrap();
        s.read_exact(&mut [0u8; 3]).await.unwrap();
    });
    let proxy = ProxyConfig::socks5("127.0.0.1", port);
    let err = dial_err(&proxy, "1.2.3.4", 80, &opts()).await;
    assert!(
        matches!(
            &err,
            ConnectError::Io {
                stage: Stage::Handshake,
                endpoint: None,
                ..
            }
        ),
        "{err:?}"
    );
    let src = err.source().expect("io source");
    assert!(src.downcast_ref::<std::io::Error>().is_some());
}

#[tokio::test]
async fn stall_at_connect_is_connect_stage() {
    // TEST-NET-1: Timeout, or Io where the network is unreachable.
    let o = opts().with_connect_timeout(Duration::from_millis(300));
    let err = dial_err(&ProxyConfig::socks5("203.0.113.1", 1080), "x.test", 80, &o).await;
    match &err {
        ConnectError::Timeout {
            stage: Stage::Connect,
            kind: TimeoutKind::TcpConnect,
            endpoint,
            ..
        } => assert_eq!(endpoint, "203.0.113.1:1080"),
        ConnectError::Io {
            stage: Stage::Connect,
            ..
        } => {}
        other => panic!("unexpected: {other:?}"),
    }
}

#[tokio::test]
async fn socks5_stall_in_greeting_is_upstream_down() {
    // Regression for the silent-upstream decision: `dial` through a
    // TCP-alive upstream that never answers the greeting reports
    // Socks5Greeting and counts the upstream as down.
    // Mutations caught: reverting the producer wiring (kind stays
    // Socks5Handshake), or excluding Socks5Greeting from
    // `is_upstream_down`, fails this test.
    let (l, port) = bind().await;
    let _stub = silent_stub(l);
    let o = opts().with_handshake_timeout(Duration::from_millis(150));
    let err = dial_err(&ProxyConfig::socks5("127.0.0.1", port), "x.test", 80, &o).await;
    match &err {
        ConnectError::Timeout {
            stage: Stage::Handshake,
            kind: TimeoutKind::Socks5Greeting,
            endpoint,
            after,
        } => {
            assert_eq!(endpoint, &format!("127.0.0.1:{port}"));
            assert_eq!(*after, Duration::from_millis(150));
        }
        other => panic!("unexpected: {other:?}"),
    }
    assert!(err.is_upstream_down());
    assert!(err
        .to_string()
        .starts_with("[SOCKS5] handshake timeout (0s) to "));
}

/// A `Duration::MAX` handshake budget must not panic the dial (unchecked
/// `Instant + Duration`): against a silent upstream it simply keeps waiting,
/// cut here by the outer timeout. Mutation: the unchecked add panics.
#[tokio::test]
async fn unrepresentable_handshake_budget_does_not_panic() {
    let (l, port) = bind().await;
    let _stub = silent_stub(l);
    let o = opts().with_handshake_timeout(Duration::MAX);
    let outcome = timeout(
        Duration::from_millis(300),
        dial(
            &ProxyConfig::socks5("127.0.0.1", port),
            "x.test",
            80,
            &o,
            None,
        ),
    )
    .await;
    assert!(outcome.is_err(), "no deadline in practice: still waiting");
}

#[tokio::test]
async fn dial_plain_socks5_matches_dial_with_none() {
    let (l, port) = bind().await;
    let stub = socks5_stub(l, 0x05, 0);
    let proxy = ProxyConfig::socks5("127.0.0.1", port);
    let up = dial_plain_guarded(&proxy, "example.com", 443, &opts())
        .await
        .unwrap();
    assert!(matches!(up, AnyUpstream::Plain(_)));
    expect_ok_payload(up).await;
    let req = stub.await.unwrap();
    assert_eq!(&req[..5], &[0x05, 0x01, 0x00, 0x03, 11]);
    assert_eq!(&req[5..16], b"example.com");
    assert_eq!(&req[16..], &443u16.to_be_bytes());
}

#[tokio::test]
async fn dial_plain_http_connect_matches_dial_with_none() {
    let (l, port) = bind().await;
    let stub = http_stub(l, b"HTTP/1.1 200 OK\r\n\r\nok");
    let proxy = ProxyConfig::http("127.0.0.1", port);
    let up = dial_plain_guarded(&proxy, "example.com", 443, &opts())
        .await
        .unwrap();
    assert!(matches!(up, AnyUpstream::Plain(_)));
    expect_ok_payload(up).await;
    let req = stub.await.unwrap();
    assert!(req.starts_with(b"CONNECT example.com:443 HTTP/1.1\r\n"));
}

#[tokio::test]
async fn dial_plain_https_proxy_is_typed_error() {
    let err = match dial_plain_guarded(&ProxyConfig::https("127.0.0.1", 1), "x.test", 443, &opts())
        .await
    {
        Ok(_) => panic!("dial_plain must fail for HTTPS"),
        Err(e) => e,
    };
    #[cfg(feature = "tls")]
    assert!(
        matches!(&err, ConnectError::Tls { source: None, .. }),
        "{err:?}"
    );
    #[cfg(not(feature = "tls"))]
    assert!(
        matches!(&err, ConnectError::TlsFeatureMissing { host } if host == "127.0.0.1"),
        "{err:?}"
    );
}

#[tokio::test]
async fn dial_plain_reports_connect_timeout() {
    // TEST-NET-1: Timeout, or Io where the network is unreachable.
    let o = opts().with_connect_timeout(Duration::from_millis(300));
    let err = match dial_plain_guarded(&ProxyConfig::socks5("203.0.113.1", 1080), "x.test", 80, &o)
        .await
    {
        Ok(_) => panic!("must fail"),
        Err(e) => e,
    };
    match &err {
        ConnectError::Timeout {
            stage: Stage::Connect,
            kind: TimeoutKind::TcpConnect,
            endpoint,
            ..
        } => assert_eq!(endpoint, "203.0.113.1:1080"),
        ConnectError::Io {
            stage: Stage::Connect,
            ..
        } => {}
        other => panic!("unexpected: {other:?}"),
    }
}

#[tokio::test]
async fn total_timeout_elapses_as_total_stage() {
    let (l, port) = bind().await;
    let _stub = silent_stub(l);
    let o = opts().with_total_timeout(Duration::from_millis(200));
    let err = dial_err(&ProxyConfig::socks5("127.0.0.1", port), "x.test", 80, &o).await;
    assert!(
        matches!(
            &err,
            ConnectError::Timeout {
                stage: Stage::Total,
                kind: TimeoutKind::Total,
                after,
                ..
            } if *after == Duration::from_millis(200)
        ),
        "{err:?}"
    );
    assert_eq!(
        err.to_string(),
        format!("total timeout (0s) to 127.0.0.1:{port}")
    );
}

#[tokio::test]
async fn total_timeout_not_hit_on_success() {
    let (l, port) = bind().await;
    let _stub = socks5_stub(l, 0x05, 0);
    let o = opts().with_total_timeout(Duration::from_secs(5));
    let proxy = ProxyConfig::socks5("127.0.0.1", port);
    let up = dial_guarded(&proxy, "1.2.3.4", 80, &o).await.unwrap();
    expect_ok_payload(up).await;
}

#[tokio::test]
async fn http_connect_ok() {
    let (l, port) = bind().await;
    let stub = http_stub(l, b"HTTP/1.1 200 OK\r\n\r\nok");
    let proxy = ProxyConfig::http("127.0.0.1", port);
    let up = dial_guarded(&proxy, "example.com", 443, &opts())
        .await
        .unwrap();
    assert!(matches!(up, AnyUpstream::Plain(_)));
    expect_ok_payload(up).await;
    let req = stub.await.unwrap();
    assert!(req.starts_with(b"CONNECT example.com:443 HTTP/1.1\r\n"));
}

#[tokio::test]
async fn http_connect_bracketed_ipv6_authority() {
    let (l, port) = bind().await;
    let stub = http_stub(l, b"HTTP/1.1 200 OK\r\n\r\nok");
    let proxy = ProxyConfig::http("127.0.0.1", port);
    let up = dial_guarded(&proxy, "[::1]", 443, &opts()).await.unwrap();
    expect_ok_payload(up).await;
    let req = stub.await.unwrap();
    assert!(req.starts_with(b"CONNECT [::1]:443 HTTP/1.1\r\n"));
}

#[tokio::test]
async fn http_non_2xx_is_proxy_rejected() {
    let (l, port) = bind().await;
    let _stub = http_stub(l, b"HTTP/1.1 403 Forbidden\r\n\r\n");
    let proxy = ProxyConfig::http("127.0.0.1", port);
    let err = dial_err(&proxy, "example.com", 443, &opts()).await;
    assert!(
        matches!(
            &err,
            ConnectError::ProxyRejected {
                protocol: ProxyProtocol::Http,
                code: Some(403),
                ..
            }
        ),
        "{err:?}"
    );
}

#[tokio::test]
async fn http_stall_in_handshake() {
    let (l, port) = bind().await;
    let _stub = silent_stub(l);
    let o = opts().with_handshake_timeout(Duration::from_millis(150));
    let err = dial_err(&ProxyConfig::http("127.0.0.1", port), "x.test", 80, &o).await;
    assert!(
        matches!(
            &err,
            ConnectError::Timeout {
                stage: Stage::Handshake,
                kind: TimeoutKind::HttpHandshake,
                ..
            }
        ),
        "{err:?}"
    );
    assert!(err
        .to_string()
        .starts_with("[HTTP] handshake timeout (0s) to "));
}

#[tokio::test]
async fn http_total_timeout() {
    let (l, port) = bind().await;
    let _stub = silent_stub(l);
    let o = opts().with_total_timeout(Duration::from_millis(200));
    let err = dial_err(&ProxyConfig::http("127.0.0.1", port), "x.test", 80, &o).await;
    assert!(
        matches!(
            &err,
            ConnectError::Timeout {
                stage: Stage::Total,
                kind: TimeoutKind::Total,
                ..
            }
        ),
        "{err:?}"
    );
}

#[cfg(feature = "tls")]
#[tokio::test]
async fn https_without_connector_is_tls_error() {
    // Rejected before any socket is opened.
    let err = dial_err(&ProxyConfig::https("127.0.0.1", 1), "x.test", 443, &opts()).await;
    assert!(
        matches!(&err, ConnectError::Tls { source: None, .. }),
        "{err:?}"
    );
    assert_eq!(err.to_string(), "HTTPS upstream requires TLS connector");
}

#[cfg(feature = "tls")]
#[tokio::test]
async fn https_stall_in_tls_handshake() {
    let (l, port) = bind().await;
    let _stub = silent_stub(l);
    let connector = crate::connect::make_tls_connector_with_provider(std::sync::Arc::new(
        rustls::crypto::ring::default_provider(),
    ));
    let o = opts().with_handshake_timeout(Duration::from_millis(150));
    let proxy = ProxyConfig::https("127.0.0.1", port);
    let res = timeout(GUARD, dial(&proxy, "x.test", 443, &o, Some(&connector)))
        .await
        .expect("test guard");
    let Err(err) = res else { panic!("must fail") };
    assert!(
        matches!(
            &err,
            ConnectError::Timeout {
                stage: Stage::Handshake,
                kind: TimeoutKind::HttpsTlsHandshake,
                ..
            }
        ),
        "{err:?}"
    );
}

#[cfg(not(feature = "tls"))]
#[tokio::test]
async fn https_in_lean_build_is_tls_feature_missing() {
    let err = dial_err(
        &ProxyConfig::https("proxy.example", 1),
        "x.test",
        443,
        &opts(),
    )
    .await;
    assert!(
        matches!(&err, ConnectError::TlsFeatureMissing { host } if host == "proxy.example"),
        "{err:?}"
    );
}

// ── dial_tcp and socket options ─────────────────────────────────

async fn dial_tcp_guarded(
    proxy: &ProxyConfig,
    opts: &DialOptions,
) -> Result<tokio::net::TcpStream, ConnectError> {
    timeout(GUARD, dial_tcp(proxy, "example.com", 443, opts))
        .await
        .expect("test guard")
}

/// `dial_tcp` hands back the bare socket to the proxy, already past the
/// handshake: the tunnel bytes are the first thing it reads. Mutation:
/// returning the socket before the CONNECT reply is consumed reads the
/// reply instead of the payload.
#[tokio::test]
async fn dial_tcp_returns_the_tunnel_socket() {
    for http in [false, true] {
        let (l, port) = bind().await;
        let (stub, proxy) = if http {
            (
                http_stub(l, b"HTTP/1.1 200 OK\r\n\r\nok"),
                ProxyConfig::http("127.0.0.1", port),
            )
        } else {
            (
                socks5_stub(l, 0x05, 0),
                ProxyConfig::socks5("127.0.0.1", port),
            )
        };
        let mut tcp = dial_tcp_guarded(&proxy, &opts()).await.unwrap();
        assert_eq!(tcp.peer_addr().unwrap().port(), port);
        let mut buf = [0u8; 2];
        tcp.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ok", "http={http}");
        drop(tcp);
        stub.await.unwrap();
    }
}

/// An HTTPS upstream is refused before any connect: its tunnel is TLS.
/// Mutation: dialing first leaves an accepted connection on the listener.
#[tokio::test]
async fn dial_tcp_refuses_https_without_connecting() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let port = listener.local_addr().unwrap().port();
    let err = dial_tcp_guarded(&ProxyConfig::https("127.0.0.1", port), &opts())
        .await
        .unwrap_err();
    #[cfg(feature = "tls")]
    assert!(
        matches!(&err, ConnectError::Tls { source: None, .. }),
        "{err:?}"
    );
    #[cfg(not(feature = "tls"))]
    assert!(
        matches!(&err, ConnectError::TlsFeatureMissing { .. }),
        "{err:?}"
    );
    assert!(
        matches!(listener.accept(), Err(e) if e.kind() == std::io::ErrorKind::WouldBlock),
        "nothing may connect"
    );
}

/// `nodelay` and `keepalive` reach the socket to the proxy; defaults leave
/// these options off. Mutation: not applying an option leaves its readback at
/// the default.
#[tokio::test]
async fn socket_options_reach_the_proxy_socket() {
    for set in [false, true] {
        let (l, port) = bind().await;
        let stub = socks5_stub(l, 0x05, 0);
        let mut options = opts();
        if set {
            options = options
                .with_nodelay(true)
                .with_keepalive(Duration::from_secs(45))
                .with_keepalive_interval(Duration::from_secs(5));
        }
        let tcp = dial_tcp_guarded(&ProxyConfig::socks5("127.0.0.1", port), &options)
            .await
            .unwrap();
        assert_eq!(tcp.nodelay().unwrap(), set, "nodelay, set={set}");
        let sock = socket2::SockRef::from(&tcp);
        assert_eq!(sock.keepalive().unwrap(), set, "keepalive, set={set}");
        #[cfg(any(
            target_os = "android",
            target_os = "dragonfly",
            target_os = "freebsd",
            target_os = "fuchsia",
            target_os = "illumos",
            target_os = "ios",
            target_os = "visionos",
            target_os = "linux",
            target_os = "macos",
            target_os = "netbsd",
            target_os = "tvos",
            target_os = "watchos",
            target_os = "cygwin",
        ))]
        if set {
            assert_eq!(
                sock.tcp_keepalive_interval().unwrap(),
                Duration::from_secs(5),
                "keepalive interval, set={set}"
            );
        }
        drop(tcp);
        stub.await.unwrap();
    }
}

/// An interval without an idle setting must not enable keepalive.
#[tokio::test]
async fn keepalive_interval_alone_does_not_enable_keepalive() {
    let (l, port) = bind().await;
    let stub = socks5_stub(l, 0x05, 0);
    let options = opts().with_keepalive_interval(Duration::from_secs(5));
    let tcp = dial_tcp_guarded(&ProxyConfig::socks5("127.0.0.1", port), &options)
        .await
        .unwrap();
    assert!(!socket2::SockRef::from(&tcp).keepalive().unwrap());
    drop(tcp);
    stub.await.unwrap();
}
