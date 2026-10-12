//! Per-variant tests driven through the real code paths where a
//! loopback stub can produce the error, plus Display pins on the
//! legacy message text.
#[cfg(feature = "pool")]
use std::time::Duration;

use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt};

use super::ConnectError;
use super::ProtocolViolation;
#[cfg(feature = "pool")]
use super::{Stage, TimeoutKind};
use crate::connect::connect_http_proxy::http_connect_handshake;
use crate::connect::handshake_over_stream::handshake_over_stream;
#[cfg(feature = "pool")]
use crate::pool::{PoolConfig, ProxyPool};
use crate::types::{ProxyConfig, ProxyProtocol};

fn http_proxy_config(host: &str, port: u16) -> ProxyConfig {
    ProxyConfig {
        protocol: ProxyProtocol::Http,
        host: host.into(),
        port,
        user: None,
        password: None,
        is_gate: false,
        gate: None,
    }
}

#[cfg(feature = "pool")]
fn socks5_proxy_config(host: &str, port: u16) -> ProxyConfig {
    ProxyConfig {
        protocol: ProxyProtocol::Socks5,
        host: host.into(),
        port,
        user: None,
        password: None,
        is_gate: false,
        gate: None,
    }
}

#[cfg(feature = "pool")]
/// SOCKS5 stub that swallows the greeting, replies with
/// `method_reply` (method selection or auth status), then sends
/// `connect_reply` (consumed as the CONNECT response). Returns the
/// loopback `(host, port)` it listens on.
async fn socks5_stub_replying(
    method_reply: &'static [u8],
    connect_reply: &'static [u8],
) -> (String, u16) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut sock, _) = listener.accept().await.unwrap();
        let mut greeting = [0u8; 3];
        let _ = sock.read_exact(&mut greeting).await;
        let _ = sock.write_all(method_reply).await;
        // Read the CONNECT request (10 bytes for the IPv4 targets
        // these tests use) before replying — a shutdown with unread
        // data would RST the socket and discard the reply.
        let mut request = [0u8; 10];
        let _ = sock.read_exact(&mut request).await;
        let _ = sock.write_all(connect_reply).await;
        let _ = sock.shutdown().await;
    });
    (addr.ip().to_string(), addr.port())
}

#[cfg(feature = "pool")]
async fn handshake_error(
    target: &str,
    method_reply: &'static [u8],
    connect_reply: &'static [u8],
) -> ConnectError {
    let (host, port) = socks5_stub_replying(method_reply, connect_reply).await;
    let proxy = socks5_proxy_config(&host, port);
    crate::connect::connect_socks5_proxy(
        target,
        &proxy,
        &ProxyPool::new(PoolConfig::default(), Duration::from_secs(2), 1),
        Duration::from_secs(2),
    )
    .await
    .expect_err("stub reply must fail the handshake")
}

/// Same as [`handshake_error`] but the proxy config carries
/// credentials, so the client asks for username/password auth.
#[cfg(feature = "pool")]
async fn authed_handshake_error(
    target: &str,
    method_reply: &'static [u8],
    connect_reply: &'static [u8],
) -> ConnectError {
    let (host, port) = socks5_stub_replying(method_reply, connect_reply).await;
    let mut proxy = socks5_proxy_config(&host, port);
    proxy.user = Some("user".into());
    proxy.password = Some("pass".into());
    crate::connect::connect_socks5_proxy(
        target,
        &proxy,
        &ProxyPool::new(PoolConfig::default(), Duration::from_secs(2), 1),
        Duration::from_secs(2),
    )
    .await
    .expect_err("stub reply must fail the handshake")
}

#[cfg(feature = "pool")]
#[tokio::test]
async fn pool_connect_timeout_yields_typed_timeout() {
    let pool = ProxyPool::new(PoolConfig::default(), Duration::from_millis(100), 1);
    let proxy = socks5_proxy_config("10.255.255.1", 6550);
    let err = pool
        .acquire(&proxy)
        .await
        .expect_err("unroutable address must time out");
    assert!(matches!(
        &err,
        ConnectError::Timeout {
            stage: Stage::Connect,
            kind: TimeoutKind::TcpConnect,
            ..
        }
    ));
    assert!(
        err.to_string()
            .starts_with("connect timeout (0s) to 10.255.255.1:6550"),
        "legacy text lost: {}",
        err
    );
}

#[cfg(feature = "pool")]
#[tokio::test]
async fn socks5_handshake_timeout_yields_typed_timeout() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    // Accept and stay silent — the handshake budget must expire.
    tokio::spawn(async move {
        // Hold the accepted socket open — dropping it would reset
        // the client's read before its handshake budget expires.
        let (sock, _) = listener.accept().await.unwrap();
        tokio::time::sleep(Duration::from_secs(5)).await;
        drop(sock);
    });
    let proxy = socks5_proxy_config(&addr.ip().to_string(), addr.port());
    let err = crate::connect::connect_socks5_proxy(
        "1.2.3.4:443",
        &proxy,
        &ProxyPool::new(PoolConfig::default(), Duration::from_secs(2), 1),
        Duration::from_millis(100),
    )
    .await
    .expect_err("silent proxy must time out");
    assert!(
        matches!(
            &err,
            ConnectError::Timeout {
                stage: Stage::Handshake,
                kind: TimeoutKind::Socks5Handshake,
                ..
            }
        ),
        "got: {err:?}"
    );
    assert!(
        err.to_string()
            .starts_with("[SOCKS5] handshake timeout (0s) to "),
        "legacy text lost: {}",
        err
    );
}

#[cfg(feature = "pool")]
#[tokio::test]
async fn io_error_keeps_source_chain_and_legacy_prefix() {
    // A broadcast address fails the TCP connect() call itself,
    // immediately and without a listener to race against.
    let pool = ProxyPool::new(PoolConfig::default(), Duration::from_secs(2), 1);
    let err = pool
        .acquire(&socks5_proxy_config("255.255.255.255", 80))
        .await
        .expect_err("unusable address must fail the connect");
    assert!(
        matches!(
            &err,
            ConnectError::Io {
                stage: Stage::Connect,
                ..
            }
        ),
        "got: {err:?}"
    );
    let source = std::error::Error::source(&err)
        .expect("Io must expose its io::Error")
        .downcast_ref::<std::io::Error>()
        .expect("source must be the io::Error");
    assert!(
        source.kind() != std::io::ErrorKind::WouldBlock,
        "unexpected io kind: {source}"
    );
    assert!(
        err.to_string()
            .starts_with("connect to 255.255.255.255:80: "),
        "legacy text lost: {}",
        err
    );
}

#[cfg(feature = "pool")]
#[tokio::test]
async fn socks5_rejected_connect_yields_proxy_rejected() {
    let err = handshake_error(
        "1.2.3.4:443",
        &[0x05, 0x00],
        &[0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0],
    )
    .await;
    match &err {
        ConnectError::ProxyRejected {
            protocol: ProxyProtocol::Socks5,
            code: Some(code),
            ..
        } => assert_eq!(*code, 0x05),
        other => panic!("expected ProxyRejected, got: {other:?}"),
    }
    assert_eq!(
        err.to_string(),
        "[SOCKS5] CONNECT request error, error code: 05"
    );
}

#[tokio::test]
async fn http_rejected_connect_yields_proxy_rejected_with_status_line() {
    let (mut client, mut upstream) = duplex(4096);
    let proxy = http_proxy_config("proxy.example", 8080);
    let (client, _upstream) = tokio::join!(
        async {
            http_connect_handshake(&mut client, "example.com:443", &proxy)
                .await
                .expect_err("403 must reject")
        },
        async {
            let mut request = Vec::new();
            while !request.ends_with(b"\r\n\r\n") {
                let mut byte = [0u8; 1];
                upstream.read_exact(&mut byte).await.unwrap();
                request.push(byte[0]);
            }
            upstream
                .write_all(b"HTTP/1.1 403 Forbidden\r\n\r\n")
                .await
                .unwrap();
        }
    );
    match &client {
        ConnectError::ProxyRejected {
            protocol: ProxyProtocol::Http,
            code: Some(code),
            response,
        } => {
            assert_eq!(*code, 403u16);
            assert_eq!(response, "HTTP/1.1 403 Forbidden");
        }
        other => panic!("expected ProxyRejected, got: {other:?}"),
    }
    assert_eq!(
        client.to_string(),
        "[HTTP] upstream proxy rejected CONNECT: HTTP/1.1 403 Forbidden"
    );
}

#[cfg(feature = "pool")]
#[tokio::test]
async fn auth_failure_yields_typed_auth_failed() {
    let err = authed_handshake_error("1.2.3.4:443", &[0x05, 0x02], &[0x01, 0x2a]).await;
    match &err {
        ConnectError::AuthFailed { status } => assert_eq!(*status, 0x2a),
        other => panic!("expected AuthFailed, got: {other:?}"),
    }
    assert_eq!(
        err.to_string(),
        "[SOCKS5] Authentication failed (status 2a)"
    );
}

#[cfg(feature = "pool")]
#[tokio::test]
async fn method_unsupported_yields_typed_variant_both_flavors() {
    // Proxy refuses username/password auth.
    let err = authed_handshake_error("1.2.3.4:443", &[0x05, 0x00], &[]).await;
    assert!(
        matches!(
            &err,
            ConnectError::MethodUnsupported {
                got: 0x00,
                with_auth: true
            }
        ),
        "got: {err:?}"
    );
    assert_eq!(
        err.to_string(),
        "[SOCKS5] Proxy does not support username/password authentication (received: 00)"
    );

    // Proxy refuses no-auth.
    let err = handshake_error("1.2.3.4:443", &[0x05, 0x02], &[]).await;
    assert!(
        matches!(
            &err,
            ConnectError::MethodUnsupported {
                got: 0x02,
                with_auth: false
            }
        ),
        "got: {err:?}"
    );
    assert_eq!(
        err.to_string(),
        "[SOCKS5] Proxy does not support no-authentication method (received: 02)"
    );
}

#[cfg(feature = "pool")]
#[tokio::test]
async fn protocol_violations_yield_typed_protocol() {
    // Bad version in the CONNECT response header.
    let err = handshake_error(
        "1.2.3.4:443",
        &[0x05, 0x00],
        &[0x04, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0],
    )
    .await;
    assert!(
        matches!(
            &err,
            ConnectError::Protocol(ProtocolViolation::Socks5BadVersion { got: 4 })
        ),
        "got: {err:?}"
    );
    assert_eq!(err.to_string(), "[SOCKS5] Invalid proxy response version");

    // Unknown ATYP in the CONNECT response.
    let err = handshake_error(
        "1.2.3.4:443",
        &[0x05, 0x00],
        &[0x05, 0x00, 0x00, 0x07, 0, 0, 0, 0, 0, 0],
    )
    .await;
    assert!(
        matches!(
            &err,
            ConnectError::Protocol(ProtocolViolation::Socks5UnknownAddressType { got: 7 })
        ),
        "got: {err:?}"
    );
    assert_eq!(err.to_string(), "[SOCKS5] Unknown address type in response");
}

#[cfg(feature = "pool")]
#[tokio::test]
async fn non_socks5_greeting_reply_is_bad_version_not_method_unsupported() {
    // No-auth greeting answered by something that is not SOCKS5.
    let err = handshake_error("1.2.3.4:443", &[0x04, 0x00], &[]).await;
    assert!(
        matches!(
            &err,
            ConnectError::Protocol(ProtocolViolation::Socks5BadVersion { got: 4 })
        ),
        "got: {err:?}"
    );

    // Same on the username/password greeting.
    let err = authed_handshake_error("1.2.3.4:443", &[0x48, 0x54], &[]).await;
    assert!(
        matches!(
            &err,
            ConnectError::Protocol(ProtocolViolation::Socks5BadVersion { got: 0x48 })
        ),
        "got: {err:?}"
    );
}

#[cfg(feature = "pool")]
#[tokio::test]
async fn bad_auth_subnegotiation_version_is_protocol_not_auth_failed() {
    let err = authed_handshake_error("1.2.3.4:443", &[0x05, 0x02], &[0x05, 0x00]).await;
    assert!(
        matches!(
            &err,
            ConnectError::Protocol(ProtocolViolation::Socks5BadAuthVersion { got: 5 })
        ),
        "got: {err:?}"
    );
    assert_eq!(
        err.to_string(),
        "[SOCKS5] Invalid authentication response version"
    );
}

#[test]
fn socks5_rep_descriptions_follow_rfc_1928() {
    let expected = [
        (0, "succeeded"),
        (1, "general SOCKS server failure"),
        (2, "connection not allowed by ruleset"),
        (3, "network unreachable"),
        (4, "host unreachable"),
        (5, "connection refused"),
        (6, "TTL expired"),
        (7, "command not supported"),
        (8, "address type not supported"),
        (9, "unassigned"),
        (0xff, "unassigned"),
        (0x1ff, "unassigned"),
    ];
    for (code, text) in expected {
        assert_eq!(super::socks5_rep_description(code), text, "REP {code:#x}");
    }
}

#[tokio::test]
async fn oversized_domain_yields_typed_protocol() {
    let (mut client, mut upstream) = duplex(4096);
    // Complete the greeting so the target parse (and its error) is
    // actually reached.
    let peer = tokio::spawn(async move {
        let mut greeting = [0u8; 3];
        upstream.read_exact(&mut greeting).await.unwrap();
        upstream.write_all(&[0x05, 0x00]).await.unwrap();
    });
    let domain = "a".repeat(300);
    let target = format!("{domain}:443");
    let err = handshake_over_stream(&mut client, &target, None)
        .await
        .expect_err("oversized domain must fail");
    assert!(
        matches!(
            &err,
            ConnectError::Protocol(ProtocolViolation::Socks5DomainTooLong { len: 300 })
        ),
        "got: {err:?}"
    );
    assert_eq!(err.to_string(), "[SOCKS5] Domain name too long");
    peer.await.unwrap();
}

#[tokio::test]
async fn oversized_credentials_yield_typed_protocol_with_lengths() {
    let (mut client, mut upstream) = duplex(8192);
    let peer = tokio::spawn(async move {
        let mut greeting = [0u8; 3];
        upstream.read_exact(&mut greeting).await.unwrap();
        upstream.write_all(&[0x05, 0x02]).await.unwrap();
    });
    let long = "u".repeat(256);
    let err = handshake_over_stream(&mut client, "1.2.3.4:443", Some((&long, "p")))
        .await
        .expect_err("oversized credentials must fail");
    assert!(
        matches!(
            &err,
            ConnectError::Protocol(ProtocolViolation::Socks5CredentialsTooLong {
                username_len: 256,
                password_len: 1
            })
        ),
        "got: {err:?}"
    );
    assert_eq!(err.to_string(), "[SOCKS5] Username or password too long");
    peer.await.unwrap();
}

#[tokio::test]
async fn http_invalid_connect_target_yields_typed_protocol() {
    let (mut client, mut upstream) = duplex(4096);
    let proxy = http_proxy_config("proxy.example", 8080);
    let err = http_connect_handshake(&mut client, "bad target:443", &proxy)
        .await
        .expect_err("control characters must reject");
    assert!(
        matches!(
            &err,
            ConnectError::Protocol(ProtocolViolation::HttpInvalidConnectTarget)
        ),
        "got: {err:?}"
    );
    assert_eq!(err.to_string(), "[HTTP] invalid CONNECT target");
    drop(client);
    let mut rest = Vec::new();
    upstream.read_to_end(&mut rest).await.unwrap();
    assert!(rest.is_empty());
}

#[tokio::test]
async fn http_too_large_response_yields_typed_protocol() {
    let (mut client, mut upstream) = duplex(16384);
    let peer = tokio::spawn(async move {
        let mut request = Vec::new();
        while !request.ends_with(b"\r\n\r\n") {
            let mut byte = [0u8; 1];
            upstream.read_exact(&mut byte).await.unwrap();
            request.push(byte[0]);
        }
        // 4096 bytes with no header terminator must overflow the head.
        let junk = vec![b'a'; 4096];
        upstream.write_all(&junk).await.unwrap();
        upstream.write_all(&junk).await.unwrap();
    });
    let proxy = http_proxy_config("proxy.example", 8080);
    let err = http_connect_handshake(&mut client, "example.com:443", &proxy)
        .await
        .expect_err("oversized response must fail");
    assert!(
        matches!(
            &err,
            ConnectError::Protocol(ProtocolViolation::HttpResponseTooLarge)
        ),
        "got: {err:?}"
    );
    assert_eq!(err.to_string(), "[HTTP] upstream proxy response too large");
    peer.await.unwrap();
}

#[tokio::test]
async fn http_closed_early_yields_typed_protocol() {
    let (mut client, mut upstream) = duplex(4096);
    let peer = tokio::spawn(async move {
        let mut request = Vec::new();
        while !request.ends_with(b"\r\n\r\n") {
            let mut byte = [0u8; 1];
            upstream.read_exact(&mut byte).await.unwrap();
            request.push(byte[0]);
        }
        upstream.write_all(b"HTTP/1.1 200 OK\r\n").await.unwrap();
        drop(upstream);
    });
    let proxy = http_proxy_config("proxy.example", 8080);
    let err = http_connect_handshake(&mut client, "example.com:443", &proxy)
        .await
        .expect_err("early close must fail");
    assert!(
        matches!(
            &err,
            ConnectError::Protocol(ProtocolViolation::HttpClosedEarly)
        ),
        "got: {err:?}"
    );
    assert_eq!(
        err.to_string(),
        "[HTTP] upstream proxy closed before completing response"
    );
    peer.await.unwrap();
}

#[tokio::test]
async fn unparseable_target_yields_invalid_target() {
    let (mut client, mut upstream) = duplex(4096);
    let err = handshake_over_stream(&mut client, "no-port-target", None)
        .await
        .expect_err("invalid target must fail");
    assert!(matches!(
        &err,
        ConnectError::InvalidTarget(t) if t == "no-port-target"
    ));
    assert_eq!(
        err.to_string(),
        "[SOCKS5] Invalid target address format: no-port-target"
    );
    // Nothing reached the wire.
    drop(client);
    let mut rest = Vec::new();
    upstream.read_to_end(&mut rest).await.unwrap();
    assert!(rest.is_empty());
}

#[cfg(feature = "pool")]
#[tokio::test]
async fn pool_at_capacity_yields_typed_variant() {
    let pool = ProxyPool::new(PoolConfig::default(), Duration::from_secs(2), 1);
    let proxy = socks5_proxy_config("203.0.113.1", 1080);
    let _hold = pool.reserve_permit(&proxy).expect("first reserve");
    let err = pool.reserve_permit(&proxy).expect_err("cap is 1");
    assert!(
        matches!(&err, ConnectError::AtCapacity(cap) if cap.host == "203.0.113.1" && cap.port == 1080)
    );
    assert_eq!(err.to_string(), "upstream cap reached for 203.0.113.1:1080");
}

#[cfg(feature = "pool")]
#[cfg(feature = "tls")]
#[tokio::test]
async fn https_without_connector_yields_tls_variant_with_legacy_text() {
    let proxy = ProxyConfig {
        protocol: ProxyProtocol::Https,
        host: "proxy.example".into(),
        port: 443,
        user: None,
        password: None,
        is_gate: false,
        gate: None,
    };
    let Err(err) = crate::connect::connect_proxy(
        "example.com:443",
        &proxy,
        &ProxyPool::new(PoolConfig::default(), Duration::from_secs(2), 1),
        Duration::from_secs(2),
        None,
    )
    .await
    else {
        panic!("missing connector must fail")
    };
    assert!(matches!(&err, ConnectError::Tls { source: None, .. }));
    assert_eq!(err.to_string(), "HTTPS upstream requires TLS connector");
}

#[cfg(feature = "pool")]
#[cfg(not(feature = "tls"))]
#[tokio::test]
async fn https_in_lean_build_yields_tls_feature_missing() {
    let proxy = ProxyConfig {
        protocol: ProxyProtocol::Https,
        host: "proxy.example".into(),
        port: 443,
        user: None,
        password: None,
        is_gate: false,
        gate: None,
    };
    let Err(err) = crate::connect::connect_proxy(
        "example.com:443",
        &proxy,
        &ProxyPool::new(PoolConfig::default(), Duration::from_secs(2), 1),
        Duration::from_secs(2),
        None,
    )
    .await
    else {
        panic!("HTTPS without the tls feature must fail")
    };
    assert!(matches!(
        &err,
        ConnectError::TlsFeatureMissing { host } if host == "proxy.example"
    ));
    assert!(
        err.to_string().starts_with(
            "HTTPS upstream to proxy.example requested, but resocks5-net was built without the `tls` feature"
        ) && err.to_string().ends_with("refusing to fall back to plaintext"),
        "legacy text lost: {}",
        err
    );
}
