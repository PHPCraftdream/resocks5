//! The scripted upstream mock drives the dial API through every script:
//! tunnel, refusal, silent phases, hang-up and secure auth.

use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::timeout;

use super::MockAuth;
use super::{MockUpstream, Script};
use crate::connect::{dial_tcp, DialOptions};
use crate::error::{Stage, TimeoutKind};
use crate::types::{ProxyConfig, ProxyProtocol};
use crate::ConnectError;

const GUARD: Duration = Duration::from_secs(20);

#[derive(Clone)]
struct WriteTrace {
    writes: std::sync::Arc<std::sync::Mutex<Vec<usize>>>,
    flushes: std::sync::Arc<std::sync::atomic::AtomicUsize>,
}

impl AsyncWrite for WriteTrace {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        self.writes.lock().unwrap().push(bytes.len());
        Poll::Ready(Ok(bytes.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        self.flushes
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

fn opts() -> DialOptions {
    DialOptions::new()
        .with_connect_timeout(Duration::from_secs(5))
        .with_handshake_timeout(Duration::from_millis(500))
}

async fn dial(proxy: &ProxyConfig) -> Result<tokio::net::TcpStream, ConnectError> {
    timeout(GUARD, dial_tcp(proxy, "example.test", 443, &opts()))
        .await
        .expect("test guard")
}

async fn assert_echo(mut tunnel: tokio::net::TcpStream) {
    tunnel.write_all(b"ping").await.unwrap();
    let mut back = [0u8; 4];
    tunnel.read_exact(&mut back).await.unwrap();
    assert_eq!(&back, b"ping");
}

/// Both protocols tunnel and echo, and record the CONNECT target.
#[tokio::test]
async fn a_tunnel_echoes_and_records_the_target() {
    for mock in [MockUpstream::socks5(), MockUpstream::http()] {
        let mock = mock.spawn().await.unwrap();
        assert_echo(dial(&mock.proxy()).await.unwrap()).await;
        assert_eq!(mock.targets(), ["example.test:443"]);
        assert_eq!(mock.connections(), 1);
    }
}

/// A refusal is the typed `ProxyRejected` with the scripted code.
#[tokio::test]
async fn a_refusal_carries_its_code() {
    for (builder, code, protocol) in [
        (MockUpstream::socks5(), 5, ProxyProtocol::Socks5),
        (MockUpstream::http(), 403, ProxyProtocol::Http),
    ] {
        let mock = builder.script(Script::Refuse(code)).spawn().await.unwrap();
        let error = dial(&mock.proxy()).await.unwrap_err();
        assert!(
            matches!(
                &error,
                ConnectError::ProxyRejected { protocol: p, code: Some(c), .. }
                    if *p == protocol && *c == code
            ),
            "{error:?}"
        );
    }
}

/// A silent greeting and a silent CONNECT are handshake timeouts of the
/// matching kind (SOCKS5 tells them apart).
#[tokio::test]
async fn silent_phases_time_out_with_their_kind() {
    for (script, kind) in [
        (Script::SilentGreeting, TimeoutKind::Socks5Greeting),
        (Script::SilentConnect, TimeoutKind::Socks5Handshake),
    ] {
        let mock = MockUpstream::socks5().script(script).spawn().await.unwrap();
        let error = dial(&mock.proxy()).await.unwrap_err();
        assert!(
            matches!(
                &error,
                ConnectError::Timeout { stage: Stage::Handshake, kind: k, .. } if *k == kind
            ),
            "{script:?}: {error:?}"
        );
    }
    let mock = MockUpstream::http()
        .script(Script::SilentConnect)
        .spawn()
        .await
        .unwrap();
    let error = dial(&mock.proxy()).await.unwrap_err();
    assert!(
        matches!(
            &error,
            ConnectError::Timeout {
                kind: TimeoutKind::HttpHandshake,
                ..
            }
        ),
        "{error:?}"
    );
}

/// A hang-up right after accept is an I/O error, not a timeout.
#[tokio::test]
async fn a_hangup_is_an_io_error() {
    for builder in [MockUpstream::socks5(), MockUpstream::http()] {
        let mock = builder.script(Script::Hangup).spawn().await.unwrap();
        let error = dial(&mock.proxy()).await.unwrap_err();
        assert!(
            matches!(&error, ConnectError::Io { .. } | ConnectError::Protocol(_)),
            "{error:?}"
        );
        assert!(mock.targets().is_empty());
    }
}

/// The secure-auth mock lets the right password through and denies a wrong
/// one before any CONNECT is recorded.
#[cfg(feature = "secure-auth")]
#[tokio::test]
async fn the_secure_auth_mock_checks_the_password() {
    use crate::secure_auth::{KdfParams, SecureCredentials, UserSecret};
    const WEAK: KdfParams = KdfParams {
        memory_kib: 64,
        iterations: 1,
        parallelism: 1,
    };
    let mock = MockUpstream::socks5()
        .auth(MockAuth::Secure {
            user: "alice".into(),
            secret: UserSecret::from_password("right", WEAK).unwrap(),
        })
        .spawn()
        .await
        .unwrap();
    let with = |password: &str| {
        mock.proxy()
            .with_secure_auth(SecureCredentials::new("alice", password).with_min_kdf(WEAK))
    };
    let error = dial(&with("wrong")).await.unwrap_err();
    assert!(
        matches!(
            error,
            ConnectError::SecureAuth(crate::SecureAuthError::Denied)
        ),
        "{error:?}"
    );
    assert!(mock.targets().is_empty());
    assert_echo(dial(&with("right")).await.unwrap()).await;
    assert_eq!(mock.targets(), ["example.test:443"]);
}

/// In-memory connections use the exact same SOCKS5 and HTTP handlers.
#[tokio::test]
async fn in_memory_socks_and_http_round_trip() {
    use crate::connect::{http_connect_handshake, socks5_handshake};
    for (mock, is_http) in [
        (MockUpstream::socks5().spawn().await.unwrap(), false),
        (MockUpstream::http().spawn().await.unwrap(), true),
    ] {
        let mut client = mock.connect_in_memory();
        if is_http {
            http_connect_handshake(&mut client, "mem.test:443", &mock.proxy())
                .await
                .unwrap();
        } else {
            socks5_handshake(&mut client, "mem.test", 443)
                .await
                .unwrap();
        }
        client.write_all(b"ping").await.unwrap();
        let mut echo = [0; 4];
        client.read_exact(&mut echo).await.unwrap();
        assert_eq!(&echo, b"ping");
        assert_eq!(mock.targets(), ["mem.test:443"]);
        assert_eq!(mock.connections(), 1);
    }
}

#[tokio::test]
async fn dropping_mock_aborts_active_in_memory_handlers() {
    use crate::connect::{http_connect_handshake, socks5_handshake};
    for mock in [
        MockUpstream::socks5().spawn().await.unwrap(),
        MockUpstream::http().spawn().await.unwrap(),
    ] {
        let mut peer = mock.connect_in_memory();
        if mock.protocol == ProxyProtocol::Http {
            http_connect_handshake(&mut peer, "active.test:443", &mock.proxy())
                .await
                .unwrap();
        } else {
            socks5_handshake(&mut peer, "active.test", 443)
                .await
                .unwrap();
        }
        drop(mock);
        let mut byte = [0];
        assert_eq!(peer.read(&mut byte).await.unwrap(), 0);
    }
}

#[tokio::test(start_paused = true)]
async fn in_memory_reply_delay_uses_one_handshake_deadline() {
    use crate::connect::socks5_handshake_until;
    let mock = MockUpstream::socks5()
        .reply_delay(Duration::from_millis(600))
        .spawn()
        .await
        .unwrap();
    let mut peer = mock.connect_in_memory();
    let start = tokio::time::Instant::now();
    let deadline = start + Duration::from_secs(1);
    let result = socks5_handshake_until(&mut peer, "delay.test", 443, deadline, "mock:0").await;
    assert!(matches!(
        result,
        Err(ConnectError::Timeout {
            stage: Stage::Handshake,
            kind: TimeoutKind::Socks5Handshake,
            ..
        })
    ));
    assert_eq!(tokio::time::Instant::now() - start, Duration::from_secs(1));
}

#[tokio::test(start_paused = true)]
async fn in_memory_http_reply_delay_completes_within_single_deadline() {
    use crate::connect::http_connect_handshake_until;
    let mock = MockUpstream::http()
        .reply_delay(Duration::from_millis(600))
        .spawn()
        .await
        .unwrap();
    let mut peer = mock.connect_in_memory();
    let start = tokio::time::Instant::now();
    let deadline = start + Duration::from_secs(1);
    http_connect_handshake_until(&mut peer, "delay.test:443", &mock.proxy(), deadline)
        .await
        .unwrap();
    assert_eq!(
        tokio::time::Instant::now() - start,
        Duration::from_millis(600)
    );
}

#[tokio::test]
async fn drip_writes_and_flushes_each_reply_byte() {
    let mock = MockUpstream::socks5().drip(true).spawn().await.unwrap();
    let writes = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let flushes = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let mut sink = WriteTrace {
        writes: std::sync::Arc::clone(&writes),
        flushes: std::sync::Arc::clone(&flushes),
    };
    super::write_reply(&mut sink, &mock.state, b"reply")
        .await
        .unwrap();
    assert_eq!(*writes.lock().unwrap(), [1, 1, 1, 1, 1]);
    assert_eq!(flushes.load(std::sync::atomic::Ordering::SeqCst), 5);
}

#[tokio::test(start_paused = true)]
async fn reply_delay_applies_to_refusals() {
    use crate::connect::http_connect_handshake_until;
    let mock = MockUpstream::http()
        .script(Script::Refuse(403))
        .reply_delay(Duration::from_millis(250))
        .spawn()
        .await
        .unwrap();
    let mut peer = mock.connect_in_memory();
    let start = tokio::time::Instant::now();
    let deadline = start + Duration::from_secs(1);
    let result =
        http_connect_handshake_until(&mut peer, "no.test:443", &mock.proxy(), deadline).await;
    assert!(matches!(
        result,
        Err(ConnectError::ProxyRejected {
            code: Some(403),
            ..
        })
    ));
    assert_eq!(
        tokio::time::Instant::now() - start,
        Duration::from_millis(250)
    );
}

#[tokio::test]
async fn drip_replies_parse_for_both_protocols() {
    use crate::connect::{http_connect_handshake, socks5_handshake};
    for mock in [
        MockUpstream::socks5().drip(true).spawn().await.unwrap(),
        MockUpstream::http().drip(true).spawn().await.unwrap(),
    ] {
        let mut peer = mock.connect_in_memory();
        if mock.protocol == ProxyProtocol::Http {
            http_connect_handshake(&mut peer, "drip.test:443", &mock.proxy())
                .await
                .unwrap();
        } else {
            socks5_handshake(&mut peer, "drip.test", 443).await.unwrap();
        }
        assert_eq!(mock.targets(), ["drip.test:443"]);
    }
}

#[tokio::test]
async fn no_acceptable_method_socks5_error_without_secure_auth() {
    use crate::connect::socks5_handshake;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mock = MockUpstream::socks5()
        .auth(MockAuth::NoAcceptableMethod)
        .spawn()
        .await
        .unwrap();
    let result = socks5_handshake(mock.connect_in_memory(), "example.test", 443).await;
    assert!(matches!(
        result,
        Err(ConnectError::MethodUnsupported {
            got: 0xFF,
            with_auth: false
        })
    ));

    let mock = MockUpstream::socks5()
        .auth(MockAuth::NoAcceptableMethod)
        .spawn()
        .await
        .unwrap();
    let mut peer = mock.connect_in_memory();
    peer.write_all(&[0x05, 0x01, 0xFF]).await.unwrap();
    let mut response = [0; 2];
    peer.read_exact(&mut response).await.unwrap();
    assert_eq!(response, [0x05, 0xFF]);
}

#[cfg(feature = "secure-auth")]
#[tokio::test]
async fn secure_auth_modes_report_exact_errors_over_memory() {
    use crate::connect::handshake_over_stream::{socks5_handshake_bounded, Socks5Auth};
    use crate::secure_auth::SecureCredentials;

    for (username, password) in [("alice", "password"), ("bob", "wrong")] {
        let mock = MockUpstream::socks5()
            .auth(MockAuth::SecureDenied)
            .spawn()
            .await
            .unwrap();
        let credentials = SecureCredentials::new(username, password);
        let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
        let error = socks5_handshake_bounded(
            mock.connect_in_memory(),
            "auth.test",
            443,
            Socks5Auth::Strong(crate::connect::handshake_over_stream::Strong {
                #[cfg(feature = "gssapi")]
                gssapi: None,
                secure: Some(&credentials),
            }),
            deadline,
            "mock:0",
            Duration::from_secs(60),
        )
        .await
        .unwrap_err();
        assert!(matches!(
            error,
            ConnectError::SecureAuth(crate::SecureAuthError::Denied)
        ));
    }

    for status in [0xFF, 0x01, 0x7F] {
        let mock = MockUpstream::socks5()
            .auth(MockAuth::AuthStatus(status))
            .spawn()
            .await
            .unwrap();
        let credentials = SecureCredentials::new("alice", "password");
        let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
        let error = socks5_handshake_bounded(
            mock.connect_in_memory(),
            "auth.test",
            443,
            Socks5Auth::Strong(crate::connect::handshake_over_stream::Strong {
                #[cfg(feature = "gssapi")]
                gssapi: None,
                secure: Some(&credentials),
            }),
            deadline,
            "mock:0",
            Duration::from_secs(60),
        )
        .await
        .unwrap_err();
        let expected = match status {
            0xFF => crate::SecureAuthError::Refused,
            0x01 => crate::SecureAuthError::EnrollmentNotAllowed,
            _ => crate::SecureAuthError::BadVersion,
        };
        assert!(
            matches!(&error, ConnectError::SecureAuth(e) if *e == expected),
            "status {status:#04x}: {error:?}"
        );
    }
}

#[tokio::test]
async fn no_acceptable_method_http_auth_always_rejects_with_407() {
    use crate::connect::http_connect_handshake;
    let mock = MockUpstream::http()
        .auth(MockAuth::NoAcceptableMethod)
        .spawn()
        .await
        .unwrap();
    let mut peer = mock.connect_in_memory();
    let error = http_connect_handshake(&mut peer, "no-method.test:443", &mock.proxy())
        .await
        .unwrap_err();
    assert!(matches!(
        error,
        ConnectError::ProxyRejected {
            protocol: ProxyProtocol::Http,
            code: Some(407),
            ..
        }
    ));
}

#[cfg(feature = "secure-auth")]
#[tokio::test]
async fn http_secure_auth_modes_reject_with_407() {
    use crate::connect::http_connect_handshake;
    for auth in [MockAuth::SecureDenied, MockAuth::AuthStatus(0xFF)] {
        let mock = MockUpstream::http().auth(auth).spawn().await.unwrap();
        let mut peer = mock.connect_in_memory();
        let error = http_connect_handshake(&mut peer, "auth.test:443", &mock.proxy())
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            ConnectError::ProxyRejected {
                protocol: ProxyProtocol::Http,
                code: Some(407),
                ..
            }
        ));
    }
}
