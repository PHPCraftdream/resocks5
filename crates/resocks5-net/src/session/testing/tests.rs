//! The scripted upstream mock drives the dial API through every script:
//! tunnel, refusal, silent phases, hang-up and secure auth.

use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;

#[cfg(feature = "secure-auth")]
use super::MockAuth;
use super::{MockUpstream, Script};
use crate::connect::{dial_tcp, DialOptions};
use crate::error::{Stage, TimeoutKind};
use crate::types::{ProxyConfig, ProxyProtocol};
use crate::ConnectError;

const GUARD: Duration = Duration::from_secs(20);

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
