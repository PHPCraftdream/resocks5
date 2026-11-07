use std::time::Duration;

use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt};
use tokio::time::Instant;

use super::socks5_handshake_until;
use crate::error::{ConnectError, Stage, TimeoutKind};

fn soon() -> Instant {
    Instant::now() + Duration::from_millis(200)
}

/// Silence on the greeting: the typed kind says "the upstream never spoke"
/// and the error counts the upstream as down. Mutation: reporting every
/// stall as `Socks5Handshake` (the lost distinction) fails the match.
#[tokio::test]
async fn silent_greeting_is_a_greeting_timeout() {
    let (client, _server) = duplex(64);
    let error = socks5_handshake_until(client, "example.test", 443, soon(), "up:1080")
        .await
        .unwrap_err();
    match &error {
        ConnectError::Timeout {
            stage: Stage::Handshake,
            kind: TimeoutKind::Socks5Greeting,
            endpoint,
            after,
        } => {
            assert_eq!(endpoint, "up:1080");
            assert!(*after <= Duration::from_millis(200));
        }
        other => panic!("unexpected: {other:?}"),
    }
    assert!(error.is_upstream_down());
}

/// The method reply arrives but the CONNECT reply never does: the stall
/// may be the destination's, so it is the plain handshake kind and not
/// "upstream down". Mutation: classifying it as a greeting timeout (or
/// the other way round) fails here or above.
#[tokio::test]
async fn silent_connect_reply_is_a_handshake_timeout() {
    let (client, mut server) = duplex(64);
    let stub = tokio::spawn(async move {
        let mut greeting = [0u8; 3];
        server.read_exact(&mut greeting).await.unwrap();
        server.write_all(&[5, 0]).await.unwrap();
        let mut request = [0u8; 4];
        server.read_exact(&mut request).await.unwrap();
        std::future::pending::<()>().await; // never answers the CONNECT
    });
    let error = socks5_handshake_until(client, "10.0.0.1", 80, soon(), "up:1080")
        .await
        .unwrap_err();
    assert!(
        matches!(
            error,
            ConnectError::Timeout {
                stage: Stage::Handshake,
                kind: TimeoutKind::Socks5Handshake,
                ..
            }
        ),
        "{error:?}"
    );
    assert!(!error.is_upstream_down());
    stub.abort();
}

/// A deadline that already passed fails at once as a greeting timeout.
#[tokio::test]
async fn an_expired_deadline_fails_immediately() {
    let (client, _server) = duplex(64);
    let error = socks5_handshake_until(client, "h", 80, Instant::now(), "up:1")
        .await
        .unwrap_err();
    assert!(matches!(
        error,
        ConnectError::Timeout {
            kind: TimeoutKind::Socks5Greeting,
            ..
        }
    ));
}

/// A full handshake inside the deadline succeeds and leaves the stream
/// ready for payload.
#[tokio::test]
async fn a_handshake_inside_the_deadline_succeeds() {
    let (client, mut server) = duplex(64);
    let stub = tokio::spawn(async move {
        let mut greeting = [0u8; 3];
        server.read_exact(&mut greeting).await.unwrap();
        server.write_all(&[5, 0]).await.unwrap();
        let mut request = [0u8; 10];
        server.read_exact(&mut request).await.unwrap();
        server
            .write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0])
            .await
            .unwrap();
        server.write_all(b"payload").await.unwrap();
    });
    let mut stream = socks5_handshake_until(
        client,
        "10.0.0.1",
        80,
        Instant::now() + Duration::from_secs(10),
        "up:1080",
    )
    .await
    .unwrap();
    let mut payload = [0u8; 7];
    stream.read_exact(&mut payload).await.unwrap();
    assert_eq!(&payload, b"payload");
    stub.await.unwrap();
}

/// An empty host or port 0 is refused before a single byte is written.
#[tokio::test]
async fn an_invalid_target_is_refused_before_any_byte() {
    for (host, port) in [("", 80u16), ("h", 0u16)] {
        let (client, mut server) = duplex(64);
        let error = socks5_handshake_until(client, host, port, soon(), "up:1")
            .await
            .unwrap_err();
        assert!(
            matches!(error, ConnectError::InvalidTarget(_)),
            "{host:?}:{port}"
        );
        // The client half is gone: the server sees EOF with nothing sent.
        let mut sent = Vec::new();
        server.read_to_end(&mut sent).await.unwrap();
        assert!(sent.is_empty(), "no byte may precede the target check");
    }
}
