//! The RFC 1961 layer against the mock mechanism.

use std::sync::{Arc, Mutex};

use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt};

use super::mock::MockBackend;
use super::*;

const KEY: [u8; 32] = [7; 32];
const SERVICE: &str = "socks@proxy.test";

fn client_backend(principal: &str) -> Arc<dyn GssBackend> {
    MockBackend::new(KEY).with_principal(principal).shared()
}

fn server_backend() -> Arc<dyn GssBackend> {
    MockBackend::new(KEY).with_service(SERVICE).shared()
}

/// One full exchange; the two sides' results.
async fn run(
    credentials: &GssCredentials,
    acceptor: &GssAcceptor,
) -> (
    Result<GssSession, GssapiError>,
    Result<(GssSession, String), GssapiError>,
) {
    let (client, server) = duplex(4096);
    tokio::join!(
        async move {
            let mut client = client;
            client_gssapi(&mut client, credentials).await
        },
        async move {
            let mut server = server;
            server_gssapi(&mut server, acceptor).await
        },
    )
}

fn creds(principal: &str) -> GssCredentials {
    GssCredentials::new(client_backend(principal), SERVICE)
}

/// The server learns the client's principal, both sides agree on the
/// strongest level, and a message round-trips in each direction. Mutation:
/// returning the service name as the peer (or no name) fails the principal.
#[tokio::test]
async fn a_context_is_established_and_messages_round_trip() {
    let acceptor = GssAcceptor::new(server_backend());
    let (client, server) = run(&creds("alice@TEST"), &acceptor).await;
    let mut client = client.unwrap();
    let (mut server, principal) = server.unwrap();
    assert_eq!(principal, "alice@TEST");
    assert_eq!(client.protection(), Protection::Confidential);
    assert_eq!(server.protection(), Protection::Confidential);

    let request = b"\x05\x01\x00\x03\x0bexample.com\x01\xbb";
    let sealed = client.seal(request).unwrap();
    assert_eq!(&sealed[..2], &[1, 3], "an encapsulated data message");
    assert!(
        !sealed.windows(request.len()).any(|w| w == request),
        "level 2 encrypts the request"
    );
    let mut reader = &sealed[..];
    assert_eq!(server.read_message(&mut reader).await.unwrap(), request);

    let (mut a, mut b) = duplex(1024);
    server
        .write_message(&mut a, b"\x05\x00\x00\x01\0\0\0\0\0\0")
        .await
        .unwrap();
    assert_eq!(
        client.read_message(&mut b).await.unwrap(),
        b"\x05\x00\x00\x01\0\0\0\0\0\0"
    );
}

/// The client asks for the strongest level and the server agrees; a client
/// asking for integrity only is answered with integrity (the server's
/// minimum is integrity). Mutation: ignoring the request always answers 2.
#[tokio::test]
async fn the_agreed_level_follows_the_request() {
    let acceptor = GssAcceptor::new(server_backend());
    let weak = creds("alice@TEST").with_requested_protection(Protection::Integrity);
    let (client, server) = run(&weak, &acceptor).await;
    assert_eq!(client.unwrap().protection(), Protection::Integrity);
    assert_eq!(server.unwrap().0.protection(), Protection::Integrity);
}

/// A server whose minimum is confidentiality lifts a weaker request to it; a
/// client whose minimum is confidentiality refuses a server that agrees to
/// less. Mutation: no minimum check accepts the weak level.
#[tokio::test]
async fn minimum_protection_is_enforced_on_both_sides() {
    let strict_server =
        GssAcceptor::new(server_backend()).with_min_protection(Protection::Confidential);
    let weak = creds("alice@TEST").with_requested_protection(Protection::Integrity);
    let (client, server) = run(&weak, &strict_server).await;
    assert_eq!(client.unwrap().protection(), Protection::Confidential);
    assert_eq!(server.unwrap().0.protection(), Protection::Confidential);

    let lenient_server = GssAcceptor::new(server_backend());
    let strict_client = creds("alice@TEST")
        .with_requested_protection(Protection::Integrity)
        .with_min_protection(Protection::Confidential);
    let (client, _) = run(&strict_client, &lenient_server).await;
    assert_eq!(client.unwrap_err(), GssapiError::ProtectionTooWeak);
}

/// A ticket from another KDC, or for another service, is refused: the client
/// is aborted (0xFF) and no session exists. Mutation: a server that does not
/// check the ticket authenticates anyone.
#[tokio::test]
async fn a_bad_ticket_is_aborted() {
    let acceptor = GssAcceptor::new(server_backend());
    let foreign = GssCredentials::new(
        MockBackend::new([9; 32])
            .with_principal("mallory@TEST")
            .shared(),
        SERVICE,
    );
    let (client, server) = run(&foreign, &acceptor).await;
    assert_eq!(client.unwrap_err(), GssapiError::Aborted);
    assert!(matches!(server.unwrap_err(), GssapiError::Backend(_)));

    let other_service = GssCredentials::new(client_backend("alice@TEST"), "socks@elsewhere");
    let (client, server) = run(&other_service, &acceptor).await;
    assert_eq!(client.unwrap_err(), GssapiError::Aborted);
    assert!(server.is_err());
}

/// A server that cannot prove itself fails the client (mutual
/// authentication). Mutation: not verifying the server token trusts a rogue
/// server.
#[tokio::test]
async fn a_rogue_server_fails_mutual_authentication() {
    let (client, mut server) = duplex(4096);
    let rogue = tokio::spawn(async move {
        let mut head = [0u8; 4];
        server.read_exact(&mut head).await.unwrap();
        let mut token = vec![0u8; usize::from(u16::from_be_bytes([head[2], head[3]]))];
        server.read_exact(&mut token).await.unwrap();
        // Answer with garbage of the right shape.
        server.write_all(&[1, 1, 0, 32]).await.unwrap();
        server.write_all(&[0xAA; 32]).await.unwrap();
        server
    });
    let mut client = client;
    let error = client_gssapi(&mut client, &creds("alice@TEST"))
        .await
        .unwrap_err();
    assert!(matches!(error, GssapiError::Backend(_)), "{error:?}");
    drop(rogue.await.unwrap());
}

/// Protected messages are bound to the session: a tampered one, a replayed
/// one and one reflected back to its sender are all refused. Mutations: no
/// MAC check, no sequence check, no direction.
#[tokio::test]
async fn protected_messages_resist_tampering_replay_and_reflection() {
    let acceptor = GssAcceptor::new(server_backend());
    let (client, server) = run(&creds("alice@TEST"), &acceptor).await;
    let (mut client, (mut server, _)) = (client.unwrap(), server.unwrap());

    let frame = client.seal(b"first").unwrap();
    let token = &frame[4..];
    let mut tampered = token.to_vec();
    let last = tampered.len() - 1;
    tampered[last] ^= 1;
    assert_eq!(server.open(&tampered).unwrap_err(), GssapiError::Integrity);
    // The failed open did not consume the sequence number.
    assert_eq!(server.open(token).unwrap(), b"first");
    assert_eq!(
        server.open(token).unwrap_err(),
        GssapiError::Integrity,
        "replay"
    );

    let own = client.seal(b"second").unwrap();
    assert_eq!(
        client.open(&own[4..]).unwrap_err(),
        GssapiError::Integrity,
        "reflection to the sender"
    );
}

/// Framing errors are typed: a wrong version, a wrong message type, and an
/// abort from the peer.
#[tokio::test]
async fn framing_errors_are_typed() {
    for (bytes, expected) in [
        (vec![2u8, 1, 0, 0], GssapiError::BadVersion),
        (vec![1, 2, 0, 0], GssapiError::BadFrame),
        (vec![1, 0xFF], GssapiError::Aborted),
        (
            vec![1, 1, 0],
            GssapiError::Io(std::io::ErrorKind::UnexpectedEof),
        ),
    ] {
        let (mut peer, mut stream) = duplex(64);
        peer.write_all(&bytes).await.unwrap();
        drop(peer);
        let error = read_frame(&mut stream, MTYP_AUTH).await.unwrap_err();
        assert_eq!(error, expected, "{bytes:?}");
    }
}

/// Records everything read through it.
struct Tap<S>(S, Arc<Mutex<Vec<u8>>>);

impl<S: tokio::io::AsyncRead + Unpin> tokio::io::AsyncRead for Tap<S> {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        let poll = std::pin::Pin::new(&mut self.0).poll_read(cx, buf);
        let new = buf.filled()[before..].to_vec();
        self.1.lock().unwrap().extend_from_slice(&new);
        poll
    }
}

impl<S: tokio::io::AsyncWrite + Unpin> tokio::io::AsyncWrite for Tap<S> {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.0).poll_write(cx, buf)
    }
    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.0).poll_flush(cx)
    }
    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.0).poll_shutdown(cx)
    }
}

/// Everything the server sends the client is tokens: the KDC key never
/// appears, and the request is not readable on the wire at level 2. There is
/// no password input anywhere in this protocol.
#[tokio::test]
async fn the_wire_carries_only_tokens() {
    let acceptor = GssAcceptor::new(server_backend());
    let credentials = creds("alice@TEST");
    let (client, server) = duplex(4096);
    let seen = Arc::new(Mutex::new(Vec::new()));
    let request: &[u8] = b"\x05\x01\x00\x03\x0bexample.com\x01\xbb";
    let (client_result, server_result) = tokio::join!(
        async {
            let mut client = Tap(client, Arc::clone(&seen));
            let mut session = client_gssapi(&mut client, &credentials).await?;
            session.write_message(&mut client, request).await?;
            Ok::<_, GssapiError>(())
        },
        async {
            let mut server = Tap(server, Arc::clone(&seen));
            let (mut session, _) = server_gssapi(&mut server, &acceptor).await?;
            session.read_message(&mut server).await
        },
    );
    client_result.unwrap();
    assert_eq!(server_result.unwrap(), request);
    let wire = seen.lock().unwrap().clone();
    assert!(wire.len() > 40);
    assert!(
        !wire.windows(KEY.len()).any(|w| w == KEY),
        "KDC key on the wire"
    );
    assert!(
        !wire.windows(request.len()).any(|w| w == request),
        "the request travels encrypted at level 2"
    );
}
