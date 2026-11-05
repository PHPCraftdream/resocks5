//! Method negotiation on real sockets: the client offers every strong method it
//! is configured with, strongest first, and the server picks the strongest it
//! has enabled. Nothing weaker than what is configured is ever used.

use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{timeout, Instant};

use super::mock::MockBackend;
use super::{GssAcceptor, GssCredentials, Protection};
use crate::connect::{dial_tcp, DialOptions};
use crate::secure_auth::{
    DecoyKey, KdfParams, SecretStore, SecureCredentials, StoredUser, UserSecret,
};
use crate::server::{accept_with, AuthMethod, AuthMethods, Reply, ServerError, ServerOptions};
use crate::types::ProxyConfig;
use crate::{ConnectError, GssapiError};

const KEY: [u8; 32] = [5; 32];
const SERVICE: &str = "socks@proxy.test";
const WEAK: KdfParams = KdfParams {
    memory_kib: 64,
    iterations: 1,
    parallelism: 1,
};

struct OneUser(UserSecret);

impl SecretStore for OneUser {
    async fn lookup(&self, user: &str) -> Option<StoredUser> {
        (user == "alice").then(|| StoredUser::Secret(self.0.clone()))
    }
    async fn claim(&self, _user: &str, _secret: UserSecret) -> bool {
        false
    }
    fn enrollment_floor(&self) -> KdfParams {
        WEAK
    }
}

/// What a server enables.
#[derive(Clone, Copy)]
struct Server {
    secure: bool,
    gssapi: bool,
    anonymous: bool,
    /// Fixed GSSAPI protection level, if any.
    level: Option<Protection>,
}

type Outcome = Result<(AuthMethod, Option<String>), ServerError>;

/// One connection: authenticate, reply Established, echo.
async fn serve(server: Server) -> (u16, tokio::task::JoinHandle<Outcome>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let task = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let store = OneUser(UserSecret::from_password("pw", WEAK).unwrap());
        let decoy = DecoyKey::generate().unwrap();
        let mut acceptor = GssAcceptor::new(MockBackend::new(KEY).with_service(SERVICE).shared());
        if let Some(level) = server.level {
            acceptor = acceptor.with_protection(level);
        }
        let options = ServerOptions::new(
            Instant::now() + Duration::from_secs(10),
            server.anonymous,
            server.secure || server.gssapi,
        );
        let methods = match (server.secure, server.gssapi) {
            (true, true) => AuthMethods::secure(&store, &decoy).with_gssapi(&acceptor),
            (true, false) => AuthMethods::secure(&store, &decoy),
            _ => AuthMethods::<OneUser>::gssapi(&acceptor),
        };
        let request = accept_with(&mut socket, &options, &methods).await?;
        request.reply(&mut socket, Reply::Established).await?;
        let mut ping = [0u8; 4];
        socket.read_exact(&mut ping).await?;
        socket.write_all(&ping).await?;
        Ok((request.auth_method(), request.username().map(str::to_owned)))
    });
    (port, task)
}

/// A client with the given strong methods.
fn client(port: u16, secure: bool, gssapi: bool, principal: &str) -> ProxyConfig {
    let mut proxy = ProxyConfig::socks5("127.0.0.1", port);
    if secure {
        proxy = proxy.with_secure_auth(SecureCredentials::new("alice", "pw").with_min_kdf(WEAK));
    }
    if gssapi {
        let backend = MockBackend::new(KEY).with_principal(principal).shared();
        proxy = proxy.with_gssapi(GssCredentials::new(backend, SERVICE));
    }
    proxy
}

async fn dial(proxy: &ProxyConfig) -> Result<TcpStream, ConnectError> {
    timeout(
        Duration::from_secs(20),
        dial_tcp(proxy, "example.test", 443, &DialOptions::new()),
    )
    .await
    .expect("test guard")
}

async fn echo(mut tunnel: TcpStream) {
    tunnel.write_all(b"ping").await.unwrap();
    let mut back = [0u8; 4];
    tunnel.read_exact(&mut back).await.unwrap();
    assert_eq!(&back, b"ping");
}

const BOTH: Server = Server {
    secure: true,
    gssapi: true,
    anonymous: false,
    level: None,
};

/// With both enabled on both sides GSSAPI wins; the server sees the principal
/// and the tunnel (reply included) works. Mutation: preferring secure auth, or
/// not protecting the reply, fails the method or the dial.
#[tokio::test]
async fn gssapi_is_preferred_when_both_sides_have_both() {
    let (port, server) = serve(BOTH).await;
    echo(dial(&client(port, true, true, "alice@TEST")).await.unwrap()).await;
    let (method, user) = server.await.unwrap().unwrap();
    assert_eq!(method, AuthMethod::Gssapi);
    assert_eq!(user.as_deref(), Some("alice@TEST"));
}

/// The server adapts: only secure auth enabled → secure auth, though the
/// client also offers GSSAPI. Mutation: choosing the first offered method
/// regardless of the server's configuration fails the dial.
#[tokio::test]
async fn the_server_falls_back_to_what_it_has() {
    let (port, server) = serve(Server {
        gssapi: false,
        ..BOTH
    })
    .await;
    echo(dial(&client(port, true, true, "alice@TEST")).await.unwrap()).await;
    let (method, user) = server.await.unwrap().unwrap();
    assert_eq!(method, AuthMethod::Secure);
    assert_eq!(user.as_deref(), Some("alice"));
}

/// The client adapts too: it offers only what it is configured with, and the
/// server enabling more changes nothing. Mutation: a client always offering
/// both fails one row.
#[tokio::test]
async fn each_single_method_client_gets_its_method() {
    for (secure, gssapi, expected) in [
        (true, false, AuthMethod::Secure),
        (false, true, AuthMethod::Gssapi),
    ] {
        let (port, server) = serve(BOTH).await;
        echo(
            dial(&client(port, secure, gssapi, "alice@TEST"))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(server.await.unwrap().unwrap().0, expected);
    }
}

/// No common strong method is a clean refusal on both sides; a client with
/// only GSSAPI against a secure-only server never falls back to anything
/// else. Mutation: answering with anonymous or the client sending a password
/// fails here.
#[tokio::test]
async fn no_common_method_is_refused() {
    let (port, server) = serve(Server {
        gssapi: false,
        ..BOTH
    })
    .await;
    let error = dial(&client(port, false, true, "alice@TEST"))
        .await
        .unwrap_err();
    assert!(
        matches!(error, ConnectError::MethodUnsupported { got: 0xFF, .. }),
        "{error:?}"
    );
    assert!(matches!(
        server.await.unwrap(),
        Err(ServerError::Authentication(_))
    ));
}

/// A strong client is never downgraded: a server answering "no
/// authentication" (a man in the middle stripping methods, or a rogue server)
/// fails the dial. Mutation: accepting a method the client did not offer.
#[tokio::test]
async fn a_strong_client_is_never_downgraded_to_anonymous() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let rogue = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut greeting = [0u8; 4];
        socket.read_exact(&mut greeting).await.unwrap();
        assert_eq!(greeting, [5, 2, 1, 0x80], "GSSAPI first, then secure auth");
        socket.write_all(&[5, 0]).await.unwrap();
        let mut rest = Vec::new();
        let _ = socket.read_to_end(&mut rest).await;
        rest
    });
    let error = dial(&client(port, true, true, "alice@TEST"))
        .await
        .unwrap_err();
    assert!(
        matches!(error, ConnectError::MethodUnsupported { got: 0, .. }),
        "{error:?}"
    );
    assert!(rogue.await.unwrap().is_empty(), "no request was sent");
}

/// A client offering anonymous and GSSAPI gets GSSAPI from a server that
/// allows both: anonymous is the weakest and chosen last. Mutation: picking
/// the first offered method answers 0x00.
#[tokio::test]
async fn anonymous_is_chosen_last() {
    let (port, _server) = serve(Server {
        anonymous: true,
        ..BOTH
    })
    .await;
    let mut socket = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    socket.write_all(&[5, 3, 0, 0x80, 1]).await.unwrap();
    let mut chosen = [0u8; 2];
    socket.read_exact(&mut chosen).await.unwrap();
    assert_eq!(chosen, [5, 1]);

    let (port, _server) = serve(Server {
        gssapi: false,
        secure: false,
        anonymous: true,
        level: None,
    })
    .await;
    let mut socket = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    socket.write_all(&[5, 2, 1, 0]).await.unwrap();
    socket.read_exact(&mut chosen).await.unwrap();
    assert_eq!(
        chosen,
        [5, 0],
        "anonymous only when nothing stronger is enabled"
    );
}

/// The server never takes a clear-text password: UNAME/PASSWD is not chosen
/// even when it is all the client offers.
#[tokio::test]
async fn cleartext_is_never_chosen() {
    let (port, server) = serve(BOTH).await;
    let mut socket = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    socket.write_all(&[5, 1, 2]).await.unwrap();
    let mut chosen = [0u8; 2];
    socket.read_exact(&mut chosen).await.unwrap();
    assert_eq!(chosen, [5, 0xFF]);
    assert!(server.await.unwrap().is_err());
}

/// A wrong ticket is a typed GSSAPI failure at the dial, with no tunnel.
#[tokio::test]
async fn a_bad_ticket_fails_the_dial_with_a_typed_error() {
    let (port, server) = serve(Server {
        secure: false,
        ..BOTH
    })
    .await;
    let backend = MockBackend::new([9; 32])
        .with_principal("mallory@TEST")
        .shared();
    let proxy =
        ProxyConfig::socks5("127.0.0.1", port).with_gssapi(GssCredentials::new(backend, SERVICE));
    let error = dial(&proxy).await.unwrap_err();
    assert!(
        matches!(error, ConnectError::Gssapi(GssapiError::Aborted)),
        "{error:?}"
    );
    assert!(server.await.unwrap().is_err());
}

/// By default the SOCKS request and reply are plain (level 0, the curl case):
/// only the authentication is protected, and the tunnel works. Mutation:
/// wrapping the reply when level 0 was agreed breaks the client's read.
#[tokio::test]
async fn the_default_serves_plain_socks_messages() {
    let (port, server) = serve(Server {
        secure: false,
        ..BOTH
    })
    .await;
    echo(
        dial(&client(port, false, true, "alice@TEST"))
            .await
            .unwrap(),
    )
    .await;
    let (method, user) = server.await.unwrap().unwrap();
    assert_eq!(method, AuthMethod::Gssapi);
    assert_eq!(user.as_deref(), Some("alice@TEST"));
}

/// A server set to protect (integrity, confidentiality) is served with
/// protected request and reply by a default client, which adapts to the
/// answer. Mutation: not wrapping at levels 1 or 2 breaks one of the dials.
#[tokio::test]
async fn a_protecting_server_gets_protected_messages() {
    for level in [Protection::Integrity, Protection::Confidential] {
        let (port, server) = serve(Server {
            secure: false,
            level: Some(level),
            ..BOTH
        })
        .await;
        echo(
            dial(&client(port, false, true, "alice@TEST"))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(server.await.unwrap().unwrap().0, AuthMethod::Gssapi);
    }
}

/// A client that requires protection does not use an unprotecting server: the
/// dial fails with the typed error before any request is sent.
#[tokio::test]
async fn a_client_requiring_protection_does_not_use_a_plain_server() {
    let (port, server) = serve(Server {
        secure: false,
        ..BOTH
    })
    .await;
    let backend = MockBackend::new(KEY).with_principal("alice@TEST").shared();
    let proxy = ProxyConfig::socks5("127.0.0.1", port).with_gssapi(
        GssCredentials::new(backend, SERVICE).with_min_protection(Protection::Integrity),
    );
    let error = dial(&proxy).await.unwrap_err();
    assert!(
        matches!(error, ConnectError::Gssapi(GssapiError::ProtectionTooWeak)),
        "{error:?}"
    );
    assert!(server.await.unwrap().is_err());
}
