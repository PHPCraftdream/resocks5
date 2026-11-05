//! GSSAPI clients through `handle_client`: the authenticated principal maps to
//! the account of the same name (enabled, IP-admitted, direct/pool), and an
//! unknown, disabled or filtered principal is refused. Kerberos itself is the
//! mock mechanism; the real one has its own CI job.

use std::sync::Arc;
use std::time::Duration;

use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{timeout, Instant};

use super::handle_client::handle_client;
use crate::auth::state::gssapi::GSSAPI_HASH;
use crate::auth::AuthState;
use crate::config::{AllowedClients, NetworkConfig, TlsFragmentConfig, User, UsersConfig};
use resocks5_net::chain::GateLevels;
use resocks5_net::gssapi::mock::MockBackend;
use resocks5_net::gssapi::{client_gssapi, GssAcceptor, GssCredentials, METHOD};
use resocks5_net::rotator::ProxyRotator;
use resocks5_net::server::ServerError;
use tokio::io::AsyncWriteExt;

const KEY: [u8; 32] = [3; 32];
const SERVICE: &str = "socks@proxy.test";
const BANNED: &str = "^blocked[.]invalid:443$";

fn account(name: &str, enabled: bool, allowed: Option<&str>) -> User {
    User {
        name: name.to_owned(),
        hash: GSSAPI_HASH.to_owned(),
        is_enabled: enabled,
        direct: false,
        allowed_clients: allowed.map(str::to_owned),
    }
}

/// What the client saw and how the handler ended.
struct Outcome {
    handler: anyhow::Error,
    reply: Option<Vec<u8>>,
}

/// One GSSAPI client as `principal` (a ticket from `kdc_key`) connects to a
/// server with `users`; the client CONNECTs to a banned target, so an
/// authenticated, mapped client ends in "Banned target address".
async fn connect_as(principal: &str, kdc_key: [u8; 32], users: Vec<User>) -> Outcome {
    let acceptor = GssAcceptor::new(MockBackend::new(KEY).with_service(SERVICE).shared());
    let auth = Arc::new(
        AuthState::build(
            &crate::config::AuthConfig {
                allow_anonymous: false,
                ..Default::default()
            },
            &UsersConfig { users },
            "unused-gssapi-tests",
        )
        .unwrap()
        .with_gssapi(acceptor),
    );
    let banned = Arc::new(regex::RegexSet::new([BANNED]).unwrap());
    let (sender, _receiver) = tokio::sync::mpsc::channel(64);
    let logger = Arc::new(crate::logger::Logger::new(
        sender,
        crate::logger::LogConfig::default(),
    ));
    let pool = Arc::new(resocks5_net::pool::ProxyPool::new(
        Default::default(),
        Duration::from_secs(1),
        1,
    ));
    let frag = Arc::new(TlsFragmentConfig::default());
    let network = Arc::new(NetworkConfig::default());
    let direct_limiter = Arc::new(tokio::sync::Semaphore::new(8));
    let no_gates = Arc::new(GateLevels::default());
    let no_rotator: Option<Arc<ProxyRotator>> = None;
    let allowed: Option<Arc<AllowedClients>> = None;
    let credentials = GssCredentials::new(
        MockBackend::new(kdc_key).with_principal(principal).shared(),
        SERVICE,
    );

    timeout(Duration::from_secs(15), async {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut client = TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (stream, _) = listener.accept().await.unwrap();
        let handler = handle_client(
            stream,
            &auth,
            &no_gates,
            &no_rotator,
            &no_rotator,
            &logger,
            &banned,
            &pool,
            &frag,
            &network,
            None,
            &direct_limiter,
            &allowed,
            Instant::now() + Duration::from_secs(10),
        );
        let leg = async {
            client.write_all(&[5, 1, METHOD]).await.unwrap();
            let mut chosen = [0u8; 2];
            client.read_exact(&mut chosen).await.unwrap();
            assert_eq!(chosen, [5, METHOD], "GSSAPI is chosen");
            let mut session = match client_gssapi(&mut client, &credentials).await {
                Ok(session) => session,
                Err(_) => return None,
            };
            let mut request = vec![5, 1, 0, 3, 15];
            request.extend_from_slice(b"blocked.invalid");
            request.extend_from_slice(&443u16.to_be_bytes());
            session.write_message(&mut client, &request).await.unwrap();
            session.read_message(&mut client).await.ok()
        };
        let (handler, reply) = tokio::join!(handler, leg);
        Outcome {
            handler: handler.expect_err("every case ends in an error"),
            reply,
        }
    })
    .await
    .expect("bounded GSSAPI exchange")
}

fn is_auth_refusal(error: &anyhow::Error) -> bool {
    matches!(
        error.downcast_ref::<ServerError>(),
        Some(ServerError::Authentication(_))
    )
}

/// The principal logs in as the account of its name: it gets past
/// authentication and the account's policy to the routing stage, where the
/// banned target ends it, with the reply protected. Mutation: not mapping the
/// identity (or not protecting the reply) fails the error or the read.
#[tokio::test]
async fn a_mapped_principal_reaches_routing() {
    let outcome = connect_as("alice@TEST", KEY, vec![account("alice@TEST", true, None)]).await;
    assert!(
        outcome
            .handler
            .to_string()
            .contains("Banned target address"),
        "{}",
        outcome.handler
    );
    let reply = outcome.reply.expect("a protected reply");
    assert_eq!(&reply[..2], &[5, 2], "Forbidden for the banned target");
}

/// A valid ticket for a principal without an account, a disabled account and
/// an account whose `allowed_clients` excludes the peer are all refused as an
/// authentication failure (with a protected Forbidden reply), never routed.
/// Mutations: dropping the account lookup, the enabled check, or the IP rule
/// reaches routing instead.
#[tokio::test]
async fn unmapped_disabled_and_filtered_principals_are_refused() {
    for (what, users) in [
        ("no account", vec![account("someone@TEST", true, None)]),
        ("disabled", vec![account("alice@TEST", false, None)]),
        (
            "filtered peer",
            vec![account("alice@TEST", true, Some("203.0.113.9"))],
        ),
    ] {
        let outcome = connect_as("alice@TEST", KEY, users).await;
        assert!(
            is_auth_refusal(&outcome.handler),
            "{what}: {}",
            outcome.handler
        );
        assert_eq!(&outcome.reply.expect("a reply")[..2], &[5, 2], "{what}");
    }
}

/// A ticket from another KDC never authenticates, whatever accounts exist.
#[tokio::test]
async fn a_ticket_from_another_kdc_is_refused() {
    let outcome = connect_as(
        "alice@TEST",
        [9; 32],
        vec![account("alice@TEST", true, None)],
    )
    .await;
    assert!(is_auth_refusal(&outcome.handler), "{}", outcome.handler);
    assert!(outcome.reply.is_none(), "no session, no reply");
}
