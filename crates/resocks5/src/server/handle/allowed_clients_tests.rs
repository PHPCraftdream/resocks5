//! Regression tests of the allowed_clients AND-cascade via the shared
//! `handle_client`: real TCP exchanges, without calling `client_ip_allowed`
//! directly and without mocking the matcher.
//!
//! Observable boundary with no external upstream: rotators = None, target
//! `blocked.invalid:443` banned by the banned-regex → an allowed client
//! gets 403 (HTTP) / SOCKS reply `Forbidden` ([5,2,…]); a disallowed one —
//! a plain auth failure (secure auth `Denied` / 407) or a close without
//! a single byte. Passwords — secure auth only (SOCKS5 0x80); HTTP Basic and
//! SOCKS5 UNAME/PASSWD are always rejected.

use std::sync::Arc;
use std::time::Duration;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use super::handle_client::handle_client;
use crate::auth::test_support::{creds, enrolling};
use crate::auth::AuthState;
use crate::config::{AllowedClients, NetworkConfig, TlsFragmentConfig, User, UsersConfig};
use resocks5_net::chain::GateLevels;
use resocks5_net::rotator::ProxyRotator;
use resocks5_net::secure_auth::{client_authenticate, METHOD};
use resocks5_net::server::ServerError;
use resocks5_net::SecureAuthError;
use tokio::time::{timeout, Instant};

const BANNED: &str = "^blocked[.]invalid:443$";
const TARGET_HOST: &str = "blocked.invalid";
const TARGET_PORT: u16 = 443;

/// SOCKS5 reply `Forbidden` — exactly what negotiate.rs sends.
const SOCKS_FORBIDDEN: [u8; 10] = [5, 2, 0, 1, 0, 0, 0, 0, 0, 0];

#[derive(Clone, Copy)]
enum Protocol {
    Socks5,
    Http,
}

/// Expected outcome of the ENTIRE cascade.
#[derive(Clone, Copy)]
enum Expect {
    /// Global filter: close without a single response byte.
    GlobalDeny,
    /// Plain auth failure: secure auth `Denied` / 407.
    AuthFail,
    /// Filters passed, reached routing: 403 / Forbidden reply.
    RouteBanned,
}

struct Case {
    protocol: Protocol,
    expect: Expect,
    global_rule: Option<&'static str>,
    users: Vec<User>,
    allow_anonymous: bool,
    creds: Option<(&'static str, &'static str)>,
}

fn user(name: &str, password: &str, allowed: Option<&str>, direct: bool) -> User {
    User {
        name: name.to_string(),
        hash: crate::auth::compute_hash(password).unwrap(),
        is_enabled: true,
        direct,
        allowed_clients: allowed.map(str::to_string),
    }
}

fn init_user(name: &str, allowed: Option<&str>) -> User {
    User {
        name: name.to_string(),
        hash: "init".to_string(),
        is_enabled: true,
        direct: false,
        allowed_clients: allowed.map(str::to_string),
    }
}

fn test_logger() -> Arc<crate::logger::Logger> {
    let (tx, _rx) = tokio::sync::mpsc::channel::<crate::logger::ELog>(64);
    Arc::new(crate::logger::Logger::new(
        tx,
        crate::logger::LogConfig::default(),
    ))
}

/// Build AuthState and run one exchange. The network part runs in
/// [`run_case_with_auth`].
async fn run_case(c: Case) -> Arc<AuthState> {
    let Case {
        protocol,
        expect,
        global_rule,
        users,
        allow_anonymous,
        creds,
    } = c;
    let auth = Arc::new(
        AuthState::build(
            &crate::config::AuthConfig {
                allow_anonymous,
                ..Default::default()
            },
            &UsersConfig { users },
            "unused",
        )
        .unwrap(),
    );
    let case = Case {
        protocol,
        expect,
        global_rule,
        users: Vec::new(),
        allow_anonymous,
        creds,
    };
    run_case_with_auth(&case, auth.clone()).await;
    auth
}

/// Same with an already built AuthState (persistent users file).
async fn run_case_with_auth(c: &Case, auth: Arc<AuthState>) {
    let logger = test_logger();
    let banned = Arc::new(regex::RegexSet::new([BANNED]).unwrap());
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
    let allowed: Option<Arc<AllowedClients>> = c.global_rule.map(|s| {
        Arc::new(
            crate::config::compile_allowed_clients(s)
                .expect("правило кейса должно компилироваться"),
        )
    });

    // One timeout for the ENTIRE exchange: connect/accept, handler and the
    // client leg in one block. handler is a Future (not spawned): on panic
    // or client-leg timeout the join panics/drops, and the handler
    // is destroyed along with the stream — no tasks left behind.
    let result = timeout(Duration::from_secs(8), async {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        // connect before accept — listener backlog suffices.
        let mut client = TcpStream::connect(address).await.unwrap();
        let (stream, _) = listener.accept().await.unwrap();

        let deadline = Instant::now() + Duration::from_secs(5);
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
            deadline,
        );
        // Client leg panics — the whole block fails, test is done.
        let (handler_res, ()) = tokio::join!(handler, client_leg(&mut client, c));
        handler_res
    })
    .await
    .expect("общий таймаут 8с на весь обмен");
    let err = result.expect_err("все кейсы обязаны завершаться ошибкой handler'а");
    let text = err.to_string();
    match c.expect {
        Expect::GlobalDeny => assert!(
            text.contains("global allowed_clients"),
            "ожидался отказ глобального фильтра, получено: {text}"
        ),
        Expect::AuthFail => assert!(
            matches!(
                err.downcast_ref::<ServerError>(),
                Some(ServerError::Authentication(_))
            ),
            "ожидался обычный auth failure, получено: {text}"
        ),
        Expect::RouteBanned => assert!(
            text.contains("Banned target address"),
            "ожидался отказ на banned target (фильтры пройдены), получено: {text}"
        ),
    }
}

/// Client leg: byte exchange per the case protocol, with checks
/// of exactly the responses distinguishing the three outcomes.
async fn client_leg(client: &mut TcpStream, c: &Case) {
    match (c.protocol, c.expect) {
        // Global deny: write nothing, wait for EOF/RST.
        (_, Expect::GlobalDeny) => {
            let mut reply = [0u8; 2];
            match client.read(&mut reply).await {
                Ok(0) => {}
                Ok(n) => panic!("{n} байт(ы) ответа после глобального фильтра"),
                Err(e) => match e.kind() {
                    std::io::ErrorKind::ConnectionReset
                    | std::io::ErrorKind::BrokenPipe
                    | std::io::ErrorKind::UnexpectedEof => {}
                    other => panic!("неожиданная ошибка чтения: {other}"),
                },
            }
        }
        (Protocol::Socks5, Expect::AuthFail) => {
            let (u, p) = c.creds.expect("AuthFail-кейс требует credentials");
            secure_greeting(client).await;
            let error = client_authenticate(client, &enrolling(u, p))
                .await
                .unwrap_err();
            assert_eq!(
                error,
                SecureAuthError::Denied,
                "аутентификация обязана отказать"
            );
            // Server closes the connection after rejection: accept only
            // EOF-class outcomes, swallow no other Err.
            let mut rest = [0u8; 1];
            match client.read(&mut rest).await {
                Ok(0) => {}
                Ok(n) => panic!("{n} байт(ы) после отказа аутентификации"),
                Err(e) => match e.kind() {
                    std::io::ErrorKind::ConnectionReset
                    | std::io::ErrorKind::BrokenPipe
                    | std::io::ErrorKind::UnexpectedEof => {}
                    other => panic!("неожиданная ошибка чтения: {other}"),
                },
            }
        }
        (Protocol::Socks5, Expect::RouteBanned) => {
            if let Some((u, p)) = c.creds {
                secure_greeting(client).await;
                client_authenticate(client, &creds(u, p))
                    .await
                    .expect("валидные credentials обязаны пройти");
            } else {
                client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
                let mut method = [0u8; 2];
                client.read_exact(&mut method).await.unwrap();
                assert_eq!(method, [0x05, 0x00]);
            }
            client.write_all(&socks_connect()).await.unwrap();
            let mut reply = [0u8; 10];
            client.read_exact(&mut reply).await.unwrap();
            assert_eq!(
                reply, SOCKS_FORBIDDEN,
                "banned target обязан дать Forbidden"
            );
        }
        (Protocol::Http, Expect::AuthFail) => {
            let (u, p) = c.creds.expect("AuthFail-кейс требует credentials");
            client
                .write_all(&http_connect(Some(&B64.encode(format!("{u}:{p}")))))
                .await
                .unwrap();
            let mut response = Vec::new();
            client.read_to_end(&mut response).await.unwrap();
            let text = String::from_utf8_lossy(&response);
            assert!(
                text.starts_with("HTTP/1.1 407"),
                "ожидался 407, получено: {text:?}"
            );
        }
        (Protocol::Http, Expect::RouteBanned) => {
            assert!(c.creds.is_none(), "HTTP никогда не аутентифицирует пароль");
            client.write_all(&http_connect(None)).await.unwrap();
            let mut response = Vec::new();
            client.read_to_end(&mut response).await.unwrap();
            assert_eq!(
                response,
                b"HTTP/1.1 403 Forbidden\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",
                "banned target обязан дать 403"
            );
        }
    }
}

/// SOCKS5 greeting offers only secure auth (0x80).
async fn secure_greeting(client: &mut TcpStream) {
    client.write_all(&[0x05, 0x01, METHOD]).await.unwrap();
    let mut method = [0u8; 2];
    client.read_exact(&mut method).await.unwrap();
    assert_eq!(method, [0x05, METHOD]);
}

fn socks_connect() -> Vec<u8> {
    let mut out = vec![0x05, 0x01, 0x00, 0x03, TARGET_HOST.len() as u8];
    out.extend_from_slice(TARGET_HOST.as_bytes());
    out.extend_from_slice(&TARGET_PORT.to_be_bytes());
    out
}

fn http_connect(b64_creds: Option<&str>) -> Vec<u8> {
    let mut req = format!("CONNECT {TARGET_HOST}:{TARGET_PORT} HTTP/1.1\r\n").into_bytes();
    if let Some(token) = b64_creds {
        req.extend_from_slice(format!("Proxy-Authorization: Basic {token}\r\n").as_bytes());
    }
    req.extend_from_slice(b"\r\n");
    req
}

const BOTH: [Protocol; 2] = [Protocol::Socks5, Protocol::Http];

/// Password cases: HTTP replies 407 to any credentials, the filter
/// distinguishes nothing there — we check SOCKS5 (secure auth).
const WITH_PASSWORD: [Protocol; 1] = [Protocol::Socks5];

/// Case 1a: global deny is stronger than a permissive user.
/// The client sends nothing; with the global filter removed there would be
/// no 403/407 — the handler would hang until the protocol timeout, and the
/// test would fail on the shared timeout or another error outcome.
#[tokio::test]
async fn global_deny_beats_permissive_user() {
    for protocol in BOTH {
        run_case(Case {
            protocol,
            expect: Expect::GlobalDeny,
            global_rule: Some("203.0.113.7"),
            users: vec![user("alice", "pw", None, false)],
            allow_anonymous: false,
            creds: Some(("alice", "pw")),
        })
        .await;
    }
}

/// Case 1b: user-deny with a global `*` — plain auth failure.
/// Without the user filter secure auth would pass instead of `Denied`.
#[tokio::test]
async fn user_deny_beats_global_star() {
    for protocol in WITH_PASSWORD {
        run_case(Case {
            protocol,
            expect: Expect::AuthFail,
            global_rule: Some("*"),
            users: vec![user("alice", "pw", Some("203.0.113.9"), false)],
            allow_anonymous: false,
            creds: Some(("alice", "pw")),
        })
        .await;
    }
}

/// Cases 1c and 3: global allow + user None → reach the routing
/// boundary (banned target → 403/Forbidden); None does not restrict.
/// Counterfactual: a filter falsely banning loopback — would be `Denied`
/// or a close.
#[tokio::test]
async fn global_allow_and_user_none_reach_routing_boundary() {
    for protocol in WITH_PASSWORD {
        run_case(Case {
            protocol,
            expect: Expect::RouteBanned,
            global_rule: Some("loopback"),
            users: vec![user("alice", "pw", None, false)],
            allow_anonymous: false,
            creds: Some(("alice", "pw")),
        })
        .await;
    }
}

/// Case 4: anonymous obeys ONLY the global rule (SOCKS5
/// method 0x00 and HTTP without Authorization do not pass the user filter).
/// Counterfactual: anonymous through the user filter — would be a rejection
/// instead of 403.
#[tokio::test]
async fn anonymous_obeys_only_global_rule() {
    for protocol in BOTH {
        // Global allow → passes to the boundary, despite restrictive alice.
        run_case(Case {
            protocol,
            expect: Expect::RouteBanned,
            global_rule: Some("loopback"),
            users: vec![user("alice", "pw", Some("203.0.113.9"), false)],
            allow_anonymous: true,
            creds: None,
        })
        .await;
        // Global deny → rejection before auth/routing. With the
        // global filter removed the handler waits for the protocol timeout — the test fails
        // on the shared timeout, not on 403.
        run_case(Case {
            protocol,
            expect: Expect::GlobalDeny,
            global_rule: Some("203.0.113.7"),
            users: vec![user("alice", "pw", Some("203.0.113.9"), false)],
            allow_anonymous: true,
            creds: None,
        })
        .await;
    }
}

/// Case 5: a cleartext password is never accepted even if correct and from an allowed
/// peer: SOCKS5 UNAME/PASSWD is not selected ([5,0xFF]), HTTP Basic — 407.
/// Counterfactual: an app on a clear-text `accept` would let both through.
#[tokio::test]
async fn a_cleartext_password_is_never_accepted() {
    for protocol in BOTH {
        let auth = Arc::new(
            AuthState::build(
                &crate::config::AuthConfig {
                    allow_anonymous: false,
                    ..Default::default()
                },
                &UsersConfig {
                    users: vec![user("alice", "pw", None, false)],
                },
                "unused",
            )
            .unwrap(),
        );
        let request = match protocol {
            Protocol::Socks5 => vec![0x05, 0x01, 0x02],
            Protocol::Http => http_connect(Some(&B64.encode("alice:pw"))),
        };
        let response = exchange_raw(auth, &request).await;
        match protocol {
            Protocol::Socks5 => assert_eq!(response, [0x05, 0xFF], "0x02 не выбирается"),
            Protocol::Http => assert!(
                response.starts_with(b"HTTP/1.1 407 "),
                "ожидался 407, получено: {:?}",
                String::from_utf8_lossy(&response)
            ),
        }
    }
}

/// One exchange: the client writes `request` and reads everything until close.
async fn exchange_raw(auth: Arc<AuthState>, request: &[u8]) -> Vec<u8> {
    let logger = test_logger();
    let banned = Arc::new(regex::RegexSet::new([BANNED]).unwrap());
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
    timeout(Duration::from_secs(8), async {
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
            &None,
            Instant::now() + Duration::from_secs(5),
        );
        let leg = async {
            client.write_all(request).await.unwrap();
            let mut response = Vec::new();
            let _ = client.read_to_end(&mut response).await;
            response
        };
        let (handler_res, response) = tokio::join!(handler, leg);
        assert!(handler_res.is_err(), "открытый пароль обязан дать ошибку");
        response
    })
    .await
    .expect("общий таймаут 8с на обмен")
}

/// Case 6: a direct user obeys the filter; a banned IP
/// gets an auth failure BEFORE the direct paths.
/// Counterfactual: remove the user filter — the request would go to the direct branch.
#[tokio::test]
async fn direct_user_denied_before_direct_paths() {
    for protocol in WITH_PASSWORD {
        run_case(Case {
            protocol,
            expect: Expect::AuthFail,
            global_rule: Some("*"),
            users: vec![user("alice", "pw", Some("203.0.113.9"), true)],
            allow_anonymous: false,
            creds: Some(("alice", "pw")),
        })
        .await;
    }
}

/// Case 7: a user with hash='init' and a filter excluding the peer: enrollment
/// yields a plain auth failure; init-claim does NOT happen — the users file on
/// disk is unchanged byte-for-byte.
/// Counterfactual: remove the user filter — the claim would pass, the file would change,
/// the test would fail on the byte comparison and on the outcome.
#[tokio::test]
async fn user_filter_blocks_init_claim() {
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let i = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let path = std::env::temp_dir()
        .join(format!(
            "resocks5_ac_test_users_{}_{}.ktav",
            std::process::id(),
            i
        ))
        .to_string_lossy()
        .into_owned();
    let _ = std::fs::remove_file(&path);

    let users = vec![init_user("bob", Some("203.0.113.9"))];
    // Baseline on disk — as in the auth tests with a persistent file.
    crate::config::users_file::write_atomic(
        std::path::Path::new(&path),
        &UsersConfig {
            users: users.clone(),
        },
    )
    .unwrap();
    let before = std::fs::read(&path).unwrap();

    let auth = Arc::new(
        AuthState::build(
            &crate::config::AuthConfig {
                allow_anonymous: false,
                ..Default::default()
            },
            &UsersConfig { users },
            &path,
        )
        .unwrap(),
    );
    for protocol in BOTH {
        run_case_with_auth(
            &Case {
                protocol,
                expect: Expect::AuthFail,
                global_rule: Some("*"),
                users: Vec::new(), // auth is built separately
                allow_anonymous: false,
                creds: Some(("bob", "first-password")),
            },
            auth.clone(),
        )
        .await;

        // No mutation: the file is byte-for-byte unchanged after EVERY run.
        let after = std::fs::read(&path).unwrap();
        assert_eq!(
            before, after,
            "запрещённый peer не должен инициировать init-claim (файл неизменен)"
        );
    }
    let _ = std::fs::remove_file(&path);
}
