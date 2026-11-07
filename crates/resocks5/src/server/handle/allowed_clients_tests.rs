//! Regression tests of the allowed_clients AND-cascade via the shared
//! `handle_client`: real TCP exchanges, without calling `client_ip_allowed`
//! directly and without mocking the matcher.
//!
//! Observable boundary without an external upstream: rotators = None, target
//! `blocked.invalid:443` banned by the banned-regex → an allowed client
//! gets 403 (HTTP) / SOCKS reply `Forbidden` ([5,2,…]); a disallowed one —
//! a plain auth failure (407 / [1,1]) or a close without a single byte.

use std::sync::Arc;
use std::time::Duration;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use super::handle_client::handle_client;
use crate::auth::AuthState;
use crate::config::{AllowedClients, NetworkConfig, TlsFragmentConfig, User, UsersConfig};
use resocks5_net::chain::GateLevels;
use resocks5_net::rotator::ProxyRotator;
use resocks5_net::server::ServerError;
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
    /// A plain auth failure: [1,1] / 407.
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

/// Build AuthState and run one exchange; return the auth for cache checks.
/// The network part runs in [`run_case_with_auth`].
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
            &crate::config::AuthConfig { allow_anonymous },
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

/// Same with an already built AuthState (cache warm-up, persistent users
/// file).
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
            client.write_all(&[0x05, 0x01, 0x02]).await.unwrap();
            let mut method = [0u8; 2];
            client.read_exact(&mut method).await.unwrap();
            assert_eq!(method, [0x05, 0x02]);
            let (u, p) = c.creds.expect("AuthFail-кейс требует credentials");
            client.write_all(&subnegotiation(u, p)).await.unwrap();
            let mut verdict = [0u8; 2];
            client.read_exact(&mut verdict).await.unwrap();
            assert_eq!(verdict, [0x01, 0x01], "аутентификация обязана отказать");
            // The server closes the connection after rejection: accept only
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
                client.write_all(&[0x05, 0x01, 0x02]).await.unwrap();
                let mut method = [0u8; 2];
                client.read_exact(&mut method).await.unwrap();
                assert_eq!(method, [0x05, 0x02]);
                client.write_all(&subnegotiation(u, p)).await.unwrap();
                let mut verdict = [0u8; 2];
                client.read_exact(&mut verdict).await.unwrap();
                assert_eq!(verdict, [0x01, 0x00], "валидные credentials обязаны пройти");
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
            let token = c.creds.map(|(u, p)| B64.encode(format!("{u}:{p}")));
            client
                .write_all(&http_connect(token.as_deref()))
                .await
                .unwrap();
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

fn subnegotiation(user: &str, pass: &str) -> Vec<u8> {
    let mut out = vec![0x01, user.len() as u8];
    out.extend_from_slice(user.as_bytes());
    out.push(pass.len() as u8);
    out.extend_from_slice(pass.as_bytes());
    out
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

/// Case 1a: global deny is stronger than a permissive user.
/// The client sends nothing; with the global filter removed there would be
/// no 403/407 — the handler would hang until the protocol timeout, and the
/// test would fail on the shared timeout or another error outcome.
#[tokio::test]
async fn global_deny_beats_permissive_user() {
    for protocol in BOTH {
        let auth = run_case(Case {
            protocol,
            expect: Expect::GlobalDeny,
            global_rule: Some("203.0.113.7"),
            users: vec![user("alice", "pw", None, false)],
            allow_anonymous: false,
            creds: Some(("alice", "pw")),
        })
        .await;
        assert!(
            !auth.cache_contains("alice"),
            "запрещённый peer не должен доходить до verify (кеш пуст)"
        );
    }
}

/// Case 1b: user-deny with a global `*` — a plain auth failure.
/// Without the user filter SOCKS5 would return the success verdict [1,0]
/// instead of [1,1], and HTTP would reach 403 instead of the 407 refusal.
#[tokio::test]
async fn user_deny_beats_global_star() {
    for protocol in BOTH {
        let auth = run_case(Case {
            protocol,
            expect: Expect::AuthFail,
            global_rule: Some("*"),
            users: vec![user("alice", "pw", Some("203.0.113.9"), false)],
            allow_anonymous: false,
            creds: Some(("alice", "pw")),
        })
        .await;
        assert!(
            !auth.cache_contains("alice"),
            "фильтр обязан сработать ДО verify: кеш паролей не заполняется"
        );
    }
}

/// Cases 1c and 3: global allow + user None → reach the routing
/// boundary (banned target → 403/Forbidden); None does not restrict.
/// Counterfactual: a filter falsely banning loopback — would give [1,1]/407
/// or a close.
#[tokio::test]
async fn global_allow_and_user_none_reach_routing_boundary() {
    for protocol in BOTH {
        let auth = run_case(Case {
            protocol,
            expect: Expect::RouteBanned,
            global_rule: Some("loopback"),
            users: vec![user("alice", "pw", None, false)],
            allow_anonymous: false,
            creds: Some(("alice", "pw")),
        })
        .await;
        assert!(
            auth.cache_contains("alice"),
            "успешный verify обязан прогреть кеш паролей"
        );
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

/// Case 5: a warmed password cache is not bypassed by the user filter. The
/// warm-up is a direct `verify_async` without an IP binding; this checks that
/// the filter fires BEFORE the cache hit on an exchange from a forbidden
/// peer.
#[tokio::test]
async fn warm_cache_does_not_bypass_user_filter() {
    let auth = Arc::new(
        AuthState::build(
            &crate::config::AuthConfig {
                allow_anonymous: false,
            },
            &UsersConfig {
                users: vec![user("alice", "pw", Some("203.0.113.9"), false)],
            },
            "unused",
        )
        .unwrap(),
    );
    // Прогрев: hash известен, пароль в кеше.
    assert!(auth.verify_async("alice", "pw").await);
    assert!(auth.cache_contains("alice"));

    for protocol in BOTH {
        run_case_with_auth(
            &Case {
                protocol,
                expect: Expect::AuthFail,
                global_rule: Some("*"),
                users: Vec::new(), // auth is built separately
                allow_anonymous: false,
                creds: Some(("alice", "pw")),
            },
            auth.clone(),
        )
        .await;
    }
    // The filter refused, not a failed verify: the cache is still in place.
    assert!(
        auth.cache_contains("alice"),
        "прогретый кеш не должен быть испорчен"
    );
}

/// Case 6: a direct user obeys the filter; a banned IP
/// gets an auth failure BEFORE the direct paths.
/// Counterfactual: remove the user filter — the request would go to the direct branch.
#[tokio::test]
async fn direct_user_denied_before_direct_paths() {
    for protocol in BOTH {
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

/// Case 7: a user with hash='init' and a filter excluding the peer:
/// valid-looking credentials give a plain auth failure; the init-claim does
/// NOT happen — the users file on disk is unchanged byte-for-byte, the cache
/// is not filled.
/// Counterfactual: remove the user filter — the claim would pass, the file
/// would change, the test would fail on the byte comparison and on the
/// outcome.
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
        assert!(!auth.cache_contains("bob"));
    }
    let _ = std::fs::remove_file(&path);
}
