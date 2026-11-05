use super::*;
use crate::auth::compute_hash;
use crate::auth::test_support::creds;
use crate::config::User;
use resocks5_net::secure_auth::{client_authenticate, server_authenticate, SecureCredentials};
use resocks5_net::SecureAuthError;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

mod claim_tests;

const PEER: &str = "198.51.100.7";

fn make_user(name: &str, password: &str, enabled: bool) -> User {
    user_with_rule(name, password, enabled, None)
}

fn user_with_rule(
    name: &str,
    password: &str,
    enabled: bool,
    allowed_clients: Option<String>,
) -> User {
    User {
        name: name.to_string(),
        hash: compute_hash(password).unwrap(),
        is_enabled: enabled,
        direct: false,
        allowed_clients,
    }
}

fn make_init_user(name: &str, enabled: bool) -> User {
    User {
        name: name.to_string(),
        hash: INIT_HASH.to_string(),
        is_enabled: enabled,
        direct: false,
        allowed_clients: None,
    }
}

/// Build with a path that is never touched (no enrollment happens).
fn build_state(users: Vec<User>, allow_anonymous: bool) -> Arc<AuthState> {
    Arc::new(
        AuthState::build(
            &AuthConfig { allow_anonymous },
            &UsersConfig { users },
            "/__resocks5_test_never_written__",
        )
        .unwrap(),
    )
}

/// Build with a per-test temp users.ktav path (not created). The test
/// removes it.
fn build_state_persistent(users: Vec<User>) -> (Arc<AuthState>, String) {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let i = COUNTER.fetch_add(1, Ordering::Relaxed);
    let path = std::env::temp_dir()
        .join(format!(
            "resocks5_test_users_{}_{}.ktav",
            std::process::id(),
            i,
        ))
        .to_string_lossy()
        .into_owned();
    let _ = std::fs::remove_file(&path);
    let state = AuthState::build(
        &AuthConfig {
            allow_anonymous: false,
        },
        &UsersConfig { users },
        path.clone(),
    )
    .unwrap();
    (Arc::new(state), path)
}

/// Like `build_state_persistent`, with the users file written first.
fn build_state_with_disk_file(users: Vec<User>) -> (Arc<AuthState>, String) {
    let (state, path) = build_state_persistent(users.clone());
    crate::config::users_file::write_atomic(Path::new(&path), &UsersConfig { users }).unwrap();
    (state, path)
}

fn ip(s: &str) -> Option<std::net::IpAddr> {
    Some(s.parse().unwrap())
}

/// One secure-auth exchange from `peer` against `state`: (client, server).
async fn login_from(
    state: &Arc<AuthState>,
    peer: &str,
    credentials: &SecureCredentials,
) -> (Result<(), SecureAuthError>, Result<String, SecureAuthError>) {
    let store = state.peer_store(ip(peer));
    let (client, server) = tokio::io::duplex(4096);
    // Each side drops its half when done, so a side that fails without a
    // reply does not leave the other waiting.
    tokio::join!(
        async move {
            let mut client = client;
            client_authenticate(&mut client, credentials).await
        },
        async move {
            let mut server = server;
            server_authenticate(&mut server, &store, state.decoy()).await
        },
    )
}

async fn login(
    state: &Arc<AuthState>,
    credentials: &SecureCredentials,
) -> (Result<(), SecureAuthError>, Result<String, SecureAuthError>) {
    login_from(state, PEER, credentials).await
}

/// Both sides agree the login was denied.
fn assert_denied(
    (c, s): (Result<(), SecureAuthError>, Result<String, SecureAuthError>),
    what: &str,
) {
    assert_eq!(c, Err(SecureAuthError::Denied), "client side: {what}");
    assert_eq!(s, Err(SecureAuthError::Denied), "server side: {what}");
}

#[tokio::test]
async fn the_right_password_logs_in_as_the_user() {
    let state = build_state(vec![make_user("alice", "s3cret", true)], false);
    let (c, s) = login(&state, &creds("alice", "s3cret")).await;
    c.unwrap();
    assert_eq!(s.unwrap(), "alice");
}

/// Wrong password, unknown, disabled and unusable-hash users all fail the
/// same way (the decoy). Mutation: answering an unknown name with a refusal
/// instead of the decoy, or skipping the enabled check, fails a row.
#[tokio::test]
async fn every_rejection_looks_like_a_wrong_password() {
    let state = build_state(
        vec![
            make_user("alice", "s3cret", true),
            make_user("bob", "s3cret", false),
            User {
                hash: "plain-text-password".into(),
                ..make_user("carol", "unused", true)
            },
        ],
        false,
    );
    for (user, what) in [
        ("alice", "wrong password"),
        ("bob", "disabled"),
        ("carol", "unusable hash"),
        ("dave", "unknown"),
    ] {
        let password = if user == "alice" { "wrong" } else { "s3cret" };
        assert_denied(login(&state, &creds(user, password)).await, what);
    }
}

/// A hash written by the old password-verify code logs in through secure
/// auth with the same password: existing accounts keep working. Mutation:
/// re-deriving with other parameters than the stored ones fails the login.
#[tokio::test]
async fn an_old_argon2_hash_logs_in_unchanged() {
    use argon2::password_hash::{PasswordHasher, SaltString};
    let salt = SaltString::encode_b64(&[3u8; 16]).unwrap();
    let old = argon2::Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        argon2::Params::new(64, 1, 1, None).unwrap(),
    )
    .hash_password(b"old-password", &salt)
    .unwrap()
    .to_string();
    let state = build_state(
        vec![User {
            hash: old,
            ..make_user("alice", "unused", true)
        }],
        false,
    );
    let (c, s) = login(&state, &creds("alice", "old-password")).await;
    c.unwrap();
    assert_eq!(s.unwrap(), "alice");
}

/// The per-user `allowed_clients` rule applies per connection: the same
/// password is denied from a peer outside the rule. Mutation: a
/// `PeerStore::lookup` that skips the rule logs the peer in.
#[tokio::test]
async fn a_peer_outside_the_user_rule_is_denied() {
    let state = build_state(
        vec![user_with_rule(
            "alice",
            "s3cret",
            true,
            Some("10.*.0.1".into()),
        )],
        false,
    );
    let (c, s) = login_from(&state, "10.9.0.1", &creds("alice", "s3cret")).await;
    c.unwrap();
    s.unwrap();
    assert_denied(
        login_from(&state, "10.9.0.2", &creds("alice", "s3cret")).await,
        "peer outside the rule",
    );
}

#[test]
fn shared_password_distinct_secrets() {
    // Per-user random salt: same password produces different secrets.
    let h1 = compute_hash("shared").unwrap();
    let h2 = compute_hash("shared").unwrap();
    assert_ne!(h1, h2);
}

/// The stored secret never contains the password, in any encoding the
/// file could show it. Mutation: storing the password next to the key
/// fails here.
#[test]
fn a_stored_secret_does_not_contain_the_password() {
    let password = "visible-password-123";
    let stored = compute_hash(password).unwrap();
    assert!(!stored.contains(password));
    use base64::Engine as _;
    for engine in [
        base64::engine::general_purpose::STANDARD_NO_PAD,
        base64::engine::general_purpose::STANDARD,
    ] {
        assert!(!stored.contains(&engine.encode(password)));
    }
}

// ─── allowed_clients: пользовательский фильтр ───────────────────────

/// `None` у пользователя не ограничивает IP.
#[test]
fn user_rule_none_does_not_restrict() {
    let state = build_state(vec![make_user("alice", "s3cret", true)], false);
    assert!(state.client_ip_allowed("alice", ip("203.0.113.7")));
    assert!(state.client_ip_allowed("alice", ip("::1")));
}

/// Пользовательское правило применяется; disabled/unknown → false.
#[test]
fn user_rule_and_disabled_unknown_semantics() {
    let state = build_state(
        vec![
            user_with_rule("alice", "s3cret", true, Some("10.*.0.1".into())),
            user_with_rule("bob", "s3cret", false, None),
        ],
        false,
    );
    assert!(state.client_ip_allowed("alice", ip("10.9.0.1")));
    assert!(!state.client_ip_allowed("alice", ip("10.9.0.2")));
    assert!(!state.client_ip_allowed("bob", ip("10.9.0.1")));
    assert!(!state.client_ip_allowed("carol", ip("10.9.0.1")));
    // Недоступный адрес — fail-closed.
    assert!(!state.client_ip_allowed("alice", None));
}

/// Невалидная строка у DISABLED пользователя валит build (старт).
#[test]
fn disabled_user_invalid_rule_fails_build() {
    let res = AuthState::build(
        &AuthConfig {
            allow_anonymous: false,
        },
        &UsersConfig {
            users: vec![user_with_rule(
                "alice",
                "s3cret",
                false,
                Some("10.*.0".into()),
            )],
        },
        "/__resocks5_test_never_written__",
    );
    let err = res
        .err()
        .expect("invalid rule of a disabled user must fail startup");
    assert!(err.to_string().contains("alice"), "got: {err}");
}

/// Дубликат имени с невалидной строкой тоже валит build.
#[test]
fn duplicate_user_invalid_rule_fails_build() {
    let res = AuthState::build(
        &AuthConfig {
            allow_anonymous: false,
        },
        &UsersConfig {
            users: vec![
                make_user("alice", "s3cret", true),
                user_with_rule("alice", "other", true, Some("no-such-host".into())),
            ],
        },
        "/__resocks5_test_never_written__",
    );
    assert!(res.is_err());
}

/// First-wins для дубликатов имени: действует ПЕРВОЕ вхождение — и его
/// правило, и его секрет.
#[tokio::test]
async fn duplicate_names_keep_the_first_entry() {
    let state = build_state(
        vec![
            user_with_rule("alice", "first", true, Some("10.1.1.1".into())),
            user_with_rule("alice", "second", true, None),
        ],
        false,
    );
    assert!(state.client_ip_allowed("alice", ip("10.1.1.1")));
    assert!(!state.client_ip_allowed("alice", ip("203.0.113.7")));
    let (c, _) = login_from(&state, "10.1.1.1", &creds("alice", "first")).await;
    c.unwrap();
    assert_denied(
        login_from(&state, "10.1.1.1", &creds("alice", "second")).await,
        "the duplicate's password",
    );
}

#[test]
fn is_direct_follows_enabled_and_direct() {
    let direct = User {
        direct: true,
        ..make_user("alice", "pw", true)
    };
    let disabled_direct = User {
        direct: true,
        ..make_user("carol", "pw", false)
    };
    let state = build_state(
        vec![direct, make_user("bob", "pw", true), disabled_direct],
        false,
    );
    assert!(state.is_direct("alice"));
    assert!(!state.is_direct("bob"), "pool user");
    assert!(!state.is_direct("carol"), "disabled direct user");
    assert!(!state.is_direct("dave"), "unknown user");
}

#[test]
fn counts_include_init_placeholders() {
    let state = build_state(
        vec![make_user("alice", "pw", true), make_init_user("bob", true)],
        false,
    );
    assert_eq!(state.users_count(), 2);
    assert!(!state.is_empty());
    assert!(build_state(Vec::new(), true).is_empty());
}
