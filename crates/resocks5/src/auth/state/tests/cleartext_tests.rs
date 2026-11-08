//! Clear-text password verification against the SAME stored secret:
//! `PeerStore::check_password` (SOCKS5 0x02 / HTTP Basic path).

use super::*;
use crate::auth::secret::parse_secret;
use resocks5_net::secure_auth::SecretStore as _;

fn disk_hash(path: &str, name: &str) -> String {
    let loaded: UsersConfig = ktav::from_file(path).unwrap();
    loaded
        .users
        .into_iter()
        .find(|u| u.name == name)
        .unwrap()
        .hash
}

fn cleanup(path: &str) {
    let _ = std::fs::remove_file(path);
    let _ = std::fs::remove_file(format!("{path}.lock"));
}

/// Clear text verifies the same stored key secure auth uses.
/// Mutation: deriving with other parameters than the stored ones, or
/// comparing non-constant-time to a different key, fails here.
#[tokio::test]
async fn check_password_verifies_the_same_stored_secret() {
    use resocks5_net::secure_auth::PasswordCheck;
    let (state, path) = build_state_with_disk_file(vec![make_user("alice", "pw", true)]);
    let store = state.peer_store(ip("127.0.0.1"));
    assert!(matches!(
        store.check_password("alice", "pw").await,
        PasswordCheck::Accepted
    ));
    assert!(matches!(
        store.check_password("alice", "wrong").await,
        PasswordCheck::Rejected
    ));
    assert!(matches!(
        store.check_password("nobody", "pw").await,
        PasswordCheck::Rejected
    ));
    cleanup(&path);
}

/// A clear-text login claims an init user, and the claimed secret then
/// works over secure auth too — one secret, both methods. Mutation: the
/// default impl not claiming, or deriving the fresh secret with other
/// params than the SDK's DEFAULT, fails here.
#[tokio::test]
async fn a_clear_text_login_claims_init_and_the_secret_works_over_secure_auth() {
    use resocks5_net::secure_auth::{derive_key, PasswordCheck};
    let (state, path) = build_state_with_disk_file(vec![make_init_user("bob", true)]);
    let store = state.peer_store(ip("127.0.0.1"));
    assert!(matches!(
        store.check_password("bob", "first-pw").await,
        PasswordCheck::Claimed
    ));

    let stored = disk_hash(&path, "bob");
    assert_ne!(stored, INIT_HASH, "the disk hash is no longer the sentinel");
    let secret = parse_secret(&stored).unwrap();
    let expected = derive_key(b"first-pw", &secret.salt, &secret.params).unwrap();
    assert_eq!(secret.key(), &*expected);

    let (c, s) = login(&state, &creds("bob", "first-pw")).await;
    c.unwrap();
    assert_eq!(s.unwrap(), "bob");
    cleanup(&path);
}

/// An empty clear-text password is refused and never claims an init
/// account. Mutation: accepting `""` (or letting it claim) fails here.
#[tokio::test]
async fn an_empty_clear_text_password_is_rejected_and_never_claims() {
    use resocks5_net::secure_auth::PasswordCheck;
    let (state, path) = build_state_with_disk_file(vec![make_init_user("bob", true)]);
    let store = state.peer_store(ip("127.0.0.1"));
    assert!(matches!(
        store.check_password("bob", "").await,
        PasswordCheck::Rejected
    ));
    assert_eq!(disk_hash(&path, "bob"), INIT_HASH);
    cleanup(&path);
}

/// A peer filtered out by the user's `allowed_clients` rule is answered
/// like a wrong password and can never claim. Mutation: a
/// `PeerStore` that skips the rule lets the stranger in or claim.
#[tokio::test]
async fn a_filtered_peer_is_rejected_and_never_claims_via_clear_text() {
    use resocks5_net::secure_auth::PasswordCheck;
    let user = User {
        allowed_clients: Some("203.0.113.9".into()),
        ..make_init_user("bob", true)
    };
    let (state, path) = build_state_with_disk_file(vec![user]);
    let store = state.peer_store(Some("198.51.100.7".parse().unwrap()));
    assert!(matches!(
        store.check_password("bob", "pw").await,
        PasswordCheck::Rejected
    ));
    assert_eq!(disk_hash(&path, "bob"), INIT_HASH);
    cleanup(&path);
}

/// A leftover 0.4.x `hash: gssapi` account has no secret: clear text
/// fails exactly like secure auth (decoy). Mutation: special-casing the
/// `gssapi` value instead of the decoy fails here.
#[tokio::test]
async fn an_unusable_stored_hash_fails_clear_text_like_secure() {
    use resocks5_net::secure_auth::PasswordCheck;
    let user = User {
        hash: "gssapi".into(),
        ..make_user("alice", "unused", true)
    };
    let (state, path) = build_state_with_disk_file(vec![user]);
    let store = state.peer_store(ip("127.0.0.1"));
    assert!(matches!(
        store.check_password("alice", "unused").await,
        PasswordCheck::Rejected
    ));
    cleanup(&path);
}
