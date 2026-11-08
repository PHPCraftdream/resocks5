//! The clear-text verified-credential cache in `PeerStore::check_password`:
//! hits skip the Argon2id derivation, failures and expiries do not.

use super::*;
use crate::auth::compute_hash;
use resocks5_net::secure_auth::{PasswordCheck, SecretStore as _};
use std::time::Duration;

/// A right password is accepted (one derivation), and the same pair again
/// is answered from the cache: no second derivation. Mutation: dropping the
/// cache insert on success makes the second login derive again (counter 2).
#[tokio::test]
async fn a_second_login_with_the_same_password_does_not_derive_again() {
    let state = build_state(vec![make_user("alice", "s3cret", true)], false);
    let store = state.peer_store(ip(PEER));
    assert!(matches!(
        store.check_password("alice", "s3cret").await,
        PasswordCheck::Accepted
    ));
    assert_eq!(state.derive_count(), 1);
    assert!(matches!(
        store.check_password("alice", "s3cret").await,
        PasswordCheck::Accepted
    ));
    assert_eq!(state.derive_count(), 1, "cache hit: no second derivation");
}

/// Wrong answers are never cached: both wrong attempts derive, and only
/// then does the right password populate the cache. Mutation: inserting on
/// `Rejected` makes the second wrong attempt a hit (counter 2, not 3).
#[tokio::test]
async fn a_wrong_password_never_populates_the_cache() {
    let state = build_state(vec![make_user("alice", "s3cret", true)], false);
    let store = state.peer_store(ip(PEER));
    for _ in 0..2 {
        assert!(matches!(
            store.check_password("alice", "wrong").await,
            PasswordCheck::Rejected
        ));
    }
    assert!(matches!(
        store.check_password("alice", "s3cret").await,
        PasswordCheck::Accepted
    ));
    assert!(matches!(
        store.check_password("alice", "s3cret").await,
        PasswordCheck::Accepted
    ));
    assert_eq!(state.derive_count(), 3, "both wrongs derived, no more");
}

/// The cached credential is tied to the stored secret's key tag: rewriting
/// the users file with a new hash invalidates the old password's entry.
/// Mutation: dropping the stored-secret-tag match lets the old password be
/// answered `Accepted` from the stale entry (counter stays 1).
#[tokio::test]
async fn changing_the_stored_secret_invalidates_the_cache() {
    let (state, path) = build_state_with_disk_file(vec![make_user("alice", "old-pw", true)]);
    let store = state.peer_store(ip(PEER));
    assert!(matches!(
        store.check_password("alice", "old-pw").await,
        PasswordCheck::Accepted
    ));
    assert_eq!(state.derive_count(), 1);

    let mut cfg: UsersConfig = ktav::from_file(&path).unwrap();
    for user in &mut cfg.users {
        if user.name == "alice" {
            user.hash = compute_hash("new-pw").unwrap();
        }
    }
    crate::config::users_file::write_atomic(Path::new(&path), &cfg).unwrap();
    // Mirror the disk change into the startup snapshot (what a restart
    // would load): the stored secret the cache validates against changes.
    *state.users.write().expect("users RwLock poisoned") = cfg.users;
    // The old password's entry now fails the stored-secret tag match: a
    // real derive runs and the comparison against the NEW key fails.
    assert!(matches!(
        store.check_password("alice", "old-pw").await,
        PasswordCheck::Rejected
    ));
    assert_eq!(state.derive_count(), 2);
    // The new password verifies against the NEW stored secret and is
    // cached like any other success.
    assert!(matches!(
        store.check_password("alice", "new-pw").await,
        PasswordCheck::Accepted
    ));
    assert_eq!(state.derive_count(), 3);
    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(format!("{path}.lock"));
}

/// A cached credential stops being a hit once the TTL has passed: the next
/// login derives again. Mutation: removing the expiry check keeps the
/// second login a cache hit (counter stays 1).
#[tokio::test(start_paused = true)]
async fn a_cached_credential_expires_after_the_ttl() {
    let state = build_state(vec![make_user("alice", "s3cret", true)], false);
    let store = state.peer_store(ip(PEER));
    assert!(matches!(
        store.check_password("alice", "s3cret").await,
        PasswordCheck::Accepted
    ));
    assert_eq!(state.derive_count(), 1);
    // No timers registered so far: the paused clock has not auto-advanced
    // past the TTL.
    tokio::time::advance(
        crate::auth::state::password_cache::PASSWORD_CACHE_TTL + Duration::from_secs(1),
    )
    .await;
    assert!(matches!(
        store.check_password("alice", "s3cret").await,
        PasswordCheck::Accepted
    ));
    assert_eq!(state.derive_count(), 2, "expired entry: derived again");
}

/// The cache never holds more than `PASSWORD_CACHE_CAP` entries and evicts
/// the oldest first. Mutation: removing the cap lets the size grow past it.
#[test]
fn the_cache_is_bounded_and_evicts_oldest() {
    let state = build_state(vec![make_user("alice", "pw", true)], false);
    let cache = &state.password_cache;
    let cap = crate::auth::state::password_cache::PASSWORD_CACHE_CAP;
    for i in 0..(cap + 100) {
        let mut tag = [0u8; 32];
        tag[..8].copy_from_slice(&(i as u64).to_le_bytes());
        cache.insert_dummy(tag);
    }
    assert!(cache.len() <= cap);
    assert!(
        !cache.contains(&{
            let mut t = [0u8; 32];
            t[..8].copy_from_slice(&0u64.to_le_bytes());
            t
        }),
        "oldest evicted"
    );
    assert!(
        cache.contains(&{
            let mut t = [0u8; 32];
            t[..8].copy_from_slice(&((cap + 99) as u64).to_le_bytes());
            t
        }),
        "newest kept"
    );
}
