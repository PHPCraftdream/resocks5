use super::claim::{Prepared, INIT_HASH};
use super::verify::compute_cache_hmac;
use super::*;
use crate::auth::compute_hash;
use crate::config::User;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

fn make_user(name: &str, password: &str, enabled: bool) -> User {
    User {
        name: name.to_string(),
        hash: compute_hash(password).unwrap(),
        is_enabled: enabled,
        direct: false,
    }
}

fn make_init_user(name: &str, enabled: bool) -> User {
    User {
        name: name.to_string(),
        hash: INIT_HASH.to_string(),
        is_enabled: enabled,
        direct: false,
    }
}

/// Build with a path that is guaranteed never to be touched by the
/// test (because the test does not trigger the init-claim disk
/// write). Used for the non-init-claim tests.
fn build_state(users: Vec<User>, allow_anonymous: bool) -> AuthState {
    AuthState::build(
        &AuthConfig { allow_anonymous },
        &UsersConfig { users },
        "/__resocks5_test_never_written__",
    )
    .unwrap()
}

/// Build with a per-test temp users.ktav path. Returned `String`
/// must be unlinked by the test (the helper does not Drop it for
/// us). Callers that don't trigger disk writes can use
/// `build_state` instead.
fn build_state_persistent(users: Vec<User>, allow_anonymous: bool) -> (AuthState, String) {
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
    // Make sure no leftover file exists from a previous run.
    let _ = std::fs::remove_file(&path);
    let state = AuthState::build(
        &AuthConfig { allow_anonymous },
        &UsersConfig { users },
        path.clone(),
    )
    .unwrap();
    (state, path)
}

/// Like `build_state_persistent`, but also writes the users file to
/// disk first, so the state has an on-disk baseline that a simulated
/// CLI edit can diverge from.
fn build_state_with_disk_file(users: Vec<User>, allow_anonymous: bool) -> (AuthState, String) {
    let (state, path) = build_state_persistent(users.clone(), allow_anonymous);
    crate::config::users_file::write_atomic(Path::new(&path), &UsersConfig { users }).unwrap();
    (state, path)
}

/// R7-04: block until the claim probe delivers `expected`, ignoring
/// any earlier event (seeing `claim_commit_entered` while waiting
/// for `persist_region_entered` is fine — keep looping). Panics with
/// a clear message if the specific event never arrives within
/// `guard`. Guards are sized several SECONDS — well above the worst
/// Argon2id-under-load stretches observed on this machine (hashing
/// degrades from ~15 ms to multiple seconds under concurrent CPU
/// load).
///
/// A slow hash can make an event unreachable rather than merely
/// late, and no guard size fixes that: `prepare_claim` resolves a
/// racer inline when the winner published while it was hashing, so
/// that racer never reaches `claim_commit` and never emits. Callers
/// must keep the winner from publishing until they have observed
/// what they are waiting for — see the signal-driven phase A in
/// `init_claim_racer_rechecks_after_claim_lock_and_does_not_clobber_winner`.
/// Sizing the guard against hashing speed alone is exactly what made
/// that test fail ~50% of the time in a loaded full-suite run.
fn wait_for_claim_event(
    rx: &mut std::sync::mpsc::Receiver<&'static str>,
    expected: &'static str,
    guard: std::time::Duration,
    what: &str,
) {
    let deadline = std::time::Instant::now() + guard;
    loop {
        match rx.recv_timeout(deadline.saturating_duration_since(std::time::Instant::now())) {
            Ok(event) if event == expected => return,
            Ok(_earlier) => {} // a legitimate earlier stage; keep waiting
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                panic!("claim probe: {what} did not happen within {guard:?}")
            }
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                panic!("claim probe: channel closed before {expected:?} ({what})")
            }
        }
    }
}

/// Like `wait_for_claim_event`, but returns after `expected` has
/// arrived `count` times and records EVERY event it received into
/// `sink` along the way.
///
/// Collecting matters whenever a later assertion counts a different
/// event than the awaited one: `persist_region_entered` legitimately
/// interleaves with the two `claim_commit_entered` arrivals, and a
/// plain wait would consume and discard it, leaving the persistence
/// check unable to tell "the winner persisted once" from "nobody
/// persisted at all".
fn collect_claim_events_until(
    rx: &mut std::sync::mpsc::Receiver<&'static str>,
    sink: &mut Vec<&'static str>,
    expected: &'static str,
    count: usize,
    guard: std::time::Duration,
    what: &str,
) {
    let deadline = std::time::Instant::now() + guard;
    let mut seen = 0usize;
    while seen < count {
        match rx.recv_timeout(deadline.saturating_duration_since(std::time::Instant::now())) {
            Ok(event) => {
                sink.push(event);
                if event == expected {
                    seen += 1;
                }
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => panic!(
                "claim probe: {what} did not happen within {guard:?} \
                 (saw {seen} of {count}; events so far: {sink:?})"
            ),
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                panic!("claim probe: channel closed before {expected:?} ({what})")
            }
        }
    }
}

#[test]
fn correct_password_verifies() {
    let state = build_state(vec![make_user("alice", "s3cret", true)], false);
    assert!(state.verify("alice", "s3cret"));
}

#[test]
fn wrong_password_rejects() {
    let state = build_state(vec![make_user("alice", "s3cret", true)], false);
    assert!(!state.verify("alice", "wrong"));
}

#[test]
fn unknown_user_rejects() {
    let state = build_state(vec![make_user("alice", "s3cret", true)], false);
    assert!(!state.verify("bob", "s3cret"));
}

#[test]
fn disabled_user_rejects_even_with_correct_password() {
    let state = build_state(vec![make_user("alice", "s3cret", false)], false);
    assert!(!state.verify("alice", "s3cret"));
}

#[test]
fn shared_password_distinct_hashes() {
    // Per-user random salt: same password produces different PHC strings.
    let h1 = compute_hash("shared").unwrap();
    let h2 = compute_hash("shared").unwrap();
    assert_ne!(h1, h2);
}

#[test]
fn cache_hit_after_first_verify() {
    let state = build_state(vec![make_user("alice", "s3cret", true)], false);
    // First call runs Argon2 + populates cache.
    assert!(state.verify("alice", "s3cret"));
    assert_eq!(state.cache.len(), 1);
    // Second call hits the cache — same answer.
    assert!(state.verify("alice", "s3cret"));
}

#[tokio::test]
async fn cached_async_verify_skips_hashing_slots() {
    let state = Arc::new(build_state(vec![make_user("alice", "secret", true)], false));
    assert!(state.verify("alice", "secret"));
    let slots = u32::try_from(state.verify_slots.available_permits()).unwrap();
    let _all_slots = state
        .verify_slots
        .clone()
        .acquire_many_owned(slots)
        .await
        .unwrap();
    let accepted = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        state.verify_async("alice", "secret"),
    )
    .await
    .unwrap();
    assert!(accepted);
    assert!(!state.verify_async("unknown", "secret").await);
}

#[tokio::test]
async fn uncached_async_verify_waits_for_hashing_slot() {
    use std::future::{poll_fn, Future};
    use std::task::Poll;

    let state = Arc::new(build_state(vec![make_user("alice", "secret", true)], false));
    let slots = u32::try_from(state.verify_slots.available_permits()).unwrap();
    let all_slots = state
        .verify_slots
        .clone()
        .acquire_many_owned(slots)
        .await
        .unwrap();
    let verification = state.verify_async("alice", "secret");
    tokio::pin!(verification);
    poll_fn(|cx| {
        assert!(verification.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;
    assert!(state.cache.is_empty());
    drop(all_slots);
    assert!(verification.await);
    assert!(!state.verify_async("alice", "wrong").await);
    assert_eq!(
        state.verify_slots.available_permits(),
        usize::try_from(slots).unwrap()
    );
}

#[test]
fn malformed_stored_hash_rejects_safely() {
    let bad = User {
        name: "alice".into(),
        hash: "not-a-phc-string".into(),
        is_enabled: true,
        direct: false,
    };
    let state = build_state(vec![bad], false);
    assert!(!state.verify("alice", "anything"));
}

// ─── init-on-first-login claim flow ─────────────────────────────

#[test]
fn init_user_first_login_claims_password() {
    let (state, path) = build_state_persistent(vec![make_init_user("bob", true)], false);
    assert!(state.verify("bob", "first-password"));
    // The in-memory hash is no longer the sentinel.
    {
        let users = state.users.read().unwrap();
        let bob = users.iter().find(|u| u.name == "bob").unwrap();
        assert_ne!(bob.hash, INIT_HASH);
        assert!(bob.hash.starts_with("$argon2id$"));
    }
    let _ = std::fs::remove_file(&path);
}

#[test]
fn init_user_after_claim_same_password_verifies() {
    let (state, path) = build_state_persistent(vec![make_init_user("bob", true)], false);
    assert!(state.verify("bob", "pw1"));
    // Second call now goes the cache-hit fast path (or argon2 if the
    // cache entry is missing) — either way must succeed.
    assert!(state.verify("bob", "pw1"));
    let _ = std::fs::remove_file(&path);
}

#[test]
fn init_user_after_claim_different_password_rejects() {
    let (state, path) = build_state_persistent(vec![make_init_user("bob", true)], false);
    assert!(state.verify("bob", "pw1"));
    assert!(!state.verify("bob", "pw2"));
    let _ = std::fs::remove_file(&path);
}

#[test]
fn init_user_disabled_rejects_without_claiming() {
    let (state, path) = build_state_persistent(vec![make_init_user("bob", false)], false);
    assert!(!state.verify("bob", "anything"));
    // is_enabled=false → we exit before touching the init path, the
    // sentinel must remain in place.
    let users = state.users.read().unwrap();
    let bob = users.iter().find(|u| u.name == "bob").unwrap();
    assert_eq!(bob.hash, INIT_HASH);
    drop(users);
    let _ = std::fs::remove_file(&path);
}

#[test]
fn init_claim_persists_to_disk() {
    let (state, path) = build_state_persistent(vec![make_init_user("bob", true)], false);
    assert!(state.verify("bob", "disk-pw"));

    // Re-load the persisted file from scratch and verify against
    // the password that was used to claim the account.
    let loaded: UsersConfig = ktav::from_file(&path).unwrap();
    let bob = loaded.users.iter().find(|u| u.name == "bob").unwrap();
    assert_ne!(bob.hash, INIT_HASH);
    assert!(bob.hash.starts_with("$argon2id$"));

    let fresh = AuthState::build(
        &AuthConfig {
            allow_anonymous: false,
        },
        &loaded,
        path.clone(),
    )
    .unwrap();
    assert!(fresh.verify("bob", "disk-pw"));
    assert!(!fresh.verify("bob", "other"));

    let _ = std::fs::remove_file(&path);
}

#[test]
fn init_claim_does_not_disturb_other_users() {
    let (state, path) = build_state_persistent(
        vec![
            make_user("alice", "alice-pw", true),
            make_init_user("bob", true),
        ],
        false,
    );
    assert!(state.verify("bob", "bob-pw"));

    let loaded: UsersConfig = ktav::from_file(&path).unwrap();
    let alice = loaded.users.iter().find(|u| u.name == "alice").unwrap();
    let bob = loaded.users.iter().find(|u| u.name == "bob").unwrap();
    assert!(alice.hash.starts_with("$argon2id$"));
    assert!(bob.hash.starts_with("$argon2id$"));
    assert_ne!(bob.hash, INIT_HASH);

    // alice's password must keep working through the persisted file.
    let fresh = AuthState::build(
        &AuthConfig {
            allow_anonymous: false,
        },
        &loaded,
        path.clone(),
    )
    .unwrap();
    assert!(fresh.verify("alice", "alice-pw"));
    assert!(fresh.verify("bob", "bob-pw"));

    let _ = std::fs::remove_file(&path);
}

#[test]
fn init_claim_disk_write_failure_keeps_sentinel() {
    // Path under a non-existent directory → ktav::to_file fails.
    // The verify call must therefore return false AND the in-memory
    // hash must still be "init", so the next attempt can retry.
    let path = std::env::temp_dir()
        .join("resocks5_test_nonexistent_dir_xyz")
        .join("users.ktav")
        .to_string_lossy()
        .into_owned();
    let state = AuthState::build(
        &AuthConfig {
            allow_anonymous: false,
        },
        &UsersConfig {
            users: vec![make_init_user("bob", true)],
        },
        path,
    )
    .unwrap();

    assert!(!state.verify("bob", "anything"));
    let users = state.users.read().unwrap();
    let bob = users.iter().find(|u| u.name == "bob").unwrap();
    assert_eq!(bob.hash, INIT_HASH);
}

#[test]
fn init_claim_concurrent_only_one_winner_with_different_passwords() {
    // Two threads claim "bob" simultaneously with different passwords.
    // Exactly one wins (because the loser falls through to
    // argon2_verify against the winner's hash, fails, and returns
    // false). Run several times because the race ordering is
    // non-deterministic.
    for _ in 0..5 {
        let (state, path) = build_state_persistent(vec![make_init_user("bob", true)], false);
        let state = Arc::new(state);
        let s1 = state.clone();
        let s2 = state.clone();
        let t1 = std::thread::spawn(move || s1.verify("bob", "pwA"));
        let t2 = std::thread::spawn(move || s2.verify("bob", "pwB"));
        let r1 = t1.join().unwrap();
        let r2 = t2.join().unwrap();

        // Exactly one true.
        assert_ne!(r1, r2, "exactly one thread must win the claim race");

        // Hash must no longer be the sentinel.
        let users = state.users.read().unwrap();
        let bob = users.iter().find(|u| u.name == "bob").unwrap();
        assert_ne!(bob.hash, INIT_HASH);
        assert!(bob.hash.starts_with("$argon2id$"));
        drop(users);

        let _ = std::fs::remove_file(&path);
    }
}

#[test]
fn empty_password_cannot_claim_init() {
    let (state, path) = build_state_persistent(vec![make_init_user("bob", true)], false);
    assert!(!state.verify("bob", ""));
    // Rejected before any claim machinery: sentinel intact, no cache
    // entry, no disk write.
    {
        let users = state.users.read().unwrap();
        let bob = users.iter().find(|u| u.name == "bob").unwrap();
        assert_eq!(bob.hash, INIT_HASH);
    }
    assert!(state.cache.is_empty());
    assert!(!Path::new(&path).exists());
    // Same rejection directly through the claim fn, independent of
    // verify()'s framing.
    let hmac = compute_cache_hmac(&state.server_secret, "bob", "");
    assert!(matches!(
        state.prepare_claim("bob", "", hmac),
        Prepared::Done(false)
    ));
    {
        let users = state.users.read().unwrap();
        let bob = users.iter().find(|u| u.name == "bob").unwrap();
        assert_eq!(bob.hash, INIT_HASH);
    }
    // The claim path itself still works.
    assert!(state.verify("bob", "real-pw"));
    let _ = std::fs::remove_file(&path);
}

#[test]
fn empty_password_claim_leaves_existing_disk_file_intact() {
    let (state, path) = build_state_with_disk_file(vec![make_init_user("bob", true)], false);
    let before = std::fs::read_to_string(&path).unwrap();
    assert!(!state.verify("bob", ""));
    let after = std::fs::read_to_string(&path).unwrap();
    assert_eq!(before, after);
    let users = state.users.read().unwrap();
    let bob = users.iter().find(|u| u.name == "bob").unwrap();
    assert_eq!(bob.hash, INIT_HASH);
    drop(users);
    let _ = std::fs::remove_file(&path);
}

#[test]
fn password_length_1_and_255_can_claim_init() {
    for pw in ["x", &"a".repeat(255)] {
        let (state, path) = build_state_persistent(vec![make_init_user("bob", true)], false);
        assert!(state.verify("bob", pw));
        {
            let users = state.users.read().unwrap();
            let bob = users.iter().find(|u| u.name == "bob").unwrap();
            assert!(bob.hash.starts_with("$argon2id$"));
        }
        let loaded: UsersConfig = ktav::from_file(&path).unwrap();
        let bob = loaded.users.iter().find(|u| u.name == "bob").unwrap();
        assert_ne!(bob.hash, INIT_HASH);
        assert!(bob.hash.starts_with("$argon2id$"));
        let _ = std::fs::remove_file(&path);
    }
}

#[test]
fn password_length_256_cannot_claim_init() {
    let (state, path) = build_state_persistent(vec![make_init_user("bob", true)], false);
    let too_long = "a".repeat(256);
    assert_eq!(too_long.len(), 256);
    assert!(!state.verify("bob", &too_long));
    // Rejected before any claim machinery: sentinel intact, no
    // cache entry, no disk write.
    {
        let users = state.users.read().unwrap();
        let bob = users.iter().find(|u| u.name == "bob").unwrap();
        assert_eq!(bob.hash, INIT_HASH);
    }
    assert!(state.cache.is_empty());
    assert!(!Path::new(&path).exists());
    // The claim path itself still works.
    assert!(state.verify("bob", "real-pw"));
    let _ = std::fs::remove_file(&path);
}

#[tokio::test]
async fn password_length_256_cannot_claim_init_async() {
    // The production path (verify_async — both SOCKS5 and HTTP
    // handlers go through it) must refuse to claim an over-255-byte
    // password (R8-04) while the 1..=255 byte bounds keep working.
    // "é" is two bytes in UTF-8, so 128 of them are 128 characters
    // but 256 bytes: the limit is byte length, not char count.
    let pw_1 = "x";
    let pw_255 = "a".repeat(255);
    let pw_255_mixed = format!("{}x", "é".repeat(127));
    let pw_256 = "a".repeat(256);
    let pw_256_mixed = "é".repeat(128);
    let cases: [(&str, bool); 5] = [
        (pw_1, true),
        (pw_255.as_str(), true),
        (pw_255_mixed.as_str(), true),
        (pw_256.as_str(), false),
        (pw_256_mixed.as_str(), false),
    ];
    for (pw, ok) in cases {
        let (state, path) = build_state_persistent(vec![make_init_user("bob", true)], false);
        let state = Arc::new(state);
        assert_eq!(
            state.verify_async("bob", pw).await,
            ok,
            "pw len {}",
            pw.len()
        );
        {
            let users = state.users.read().unwrap();
            let bob = users.iter().find(|u| u.name == "bob").unwrap();
            if ok {
                assert!(bob.hash.starts_with("$argon2id$"));
            } else {
                // Rejected before any claim machinery: sentinel
                // intact, no cache entry, no disk write.
                assert_eq!(bob.hash, INIT_HASH);
            }
        }
        if !ok {
            assert!(state.cache.is_empty());
            assert!(!Path::new(&path).exists());
        }
        let _ = std::fs::remove_file(&path);
    }
}

mod claim_tests;
mod concurrency_tests;
mod gate_tests;
