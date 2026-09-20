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
/// load) — so the timeout fires only when the event is genuinely
/// missing (seam removed or guarded region restructured), never
/// because hashing was slow.
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

// ─── is_direct tests ─────────────────────────────────────────────

#[test]
fn is_direct_true_for_enabled_direct_user() {
    let user = User {
        name: "direct_alice".to_string(),
        hash: compute_hash("pw").unwrap(),
        is_enabled: true,
        direct: true,
    };
    let state = build_state(vec![user], false);
    assert!(state.is_direct("direct_alice"));
}

#[test]
fn is_direct_false_for_pool_user() {
    let state = build_state(vec![make_user("alice", "pw", true)], false);
    assert!(!state.is_direct("alice"));
}

#[test]
fn is_direct_false_for_disabled_direct_user() {
    let user = User {
        name: "disabled_alice".to_string(),
        hash: compute_hash("pw").unwrap(),
        is_enabled: false,
        direct: true,
    };
    let state = build_state(vec![user], false);
    assert!(!state.is_direct("disabled_alice"));
}

#[test]
fn is_direct_false_for_unknown_user() {
    let state = build_state(vec![make_user("alice", "pw", true)], false);
    assert!(!state.is_direct("unknown"));
}

#[test]
fn init_claim_concurrent_same_password_both_win() {
    // Two threads claim "bob" with the SAME password. Whichever
    // wins the write lock first records the hash; the loser falls
    // through to argon2_verify, which succeeds (same password) so
    // both return true.
    let (state, path) = build_state_persistent(vec![make_init_user("bob", true)], false);
    let state = Arc::new(state);
    let s1 = state.clone();
    let s2 = state.clone();
    let t1 = std::thread::spawn(move || s1.verify("bob", "samepw"));
    let t2 = std::thread::spawn(move || s2.verify("bob", "samepw"));
    let r1 = t1.join().unwrap();
    let r2 = t2.join().unwrap();
    assert!(r1 && r2);
    let _ = std::fs::remove_file(&path);
}

#[test]
fn init_claim_racer_rechecks_after_claim_lock_and_does_not_clobber_winner() {
    // R6-01: two concurrent logins with the SAME correct password.
    // A helper thread pins the cross-process users-file lock in two
    // phases. Phase A (3 s) parks the first claimer inside
    // persist_claim, so the second login queues on claim_lock behind
    // it and both pass the pre-mutex init check. Phase B starts 5 s
    // after A is released — the winner only needs to notice the file
    // lock is free and grab it sometime in that window, which costs
    // real milliseconds once scheduled, but this machine can see
    // multi-second scheduling latency under heavy concurrent CPU
    // load from sibling cargo processes (same class as the Argon2id
    // degradation noted elsewhere in this file); a 200 ms gap was
    // observed to let the external holder win that race under load,
    // pushing the winner itself into a doomed persist attempt. Phase
    // B then holds for 11 s — one second past persist_claim's 10 s
    // UsersFileLock LOCK_TIMEOUT — so any persistence attempt by the
    // loser would time out exactly like the review's "another
    // process holds the lock past its timeout" scenario. The fixed
    // loser must re-check the init state AFTER acquiring claim_lock,
    // verify against the winner's hash, and return without ever
    // entering persistence.
    // The deterministic companion test below scripts the winner's commit directly.
    use std::sync::mpsc;
    use std::time::{Duration, Instant};

    let (mut state, path) = build_state_persistent(vec![make_init_user("bob", true)], false);
    let (claim_tx, mut claim_rx) = mpsc::channel::<&'static str>();
    state.install_claim_probe(claim_tx);
    let state = Arc::new(state);

    let (locked_tx, locked_rx) = mpsc::channel::<()>();
    let holder_path = path.clone();
    let holder = std::thread::spawn(move || {
        let phase_a =
            UsersFileLock::acquire_with_timeout(Path::new(&holder_path), Duration::from_secs(5))
                .expect("holder must acquire the users-file lock (phase A)");
        locked_tx.send(()).expect("signal phase-A lock held");
        std::thread::sleep(Duration::from_secs(3));
        drop(phase_a); // the winner's persist completes in the gap below
        std::thread::sleep(Duration::from_secs(5));
        let phase_b =
            UsersFileLock::acquire_with_timeout(Path::new(&holder_path), Duration::from_secs(5))
                .expect("holder must re-acquire the users-file lock (phase B)");
        let _ = &phase_b;
        // Held past persist_claim's 10 s LOCK_TIMEOUT: a persistence
        // attempt in this window cannot succeed. The fixed loser
        // never attempts one; this hold only makes the pre-fix
        // failure mode (persist Failed → sentinel reset → winner
        // clobbered) slow and loud if the re-check ever regresses.
        std::thread::sleep(Duration::from_secs(11));
    });
    locked_rx.recv().expect("phase-A lock held");

    // Detached on purpose: the 11 s phase-B hold only matters for
    // the counterfactual persistence attempt; the fixed path is done
    // in ~3.5 s and joining would pay that hold on every test run.
    // The unique per-test path keeps the pin invisible to other
    // tests; the OS releases the lock when the process exits.
    drop(holder);

    let s1 = Arc::clone(&state);
    let s2 = Arc::clone(&state);
    let t1 = std::thread::spawn(move || {
        let started = Instant::now();
        (s1.verify("bob", "same-pw"), started.elapsed())
    });
    let t2 = std::thread::spawn(move || {
        let started = Instant::now();
        (s2.verify("bob", "same-pw"), started.elapsed())
    });
    // R7-04: anchor to the probe, not to hope. BOTH racers must
    // reach claim_commit — each emits claim_commit_entered as the
    // first statement of claim_commit, so a racer that resolved via
    // the pre-mutex fast path (its hashing finished only after the
    // winner had already committed) never emits a second event and
    // the second wait fails loudly instead of letting the test pass
    // without ever exercising the post-mutex re-check. The winner's
    // persist_region_entered may legitimately arrive between the two
    // events and is ignored here. Guards are 15 s: each arrival
    // requires one real Argon2id hash, which stretches to multiple
    // seconds under concurrent CPU load (see the machine-load note),
    // and the loser must additionally land while the winner is
    // parked in persist_claim (phase A pins the users-file lock for
    // 3 s).
    wait_for_claim_event(
        &mut claim_rx,
        "claim_commit_entered",
        Duration::from_secs(15),
        "the first claimant reaching claim_commit",
    );
    wait_for_claim_event(
        &mut claim_rx,
        "claim_commit_entered",
        Duration::from_secs(15),
        "the second claimant reaching claim_commit (it must queue on \
         claim_lock, not resolve via the pre-mutex fast path)",
    );
    let (r1, e1) = t1.join().unwrap();
    let (r2, e2) = t2.join().unwrap();
    assert!(r1, "the winning login must succeed");
    assert!(r2, "the loser must verify against the winner's hash");

    // Timing bound (Argon2id on loaded machines can degrade from
    // ~15 ms to multiple seconds — see the machine-load note):
    // ANY persistence detour costs at least phase A (3 s, queued on
    // claim_lock or parked on the file lock) plus the 10 s
    // LOCK_TIMEOUT against the phase-B pin — a ≥13 s floor — so
    // <12 s total proves no persistence attempt was made, while
    // still allowing each of the two Argon2id operations ~4 s under
    // heavy CPU load. The final-state asserts below are the
    // authoritative clobber check; this bound is the fast companion.
    assert!(e1 < Duration::from_secs(12), "winner elapsed {e1:?}");
    assert!(
        e2 < Duration::from_secs(12),
        "loser elapsed {e2:?} — looks like it entered persistence and \
         waited out the pinned users-file lock"
    );

    // Final state: the winner's commit is intact everywhere and
    // memory, disk and cache agree on one and the same hash.
    let winner_hash = {
        let users = state.users.read().unwrap();
        let bob = users.iter().find(|u| u.name == "bob").unwrap();
        assert!(
            bob.hash.starts_with("$argon2id$"),
            "winner's committed hash must not be reset to the sentinel, got {:?}",
            bob.hash
        );
        bob.hash.clone()
    };
    let loaded: UsersConfig = ktav::from_file(&path).unwrap();
    let bob = loaded.users.iter().find(|u| u.name == "bob").unwrap();
    assert_eq!(bob.hash, winner_hash, "disk and memory must agree");
    assert!(
        state.verify("bob", "same-pw"),
        "winner hash must still verify"
    );
    assert!(
        state.cache_matches(
            "bob",
            &compute_cache_hmac(&state.server_secret, "bob", "same-pw")
        ),
        "cache must hold the entry for the winning password"
    );

    // A fresh state on the persisted file accepts the same password:
    // both logins verified against one and the same winning hash.
    let fresh = AuthState::build(
        &AuthConfig {
            allow_anonymous: false,
        },
        &loaded,
        path.clone(),
    )
    .unwrap();
    assert!(fresh.verify("bob", "same-pw"));

    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(format!("{}.lock", path));
}

#[test]
fn init_claim_persist_failure_after_winner_cannot_reset_winner_hash() {
    // R6-01, deterministic variant. A real two-thread race cannot
    // reliably expose the pre-fix bug: the loser's persist enters
    // only after the winner released the file lock, so on a fast
    // machine it slips in, sees the winner's hash on disk, and
    // returns via DiskHashChanged without any clobber. Here the
    // winner's committed state (memory + disk) is scripted directly
    // while the racer is parked on claim_lock, and the cross-process
    // users-file lock is pinned continuously for longer than
    // persist_claim's 10 s UsersFileLock LOCK_TIMEOUT from before
    // the racer can reach persistence — so a pre-fix racer (no
    // post-mutex re-check) deterministically blocks for the full
    // 10 s, fails, and returns false, while the fixed racer
    // re-checks after the mutex and never touches persistence.
    use std::sync::mpsc;
    use std::time::{Duration, Instant};

    let (mut state, path) = build_state_with_disk_file(vec![make_init_user("bob", true)], false);
    let (claim_tx, mut claim_rx) = mpsc::channel::<&'static str>();
    state.install_claim_probe(claim_tx);
    let state = Arc::new(state);
    let winner_hash = compute_hash("winner-pw").unwrap();

    // Pin the users-file lock continuously, well past the 10 s
    // persist LOCK_TIMEOUT, for the whole scenario.
    let (locked_tx, locked_rx) = mpsc::channel::<()>();
    let holder_path = path.clone();
    let holder = std::thread::spawn(move || {
        let lock =
            UsersFileLock::acquire_with_timeout(Path::new(&holder_path), Duration::from_secs(5))
                .expect("holder must acquire the users-file lock");
        locked_tx.send(()).expect("signal lock held");
        std::thread::sleep(Duration::from_secs(14));
        let _ = &lock;
    });
    locked_rx.recv().expect("users-file lock pinned");

    // Hold claim_lock from before the racer starts so the racer is
    // guaranteed to park on this mutex right after its pre-mutex
    // init check. R7-04: wait for the probe event proving the racer
    // actually REACHED claim_commit — its first statement emits
    // claim_commit_entered — instead of sleeping a fixed 2 s and
    // hoping its Argon2id hashing finished: under real CPU load that
    // stretch is seconds, not the ~15 ms nominal, so no fixed sleep
    // can prove arrival. The parent still holds claim_lock here, so
    // after the event the racer is necessarily parked on the mutex
    // and cannot pass the post-mutex re-check until the winner's
    // state is injected and this guard is dropped. 15 s guard: the
    // arrival needs one real Argon2id hash (see the machine-load
    // note).
    let claim_guard = state.claim_lock.lock().expect("claim mutex poisoned");
    let racer_state = Arc::clone(&state);
    let racer = std::thread::spawn(move || {
        let started = Instant::now();
        (racer_state.verify("bob", "winner-pw"), started.elapsed())
    });
    wait_for_claim_event(
        &mut claim_rx,
        "claim_commit_entered",
        Duration::from_secs(15),
        "the racer reaching claim_commit (past its pre-mutex check)",
    );

    // Script the winner's commit exactly as the Written branch would
    // leave it: real hash in memory and on disk. The cache is
    // deliberately left empty — populating it is part of what the
    // racer's claimed-hash path must do.
    {
        let mut users = state.users.write().unwrap();
        let bob = users.iter_mut().find(|u| u.name == "bob").unwrap();
        bob.hash = winner_hash.clone();
    }
    ktav::to_file(
        &UsersConfig {
            users: vec![User {
                name: "bob".into(),
                hash: winner_hash.clone(),
                is_enabled: true,
                direct: false,
            }],
        },
        &path,
    )
    .unwrap();

    drop(claim_guard); // let the racer into the claim critical section

    let (racer_ok, racer_elapsed) = racer.join().unwrap();
    assert!(racer_ok, "racer must verify against the winner's hash");
    // R7-04 negative check: the racer's claim_commit_entered was
    // already consumed by the wait above, so after the winner-state
    // injection and the re-check resolution the probe channel must
    // hold NOTHING — in particular no persist_region_entered, which
    // would mean the racer entered persistence for a hash it never
    // published.
    assert!(
        matches!(claim_rx.try_recv(), Err(mpsc::TryRecvError::Empty)),
        "racer emitted a further claim event after the winner-state \
         injection — it entered the guarded persist region"
    );
    // Any persistence attempt blocks ≥10 s against the pinned lock
    // (persist_claim → UsersFileLock::acquire → LOCK_TIMEOUT), so a
    // sub-9 s total proves the racer never entered persistence. The
    // bound sits in the ~8 s class on purpose (see the machine-load
    // note): the fixed path runs TWO real Argon2id operations (the
    // candidate hash and the verify against the winner's hash), and
    // each has been observed to stretch into multiple seconds under
    // concurrent CPU load — the bound is a generous safety margin,
    // while the probe assertions above are the discriminator. The
    // final-state asserts below are authoritative.
    assert!(
        racer_elapsed < Duration::from_secs(9),
        "racer elapsed {racer_elapsed:?} — it entered persistence and \
         waited out the pinned users-file lock"
    );

    // The winner's commit is intact everywhere: memory hash not
    // reset to the sentinel, disk untouched, and the cache now holds
    // the winning password's entry — populated by the racer's
    // claimed-hash verify path.
    {
        let users = state.users.read().unwrap();
        let bob = users.iter().find(|u| u.name == "bob").unwrap();
        assert_eq!(
            bob.hash, winner_hash,
            "winner's committed hash must not be reset to the sentinel"
        );
    }
    let loaded: UsersConfig = ktav::from_file(&path).unwrap();
    assert_eq!(loaded.users[0].hash, winner_hash, "disk must be untouched");
    assert!(
        state.cache_matches(
            "bob",
            &compute_cache_hmac(&state.server_secret, "bob", "winner-pw")
        ),
        "cache must hold the winning password's entry"
    );

    // Detached on purpose (same reasoning as the concurrent racer
    // test above): the remaining pin hold only matters for the
    // pre-fix counterfactual.
    drop(holder);

    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(format!("{}.lock", path));
}

#[test]
fn init_claim_into_missing_file_writes_full_fallback_list() {
    // R6-05: the fallback snapshot is now built only for the
    // missing-file branch, after claim_lock and the post-mutex
    // re-check — but the branch's content contract is unchanged:
    // creating the file writes the caller's FULL in-memory list
    // (with the claimed hash applied), not just the claimed user.
    let (state, path) = build_state_persistent(
        vec![
            make_user("alice", "alice-pw", true),
            make_init_user("bob", true),
        ],
        false,
    );
    assert!(!Path::new(&path).exists());
    assert!(state.verify("bob", "bob-pw"));

    let loaded: UsersConfig = ktav::from_file(&path).unwrap();
    assert_eq!(loaded.users.len(), 2, "fallback must carry every user");
    let alice = loaded.users.iter().find(|u| u.name == "alice").unwrap();
    assert!(
        alice.hash.starts_with("$argon2id$"),
        "alice's real hash must survive the first-claim file creation"
    );
    let bob = loaded.users.iter().find(|u| u.name == "bob").unwrap();
    assert_ne!(bob.hash, INIT_HASH);
    assert!(bob.hash.starts_with("$argon2id$"));
    // Both accounts work against the freshly created file.
    assert!(state.verify("alice", "alice-pw"));

    let _ = std::fs::remove_file(&path);
}

// ─── cross-process safety: CLI edits vs init-claim (R13) ────────

#[test]
fn init_claim_preserves_concurrent_cli_edit_to_other_users() {
    // Server snapshot is [alice enabled, bob init]; a CLI process
    // then disables alice and adds carol ON DISK; finally bob
    // claims. The claim must merge into the on-disk truth, not
    // overwrite it with the stale snapshot.
    let baseline = vec![
        make_user("alice", "alice-pw", true),
        make_init_user("bob", true),
    ];
    let (state, path) = build_state_with_disk_file(baseline.clone(), false);

    // Simulated CLI edit (separate process writing the file).
    let cli_edit = vec![
        User {
            is_enabled: false,
            ..baseline[0].clone()
        },
        make_init_user("bob", true),
        make_init_user("carol", true),
    ];
    ktav::to_file(&UsersConfig { users: cli_edit }, &path).unwrap();

    assert!(state.verify("bob", "bob-pw"));

    let loaded: UsersConfig = ktav::from_file(&path).unwrap();
    assert_eq!(loaded.users.len(), 3, "CLI-added user must survive");
    let alice = loaded.users.iter().find(|u| u.name == "alice").unwrap();
    assert!(!alice.is_enabled, "CLI disable must survive the claim");
    let carol = loaded.users.iter().find(|u| u.name == "carol").unwrap();
    assert_eq!(carol.hash, INIT_HASH);
    let bob = loaded.users.iter().find(|u| u.name == "bob").unwrap();
    assert_ne!(bob.hash, INIT_HASH);
    assert!(bob.hash.starts_with("$argon2id$"));

    // A server restarted on the merged file sees the CLI's edits too.
    let fresh = AuthState::build(
        &AuthConfig {
            allow_anonymous: false,
        },
        &loaded,
        path.clone(),
    )
    .unwrap();
    assert!(fresh.verify("bob", "bob-pw"));
    assert!(
        !fresh.verify("alice", "alice-pw"),
        "alice must still be disabled on disk"
    );

    let _ = std::fs::remove_file(&path);
}

#[test]
fn init_claim_yields_to_cli_password_change_for_same_user() {
    // R13, same-user variant: the CLI set a real password for bob
    // while the server still believed bob was unclaimed. The claim
    // must adopt the on-disk hash, not overwrite it.
    let (state, path) = build_state_with_disk_file(vec![make_init_user("bob", true)], false);
    let cli_hash = compute_hash("cli-pw").unwrap();
    ktav::to_file(
        &UsersConfig {
            users: vec![User {
                name: "bob".into(),
                hash: cli_hash.clone(),
                is_enabled: true,
                direct: false,
            }],
        },
        &path,
    )
    .unwrap();

    // The client submits the password the CLI installed.
    assert!(state.verify("bob", "cli-pw"));

    // The CLI's hash is still on disk, byte-for-byte.
    let loaded: UsersConfig = ktav::from_file(&path).unwrap();
    assert_eq!(loaded.users[0].hash, cli_hash);

    // In-memory state adopted it too — wrong passwords now take the
    // normal rejection path and never rewrite the file.
    assert!(!state.verify("bob", "wrong"));
    let reloaded: UsersConfig = ktav::from_file(&path).unwrap();
    assert_eq!(reloaded.users[0].hash, cli_hash);

    let _ = std::fs::remove_file(&path);
}

#[test]
fn init_claim_fails_when_user_removed_from_disk_by_cli() {
    // R13, removal variant: CLI deleted bob from the file while the
    // server's snapshot still had him. The claim must fail closed —
    // not resurrect bob by writing the stale snapshot back.
    let baseline = vec![
        make_user("alice", "alice-pw", true),
        make_init_user("bob", true),
    ];
    let (state, path) = build_state_with_disk_file(baseline.clone(), false);

    let cli_edit = vec![baseline[0].clone()]; // bob removed
    ktav::to_file(&UsersConfig { users: cli_edit }, &path).unwrap();

    assert!(!state.verify("bob", "anything"));

    // In-memory hash reverted to the sentinel so state stays
    // consistent with disk.
    {
        let users = state.users.read().unwrap();
        let bob = users.iter().find(|u| u.name == "bob").unwrap();
        assert_eq!(bob.hash, INIT_HASH);
    }

    // On-disk file untouched: still exactly the CLI's version.
    let loaded: UsersConfig = ktav::from_file(&path).unwrap();
    assert_eq!(loaded.users.len(), 1);
    assert_eq!(loaded.users[0].name, "alice");

    let _ = std::fs::remove_file(&path);
}

#[test]
fn init_claim_write_failure_leaves_previous_disk_file_intact() {
    // R12 through the claim path: the persist starts but fails
    // mid-way (the temp-file slot is sabotaged with a directory).
    // The previous on-disk file must survive byte-for-byte and the
    // in-memory sentinel must be left in place for a retry.
    let baseline = vec![
        make_user("alice", "alice-pw", true),
        make_init_user("bob", true),
    ];
    let (state, path) = build_state_with_disk_file(baseline, false);
    let before = std::fs::read_to_string(&path).unwrap();

    let tmp = PathBuf::from(format!("{}.tmp", path));
    std::fs::create_dir(&tmp).unwrap();

    assert!(!state.verify("bob", "pw"));

    assert_eq!(
        std::fs::read_to_string(&path).unwrap(),
        before,
        "failed persist must leave the previous file intact"
    );
    {
        let users = state.users.read().unwrap();
        let bob = users.iter().find(|u| u.name == "bob").unwrap();
        assert_eq!(
            bob.hash, INIT_HASH,
            "sentinel must still be in place — the failed attempt never published anything"
        );
    }

    std::fs::remove_dir(&tmp).unwrap();
    let _ = std::fs::remove_file(&path);
}

#[test]
fn users_lock_held_externally_does_not_block_cache_miss_verify_for_other_user() {
    // R5-10: while one thread is parked inside the init-claim persist
    // (waiting on the cross-process users-file lock), a plain
    // cache-miss verify for an unrelated, fully-configured user must
    // NOT block on the `users` RwLock.
    //
    // The busy lock is held by an in-process helper thread instead of
    // a child process: byte-range locks (LockFileEx / flock) conflict
    // across OPEN FILE HANDLES even within one process, which
    // users_file.rs's `lock_is_exclusive_and_released_on_drop` proves
    // (l1 held, second acquire times out). So a second UsersFileLock
    // from a helper thread exercises the identical busy-lock path in
    // persist_claim that a foreign process would, with zero
    // subprocess overhead. Actual cross-process release-on-owner-death
    // is separately covered by users_file.rs's crash test
    // `lock_is_released_when_owner_process_dies_without_cleanup`.
    //
    // Phase synchronization is by real events, not sleeps (R6-07):
    // the holder releases the file lock only on an explicit signal,
    // and the parent only proceeds once T1's presence at the guarded
    // region is CONFIRMED (R7-04 probe): try_lock proving T1 HOLDS
    // claim_lock, then the probe event fired immediately before the
    // persist call proving T1 actually ENTERED the guarded
    // persistence region — the mutex alone does not distinguish
    // holding claim_lock from being parked inside persist_claim.
    use std::sync::mpsc;
    use std::sync::TryLockError;
    use std::time::{Duration, Instant};

    let (mut state, path) = build_state_with_disk_file(
        vec![
            make_user("alice", "alice-pw", true),
            make_init_user("bob", true),
        ],
        false,
    );
    let (claim_tx, mut claim_rx) = mpsc::channel::<&'static str>();
    state.install_claim_probe(claim_tx);

    // Holder thread: acquire the users-file lock, signal the parent
    // once it is ACTUALLY held, then keep it until the parent's
    // explicit release signal — no fixed hold timer — and ack the
    // release after dropping it.
    let (locked_tx, locked_rx) = mpsc::channel::<()>();
    let (release_tx, release_rx) = mpsc::channel::<()>();
    let (released_tx, released_rx) = mpsc::channel::<()>();
    let holder_path = path.clone();
    let holder = std::thread::spawn(move || {
        let lock =
            UsersFileLock::acquire_with_timeout(Path::new(&holder_path), Duration::from_secs(5))
                .expect("holder must acquire the users-file lock");
        locked_tx.send(()).expect("signal lock held");
        release_rx
            .recv()
            .expect("holder must receive the release signal");
        drop(lock);
        released_tx.send(()).expect("signal lock released");
    });
    locked_rx.recv().expect("lock-holder signalled");

    // T1: init-claim for bob — parks inside persist_claim on the
    // file lock the holder thread holds.
    let state = Arc::new(state);
    let t1 = std::thread::spawn({
        let state = state.clone();
        move || state.verify("bob", "bob-pw")
    });

    // Confirm T1 reached its critical section by polling for real
    // claim_lock contention (R6-07), not by a fixed sleep: try_lock
    // succeeding means T1 has not taken the mutex yet — drop the
    // guard immediately so it cannot stall T1 — and WouldBlock means
    // T1 holds it. Panic if the deadline passes without ever seeing
    // contention; that means T1 never reached the critical section
    // and the test's premise was never established.
    let contention_deadline = Instant::now() + Duration::from_secs(10);
    loop {
        match state.claim_lock.try_lock() {
            Err(TryLockError::WouldBlock) => break,
            Ok(uncontended) => drop(uncontended),
            Err(TryLockError::Poisoned(_)) => panic!("claim mutex poisoned"),
        }
        assert!(
            Instant::now() < contention_deadline,
            "T1 never took claim_lock within 10 s — the claim \
             contention this test relies on was never observed"
        );
        std::thread::sleep(Duration::from_millis(1));
    }

    // R7-04: the try_lock loop above proves only that T1 HOLDS
    // claim_lock — the post-mutex re-check and the users-file stat
    // still sit between the mutex and the guarded persistence region
    // whose users-guard-holding I/O a regression would have to
    // (re)introduce. Anchor T2's measurement to the probe event
    // fired immediately BEFORE the call into the persist helper:
    // only then is T1 genuinely inside the region this test is
    // about. 15 s guard: T1 hashes one real Argon2id digest before
    // it can arrive, and that stretch reaches seconds under real
    // CPU load (see the machine-load note).
    wait_for_claim_event(
        &mut claim_rx,
        "persist_region_entered",
        Duration::from_secs(15),
        "T1 entering the guarded persistence region",
    );

    // T2: a fresh cache-miss verify for alice (Argon2 only, no
    // claim machinery) must complete in milliseconds, not wait
    // behind T1's parked persist. The 5 s bound is a generous
    // companion guard (Argon2id can degrade from ~15 ms to seconds
    // under concurrent CPU load on this machine — see the
    // recovery-plan note), not the discriminator: in the old
    // (write-guard-held-across-persist) implementation this read
    // blocks until the holder releases the file lock — which only
    // happens after these assertions — so the regression shows up
    // as this verify never returning; the bound only catches any
    // unexpected shorter stall.
    let started = Instant::now();
    let ok = state.verify("alice", "alice-pw");
    let elapsed = started.elapsed();
    assert!(ok);
    assert!(
        elapsed < Duration::from_secs(5),
        "cache-miss verify for an unrelated user blocked {:?} behind the claim persist",
        elapsed
    );

    // Deterministic: the release signal has not been sent, so the
    // file lock is still held and T1 must still be parked inside
    // persist_claim — bob must still be the sentinel here.
    {
        let users = state.users.read().unwrap();
        let bob = users.iter().find(|u| u.name == "bob").unwrap();
        assert_eq!(bob.hash, INIT_HASH, "T1 must still be parked in persist");
    }

    // Explicit release: only now may the holder drop the lock, so
    // T1's parked persist can complete.
    release_tx
        .send(())
        .expect("signal the holder to release the file lock");
    released_rx
        .recv()
        .expect("holder acked the release (lock dropped)");

    holder.join().expect("join lock-holder thread");
    assert!(t1.join().unwrap());

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
    let _ = std::fs::remove_file(format!("{}.lock", path));
}

#[tokio::test]
async fn async_verify_completes_while_claim_parked_without_hashing_slot() {
    // R7-03: the phase split must let an ordinary cache-miss
    // verify_async run its Argon2 work while an init-claim is parked
    // in claim_commit on the cross-process users-file lock — even
    // with only ONE verify_slots permit free. This drives the REAL
    // async server path; the sync sibling test
    // users_lock_held_externally_... calls state.verify, which
    // bypasses verify_slots entirely and so cannot catch a
    // regression that keeps the permit across persistence.
    //
    // Phase synchronization is by real events, not sleeps (R6-07):
    // the holder releases the file lock only on an explicit signal,
    // and the parent confirms T1's parking via claim_lock try_lock
    // contention — T1 is the only other party contending for that
    // mutex, so WouldBlock proves T1 is parked inside its claim
    // critical section.
    use std::sync::mpsc;
    use std::sync::TryLockError;
    use std::time::{Duration, Instant};

    let (state, path) = build_state_with_disk_file(
        vec![
            make_user("alice", "alice-pw", true),
            make_init_user("bob", true),
        ],
        false,
    );
    let state = Arc::new(state);

    // Holder thread: acquire the users-file lock, signal the parent
    // once it is ACTUALLY held, then keep it until the parent's
    // explicit release signal — no fixed hold timer — and ack the
    // release after dropping it. A second UsersFileLock from a
    // helper thread exercises the identical busy-lock path in
    // persist_claim that a foreign process would (byte-range locks
    // conflict across open file handles within one process).
    let (locked_tx, locked_rx) = mpsc::channel::<()>();
    let (release_tx, release_rx) = mpsc::channel::<()>();
    let (released_tx, released_rx) = mpsc::channel::<()>();
    let holder_path = path.clone();
    let holder = std::thread::spawn(move || {
        let lock =
            UsersFileLock::acquire_with_timeout(Path::new(&holder_path), Duration::from_secs(5))
                .expect("holder must acquire the users-file lock");
        locked_tx.send(()).expect("signal lock held");
        release_rx
            .recv()
            .expect("holder must receive the release signal");
        drop(lock);
        released_tx.send(()).expect("signal lock released");
    });
    locked_rx.recv().expect("lock-holder signalled");

    // Leave exactly ONE hashing slot free: the parked claim must not
    // need it (phase 2 runs without a permit), so it stays available
    // for T2's hashing.
    let slots = u32::try_from(state.verify_slots.available_permits()).unwrap();
    let held = state
        .verify_slots
        .clone()
        .acquire_many_owned(slots - 1)
        .await
        .unwrap();

    // T1: init-claim for bob through the real async path — parks
    // inside claim_commit's persist, waiting on the held file lock.
    let t1_state = Arc::clone(&state);
    let t1 = tokio::spawn(async move { t1_state.verify_async("bob", "bob-pw").await });

    // Confirm T1 parked in claim_commit by polling for real
    // claim_lock contention (R6-07), not by a fixed sleep: try_lock
    // succeeding means T1 has not taken the mutex yet — drop the
    // guard immediately so it cannot stall T1 — and WouldBlock means
    // T1 holds it. Panic if the deadline passes without ever seeing
    // contention; that means T1 never reached the critical section
    // and the test's premise was never established.
    let contention_deadline = Instant::now() + Duration::from_secs(10);
    loop {
        match state.claim_lock.try_lock() {
            Err(TryLockError::WouldBlock) => break,
            Ok(uncontended) => drop(uncontended),
            Err(TryLockError::Poisoned(_)) => panic!("claim mutex poisoned"),
        }
        assert!(
            Instant::now() < contention_deadline,
            "T1 never took claim_lock within 10 s — the parked-claim \
             premise was never established"
        );
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    // The core R7-03 assertion: while T1 is parked on the users-file
    // lock, its hashing permit is long gone (dropped when the
    // phase-1 closure returned), so the free slot count is back
    // to 1.
    assert_eq!(
        state.verify_slots.available_permits(),
        1,
        "a claim parked on the users-file lock must not hold a hashing slot (R7-03)"
    );

    // T2: a fresh cache-miss verify_async for alice — the REAL
    // server path — must complete while T1 is still parked. The
    // 5 s timeout bound is a generous companion guard (Argon2id can
    // degrade from ~15 ms to seconds under concurrent CPU load on
    // this machine — see the machine-load note in this file), not
    // the discriminator: pre-fix, T1 holds the only free permit
    // until the file lock is released, so T2 cannot even start
    // hashing (the permit-count assert above already fails).
    let started = Instant::now();
    let ok = tokio::time::timeout(
        Duration::from_secs(5),
        state.verify_async("alice", "alice-pw"),
    )
    .await
    .expect("verify_async for an unrelated user timed out behind the parked claim");
    let elapsed = started.elapsed();
    assert!(ok);
    assert!(
        elapsed < Duration::from_secs(5),
        "unrelated verify_async blocked {:?} behind the parked claim",
        elapsed
    );

    // Deterministic: the release signal has not been sent, so the
    // file lock is still held and T1 must still be parked inside
    // persist_claim — bob must still be the sentinel here.
    assert!(!t1.is_finished(), "T1 must still be parked in claim_commit");
    {
        let users = state.users.read().unwrap();
        let bob = users.iter().find(|u| u.name == "bob").unwrap();
        assert_eq!(bob.hash, INIT_HASH, "T1 must still be parked in persist");
    }

    // Explicit release: only now may the holder drop the lock, so
    // T1's parked persist can complete.
    release_tx
        .send(())
        .expect("signal the holder to release the file lock");
    let t1_ok = t1.await.expect("T1 task must not panic");
    assert!(t1_ok, "T1's claim must succeed once the file lock frees");
    released_rx
        .recv()
        .expect("holder acked the release (lock dropped)");
    holder.join().expect("join lock-holder thread");

    // T1's claim landed in memory and on disk.
    {
        let users = state.users.read().unwrap();
        let bob = users.iter().find(|u| u.name == "bob").unwrap();
        assert!(bob.hash.starts_with("$argon2id$"));
    }
    let loaded: UsersConfig = ktav::from_file(&path).unwrap();
    let bob = loaded.users.iter().find(|u| u.name == "bob").unwrap();
    assert_ne!(bob.hash, INIT_HASH);
    assert!(bob.hash.starts_with("$argon2id$"));

    // Every hashing slot is back: T1 dropped its phase-3 permit and
    // T2 its phase-1 permit.
    drop(held);
    assert_eq!(
        state.verify_slots.available_permits(),
        usize::try_from(slots).unwrap()
    );

    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(format!("{}.lock", path));
}
