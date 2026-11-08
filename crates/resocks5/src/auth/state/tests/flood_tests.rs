//! Flood-bound properties of the clear-text path: the derivation limiter
//! refuses instead of queueing, failures never fill the cache, and init
//! enrollment stays first-login-wins. Every test gives its state a PRIVATE
//! limiter, so saturating it never disturbs a test running beside it.

use super::*;
use resocks5_net::secure_auth::{derive_key, DerivationLimiter, PasswordCheck, SecretStore as _};
use std::time::Duration;

/// Replace the (fresh, uniquely owned) state's limiter with a private one.
fn with_private_limiter(mut state: Arc<AuthState>, capacity: usize) -> Arc<AuthState> {
    Arc::get_mut(&mut state)
        .expect("a fresh state is uniquely owned")
        .limiter = Arc::new(DerivationLimiter::new(capacity));
    state
}

/// A saturated derivation limiter does not slow down a cache HIT and turns
/// a MISS into a `Rejected` after the limiter's short bounded wait (never
/// queued behind the held slots). Mutation: making the hit path derive
/// (dropping the cache lookup) makes the hit wait out the limiter and fail.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_cache_hit_survives_a_saturated_derivation_limiter() {
    let (state, path) = build_state_with_disk_file(vec![make_user("alice", "pw", true)]);
    let state = with_private_limiter(state, 1);
    let store = state.peer_store(ip("127.0.0.1"));
    // Populate the cache before any slot is held.
    assert!(matches!(
        store.check_password("alice", "pw").await,
        PasswordCheck::Accepted
    ));
    let held = state.limiter.acquire().await.expect("a free slot");
    // Cache HIT: answered at once, without touching the saturated limiter.
    let hit = tokio::time::timeout(
        Duration::from_millis(500),
        store.check_password("alice", "pw"),
    )
    .await
    .expect("a cache hit must not wait on the limiter");
    assert!(matches!(hit, PasswordCheck::Accepted));
    // Cache MISS: refused once the bounded wait runs out, not queued.
    let granted = state.limiter.granted();
    let miss = tokio::time::timeout(
        Duration::from_secs(10),
        store.check_password("alice", "never-seen-wrong"),
    )
    .await
    .expect("a miss must be refused, not queued");
    assert!(matches!(miss, PasswordCheck::Rejected));
    assert_eq!(state.limiter.granted(), granted, "no slot was granted");
    drop(held);
    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(format!("{path}.lock"));
}

/// A flood of failed clear-text logins (wrong passwords for a known user
/// and for unknown names) caches nothing and stays bounded. Mutation:
/// inserting on `Rejected` makes the zero-entries assert fail.
#[tokio::test]
async fn a_flood_of_failed_clear_text_logins_caches_nothing_and_stays_bounded() {
    let (state, path) = build_state_with_disk_file(vec![make_user("alice", "pw", true)]);
    let state = with_private_limiter(state, 2);
    let store = state.peer_store(ip("127.0.0.1"));
    for i in 0..500 {
        let (user, password) = if i % 2 == 0 {
            ("alice".to_string(), format!("wrong-{i}"))
        } else {
            (format!("intruder-{i}"), format!("bad-{i}"))
        };
        assert!(
            matches!(
                store.check_password(&user, &password).await,
                PasswordCheck::Rejected
            ),
            "attempt {i} must be rejected"
        );
    }
    let cap = crate::auth::state::password_cache::PASSWORD_CACHE_CAP;
    assert_eq!(state.password_cache.len(), 0, "failures cache nothing");
    assert!(state.password_cache.len() <= cap, "cache stays bounded");
    assert!(
        state.limiter.granted() <= 250,
        "unknown names must take no derivation slot"
    );
    assert!(matches!(
        store.check_password("alice", "pw").await,
        PasswordCheck::Accepted
    ));
    assert_eq!(state.password_cache.len(), 1, "only the success is cached");
    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(format!("{path}.lock"));
}

/// A hundred concurrent first logins of an init user produce exactly one
/// claim; the winner's password is the one stored, the losers are rejected,
/// and nothing is cached (`Claimed` is never cached — only `Accepted` is).
/// Init enrollment stays first-login-wins by design; a wrong password can
/// never claim a KNOWN user (covered by the sibling wrong-password and
/// filtered-peer tests). Mutation: dropping the claim re-check under
/// `claim_lock` (or caching on `Claimed`) fails an assert.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_concurrent_first_logins_of_an_init_user_produce_exactly_one_claim() {
    use crate::auth::secret::parse_secret;
    let (state, path) = build_state_with_disk_file(vec![make_init_user("bob", true)]);
    let state = with_private_limiter(state, 4);
    let store = Arc::new(state.peer_store(ip("127.0.0.1")));
    let mut tasks = tokio::task::JoinSet::new();
    for i in 0..100 {
        let store = Arc::clone(&store);
        tasks.spawn(async move {
            let password = format!("claim-{i}");
            let check = store.check_password("bob", &password).await;
            (password, check)
        });
    }
    let mut claimed = 0;
    let mut rejected = 0;
    let mut winners = Vec::new();
    while let Some(result) = tasks.join_next().await {
        let (password, check) = result.unwrap();
        match check {
            PasswordCheck::Claimed => {
                claimed += 1;
                winners.push(password);
            }
            PasswordCheck::Rejected => rejected += 1,
            other => panic!("unexpected check result: {other:?}"),
        }
    }
    assert_eq!(claimed, 1, "exactly one claim");
    assert_eq!(rejected, 99, "the rest are rejected");

    let stored: crate::config::UsersConfig = ktav::from_file(&path).unwrap();
    let disk_hash = stored
        .users
        .iter()
        .find(|u| u.name == "bob")
        .unwrap()
        .hash
        .clone();
    assert_ne!(disk_hash, INIT_HASH, "bob is no longer init on disk");
    let secret = parse_secret(&disk_hash).unwrap();
    let matches: Vec<&String> = winners
        .iter()
        .filter(|candidate| {
            let expected = derive_key(candidate.as_bytes(), &secret.salt, &secret.params).unwrap();
            secret.key() == &*expected
        })
        .collect();
    assert_eq!(matches.len(), 1, "exactly one candidate is the winner");
    let winner = matches[0].clone();

    assert!(matches!(
        store.check_password("bob", &winner).await,
        PasswordCheck::Accepted
    ));
    assert!(matches!(
        store.check_password("bob", "claim-not-the-winner").await,
        PasswordCheck::Rejected
    ));
    assert_eq!(state.password_cache.len(), 0, "`Claimed` is never cached");
    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(format!("{path}.lock"));
}
