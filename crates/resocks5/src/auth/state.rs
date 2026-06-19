use std::sync::RwLock;

use anyhow::{anyhow, Result};
use argon2::password_hash::{PasswordHash, PasswordVerifier};
use dashmap::DashMap;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;

use crate::auth::compute_hash::compute_hash;
use crate::auth::params::argon2_instance;
use crate::config::{AuthConfig, User, UsersConfig};

/// Sentinel value placed in a `User.hash` to indicate that the password
/// has not been chosen yet — the first successful client connection
/// will set it. Anything else is treated as a real Argon2id PHC string.
const INIT_HASH: &str = "init";

/// Server-side auth bundle, built once at startup and shared with each
/// connection-handling task via `Arc<AuthState>`. Holds the snapshot of
/// the users list as loaded from disk, the policy flag, the
/// process-local cache secret, and the verify-cache itself.
///
/// ## Cache invalidation on password change
///
/// The cache is keyed by username and the value is the HMAC of the
/// *currently valid* password. If the password changes, the new HMAC
/// mismatches the cached value and we fall back to Argon2 — on success
/// the entry is overwritten. Old passwords therefore stop authenticating
/// the moment a new one is recorded, even within a running process.
///
/// ## Init-on-first-login
///
/// A user whose `hash` is the literal string `"init"` is a placeholder
/// — the first client that connects with that username "claims" the
/// account by submitting a password that is then hashed (Argon2id),
/// written into both the in-memory state and `resocks5.users.ktav`, and
/// from that point on behaves as a normal account. Concurrent claims
/// are serialised through the `users` write lock; the loser of the race
/// either authenticates against the winner's hash (same password →
/// success) or fails (different password → standard rejection).
pub struct AuthState {
    /// `RwLock` because `verify` may mutate the list (init-claim path)
    /// while other connections are doing read-only lookups in parallel.
    /// Normal verify takes the read lock only briefly; init-claim is
    /// the only writer and runs at most once per user (lifetime of the
    /// server process / persisted file).
    users: RwLock<Vec<User>>,
    /// Mirrors `auth.allow_anonymous` from `resocks5.main.ktav`. When
    /// `true`, the server advertises SOCKS5 method `0x00` to clients
    /// (and skips Proxy-Authorization on HTTP); when `false`, only
    /// authenticated clients are accepted.
    pub allow_anonymous: bool,
    /// 32 random bytes generated at startup. Used as HMAC key for cache
    /// entries so plaintext passwords never sit in process memory.
    /// Never persisted — a fresh `server_secret` every run means a
    /// captured memory image from one run cannot be replayed.
    server_secret: [u8; 32],
    /// `name → HMAC(server_secret, name || 0x00 || password)` for the
    /// last successfully verified password. Hit = O(1) success;
    /// miss/mismatch = fall back to Argon2.
    cache: DashMap<String, [u8; 32]>,
    /// Path to `resocks5.users.ktav` (parameter so tests can point at a
    /// temp file). Used only by the init-claim path to persist the
    /// freshly-hashed password.
    users_path: String,
}

impl AuthState {
    pub fn build(
        auth_cfg: &AuthConfig,
        users: &UsersConfig,
        users_path: impl Into<String>,
    ) -> Result<Self> {
        let mut server_secret = [0u8; 32];
        getrandom::getrandom(&mut server_secret)
            .map_err(|e| anyhow!("OS random source unavailable: {}", e))?;
        Ok(Self {
            users: RwLock::new(users.users.clone()),
            allow_anonymous: auth_cfg.allow_anonymous,
            server_secret,
            cache: DashMap::new(),
            users_path: users_path.into(),
        })
    }

    /// True when no users are configured.
    pub fn is_empty(&self) -> bool {
        self.users.read().expect("users RwLock poisoned").is_empty()
    }

    /// Current number of configured users (including any unclaimed
    /// `hash == "init"` placeholders).
    pub fn users_count(&self) -> usize {
        self.users.read().expect("users RwLock poisoned").len()
    }

    /// Returns `true` when the named user exists, is enabled, and has
    /// `direct == true`. Returns `false` for missing, disabled, or
    /// pool-routed users.
    pub fn is_direct(&self, name: &str) -> bool {
        let users = self.users.read().expect("users RwLock poisoned");
        users
            .iter()
            .find(|u| u.name == name)
            .map(|u| u.is_enabled && u.direct)
            .unwrap_or(false)
    }

    /// Verify a username + password pair. `false` on any failure —
    /// unknown user, disabled user, malformed stored hash, password
    /// mismatch — so the disabled-vs-unknown distinction never leaks
    /// to the client. Cache-first; falls back to Argon2 on miss; on a
    /// `"init"` placeholder, atomically claims the password for the
    /// account and persists it to disk.
    pub fn verify(&self, name: &str, password: &str) -> bool {
        let hash_opt = {
            let users = self.users.read().expect("users RwLock poisoned");
            users
                .iter()
                .find(|u| u.name == name)
                .filter(|u| u.is_enabled)
                .map(|u| u.hash.clone())
        };
        let Some(hash) = hash_opt else {
            return false;
        };

        let candidate_hmac = compute_cache_hmac(&self.server_secret, name, password);

        if hash == INIT_HASH {
            return self.try_claim_init(name, password, candidate_hmac);
        }

        if let Some(cached) = self.cache.get(name) {
            if bool::from(cached.value().ct_eq(&candidate_hmac)) {
                return true;
            }
            // Mismatch (likely password change since last cache write) —
            // fall through to a real Argon2 verify.
        }

        if argon2_verify(&hash, password) {
            self.cache.insert(name.to_string(), candidate_hmac);
            true
        } else {
            false
        }
    }

    /// Implements the `hash == "init"` first-login claim flow. Returns
    /// `true` when the password was either just recorded for the user
    /// (we won the race), or matches the hash that was recorded by a
    /// concurrent winner. Returns `false` on hash-compute failure, disk
    /// persistence failure, or a real password mismatch.
    fn try_claim_init(&self, name: &str, password: &str, candidate_hmac: [u8; 32]) -> bool {
        // Compute the new hash outside the write lock — Argon2id takes
        // ~15 ms and we don't want it blocking concurrent read-side
        // verify calls during that window.
        let Ok(new_hash) = compute_hash(password) else {
            return false;
        };

        let mut users = self.users.write().expect("users RwLock poisoned");
        let Some(idx) = users.iter().position(|u| u.name == name) else {
            return false;
        };
        if users[idx].hash != INIT_HASH {
            // Someone else won the race between our read and write. Fall
            // back to verifying our password against the claimed hash:
            // if we're the same legitimate user we'll match, otherwise
            // we get the usual rejection.
            let claimed_hash = users[idx].hash.clone();
            drop(users);
            if argon2_verify(&claimed_hash, password) {
                self.cache.insert(name.to_string(), candidate_hmac);
                return true;
            }
            return false;
        }

        users[idx].hash = new_hash;
        let snapshot = UsersConfig {
            users: users.clone(),
        };

        // Persist the entire users file under the write lock so on-disk
        // and in-memory states stay consistent. On failure, revert the
        // in-memory change so a retry can re-attempt the claim cleanly.
        if let Err(e) = ktav::to_file(&snapshot, &self.users_path) {
            users[idx].hash = INIT_HASH.to_string();
            eprintln!(
                "init-claim: failed to persist {} after first-login of '{}': {}",
                self.users_path, name, e
            );
            return false;
        }

        drop(users);
        self.cache.insert(name.to_string(), candidate_hmac);
        true
    }
}

fn argon2_verify(stored_phc: &str, password: &str) -> bool {
    let Ok(parsed) = PasswordHash::new(stored_phc) else {
        return false;
    };
    argon2_instance()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok()
}

fn compute_cache_hmac(secret: &[u8; 32], name: &str, password: &str) -> [u8; 32] {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret).expect("HMAC accepts any key length");
    mac.update(name.as_bytes());
    // 0x00 separator so `("ab", "cd")` and `("a", "bcd")` don't collide.
    mac.update(&[0]);
    mac.update(password.as_bytes());
    mac.finalize().into_bytes().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::compute_hash;
    use crate::config::User;
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
}
