use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};

use anyhow::{anyhow, Result};
use dashmap::DashMap;
use tokio::sync::Semaphore;

#[cfg(test)]
use crate::config::users_file::UsersFileLock;
use crate::config::{AuthConfig, User, UsersConfig};

mod claim;
mod probes;
mod verify;

#[cfg(test)]
mod tests;

struct UserEntry {
    index: usize,
    enabled: bool,
    direct: bool,
}

/// Server-side auth bundle, built once at startup and shared with each
/// connection-handling task via `Arc<AuthState>`. Holds the snapshot of
/// the users list as loaded from disk, the policy flag, the
/// process-local cache secret, and the verify-cache itself.
///
/// ## Cache invalidation on password change
///
/// Users are a startup snapshot. CLI password and policy changes require a
/// server restart. Only init-claims update this process's hashes at runtime.
///
/// ## Init-on-first-login
///
/// A user whose `hash` is the literal string `"init"` is a placeholder
/// — the first client that connects with that username "claims" the
/// account by submitting a password that is then hashed (Argon2id),
/// written into both the in-memory state and `resocks5.users.ktav`, and
/// from that point on behaves as a normal account. Concurrent claims
/// are serialised through the dedicated `claim_lock` mutex (which is
/// held across the cross-process persist); the `users` write lock is
/// taken only for short publish/rollback updates. The loser of the race
/// either authenticates against the winner's hash (same password →
/// success) or fails (different password → standard rejection). Since
/// P1-01 the persistence phase is additionally capped by an independent
/// admission permit (`claim_slots`) and deduplicated per account behind
/// an async gate, so a pile-up of concurrent claims queues on the async
/// runtime instead of on blocking-pool threads.
pub struct AuthState {
    /// `RwLock` because `verify` may mutate the list (init-claim path)
    /// while other connections are doing read-only lookups in parallel.
    /// Guards are held only briefly: hashing and the cross-process
    /// persist run OUTSIDE the lock (see `claim_lock`), so normal
    /// cache-miss verifies never block behind claim file I/O. Init-claim
    /// is the only writer and runs at most once per user (lifetime of
    /// the server process / persisted file).
    users: RwLock<Vec<User>>,
    claim_lock: Mutex<()>,
    /// Serialises init-claims within this process. Held across the
    /// whole claim critical section (re-check + persist + publish), so
    /// only one thread at a time can claim a given (or any) user. The
    /// cross-process `UsersFileLock` inside `persist_claim` still
    /// serialises against other processes. A std Mutex is correct:
    /// claim work runs synchronously inside `spawn_blocking` threads
    /// and nothing `.await`s while the guard is held.
    entries: HashMap<String, UserEntry>,
    /// Caps concurrent CPU-bound Argon2 verify work. Sized
    /// `min(available_parallelism, 4)` (fallback 1). Permits are held
    /// only around the hashing phases (R7-03): claim persistence waits
    /// run WITHOUT a permit so a claim parked on the users-file lock
    /// cannot starve other users' hashing.
    verify_slots: Arc<Semaphore>,
    /// P1-01: independent admission cap for init-claim persistence.
    /// `verify_slots` bounds only the CPU hashing phases; without a
    /// separate cap every `Prepared::Claim` went straight into its own
    /// `spawn_blocking` and parked a blocking-pool thread on `claim_lock`
    /// or the cross-process users-file lock, so a pile-up of concurrent
    /// init-claims could occupy an unbounded number of threads from the
    /// pool shared with ordinary cache-miss logins, DNS and file I/O —
    /// a conditional denial of service. The permit is acquired
    /// ASYNCHRONOUSLY before the phase-2 `spawn_blocking` (a queued
    /// claimant occupies no blocking thread at all) and then moves INTO
    /// the blocking closure, so it is held until the persistence work
    /// ACTUALLY finishes — including after client cancellation, because
    /// `spawn_blocking` work is not cancelled when the awaiting future
    /// is dropped. Default 2: in-process claims serialize on
    /// `claim_lock` anyway (useful concurrency is 1), so this keeps one
    /// handoff slot warm while capping the claim footprint on the
    /// shared pool at two threads.
    claim_slots: Arc<Semaphore>,
    /// P1-01: per-account claim gates. A claimant that finds another
    /// claim for the SAME account still in flight waits on the
    /// account's async mutex instead of queueing a second blocking
    /// closure behind `claim_lock`; when the gate frees it re-checks
    /// the committed hash and resolves as a plain login (or, if the
    /// in-flight claim failed and re-armed the sentinel, retries the
    /// claim itself). Entries are created lazily per init-claimed
    /// account name and live for the process lifetime — bounded by the
    /// startup user count.
    claim_gates: std::sync::Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>,
    /// Mirrors `auth.allow_anonymous` from `resocks5.main.ktav`. When
    /// `true`, the server advertises SOCKS5 method `0x00` to clients
    /// (and skips Proxy-Authorization on HTTP); when `false`, only
    /// authenticated clients are accepted.
    pub allow_anonymous: bool,
    /// Process-local HMAC key. The cache stores no plaintext passwords.
    server_secret: [u8; 32],
    /// `name → HMAC(server_secret, name || 0x00 || password)` for the
    /// last successfully verified password. Hit = O(1) success;
    /// miss/mismatch = fall back to Argon2.
    cache: DashMap<String, [u8; 32]>,
    /// Path to `resocks5.users.ktav` (parameter so tests can point at a
    /// temp file). Used only by the init-claim path to persist the
    /// freshly-hashed password.
    users_path: String,
    /// Test-only observation seam for `claim_commit` (R7-04). Deliberately
    /// per-INSTANCE, not a global static: cargo runs this file's tests
    /// concurrently in one process, and a global sink would let one test's
    /// claimant feed another test's observer. `None` in production
    /// (`build`); a test installs a `std::sync::mpsc` sender and
    /// `claim_commit` emits stage events into it. Compiles to nothing
    /// outside test builds.
    #[cfg(test)]
    claim_probe: Mutex<Option<std::sync::mpsc::Sender<&'static str>>>,
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
        let mut entries = HashMap::with_capacity(users.users.len());
        for (index, user) in users.users.iter().enumerate() {
            entries.entry(user.name.clone()).or_insert(UserEntry {
                index,
                enabled: user.is_enabled,
                direct: user.direct,
            });
        }
        let workers = std::thread::available_parallelism().map_or(1, |n| n.get().min(4));
        Ok(Self {
            users: RwLock::new(users.users.clone()),
            claim_lock: Mutex::new(()),
            entries,
            verify_slots: Arc::new(Semaphore::new(workers)),
            claim_slots: Arc::new(Semaphore::new(2)),
            claim_gates: Mutex::new(HashMap::new()),
            allow_anonymous: auth_cfg.allow_anonymous,
            server_secret,
            cache: DashMap::new(),
            users_path: users_path.into(),
            #[cfg(test)]
            claim_probe: Mutex::new(None),
        })
    }

    /// True when no users are configured.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Current number of configured users (including any unclaimed
    /// `hash == "init"` placeholders).
    pub fn users_count(&self) -> usize {
        self.entries.len()
    }

    /// Returns `true` when the named user exists, is enabled, and has
    /// `direct == true`. Returns `false` for missing, disabled, or
    /// pool-routed users.
    pub fn is_direct(&self, name: &str) -> bool {
        self.entries
            .get(name)
            .map(|u| u.enabled && u.direct)
            .unwrap_or(false)
    }
}
