use std::path::Path;

use anyhow::anyhow;

use super::AuthState;
use crate::auth::compute_hash::compute_hash;
use crate::config::users_file::{write_atomic, UsersFileLock};
use crate::config::{User, UsersConfig};

/// Sentinel value placed in a `User.hash` to indicate that the password
/// has not been chosen yet — the first successful client connection
/// will set it. Anything else is treated as a real Argon2id PHC string.
pub(super) const INIT_HASH: &str = "init";

/// Everything `claim_commit` needs to finish an init-claim, produced by
/// the CPU-bound phase 1 (`prepare_claim`) and consumed by the
/// persistence phase 2 (`claim_commit`).
pub(super) struct ClaimWork {
    pub(super) name: String,
    candidate_hmac: [u8; 32],
    pub(super) index: usize,
    new_hash: String,
}

/// Result of phases 1/2: either a final answer, or a claim that still
/// needs `claim_commit`, or (from `claim_commit`) a committed hash the
/// caller must Argon2-verify OUTSIDE the claim mutex (phase 3).
pub(super) enum Prepared {
    Done(bool),
    Claim(ClaimWork),
}

pub(super) enum ClaimOutcome {
    Done(bool),
    VerifyAgainst(String),
}

impl AuthState {
    /// Phase 1 of the verify pipeline: entry checks, cache check, then
    /// either a plain Argon2 verify against the stored hash or the
    /// CPU-bound prefix of an init-claim. Returns `Prepared::Done` when
    /// no persistence is needed, or `Prepared::Claim` carrying the work
    /// `claim_commit` must finish.
    pub(super) fn verify_prepare(
        &self,
        name: &str,
        password: &str,
        candidate_hmac: [u8; 32],
    ) -> Prepared {
        let Some(entry) = self.entries.get(name).filter(|u| u.enabled) else {
            return Prepared::Done(false);
        };
        if self.cache_matches(name, &candidate_hmac) {
            return Prepared::Done(true);
        }
        let hash = self.users.read().expect("users RwLock poisoned")[entry.index]
            .hash
            .clone();

        if hash != INIT_HASH {
            return Prepared::Done(self.verify_against_committed(
                name,
                &hash,
                password,
                candidate_hmac,
            ));
        }
        self.prepare_claim(name, password, candidate_hmac)
    }

    /// CPU-bound prefix of the init-claim flow: empty-password
    /// rejection (R5-07), the Argon2id hash of the candidate password,
    /// and the pre-mutex fast-path race check — a claim that already
    /// committed while we hashed is resolved inline (we hold a hashing
    /// permit in the async path). Returns `Prepared::Claim` when the
    /// claim must still be persisted and published by `claim_commit`.
    pub(super) fn prepare_claim(
        &self,
        name: &str,
        password: &str,
        candidate_hmac: [u8; 32],
    ) -> Prepared {
        // An empty password must never be claimable. The CLI rejects
        // empty passwords (run_user_command::read_new_password); this
        // claim path is reachable from any input protocol, so it
        // enforces the same invariant independently of the SOCKS5
        // framing layer (R5-07).
        if password.is_empty() {
            return Prepared::Done(false);
        }

        // SOCKS5's PASSWD field carries a one-byte length prefix
        // (RFC 1929 §2): a password over 255 bytes could never be
        // transmitted in full by a compliant client, so hashing and
        // persisting one would permanently lock the account out of
        // SOCKS5 login (R8-04). Bytes, not character count.
        if password.len() > 255 {
            return Prepared::Done(false);
        }

        // Compute the new hash outside the write lock — Argon2id takes
        // ~15 ms and we don't want it blocking concurrent read-side
        // verify calls during that window.
        let Ok(new_hash) = compute_hash(password) else {
            return Prepared::Done(false);
        };

        let Some(entry) = self.entries.get(name) else {
            return Prepared::Done(false);
        };
        let idx = entry.index;

        // Fast path: the race is already decided — someone claimed the
        // account while we were hashing. SHORT read guard; the Argon2
        // verify runs outside it.
        if let Some(claimed_hash) = self.claimed_hash_if_any(idx) {
            return Prepared::Done(self.verify_against_committed(
                name,
                &claimed_hash,
                password,
                candidate_hmac,
            ));
        }

        Prepared::Claim(ClaimWork {
            name: name.to_string(),
            candidate_hmac,
            index: idx,
            new_hash,
        })
    }

    /// Phase 2 of the init-claim flow: serialise the persist+publish
    /// critical section on the claim mutex (NOT the users RwLock) —
    /// claims serialize in-process here, the file lock inside
    /// persist_claim serializes across processes, and normal cache-miss
    /// verifies for unrelated users proceed unblocked while we wait on
    /// cross-process file I/O. Callers hold NO hashing permit here
    /// (R7-03).
    ///
    /// The init state is re-checked after `claim_lock` is acquired
    /// (R6-01): a racer that queued behind a committed winner becomes a
    /// plain login against the winner's hash and never enters
    /// persistence, so its own persist failure cannot reset a hash it
    /// never published. The committed hash is immutable once published,
    /// so the Argon2 verify against it is DEFERRED to the caller (phase
    /// 3, outside the mutex) — hashing under the mutex would stall
    /// every other claim.
    pub(super) fn claim_commit(&self, work: ClaimWork) -> ClaimOutcome {
        // R7-04 test seam: the FIRST statement, before acquiring
        // claim_lock. A waiting test learns the caller genuinely reached
        // claim_commit — i.e. did not resolve via the pre-mutex fast path
        // in prepare_claim — at the exact moment it arrives at the mutex.
        #[cfg(test)]
        self.claim_probe_emit("claim_commit_entered");

        let ClaimWork {
            name,
            candidate_hmac,
            index: idx,
            new_hash,
        } = work;

        let _claim_guard = self.claim_lock.lock().expect("claim mutex poisoned");

        // Re-check AFTER the wait (R6-01): a concurrent claim may have
        // committed while we were queued on the mutex. If so, this call
        // becomes a plain login against the winner's hash and must
        // never reach persistence — its persist (which can legitimately
        // fail, e.g. another process holds the cross-process users-file
        // lock past its timeout) must not reset a hash this call never
        // published. The verify itself is deferred to the caller.
        if let Some(claimed_hash) = self.claimed_hash_if_any(idx) {
            return ClaimOutcome::VerifyAgainst(claimed_hash);
        }

        // The fallback snapshot is consumed only by persist_claim's
        // missing-file branch, so build it (R6-05) only when the file
        // is actually absent — and only now, after the mutex and the
        // re-check, so the common existing-file claim (and every race
        // loser that bailed out above) never clones the whole list.
        // SHORT read guard; handed to persist_claim by value so that
        // branch can move it into the config without a second copy.
        let fallback_users = if Path::new(&self.users_path).exists() {
            None
        } else {
            let mut snapshot = self.users.read().expect("users RwLock poisoned").clone();
            snapshot[idx].hash = new_hash.clone();
            Some(snapshot)
        };

        // Persist this one claim on top of what is CURRENTLY on disk —
        // not on top of our startup snapshot. A CLI process may have
        // edited the file since we loaded it; writing our whole stale
        // snapshot back would silently revert those edits.
        // No users guard is held here.
        // R7-04 test seam: fired only AFTER the post-mutex re-check and
        // the users-file stat, immediately before the call into the
        // persist helper — the exact guarded persistence region a
        // regression would have to (re)enter.
        #[cfg(test)]
        self.claim_probe_emit("persist_region_entered");
        match persist_claim(
            Path::new(&self.users_path),
            &name,
            &new_hash,
            fallback_users,
        ) {
            ClaimPersist::Written => {
                // Only claim threads write users[idx] and they serialize
                // on claim_lock (which we hold across persist+publish),
                // so a brief write guard is sufficient to publish.
                self.users.write().expect("users RwLock poisoned")[idx].hash = new_hash.clone();
                self.cache.insert(name.clone(), candidate_hmac);
                ClaimOutcome::Done(true)
            }
            ClaimPersist::DiskHashChanged(disk_hash) => {
                // The file's hash for this user stopped being "init"
                // while we worked — a real password landed on disk via a
                // concurrent CLI edit. Disk wins: adopt its hash and let
                // the caller treat our candidate as a normal login
                // against it instead of clobbering it.
                self.users.write().expect("users RwLock poisoned")[idx].hash = disk_hash.clone();
                ClaimOutcome::VerifyAgainst(disk_hash)
            }
            ClaimPersist::Failed(e) => {
                // Restate the sentinel. Safe (R6-01): the re-check under
                // this same lock guarantees this attempt never published
                // a committed value — only claim threads write
                // users[idx] and they serialize on the claim mutex we
                // are holding — so this assignment can only restate the
                // sentinel that is already in place.
                self.users.write().expect("users RwLock poisoned")[idx].hash =
                    INIT_HASH.to_string();
                eprintln!(
                    "init-claim: failed to persist {} after first-login of '{}': {}",
                    self.users_path, name, e
                );
                ClaimOutcome::Done(false)
            }
        }
    }

    /// If `users[idx]` is no longer the `"init"` sentinel, return the
    /// committed hash; `None` while the account is still unclaimed and
    /// the caller may proceed with the claim itself.
    ///
    /// Used before queueing on the claim mutex (fast path in
    /// `prepare_claim`) and again after acquiring it (R6-01 in
    /// `claim_commit`). The read guard is held only for the hash clone
    /// (R5-10); Argon2 and cache access run without it. This helper
    /// never touches persistence or any other shared state.
    pub(super) fn claimed_hash_if_any(&self, idx: usize) -> Option<String> {
        let users = self.users.read().expect("users RwLock poisoned");
        if users[idx].hash == INIT_HASH {
            return None;
        }
        Some(users[idx].hash.clone())
    }
}

/// Outcome of the cross-process persist of an init-claim.
pub(super) enum ClaimPersist {
    /// The claimed hash was merged into the on-disk file.
    Written,
    /// The on-disk hash for this user is no longer the `"init"`
    /// sentinel; carries the current on-disk value. Nothing was written.
    DiskHashChanged(String),
    /// Nothing was written; carries the reason.
    Failed(anyhow::Error),
}

/// Merge a single init-claim into the users file under the cross-process
/// file lock, then atomically replace the file.
///
/// `fallback_users` (the caller's full in-memory list, with the claimed
/// hash already applied) is consumed — moved in, no extra deep copy
/// (R6-05) — only when the file does not exist yet: there is nothing on
/// disk to merge into, so this preserves the old "first claim creates
/// the file" behavior. The caller builds the snapshot only when it last
/// saw the file missing; if the file vanished since, there is nothing
/// to merge into and no snapshot to recreate it from, so the claim
/// fails closed (a retry re-runs the claim and takes the create path
/// with a fresh snapshot).
pub(super) fn persist_claim(
    path: &Path,
    name: &str,
    new_hash: &str,
    fallback_users: Option<Vec<User>>,
) -> ClaimPersist {
    let _lock = match UsersFileLock::acquire(path) {
        Ok(lock) => lock,
        Err(e) => return ClaimPersist::Failed(e.context("acquire users-file lock")),
    };

    if !path.exists() {
        let Some(fallback_users) = fallback_users else {
            return ClaimPersist::Failed(anyhow!(
                "users file {} disappeared before the claim could be persisted",
                path.display()
            ));
        };
        let cfg = UsersConfig {
            users: fallback_users,
        };
        return match write_atomic(path, &cfg) {
            Ok(()) => ClaimPersist::Written,
            Err(e) => ClaimPersist::Failed(e),
        };
    }

    let mut disk: UsersConfig = match ktav::from_file(path) {
        Ok(cfg) => cfg,
        Err(e) => {
            return ClaimPersist::Failed(
                anyhow::Error::new(e).context(format!("read {}", path.display())),
            )
        }
    };

    let Some(user) = disk.users.iter_mut().find(|u| u.name == name) else {
        return ClaimPersist::Failed(anyhow!(
            "user '{}' no longer exists in {} — removed by a concurrent CLI edit, \
             not re-adding it",
            name,
            path.display()
        ));
    };

    if user.hash != INIT_HASH {
        return ClaimPersist::DiskHashChanged(user.hash.clone());
    }

    user.hash = new_hash.to_string();
    match write_atomic(path, &disk) {
        Ok(()) => ClaimPersist::Written,
        Err(e) => ClaimPersist::Failed(e),
    }
}
