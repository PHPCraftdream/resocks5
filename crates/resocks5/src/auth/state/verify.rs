use argon2::password_hash::{PasswordHash, PasswordVerifier};
use std::sync::Arc;

use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use super::claim::{ClaimOutcome, Prepared};
use super::AuthState;
use crate::auth::params::argon2_instance;

/// SEC-03: fixed dummy the equalised rejection path compares the presented
/// password against. Arbitrary public constant — the outcome is ignored; only
/// the cost profile must match the known-name path.
const DUMMY_PASSWORD: [u8; 32] = *b"RESOCKS5-EQUALISED-REJECT-DUMMYX";

/// The password a user logged in with, kept in process memory after its
/// Argon2 check so that every later login is ONE constant-time comparison:
/// no recomputation, no hashing. Plaintext on purpose (a memory dump shows
/// it); wiped when the entry is replaced or dropped. Failed attempts are
/// never stored.
pub(super) struct CachedPassword(Box<[u8]>);

impl CachedPassword {
    pub(super) fn new(password: &str) -> Self {
        Self(password.as_bytes().into())
    }

    /// Constant-time in the content; the length is not hidden.
    fn matches(&self, presented: &[u8]) -> bool {
        bool::from(self.0.as_ref().ct_eq(presented))
    }

    pub(super) fn wipe(&mut self) {
        self.0.as_mut().zeroize();
    }

    #[cfg(test)]
    pub(super) fn bytes(&self) -> &[u8] {
        &self.0
    }
}

impl Drop for CachedPassword {
    fn drop(&mut self) {
        self.wipe();
    }
}

impl AuthState {
    /// SEC-03: unknown/disabled names used to return before ANY work,
    /// so response time leaked "name exists and is enabled". The
    /// rejection now runs the same cheap constant-time comparison of the
    /// presented password (against a fixed dummy) that a known name's
    /// cache check costs, before returning false. GUARANTEE LEVEL: only
    /// this cheap first step is equalised — the Argon2 cache-miss path is
    /// intentionally NOT equalised: equalising Argon2 itself would burn
    /// ~50 ms of server CPU per enumeration probe.
    ///
    /// cancel-safe: NO — an admitted init-claim may still complete its
    /// persistence after cancellation. P1-01: the persistence phase has
    /// its OWN admission limit (`claim_slots`): the permit is awaited
    /// asynchronously BEFORE the `spawn_blocking` — a queued claimant
    /// occupies no blocking thread — and then moves INTO the blocking
    /// closure, so it is held until the persistence work actually
    /// finishes, including when the client future is cancelled mid-claim.
    /// Concurrent claims for the same account are deduplicated behind a
    /// per-account async gate: at most one claim attempt per account is
    /// in flight, and followers resolve against the committed hash
    /// instead of parking a second blocking closure on `claim_lock`.
    /// R3-P3-02: the gate guard is an owned guard moved INTO the same
    /// blocking closure as the permit, so the gate is held until the
    /// persistence work actually finishes — cancelling this future
    /// cannot free the gate for a same-account follower while a claim
    /// is still in flight.
    pub async fn verify_async(self: &Arc<Self>, name: &str, password: &str) -> bool {
        if !self.entries.get(name).is_some_and(|u| u.enabled) {
            return self.reject_equalised(name, password);
        }
        if self.cache_check(name, password) {
            return true;
        }
        // Phase 1 — CPU-bound hashing + entry/claim-state checks, under
        // a hashing permit. The permit is owned by the closure and
        // dropped when it returns, i.e. before any claim_lock or
        // users-file wait.
        let Ok(permit) = self.verify_slots.clone().acquire_owned().await else {
            return false;
        };
        let name = name.to_owned();
        let password = password.to_owned();
        let prepared = {
            let state = self.clone();
            let name = name.clone();
            let password = password.clone();
            tokio::task::spawn_blocking(move || {
                let _permit = permit;
                state.verify_prepare(&name, &password)
            })
            .await
            .unwrap_or(Prepared::Done(false))
        };

        // Phase 2 — claim persistence: post-mutex re-check, lazy
        // fallback snapshot, cross-process file I/O. NO hashing permit
        // held here (R7-03): claims parked on the users-file lock must
        // not starve other users' hashing.
        //
        // P1-01: before any blocking thread is spent, the claimant
        // (1) takes the per-account claim gate — deduplicating
        // concurrent claims for the same account asynchronously — and
        // re-checks the committed hash it may now find, then (2) awaits
        // a `claim_slots` permit asynchronously and moves it into the
        // `spawn_blocking` closure. The permit therefore lives until the
        // persistence work actually finishes, even if THIS future is
        // cancelled while awaiting the closure; a cancelled waiter never
        // occupied a blocking thread in the first place. The gate guard
        // travels WITH the closure for the same reason (R3-P3-02): a
        // guard held only in this frame would be dropped by cancellation
        // while the non-cancellable closure keeps running, letting a
        // same-account follower start a second claim for the account.
        // In the fast-path branch (a committed hash is already there)
        // the owned guard is simply dropped with the block — there is
        // no persistence work left to protect.
        let work = match prepared {
            Prepared::Done(ok) => return ok,
            Prepared::Claim(work) => work,
        };
        let outcome = {
            let gate = self.claim_gate(&work.name);
            let gate_guard = gate.lock_owned().await;
            // A concurrent claim for this account (or a disk value
            // adopted from a concurrent CLI edit) may have committed
            // while we hashed and queued — resolve as a plain login
            // against the committed hash without entering the claim
            // machinery at all.
            if let Some(claimed_hash) = self.claimed_hash_if_any(work.index) {
                ClaimOutcome::VerifyAgainst(claimed_hash)
            } else {
                let Ok(permit) = self.claim_slots.clone().acquire_owned().await else {
                    return false;
                };
                let state = self.clone();
                tokio::task::spawn_blocking(move || {
                    let _permit = permit;
                    let _gate_guard = gate_guard;
                    state.claim_commit(work)
                })
                .await
                .unwrap_or(ClaimOutcome::Done(false))
            }
        };

        // Phase 3 — verify against a committed hash (a concurrent claim
        // winner or a disk value adopted from a concurrent CLI edit).
        // Back under a hashing permit: this is real Argon2 work.
        let stored_hash = match outcome {
            ClaimOutcome::Done(ok) => return ok,
            ClaimOutcome::VerifyAgainst(stored_hash) => stored_hash,
        };
        let Ok(permit) = self.verify_slots.clone().acquire_owned().await else {
            return false;
        };
        let state = self.clone();
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            state.verify_against_committed(&name, &stored_hash, &password)
        })
        .await
        .unwrap_or(false)
    }

    /// P1-01: per-account claim gate (see `claim_gates`). Returns a
    /// clone of the account's gate; the std guard is dropped before
    /// returning so the async lock is awaited without any sync guard
    /// held across an `.await`. Callers take the lock with
    /// `lock_owned`, producing a self-owned guard that can be moved
    /// into the phase-2 blocking closure (R3-P3-02).
    fn claim_gate(&self, name: &str) -> Arc<tokio::sync::Mutex<()>> {
        let mut gates = self.claim_gates.lock().expect("claim gates poisoned");
        gates.entry(name.to_owned()).or_default().clone()
    }

    /// SEC-03: equalised rejection for unknown/disabled names — the
    /// same single comparison as the known-name cache check, against a
    /// fixed dummy whose outcome is discarded, then `false`. Never
    /// touches the cache, the hashing slots, or the claim machinery.
    fn reject_equalised(&self, _name: &str, password: &str) -> bool {
        #[cfg(test)]
        self.note_compare();
        let _ = bool::from(DUMMY_PASSWORD.as_slice().ct_eq(password.as_bytes()));
        false
    }

    /// First step of every login: the remembered password of `name`
    /// against the presented one (one constant-time comparison).
    /// Counted by the SEC-03 test seam.
    fn cache_check(&self, name: &str, password: &str) -> bool {
        #[cfg(test)]
        self.note_compare();
        self.cache_matches(name, password)
    }

    pub(super) fn cache_matches(&self, name: &str, password: &str) -> bool {
        self.cache
            .get(name)
            .is_some_and(|cached| cached.value().matches(password.as_bytes()))
    }

    /// Verify a username + password pair. `false` on any failure —
    /// unknown user, disabled user, malformed stored hash, password
    /// mismatch — so the disabled-vs-unknown distinction never leaks
    /// to the client. Cache-first; falls back to Argon2 on miss; on a
    /// `"init"` placeholder, atomically claims the password for the
    /// account and persists it to disk.
    ///
    /// Test-only after R7-03: production goes through `verify_async`
    /// (SOCKS5 + HTTP handlers). Synchronous composition of the same
    /// three phases — prepare, commit, verify-against-committed — with
    /// no semaphore involvement.
    #[allow(dead_code)]
    pub fn verify(&self, name: &str, password: &str) -> bool {
        match self.verify_prepare(name, password) {
            Prepared::Done(ok) => ok,
            Prepared::Claim(work) => match self.claim_commit(work) {
                ClaimOutcome::Done(ok) => ok,
                ClaimOutcome::VerifyAgainst(stored_hash) => {
                    self.verify_against_committed(name, &stored_hash, password)
                }
            },
        }
    }

    /// Plain Argon2 login against an already-committed hash — a
    /// concurrent claim winner, a disk value adopted from a concurrent
    /// CLI edit, or simply the stored hash. Populates the cache on
    /// success. Runs OUTSIDE any lock: a committed hash is immutable
    /// once published, so verifying after the claim mutex was released
    /// cannot observe a torn value.
    pub(super) fn verify_against_committed(
        &self,
        name: &str,
        stored_hash: &str,
        password: &str,
    ) -> bool {
        if argon2_verify(stored_hash, password) {
            self.cache
                .insert(name.to_string(), CachedPassword::new(password));
            true
        } else {
            false
        }
    }
}

pub(super) fn argon2_verify(stored_phc: &str, password: &str) -> bool {
    let Ok(parsed) = PasswordHash::new(stored_phc) else {
        return false;
    };
    // Fail closed: the verifier takes the algorithm and version from the
    // stored string, so anything but Argon2id v19 (or an absent version) must
    // be refused here. m/t/p floors are enforced by the parameter parser.
    if parsed.algorithm != argon2::ARGON2ID_IDENT || parsed.version.is_some_and(|v| v != 0x13) {
        return false;
    }
    argon2_instance()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok()
}
