use argon2::password_hash::{PasswordHash, PasswordVerifier};
use std::sync::Arc;

use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;

use super::claim::{ClaimOutcome, Prepared};
use super::AuthState;
use crate::auth::params::argon2_instance;

impl AuthState {
    /// cancel-safe: NO — an admitted init-claim may still complete its
    /// persistence after cancellation. Permits, however, are held only
    /// around the hashing phases (R7-03): the persistence wait in
    /// `claim_commit` runs without one, so a claim parked on the
    /// users-file lock does not consume a hashing slot.
    pub async fn verify_async(self: &Arc<Self>, name: &str, password: &str) -> bool {
        if !self.entries.get(name).is_some_and(|u| u.enabled) {
            return false;
        }
        let candidate = compute_cache_hmac(&self.server_secret, name, password);
        if self.cache_matches(name, &candidate) {
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
                state.verify_prepare(&name, &password, candidate)
            })
            .await
            .unwrap_or(Prepared::Done(false))
        };

        // Phase 2 — claim persistence: post-mutex re-check, lazy
        // fallback snapshot, cross-process file I/O. NO hashing permit
        // held here (R7-03): claims parked on the users-file lock must
        // not starve other users' hashing.
        let work = match prepared {
            Prepared::Done(ok) => return ok,
            Prepared::Claim(work) => work,
        };
        let outcome = {
            let state = self.clone();
            tokio::task::spawn_blocking(move || state.claim_commit(work))
                .await
                .unwrap_or(ClaimOutcome::Done(false))
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
            state.verify_against_committed(&name, &stored_hash, &password, candidate)
        })
        .await
        .unwrap_or(false)
    }

    pub(super) fn cache_matches(&self, name: &str, candidate: &[u8; 32]) -> bool {
        self.cache
            .get(name)
            .is_some_and(|cached| bool::from(cached.value().ct_eq(candidate)))
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
        let candidate_hmac = compute_cache_hmac(&self.server_secret, name, password);
        match self.verify_prepare(name, password, candidate_hmac) {
            Prepared::Done(ok) => ok,
            Prepared::Claim(work) => match self.claim_commit(work) {
                ClaimOutcome::Done(ok) => ok,
                ClaimOutcome::VerifyAgainst(stored_hash) => {
                    self.verify_against_committed(name, &stored_hash, password, candidate_hmac)
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
        candidate_hmac: [u8; 32],
    ) -> bool {
        if argon2_verify(stored_hash, password) {
            self.cache.insert(name.to_string(), candidate_hmac);
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
    argon2_instance()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok()
}

pub(super) fn compute_cache_hmac(secret: &[u8; 32], name: &str, password: &str) -> [u8; 32] {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret).expect("HMAC accepts any key length");
    mac.update(name.as_bytes());
    // 0x00 separator so `("ab", "cd")` and `("a", "bcd")` don't collide.
    mac.update(&[0]);
    mac.update(password.as_bytes());
    mac.finalize().into_bytes().into()
}
