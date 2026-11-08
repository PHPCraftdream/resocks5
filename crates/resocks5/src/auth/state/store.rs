//! The secret store one connection authenticates against: the shared
//! [`AuthState`] seen through the peer's address. A user whose
//! `allowed_clients` rule rejects the peer is unknown here (decoy), and
//! cannot be enrolled from it.
//!
//! `check_password` (clear text) overrides the SDK default with a
//! verified-credential cache in front of the Argon2id derivation: legit HTTP
//! clients send Basic on every request, so a hit (same user/password pair,
//! same stored secret's key tag, not expired) is answered without deriving.
//! The cache stores only HMAC tags — never the password, never the key —
//! is invalidated by any change to the stored secret, is bounded and TTL-
//! limited, and caches SUCCESSES only: failed attempts never fill it.
//!
//! ## Flood bound
//!
//! A cache HIT never touches the derivation limiter. Every MISS that derives
//! (an enrolled user's check or an init enrollment) first takes a slot from
//! the state's limiter (the SDK's process-wide server-side one,
//! `resocks5_net::secure_auth::derivation_limiter`), waiting at most a short
//! constant time; when none frees up the attempt is REFUSED (`Rejected`)
//! instead of queued. An unknown, disabled, filtered or unusable name derives
//! nothing at all: a cheap sleep of the order of one derivation keeps its
//! answer's timing close to a wrong password's, without spending CPU. So a
//! couple of hundred false authorizations cannot pile up unbounded work.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use resocks5_net::secure_auth::{
    derive_key, DerivationLimiter, KdfParams, PasswordCheck, SecretStore, StoredUser, UserSecret,
};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use super::AuthState;

/// Wall-time filler for names that derive nothing (unknown, disabled,
/// filtered, unusable): of the order of one derivation at the default cost.
const UNKNOWN_USER_DELAY: Duration = Duration::from_millis(5);

pub struct PeerStore {
    auth: Arc<AuthState>,
    peer_ip: Option<IpAddr>,
}

impl PeerStore {
    pub(super) fn new(auth: Arc<AuthState>, peer_ip: Option<IpAddr>) -> Self {
        Self { auth, peer_ip }
    }
}

impl SecretStore for PeerStore {
    async fn lookup(&self, user: &str) -> Option<StoredUser> {
        if !self.auth.client_ip_allowed(user, self.peer_ip) {
            return None;
        }
        self.auth.lookup_secret(user)
    }

    async fn claim(&self, user: &str, secret: UserSecret) -> bool {
        self.auth.client_ip_allowed(user, self.peer_ip)
            && self.auth.claim_secret(user, secret).await
    }

    fn enrollment_floor(&self) -> KdfParams {
        self.auth.enrollment_floor
    }

    fn derivation_limiter(&self) -> &DerivationLimiter {
        &self.auth.limiter
    }

    async fn check_password(&self, user: &str, password: &str) -> PasswordCheck {
        // An empty clear-text password is refused outright: never derived,
        // never cached, never claiming.
        if password.is_empty() {
            return PasswordCheck::Rejected;
        }
        // IP filter and stored-secret lookup run BEFORE any derivation; a
        // filtered peer is answered exactly like an unknown name and can
        // never claim.
        let stored = if self.auth.client_ip_allowed(user, self.peer_ip) {
            self.auth.lookup_secret(user)
        } else {
            None
        };
        let tag = self.auth.password_cache.tag(user, password);
        if let Some(StoredUser::Secret(secret)) = &stored {
            let k_tag = self.auth.password_cache.tag_of(secret.key());
            if self.auth.password_cache.lookup(&tag, &k_tag) {
                return PasswordCheck::Accepted;
            }
        }
        match stored {
            // Unknown, disabled, filtered or unusable: derive nothing.
            None => {
                tokio::time::sleep(UNKNOWN_USER_DELAY).await;
                PasswordCheck::Rejected
            }
            // First login: enroll a fresh secret at the app's cost policy.
            // Never cached.
            Some(StoredUser::Init) => {
                let Some(_permit) = self.auth.limiter.acquire().await else {
                    return PasswordCheck::Rejected;
                };
                let pw = Zeroizing::new(password.to_string());
                let floor = self.auth.enrollment_floor;
                let derived =
                    tokio::task::spawn_blocking(move || UserSecret::from_password(&pw, floor))
                        .await;
                match derived {
                    Ok(Ok(secret)) => {
                        if self.auth.claim_secret(user, secret).await {
                            PasswordCheck::Claimed
                        } else {
                            PasswordCheck::Rejected
                        }
                    }
                    _ => PasswordCheck::Rejected,
                }
            }
            // Enrolled user: derive on the blocking pool, compare
            // constant-time; a success is cached, a failure is not.
            Some(StoredUser::Secret(secret)) => {
                let Some(_permit) = self.auth.limiter.acquire().await else {
                    return PasswordCheck::Rejected;
                };
                #[cfg(test)]
                self.auth
                    .derive_counter
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let pw = Zeroizing::new(password.as_bytes().to_vec());
                let salt = secret.salt.clone();
                let params = secret.params;
                let derived =
                    tokio::task::spawn_blocking(move || derive_key(&pw, &salt, &params)).await;
                match derived {
                    Ok(Ok(derived)) if bool::from(derived.ct_eq(secret.key())) => {
                        let k_tag = self.auth.password_cache.tag_of(secret.key());
                        self.auth.password_cache.insert(tag, k_tag);
                        PasswordCheck::Accepted
                    }
                    _ => PasswordCheck::Rejected,
                }
            }
            // `StoredUser` is non-exhaustive: an unknown state never admits.
            Some(_) => PasswordCheck::Rejected,
        }
    }
}
