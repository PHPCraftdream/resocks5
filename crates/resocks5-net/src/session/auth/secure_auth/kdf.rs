//! Key derivation and the per-user stored secret.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};

use argon2::{Algorithm, Argon2, Params, Version};
use tokio::sync::Semaphore;
use zeroize::Zeroizing;

use crate::error::SecureAuthError;

/// Length of the derived key `K` in bytes.
pub const KEY_LEN: usize = 32;
/// Length of a freshly generated salt in bytes.
pub const SALT_LEN: usize = 16;

/// Hard ceiling on `memory_kib` this crate ever derives with or accepts
/// from a peer (256 MiB). Argon2id parameters arrive over the wire in both
/// directions — a server offers them to the client, a client seals them in
/// an enrollment — so the ceiling bounds the worst-case memory burn a
/// hostile peer can trigger per proof, here and in the host process.
pub const MAX_MEMORY_KIB: u32 = 256 * 1024;
const MAX_ITERATIONS: u32 = 16;
const MAX_PARALLELISM: u32 = 16;
/// Longest salt a message may carry.
pub(crate) const MAX_SALT_LEN: usize = 64;

/// Argon2id cost parameters (version 0x13).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KdfParams {
    /// Memory cost in KiB.
    pub memory_kib: u32,
    /// Number of passes.
    pub iterations: u32,
    /// Degree of parallelism (lanes).
    pub parallelism: u32,
}

impl KdfParams {
    /// The default Argon2id cost: 4 MiB, 1 pass, 1 lane. Below the OWASP
    /// minimum (19 MiB, 2 passes) as a documented cost trade-off (see the
    /// project SECURITY notes). Hosts that prefer the OWASP cost override
    /// `enrollment_floor()` and pass a stronger `KdfParams` when enrolling
    /// or checking.
    pub const DEFAULT: KdfParams = KdfParams {
        memory_kib: 4096,
        iterations: 1,
        parallelism: 1,
    };

    /// Whether the values are inside the hard limits this crate will ever use
    /// (`memory_kib` at least `8 * parallelism` as Argon2 requires; at most
    /// 256 MiB, 16 passes, 16 lanes).
    pub fn is_in_range(&self) -> bool {
        self.parallelism >= 1
            && self.parallelism <= MAX_PARALLELISM
            && self.iterations >= 1
            && self.iterations <= MAX_ITERATIONS
            && self.memory_kib >= 8 * self.parallelism
            && self.memory_kib <= MAX_MEMORY_KIB
    }

    /// Whether every cost is at least that of `floor`.
    pub fn at_least(&self, floor: &KdfParams) -> bool {
        self.memory_kib >= floor.memory_kib
            && self.iterations >= floor.iterations
            && self.parallelism >= floor.parallelism
    }
}

impl Default for KdfParams {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// How long a caller waits for a derivation slot before giving up. A caller
/// that times out must treat the derivation as refused, not queue
/// unboundedly.
pub(crate) const DERIVATION_WAIT: std::time::Duration = std::time::Duration::from_secs(1);

/// A cap on concurrent Argon2id derivations. Key derivation is CPU- and
/// memory-heavy; a limiter keeps many simultaneous logins from multiplying
/// that cost without bound: a caller takes a slot with [`acquire`], waits at
/// most a short constant time for one, and refuses the login instead of
/// queueing when none frees up.
///
/// The server side of this crate uses one process-wide limiter
/// ([`derivation_limiter`]) through [`SecretStore::derivation_limiter`]; the
/// client side has its own, so a flood of inbound clear-text checks can never
/// starve the outbound key derivations of a host that is both a server and a
/// client. A host may give a store a limiter of its own.
///
/// [`acquire`]: DerivationLimiter::acquire
/// [`SecretStore::derivation_limiter`]: super::SecretStore::derivation_limiter
#[derive(Debug)]
pub struct DerivationLimiter {
    semaphore: Arc<Semaphore>,
    capacity: usize,
    granted: AtomicU64,
}

/// A held derivation slot; the cap frees up when it is dropped.
#[derive(Debug)]
pub struct DerivationPermit(#[allow(dead_code)] tokio::sync::OwnedSemaphorePermit);

impl DerivationLimiter {
    /// A limiter allowing `capacity` concurrent derivations (at least 1).
    pub fn new(capacity: usize) -> Self {
        let capacity = capacity.max(1);
        Self {
            semaphore: Arc::new(Semaphore::new(capacity)),
            capacity,
            granted: AtomicU64::new(0),
        }
    }

    /// The default cap: half the available parallelism, at least 1.
    fn for_this_machine() -> Self {
        let cpus = std::thread::available_parallelism()
            .map(usize::from)
            .unwrap_or(1);
        Self::new(cpus / 2)
    }

    /// How many derivations may run at once.
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// How many slots are free right now.
    pub fn available(&self) -> usize {
        self.semaphore.available_permits()
    }

    /// How many slots this limiter has granted since it was created.
    pub fn granted(&self) -> u64 {
        self.granted.load(Ordering::Relaxed)
    }

    /// One slot, waiting at most one second for it. `None` when the
    /// limiter stays saturated: the caller must not derive. Drop the permit
    /// when the derivation has finished.
    pub async fn acquire(&self) -> Option<DerivationPermit> {
        let semaphore = Arc::clone(&self.semaphore);
        match tokio::time::timeout(DERIVATION_WAIT, semaphore.acquire_owned()).await {
            Ok(Ok(permit)) => {
                self.granted.fetch_add(1, Ordering::Relaxed);
                Some(DerivationPermit(permit))
            }
            _ => None,
        }
    }
}

static SERVER_LIMITER: OnceLock<Arc<DerivationLimiter>> = OnceLock::new();
static CLIENT_LIMITER: OnceLock<Arc<DerivationLimiter>> = OnceLock::new();

/// The process-wide cap on server-side derivations: what the default
/// `SecretStore::derivation_limiter` returns. A host that derives itself —
/// for instance in its own `check_password` behind a cache — takes a slot
/// from it around each derivation.
pub fn derivation_limiter() -> &'static Arc<DerivationLimiter> {
    SERVER_LIMITER.get_or_init(|| Arc::new(DerivationLimiter::for_this_machine()))
}

/// The process-wide cap on client-side key derivations (separate from the
/// server's).
pub(crate) fn client_limiter() -> &'static Arc<DerivationLimiter> {
    CLIENT_LIMITER.get_or_init(|| Arc::new(DerivationLimiter::for_this_machine()))
}

/// `K = Argon2id(password, salt, params)`, [`KEY_LEN`] bytes, wiped on drop.
///
/// # Errors
///
/// [`SecureAuthError::KdfOutOfRange`] for parameters outside the hard limits,
/// [`SecureAuthError::BadLength`] for a salt that is empty or longer than 64
/// bytes, [`SecureAuthError::Kdf`] if the implementation refuses the inputs.
pub fn derive_key(
    password: &[u8],
    salt: &[u8],
    params: &KdfParams,
) -> Result<Zeroizing<[u8; KEY_LEN]>, SecureAuthError> {
    if !params.is_in_range() {
        return Err(SecureAuthError::KdfOutOfRange);
    }
    // Argon2 itself needs at least 8 bytes of salt.
    if salt.len() < 8 || salt.len() > MAX_SALT_LEN {
        return Err(SecureAuthError::BadLength);
    }
    let argon_params = Params::new(
        params.memory_kib,
        params.iterations,
        params.parallelism,
        Some(KEY_LEN),
    )
    .map_err(|_| SecureAuthError::Kdf)?;
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, argon_params)
        .hash_password_into(password, salt, key.as_mut_slice())
        .map_err(|_| SecureAuthError::Kdf)?;
    Ok(key)
}

/// What a server stores for one user instead of a password: the salt, the cost
/// parameters and the derived key. Debug never prints the key.
#[derive(Clone)]
pub struct UserSecret {
    /// The salt the key was derived with.
    pub salt: Vec<u8>,
    /// The cost parameters the key was derived with.
    pub params: KdfParams,
    key: Zeroizing<[u8; KEY_LEN]>,
}

impl UserSecret {
    /// Build from stored parts.
    ///
    /// # Errors
    ///
    /// [`SecureAuthError::BadLength`] for a salt outside `8..=64` bytes,
    /// [`SecureAuthError::KdfOutOfRange`] for parameters outside the hard limits.
    pub fn from_parts(
        salt: Vec<u8>,
        params: KdfParams,
        key: [u8; KEY_LEN],
    ) -> Result<Self, SecureAuthError> {
        if salt.len() < 8 || salt.len() > MAX_SALT_LEN {
            return Err(SecureAuthError::BadLength);
        }
        if !params.is_in_range() {
            return Err(SecureAuthError::KdfOutOfRange);
        }
        Ok(Self {
            salt,
            params,
            key: Zeroizing::new(key),
        })
    }

    /// Enroll a password: a fresh random salt and the derived key.
    ///
    /// # Errors
    ///
    /// As [`derive_key`], or [`SecureAuthError::Kdf`] when the OS random source
    /// fails.
    pub fn from_password(password: &str, params: KdfParams) -> Result<Self, SecureAuthError> {
        let mut salt = vec![0u8; SALT_LEN];
        getrandom::getrandom(&mut salt).map_err(|_| SecureAuthError::Kdf)?;
        let key = derive_key(password.as_bytes(), &salt, &params)?;
        Ok(Self { salt, params, key })
    }

    /// The derived key (for the proof computation and for persisting).
    pub fn key(&self) -> &[u8; KEY_LEN] {
        &self.key
    }
}

impl std::fmt::Debug for UserSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("UserSecret { .. }")
    }
}
