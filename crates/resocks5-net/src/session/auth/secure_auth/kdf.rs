//! Key derivation and the per-user stored secret.

use argon2::{Algorithm, Argon2, Params, Version};
use zeroize::Zeroizing;

use crate::error::SecureAuthError;

/// Length of the derived key `K` in bytes.
pub const KEY_LEN: usize = 32;
/// Length of a freshly generated salt in bytes.
pub const SALT_LEN: usize = 16;

/// Hard upper limits a client accepts from a server (a malicious server must
/// not be able to make it allocate gigabytes or burn minutes).
const MAX_MEMORY_KIB: u32 = 1 << 20; // 1 GiB
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
    /// The OWASP minimum for Argon2id: 19 MiB, 2 passes, 1 lane.
    pub const DEFAULT: KdfParams = KdfParams {
        memory_kib: 19 * 1024,
        iterations: 2,
        parallelism: 1,
    };

    /// Whether the values are inside the hard limits this crate will ever use
    /// (`memory_kib` at least `8 * parallelism` as Argon2 requires; at most
    /// 1 GiB, 16 passes, 16 lanes).
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
