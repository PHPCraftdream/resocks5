use anyhow::{anyhow, Result};
use argon2::password_hash::{PasswordHasher, SaltString};

use crate::auth::params::argon2_instance;

/// Hash a fresh password into a self-contained PHC string — embeds the
/// algorithm, parameters, salt, and hash bytes in one line. Used by the
/// CLI when adding a user or changing a password; `AuthState::verify`
/// reads it back via `PasswordHash::new`.
pub fn compute_hash(password: &str) -> Result<String> {
    let mut salt_bytes = [0u8; 16];
    getrandom::getrandom(&mut salt_bytes)
        .map_err(|e| anyhow!("OS random source unavailable: {}", e))?;
    let salt =
        SaltString::encode_b64(&salt_bytes).map_err(|e| anyhow!("salt encode failed: {}", e))?;
    let phc = argon2_instance()
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| anyhow!("Argon2 hash failed: {}", e))?
        .to_string();
    Ok(phc)
}
