use anyhow::{anyhow, Result};
use resocks5_net::secure_auth::{KdfParams, UserSecret};

use crate::auth::secret::encode_secret;

/// Derive the stored secret for a fresh password: an Argon2id v19 PHC string
/// with a random salt (see `auth::secret`). Used by the CLI when adding a
/// user or changing a password, at the cost `auth.argon2` configures; the
/// password itself is not kept.
pub fn compute_hash_with(password: &str, params: KdfParams) -> Result<String> {
    let secret = UserSecret::from_password(password, params)
        .map_err(|e| anyhow!("secret derivation failed: {e}"))?;
    Ok(encode_secret(&secret))
}

/// Test-build shorthand: the cheap test cost.
#[cfg(test)]
pub fn compute_hash(password: &str) -> Result<String> {
    compute_hash_with(password, crate::auth::params::TEST)
}
