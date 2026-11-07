use anyhow::{anyhow, Result};
use resocks5_net::secure_auth::UserSecret;

use crate::auth::params::new_secret_params;
use crate::auth::secret::encode_secret;

/// Derive the stored secret for a fresh password: an Argon2id v19 PHC string
/// with a random salt (see `auth::secret`). Used by the CLI when adding a
/// user or changing a password; the password itself is not kept.
pub fn compute_hash(password: &str) -> Result<String> {
    let secret = UserSecret::from_password(password, new_secret_params())
        .map_err(|e| anyhow!("secret derivation failed: {e}"))?;
    Ok(encode_secret(&secret))
}
