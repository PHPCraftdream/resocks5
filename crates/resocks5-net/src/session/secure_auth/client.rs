//! The client side of the exchange.

use std::sync::Mutex;

use subtle::ConstantTimeEq;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use zeroize::Zeroizing;

use super::kdf::{derive_key, KdfParams, KEY_LEN};
use super::wire::{client_proof, decode_params, random_nonce, server_proof, NONCE_LEN, PROOF_LEN};
use super::VERSION;
use crate::error::SecureAuthError;

/// A user name and password for [`client_authenticate`]. The password stays in
/// this process: only the derived key is used, and it is cached after the first
/// exchange (per salt and parameters), so the Argon2id cost is paid once per
/// process and server, not per connection. Debug prints neither.
pub struct SecureCredentials {
    user: String,
    password: Zeroizing<String>,
    min_kdf: KdfParams,
    cached: Mutex<Option<Cached>>,
}

struct Cached {
    salt: Vec<u8>,
    params: KdfParams,
    key: Zeroizing<[u8; KEY_LEN]>,
}

impl SecureCredentials {
    /// Credentials with the default KDF floor ([`KdfParams::DEFAULT`]).
    pub fn new(user: impl Into<String>, password: impl Into<String>) -> Self {
        Self {
            user: user.into(),
            password: Zeroizing::new(password.into()),
            min_kdf: KdfParams::DEFAULT,
            cached: Mutex::new(None),
        }
    }

    /// Refuse a server that offers a KDF cheaper than `floor` (a downgrade
    /// would let an attacker pose as the server and harvest a cheaply
    /// attackable proof). The default floor is [`KdfParams::DEFAULT`].
    #[must_use]
    pub fn with_min_kdf(mut self, floor: KdfParams) -> Self {
        self.min_kdf = floor;
        self
    }

    /// The user name.
    pub fn user(&self) -> &str {
        &self.user
    }

    /// Whether a derived key is already cached.
    #[cfg(test)]
    pub(crate) fn is_cached(&self) -> bool {
        self.cached.lock().unwrap().is_some()
    }

    /// The key for `salt`/`params`: the cached one, or derived (on the blocking
    /// pool: Argon2id is CPU- and memory-heavy) and cached.
    async fn key_for(
        &self,
        salt: &[u8],
        params: &KdfParams,
    ) -> Result<Zeroizing<[u8; KEY_LEN]>, SecureAuthError> {
        if let Some(cached) = self.cached.lock().expect("key cache poisoned").as_ref() {
            if cached.salt == salt && cached.params == *params {
                return Ok(cached.key.clone());
            }
        }
        let password = Zeroizing::new(self.password.as_bytes().to_vec());
        let (salt_owned, params_owned) = (salt.to_vec(), *params);
        let key =
            tokio::task::spawn_blocking(move || derive_key(&password, &salt_owned, &params_owned))
                .await
                .map_err(|_| SecureAuthError::Kdf)??;
        *self.cached.lock().expect("key cache poisoned") = Some(Cached {
            salt: salt.to_vec(),
            params: *params,
            key: key.clone(),
        });
        Ok(key)
    }
}

impl std::fmt::Debug for SecureCredentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SecureCredentials { .. }")
    }
}

fn io(error: std::io::Error) -> SecureAuthError {
    SecureAuthError::Io(error.kind())
}

/// Run the client side of the exchange on `stream`, which must already be
/// past the SOCKS5 method selection that chose [`METHOD`](super::METHOD).
/// Succeeds only when the server proved it holds the user's key too.
///
/// # Errors
///
/// A [`SecureAuthError`]: `Denied`/`Refused` when the server rejects the
/// proof or the user, `ServerProofMismatch` when the server fails to prove it
/// holds the key, `KdfTooWeak`/`KdfOutOfRange` for parameters outside the
/// floor or the hard limits, and `BadVersion`/`BadLength`/`Io` for a malformed
/// or broken exchange.
///
/// cancel-safe: NO — a cancelled exchange must close the stream.
pub async fn client_authenticate<S>(
    stream: &mut S,
    credentials: &SecureCredentials,
) -> Result<(), SecureAuthError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let user = credentials.user.as_bytes();
    let ulen = u8::try_from(user.len()).map_err(|_| SecureAuthError::BadLength)?;
    if ulen == 0 {
        return Err(SecureAuthError::BadLength);
    }
    let cnonce = random_nonce()?;

    // 1. client -> server
    let mut first = Vec::with_capacity(2 + user.len() + NONCE_LEN);
    first.extend_from_slice(&[VERSION, ulen]);
    first.extend_from_slice(user);
    first.extend_from_slice(&cnonce);
    stream.write_all(&first).await.map_err(io)?;
    stream.flush().await.map_err(io)?;

    // 2. server -> client
    let mut head = [0u8; 2];
    stream.read_exact(&mut head).await.map_err(io)?;
    if head[0] != VERSION {
        return Err(SecureAuthError::BadVersion);
    }
    if head[1] == 0xFF {
        return Err(SecureAuthError::Refused);
    }
    if head[1] != 0 {
        return Err(SecureAuthError::BadVersion);
    }
    let slen = usize::from(stream.read_u8().await.map_err(io)?);
    if !(8..=super::kdf::MAX_SALT_LEN).contains(&slen) {
        return Err(SecureAuthError::BadLength);
    }
    let mut salt = vec![0u8; slen];
    stream.read_exact(&mut salt).await.map_err(io)?;
    let mut raw_params = [0u8; 6];
    stream.read_exact(&mut raw_params).await.map_err(io)?;
    let params = decode_params(raw_params);
    let mut snonce = [0u8; NONCE_LEN];
    stream.read_exact(&mut snonce).await.map_err(io)?;

    // The offered cost is checked BEFORE any work is spent on it.
    if !params.is_in_range() {
        return Err(SecureAuthError::KdfOutOfRange);
    }
    if !params.at_least(&credentials.min_kdf) {
        return Err(SecureAuthError::KdfTooWeak);
    }
    let key = credentials.key_for(&salt, &params).await?;

    // 3. client -> server
    let proof = client_proof(&key, user, &snonce, &cnonce, &salt, &params);
    let mut second = Vec::with_capacity(1 + PROOF_LEN);
    second.push(VERSION);
    second.extend_from_slice(&proof);
    stream.write_all(&second).await.map_err(io)?;
    stream.flush().await.map_err(io)?;

    // 4. server -> client
    let mut reply = [0u8; 2];
    stream.read_exact(&mut reply).await.map_err(io)?;
    if reply[0] != VERSION {
        return Err(SecureAuthError::BadVersion);
    }
    match reply[1] {
        0 => {}
        1 => return Err(SecureAuthError::Denied),
        _ => return Err(SecureAuthError::BadVersion),
    }
    let mut theirs = [0u8; PROOF_LEN];
    stream.read_exact(&mut theirs).await.map_err(io)?;
    let expected = server_proof(&key, user, &cnonce, &snonce);
    if !bool::from(expected.ct_eq(&theirs)) {
        return Err(SecureAuthError::ServerProofMismatch);
    }
    Ok(())
}
