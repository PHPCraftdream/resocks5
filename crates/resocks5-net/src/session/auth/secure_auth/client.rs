//! The client side of the exchange.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use subtle::ConstantTimeEq;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use x25519_dalek::{EphemeralSecret, PublicKey};
use zeroize::Zeroizing;

use super::init::{self, PUBLIC_LEN};
use super::kdf::{derive_key, KdfParams, UserSecret, KEY_LEN};
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
    allow_enrollment: bool,
    enrollment_kdf: KdfParams,
    /// Process-unique id: the derived keys live in [`KEY_CACHE`] under it, so
    /// the credentials themselves stay free of interior mutability (they sit
    /// inside `ProxyConfig`, which is hashed as part of chain keys).
    id: u64,
}

/// Derived keys of live credentials, by credentials id. Bounded; entries go
/// when their credentials are dropped.
static KEY_CACHE: Mutex<Vec<Cached>> = Mutex::new(Vec::new());
static NEXT_ID: AtomicU64 = AtomicU64::new(1);
const KEY_CACHE_CAP: usize = 1024;

struct Cached {
    owner: u64,
    salt: Vec<u8>,
    params: KdfParams,
    key: Zeroizing<[u8; KEY_LEN]>,
}

impl SecureCredentials {
    /// Credentials with the default KDF floor ([`KdfParams::DEFAULT`]). An
    /// empty user name or password is accepted here but refused at the first
    /// exchange (`BadLength`); `try_new` refuses up front.
    pub fn new(user: impl Into<String>, password: impl Into<String>) -> Self {
        Self {
            user: user.into(),
            password: Zeroizing::new(password.into()),
            min_kdf: KdfParams::DEFAULT,
            allow_enrollment: false,
            enrollment_kdf: KdfParams::DEFAULT,
            id: NEXT_ID.fetch_add(1, Ordering::Relaxed),
        }
    }

    /// Like [`SecureCredentials::new`], but refuses an empty user name or
    /// password with [`SecureAuthError::BadLength`].
    ///
    /// # Errors
    ///
    /// [`SecureAuthError::BadLength`] when either field is empty.
    pub fn try_new(
        user: impl Into<String>,
        password: impl Into<String>,
    ) -> Result<Self, SecureAuthError> {
        let credentials = Self::new(user, password);
        if credentials.user.is_empty() || credentials.password.is_empty() {
            return Err(SecureAuthError::BadLength);
        }
        Ok(credentials)
    }

    /// Enroll when the server says the user is waiting for its first secret
    /// (`init`). Off by default: a man in the middle could otherwise claim
    /// "init" to an already enrolled client and pose as its server. Turn it on
    /// for the first-time setup only.
    #[must_use]
    pub fn allow_enrollment(mut self, allow: bool) -> Self {
        self.allow_enrollment = allow;
        self
    }

    /// The key-derivation cost of a new enrollment (default
    /// [`KdfParams::DEFAULT`]; the server refuses one below its own floor).
    #[must_use]
    pub fn with_enrollment_kdf(mut self, params: KdfParams) -> Self {
        self.enrollment_kdf = params;
        self
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
        KEY_CACHE
            .lock()
            .unwrap()
            .iter()
            .any(|cached| cached.owner == self.id)
    }

    fn remember(&self, salt: &[u8], params: KdfParams, key: &[u8; KEY_LEN]) {
        let mut cache = KEY_CACHE.lock().expect("key cache poisoned");
        cache.retain(|cached| cached.owner != self.id);
        if cache.len() >= KEY_CACHE_CAP {
            cache.remove(0);
        }
        cache.push(Cached {
            owner: self.id,
            salt: salt.to_vec(),
            params,
            key: Zeroizing::new(*key),
        });
    }

    /// The key for `salt`/`params`: the cached one, or derived (on the blocking
    /// pool: Argon2id is CPU- and memory-heavy) and cached. The derivation
    /// holds one process-wide permit (see [`super::kdf::derivation_permit`]);
    /// when the limiter is saturated, the login fails with
    /// [`SecureAuthError::Kdf`] instead of queueing unboundedly.
    async fn key_for(
        &self,
        salt: &[u8],
        params: &KdfParams,
    ) -> Result<Zeroizing<[u8; KEY_LEN]>, SecureAuthError> {
        if let Some(cached) = KEY_CACHE
            .lock()
            .expect("key cache poisoned")
            .iter()
            .find(|cached| cached.owner == self.id)
        {
            if cached.salt == salt && cached.params == *params {
                return Ok(cached.key.clone());
            }
        }
        let Some(_permit) = super::kdf::client_limiter().acquire().await else {
            return Err(SecureAuthError::Kdf);
        };
        let password = Zeroizing::new(self.password.as_bytes().to_vec());
        let (salt_owned, params_owned) = (salt.to_vec(), *params);
        let key =
            tokio::task::spawn_blocking(move || derive_key(&password, &salt_owned, &params_owned))
                .await
                .map_err(|_| SecureAuthError::Kdf)??;
        drop(_permit);
        self.remember(salt, *params, &key);
        Ok(key)
    }
}

impl Drop for SecureCredentials {
    fn drop(&mut self) {
        if let Ok(mut cache) = KEY_CACHE.lock() {
            cache.retain(|cached| cached.owner != self.id);
        }
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
    if credentials.password.is_empty() {
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
    if head[1] == 1 {
        if !credentials.allow_enrollment {
            return Err(SecureAuthError::EnrollmentNotAllowed);
        }
        return enroll(stream, credentials, user, &cnonce).await;
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

/// The client side of a first-time enrollment (status 1 after the hello).
async fn enroll<S>(
    stream: &mut S,
    credentials: &SecureCredentials,
    user: &[u8],
    cnonce: &[u8; NONCE_LEN],
) -> Result<(), SecureAuthError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut offer = [0u8; PUBLIC_LEN + NONCE_LEN];
    stream.read_exact(&mut offer).await.map_err(io)?;
    let mut server_pub = [0u8; PUBLIC_LEN];
    server_pub.copy_from_slice(&offer[..PUBLIC_LEN]);
    let mut snonce = [0u8; NONCE_LEN];
    snonce.copy_from_slice(&offer[PUBLIC_LEN..]);

    let client_secret = EphemeralSecret::random();
    let client_pub = PublicKey::from(&client_secret).to_bytes();
    let shared = client_secret.diffie_hellman(&PublicKey::from(server_pub));
    if !shared.was_contributory() {
        return Err(SecureAuthError::Crypto);
    }

    // A fresh salt and the key, on the blocking pool (Argon2id). Like the
    // login derivation, this holds one process-wide permit; a saturated
    // limiter fails the enrollment instead of queueing.
    let Some(_permit) = super::kdf::client_limiter().acquire().await else {
        return Err(SecureAuthError::Kdf);
    };
    let password = Zeroizing::new(credentials.password.to_string());
    let params = credentials.enrollment_kdf;
    let secret = tokio::task::spawn_blocking(move || UserSecret::from_password(&password, params))
        .await
        .map_err(|_| SecureAuthError::Kdf)??;
    drop(_permit);
    let sealed = init::seal(
        &secret,
        shared.as_bytes(),
        &init::Transcript {
            user,
            cnonce,
            snonce: &snonce,
            client_pub: &client_pub,
            server_pub: &server_pub,
        },
    )?;
    let sealed_len = u16::try_from(sealed.len()).map_err(|_| SecureAuthError::BadLength)?;
    let mut message = Vec::with_capacity(1 + PUBLIC_LEN + 2 + sealed.len());
    message.push(VERSION);
    message.extend_from_slice(&client_pub);
    message.extend_from_slice(&sealed_len.to_be_bytes());
    message.extend_from_slice(&sealed);
    stream.write_all(&message).await.map_err(io)?;
    stream.flush().await.map_err(io)?;

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
    let expected = server_proof(secret.key(), user, cnonce, &snonce);
    if !bool::from(expected.ct_eq(&theirs)) {
        return Err(SecureAuthError::ServerProofMismatch);
    }
    // The enrolled key serves the following logins without a new derivation.
    credentials.remember(&secret.salt, secret.params, secret.key());
    Ok(())
}
