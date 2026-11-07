//! The server side of the exchange.

use std::future::Future;

use subtle::ConstantTimeEq;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use x25519_dalek::{EphemeralSecret, PublicKey};
use zeroize::Zeroizing;

use super::init::{self, MAX_SEALED_LEN, PUBLIC_LEN};
use super::kdf::{KdfParams, UserSecret, KEY_LEN, SALT_LEN};
use super::wire::{
    client_proof, decoy_material, encode_params, random_nonce, server_proof, NONCE_LEN, PROOF_LEN,
};
use super::VERSION;
use crate::error::SecureAuthError;

/// What a [`SecretStore`] holds for a user.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum StoredUser {
    /// An enrolled user: authenticate against this secret.
    Secret(UserSecret),
    /// A user waiting for its first secret: the first client that
    /// authenticates as it sets it (through [`SecretStore::claim`]).
    Init,
}

/// Where the server finds, and first stores, the secret of a user.
pub trait SecretStore: Send + Sync {
    /// What is stored for `user`, or `None` for an unknown or disabled user.
    /// The caller answers `None` with a decoy that is indistinguishable from a
    /// wrong password, so the answer never tells which names exist.
    fn lookup(&self, user: &str) -> impl Future<Output = Option<StoredUser>> + Send;

    /// Store `secret` for `user` if, and only if, the user is still waiting for
    /// its first secret; `true` when this call stored it. Must be atomic: of
    /// two concurrent first logins exactly one wins, and the other fails.
    fn claim(&self, user: &str, secret: UserSecret) -> impl Future<Output = bool> + Send;

    /// The cheapest key-derivation cost an enrollment may use; a sealed secret
    /// derived more cheaply is refused. Defaults to [`KdfParams::DEFAULT`].
    fn enrollment_floor(&self) -> KdfParams {
        KdfParams::DEFAULT
    }
}

/// A process-local random key from which the answers for unknown users are
/// derived: the same name always gets the same decoy salt, a different name a
/// different one, and nothing about them can be predicted from outside.
pub struct DecoyKey(Zeroizing<[u8; KEY_LEN]>);

impl DecoyKey {
    /// A fresh random key.
    ///
    /// # Errors
    ///
    /// [`SecureAuthError::Kdf`] when the OS random source fails.
    pub fn generate() -> Result<Self, SecureAuthError> {
        let mut key = Zeroizing::new([0u8; KEY_LEN]);
        getrandom::getrandom(key.as_mut_slice()).map_err(|_| SecureAuthError::Kdf)?;
        Ok(Self(key))
    }

    /// A key from fixed bytes (for tests).
    #[cfg(test)]
    pub(crate) fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    pub(super) fn decoy_secret(&self, user: &[u8]) -> UserSecret {
        let salt = decoy_material(&self.0, b"decoy salt", user)[..SALT_LEN].to_vec();
        let key = decoy_material(&self.0, b"decoy key", user);
        UserSecret::from_parts(salt, KdfParams::DEFAULT, key)
            .expect("decoy salt and default parameters are valid")
    }
}

impl std::fmt::Debug for DecoyKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("DecoyKey { .. }")
    }
}

fn io(error: std::io::Error) -> SecureAuthError {
    SecureAuthError::Io(error.kind())
}

async fn deny<S: AsyncWrite + Unpin>(stream: &mut S) -> Result<String, SecureAuthError> {
    stream.write_all(&[VERSION, 1]).await.map_err(io)?;
    stream.flush().await.map_err(io)?;
    Err(SecureAuthError::Denied)
}

async fn accept_with_proof<S: AsyncWrite + Unpin>(
    stream: &mut S,
    key: &[u8; KEY_LEN],
    user: String,
    cnonce: &[u8; NONCE_LEN],
    snonce: &[u8; NONCE_LEN],
) -> Result<String, SecureAuthError> {
    let proof = server_proof(key, user.as_bytes(), cnonce, snonce);
    let mut ok = Vec::with_capacity(2 + PROOF_LEN);
    ok.extend_from_slice(&[VERSION, 0]);
    ok.extend_from_slice(&proof);
    stream.write_all(&ok).await.map_err(io)?;
    stream.flush().await.map_err(io)?;
    Ok(user)
}

/// Run the server side of the exchange on `stream`, which must already be past
/// the SOCKS5 method selection that chose [`METHOD`](super::METHOD). Returns the
/// authenticated user name.
///
/// An unknown or disabled user is answered with a decoy salt and parameters and
/// fails at the proof, exactly like a wrong password. A user in the `init`
/// state is enrolled by this client (see the `init` module docs).
///
/// # Errors
///
/// [`SecureAuthError::Denied`] when the proof does not verify or a concurrent
/// first login won the claim (the client was told), `Crypto`/`KdfTooWeak` for a
/// bad enrollment, `BadVersion`/`BadLength` for malformed messages, `Io` when
/// the stream breaks.
///
/// cancel-safe: NO — a cancelled exchange must close the stream.
pub async fn server_authenticate<S, T>(
    stream: &mut S,
    store: &T,
    decoy: &DecoyKey,
) -> Result<String, SecureAuthError>
where
    S: AsyncRead + AsyncWrite + Unpin,
    T: SecretStore,
{
    // 1. client -> server
    let mut head = [0u8; 2];
    stream.read_exact(&mut head).await.map_err(io)?;
    if head[0] != VERSION {
        return Err(SecureAuthError::BadVersion);
    }
    let ulen = usize::from(head[1]);
    if ulen == 0 {
        return Err(SecureAuthError::BadLength);
    }
    let mut user_bytes = vec![0u8; ulen];
    stream.read_exact(&mut user_bytes).await.map_err(io)?;
    let mut cnonce = [0u8; NONCE_LEN];
    stream.read_exact(&mut cnonce).await.map_err(io)?;
    let user = String::from_utf8(user_bytes).map_err(|_| SecureAuthError::BadLength)?;

    let snonce = random_nonce()?;
    let (secret, known) = match store.lookup(&user).await {
        Some(StoredUser::Secret(secret)) => (secret, true),
        Some(StoredUser::Init) => return enroll(stream, store, user, cnonce, snonce).await,
        None => (decoy.decoy_secret(user.as_bytes()), false),
    };

    // 2. server -> client
    let mut offer = Vec::with_capacity(3 + secret.salt.len() + 6 + NONCE_LEN);
    offer.extend_from_slice(&[
        VERSION,
        0,
        u8::try_from(secret.salt.len()).unwrap_or(u8::MAX),
    ]);
    offer.extend_from_slice(&secret.salt);
    offer.extend_from_slice(&encode_params(&secret.params));
    offer.extend_from_slice(&snonce);
    stream.write_all(&offer).await.map_err(io)?;
    stream.flush().await.map_err(io)?;

    // 3. client -> server
    let mut reply_head = [0u8; 1];
    stream.read_exact(&mut reply_head).await.map_err(io)?;
    if reply_head[0] != VERSION {
        return Err(SecureAuthError::BadVersion);
    }
    let mut theirs = [0u8; PROOF_LEN];
    stream.read_exact(&mut theirs).await.map_err(io)?;
    let expected = client_proof(
        secret.key(),
        user.as_bytes(),
        &snonce,
        &cnonce,
        &secret.salt,
        &secret.params,
    );
    // The comparison runs for decoys too; the verdict is `known && match`.
    let matches = bool::from(expected.ct_eq(&theirs));

    // 4. server -> client
    if !(known && matches) {
        return deny(stream).await;
    }
    accept_with_proof(stream, secret.key(), user, &cnonce, &snonce).await
}

/// The `init` branch: offer a key exchange, open the sealed secret, claim it.
async fn enroll<S, T>(
    stream: &mut S,
    store: &T,
    user: String,
    cnonce: [u8; NONCE_LEN],
    snonce: [u8; NONCE_LEN],
) -> Result<String, SecureAuthError>
where
    S: AsyncRead + AsyncWrite + Unpin,
    T: SecretStore,
{
    let server_secret = EphemeralSecret::random();
    let server_pub = PublicKey::from(&server_secret).to_bytes();
    let mut offer = Vec::with_capacity(2 + PUBLIC_LEN + NONCE_LEN);
    offer.extend_from_slice(&[VERSION, 1]);
    offer.extend_from_slice(&server_pub);
    offer.extend_from_slice(&snonce);
    stream.write_all(&offer).await.map_err(io)?;
    stream.flush().await.map_err(io)?;

    let mut head = [0u8; 1 + PUBLIC_LEN + 2];
    stream.read_exact(&mut head).await.map_err(io)?;
    if head[0] != VERSION {
        return Err(SecureAuthError::BadVersion);
    }
    let mut client_pub = [0u8; PUBLIC_LEN];
    client_pub.copy_from_slice(&head[1..1 + PUBLIC_LEN]);
    let sealed_len = usize::from(u16::from_be_bytes([
        head[1 + PUBLIC_LEN],
        head[2 + PUBLIC_LEN],
    ]));
    if sealed_len == 0 || sealed_len > MAX_SEALED_LEN {
        return Err(SecureAuthError::BadLength);
    }
    let mut sealed = vec![0u8; sealed_len];
    stream.read_exact(&mut sealed).await.map_err(io)?;

    let shared = server_secret.diffie_hellman(&PublicKey::from(client_pub));
    if !shared.was_contributory() {
        return Err(SecureAuthError::Crypto);
    }
    let secret = init::open(
        &store.enrollment_floor(),
        &sealed,
        shared.as_bytes(),
        &init::Transcript {
            user: user.as_bytes(),
            cnonce: &cnonce,
            snonce: &snonce,
            client_pub: &client_pub,
            server_pub: &server_pub,
        },
    )?;
    let key = Zeroizing::new(*secret.key());
    if !store.claim(&user, secret).await {
        // A concurrent first login won; this one is not authenticated.
        return deny(stream).await;
    }
    accept_with_proof(stream, &key, user, &cnonce, &snonce).await
}
