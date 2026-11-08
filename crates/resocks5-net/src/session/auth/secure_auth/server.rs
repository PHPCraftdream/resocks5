//! The server side of the exchange.

use std::future::Future;

use subtle::ConstantTimeEq;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use x25519_dalek::{EphemeralSecret, PublicKey};
use zeroize::Zeroizing;

use super::init::{self, MAX_SEALED_LEN, PUBLIC_LEN};
use super::kdf::{derive_key, KdfParams, UserSecret, KEY_LEN, SALT_LEN};
use super::wire::{
    client_proof, decoy_material, encode_params, random_nonce, server_proof, NONCE_LEN, PROOF_LEN,
};
use super::VERSION;
use crate::error::SecureAuthError;

/// Wall-time filler for unknown users: cheap (no CPU) and of the same order
/// as one default-parameter derivation, so a missing name
/// does not answer noticeably faster than a wrong password.
const UNKNOWN_USER_DELAY: std::time::Duration = std::time::Duration::from_millis(5);

/// The verdict of [`SecretStore::check_password`], the clear-text half of the
/// one-secret-per-user model: the stored `UserSecret` (salt, parameters and
/// key) secures both the strong exchange and the clear-text methods, so a
/// user can enroll over secure auth and log in with RFC 1929 or HTTP Basic,
/// and the other way around. The verdict never reveals whether a user name
/// exists: unknown names answer `Rejected` exactly like wrong passwords.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum PasswordCheck {
    /// The password matched an enrolled user's stored secret.
    Accepted,
    /// The password matched and claimed a user still waiting for its first
    /// secret: this caller set the user's secret (`StoredUser::Init` →
    /// `StoredUser::Secret`).
    Claimed,
    /// Wrong password, unknown user, or an empty user name or password.
    Rejected,
}

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

    /// Verify a clear-text password (RFC 1929 UNAME/PASSWD or HTTP Basic)
    /// against the same store the strong exchange uses.
    ///
    /// The default implementation derives `Argon2id(password, salt, params)`
    /// from the looked-up [`UserSecret`] on the blocking pool and compares it
    /// to the stored key in constant time. Derivations are bounded by
    /// [`SecretStore::derivation_limiter`]: a caller that cannot get a slot
    /// within a short constant wait is answered [`PasswordCheck::Rejected`]
    /// without deriving, so a flood of clear-text attempts can never queue
    /// more derivations than the limiter has slots. A user still in the
    /// `init` state is claimed by deriving ONE fresh secret (at
    /// `enrollment_floor()`) and calling [`SecretStore::claim`] under the same
    /// limiter. An unknown or disabled user costs no derivation at all: the
    /// answer is delayed by a cheap fixed sleep of roughly one derivation's
    /// wall time (no CPU) and then [`PasswordCheck::Rejected`], so timing
    /// stays in the same order of magnitude without spending the machine. An
    /// empty user name or password is [`PasswordCheck::Rejected`]
    /// immediately, before any derivation or delay. Hosts exposed to
    /// clear-text login SHOULD override this method with a verified-credential
    /// cache: a cache hit answers without any Argon2id work, which is the
    /// only way to make repeated logins both fast and free of derivation
    /// cost.
    fn check_password(
        &self,
        user: &str,
        password: &str,
    ) -> impl Future<Output = PasswordCheck> + Send {
        let (user, password) = (user.to_owned(), Zeroizing::new(password.to_owned()));
        async move {
            if user.is_empty() || password.is_empty() {
                return PasswordCheck::Rejected;
            }
            match self.lookup(&user).await {
                Some(StoredUser::Secret(secret)) => {
                    let stored = Zeroizing::new(secret.key().to_owned());
                    let Some(permit) = self.derivation_limiter().acquire().await else {
                        // Limiter saturated: refuse without deriving.
                        return PasswordCheck::Rejected;
                    };
                    let derived = tokio::task::spawn_blocking(move || {
                        derive_key(password.as_bytes(), &secret.salt, &secret.params)
                    })
                    .await;
                    drop(permit);
                    match derived {
                        Ok(Ok(key)) if bool::from(key.as_slice().ct_eq(stored.as_slice())) => {
                            PasswordCheck::Accepted
                        }
                        _ => PasswordCheck::Rejected,
                    }
                }
                Some(StoredUser::Init) => {
                    let floor = self.enrollment_floor();
                    let Some(permit) = self.derivation_limiter().acquire().await else {
                        return PasswordCheck::Rejected;
                    };
                    let secret = tokio::task::spawn_blocking(move || {
                        UserSecret::from_password(&password, floor)
                    })
                    .await;
                    drop(permit);
                    match secret {
                        Ok(Ok(secret)) => {
                            if self.claim(&user, secret).await {
                                PasswordCheck::Claimed
                            } else {
                                PasswordCheck::Rejected
                            }
                        }
                        _ => PasswordCheck::Rejected,
                    }
                }
                // Unknown or disabled user: no derivation. One cheap sleep
                // (no CPU) keeps the answer's wall time near a real check.
                None => {
                    tokio::time::sleep(UNKNOWN_USER_DELAY).await;
                    PasswordCheck::Rejected
                }
            }
        }
    }

    /// The cap on concurrent Argon2id derivations `check_password` runs for
    /// this store. Defaults to the process-wide server-side limiter
    /// ([`derivation_limiter`](super::derivation_limiter)); a host may give a
    /// store a limiter of its own.
    fn derivation_limiter(&self) -> &super::DerivationLimiter {
        super::kdf::derivation_limiter()
    }

    /// The cheapest key-derivation cost an enrollment may use; a sealed secret
    /// derived more cheaply is refused. Defaults to [`KdfParams::DEFAULT`].
    fn enrollment_floor(&self) -> KdfParams {
        KdfParams::DEFAULT
    }
}

/// A process-local random key from which the answers for unknown users are
/// derived: the same name always gets the same decoy salt, a different name a
/// different one, and nothing about them can be predicted from outside.
///
/// The decoys advertise one set of Argon2id parameters; it should be the cost
/// the host stores its real secrets at, so an unknown name cannot be told
/// apart by the parameters it is offered.
pub struct DecoyKey {
    key: Zeroizing<[u8; KEY_LEN]>,
    params: KdfParams,
}

impl DecoyKey {
    /// A fresh random key whose decoys advertise [`KdfParams::DEFAULT`].
    ///
    /// # Errors
    ///
    /// [`SecureAuthError::Kdf`] when the OS random source fails.
    pub fn generate() -> Result<Self, SecureAuthError> {
        Self::generate_with(KdfParams::DEFAULT)
    }

    /// A fresh random key whose decoys advertise `params` — the cost the host
    /// stores its real secrets at.
    ///
    /// # Errors
    ///
    /// [`SecureAuthError::KdfOutOfRange`] when `params` are outside the
    /// limits this crate ever derives with; [`SecureAuthError::Kdf`] when the
    /// OS random source fails.
    pub fn generate_with(params: KdfParams) -> Result<Self, SecureAuthError> {
        if !params.is_in_range() {
            return Err(SecureAuthError::KdfOutOfRange);
        }
        let mut key = Zeroizing::new([0u8; KEY_LEN]);
        getrandom::getrandom(key.as_mut_slice()).map_err(|_| SecureAuthError::Kdf)?;
        Ok(Self { key, params })
    }

    /// A key from fixed bytes (for tests).
    #[cfg(test)]
    pub(crate) fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        Self::from_bytes_with(bytes, KdfParams::MIN)
    }

    /// Like [`Self::from_bytes`], advertising `params` (for tests).
    #[cfg(test)]
    pub(crate) fn from_bytes_with(bytes: [u8; KEY_LEN], params: KdfParams) -> Self {
        Self {
            key: Zeroizing::new(bytes),
            params,
        }
    }

    pub(super) fn decoy_secret(&self, user: &[u8]) -> UserSecret {
        let salt = decoy_material(&self.key, b"decoy salt", user)[..SALT_LEN].to_vec();
        let key = decoy_material(&self.key, b"decoy key", user);
        UserSecret::from_parts(salt, self.params, key)
            .expect("decoy salt and validated parameters are valid")
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
