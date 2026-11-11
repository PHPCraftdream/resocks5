//! First-time enrollment ("init"): the first client that authenticates a user
//! still in the `init` state sets the secret, without the password (or the key)
//! ever crossing the wire in the clear.
//!
//! After the client's hello the server answers `1 | 1 | server_pub(32) | snonce(32)`
//! (status 1 = "this user is waiting for its first secret"). The client picks a
//! fresh salt and its enrollment [`KdfParams`], derives `K`, and sends
//! `1 | client_pub(32) | len(2, BE) | AEAD(salt_len | salt | params(6) | K)`:
//! ChaCha20-Poly1305 under a key from X25519(client, server) expanded with
//! HKDF-SHA256 over the whole transcript (user, both nonces, both public
//! keys), nonce zero (the key is used once). The server decrypts, stores the
//! secret atomically through [`SecretStore::claim`](super::SecretStore::claim)
//! and proves it holds `K` with the ordinary server proof.
//!
//! A passive observer learns nothing about the password or `K`. An active
//! attacker can intercept a first enrollment (trust on first use, as with any
//! "first one sets it" scheme), which is why a client enrolls only when told
//! to ([`SecureCredentials::allow_enrollment`](super::SecureCredentials::allow_enrollment)):
//! otherwise a man in the middle could claim "init" to an already enrolled
//! client and pose as its server.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

use super::kdf::{KdfParams, UserSecret, KEY_LEN, MAX_SALT_LEN};
use super::wire::{decode_params, encode_params, NONCE_LEN};
use crate::error::SecureAuthError;

/// X25519 public key length.
pub(crate) const PUBLIC_LEN: usize = 32;
const AEAD_LABEL: &[u8] = b"resocks5-secure/1 init";
/// Largest sealed payload: salt length byte, salt, params, key, AEAD tag.
pub(crate) const MAX_SEALED_LEN: usize = 1 + MAX_SALT_LEN + 6 + KEY_LEN + 16;

/// Everything an enrollment's keys are bound to.
pub(crate) struct Transcript<'a> {
    pub(crate) user: &'a [u8],
    pub(crate) cnonce: &'a [u8; NONCE_LEN],
    pub(crate) snonce: &'a [u8; NONCE_LEN],
    pub(crate) client_pub: &'a [u8; PUBLIC_LEN],
    pub(crate) server_pub: &'a [u8; PUBLIC_LEN],
}

/// The AEAD key for one enrollment, bound to the whole transcript.
fn aead_key(shared: &[u8; 32], t: &Transcript<'_>) -> Zeroizing<[u8; 32]> {
    let mut info = Vec::with_capacity(1 + t.user.len() + 2 * NONCE_LEN + 2 * PUBLIC_LEN);
    info.push(u8::try_from(t.user.len()).unwrap_or(u8::MAX));
    info.extend_from_slice(t.user);
    info.extend_from_slice(t.cnonce);
    info.extend_from_slice(t.snonce);
    info.extend_from_slice(t.client_pub);
    info.extend_from_slice(t.server_pub);
    let mut okm = Zeroizing::new([0u8; 32]);
    Hkdf::<Sha256>::new(Some(AEAD_LABEL), shared)
        .expand(&info, okm.as_mut_slice())
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    okm
}

/// The AEAD key as the cipher's key type (a view of `key`, no copy).
fn cipher_key(key: &Zeroizing<[u8; 32]>) -> &Key {
    <&Key>::try_from(key.as_slice()).expect("a 32-byte key")
}

fn aad(t: &Transcript<'_>) -> Vec<u8> {
    let mut aad = Vec::with_capacity(AEAD_LABEL.len() + 1 + t.user.len() + 2 * NONCE_LEN);
    aad.extend_from_slice(AEAD_LABEL);
    aad.push(u8::try_from(t.user.len()).unwrap_or(u8::MAX));
    aad.extend_from_slice(t.user);
    aad.extend_from_slice(t.cnonce);
    aad.extend_from_slice(t.snonce);
    aad
}

/// Seal the enrollment `secret` for the server (client side).
pub(crate) fn seal(
    secret: &UserSecret,
    shared: &[u8; 32],
    transcript: &Transcript<'_>,
) -> Result<Vec<u8>, SecureAuthError> {
    let key = aead_key(shared, transcript);
    let mut plain = Zeroizing::new(Vec::with_capacity(1 + secret.salt.len() + 6 + KEY_LEN));
    plain.push(u8::try_from(secret.salt.len()).map_err(|_| SecureAuthError::BadLength)?);
    plain.extend_from_slice(&secret.salt);
    plain.extend_from_slice(&encode_params(&secret.params));
    plain.extend_from_slice(secret.key());
    ChaCha20Poly1305::new(cipher_key(&key))
        .encrypt(
            &Nonce::default(),
            Payload {
                msg: &plain,
                aad: &aad(transcript),
            },
        )
        .map_err(|_| SecureAuthError::Crypto)
}

/// Open and validate a sealed enrollment (server side); a key derived more
/// cheaply than `floor` is refused.
pub(crate) fn open(
    floor: &KdfParams,
    sealed: &[u8],
    shared: &[u8; 32],
    transcript: &Transcript<'_>,
) -> Result<UserSecret, SecureAuthError> {
    let key = aead_key(shared, transcript);
    let plain = Zeroizing::new(
        ChaCha20Poly1305::new(cipher_key(&key))
            .decrypt(
                &Nonce::default(),
                Payload {
                    msg: sealed,
                    aad: &aad(transcript),
                },
            )
            .map_err(|_| SecureAuthError::Crypto)?,
    );
    let slen = usize::from(*plain.first().ok_or(SecureAuthError::BadLength)?);
    if plain.len() != 1 + slen + 6 + KEY_LEN {
        return Err(SecureAuthError::BadLength);
    }
    let salt = plain[1..1 + slen].to_vec();
    let mut raw_params = [0u8; 6];
    raw_params.copy_from_slice(&plain[1 + slen..1 + slen + 6]);
    let mut k = [0u8; KEY_LEN];
    k.copy_from_slice(&plain[1 + slen + 6..]);
    let secret = UserSecret::from_parts(salt, decode_params(raw_params), k);
    zeroize::Zeroize::zeroize(&mut k);
    let secret = secret?;
    // A server never stores a key derived with less than its floor.
    if !secret.params.at_least(floor) {
        return Err(SecureAuthError::KdfTooWeak);
    }
    Ok(secret)
}
