//! Proof computation and nonces shared by both sides.

use hmac::{Hmac, Mac};
use sha2::Sha256;

use super::kdf::{KdfParams, KEY_LEN};
use crate::error::SecureAuthError;

/// Length of each side's random nonce.
pub(crate) const NONCE_LEN: usize = 32;
/// Length of a proof (an HMAC-SHA256 tag).
pub(crate) const PROOF_LEN: usize = 32;

const CLIENT_LABEL: &[u8] = b"resocks5-secure/1 client";
const SERVER_LABEL: &[u8] = b"resocks5-secure/1 server";

type HmacSha256 = Hmac<Sha256>;

/// A fresh random nonce from the OS.
pub(crate) fn random_nonce() -> Result<[u8; NONCE_LEN], SecureAuthError> {
    let mut nonce = [0u8; NONCE_LEN];
    getrandom::getrandom(&mut nonce).map_err(|_| SecureAuthError::Kdf)?;
    Ok(nonce)
}

/// The six parameter bytes of message 2: `m_kib(4, BE) | t | p`.
pub(crate) fn encode_params(params: &KdfParams) -> [u8; 6] {
    let mut out = [0u8; 6];
    out[..4].copy_from_slice(&params.memory_kib.to_be_bytes());
    out[4] = u8::try_from(params.iterations).unwrap_or(u8::MAX);
    out[5] = u8::try_from(params.parallelism).unwrap_or(u8::MAX);
    out
}

/// Inverse of [`encode_params`].
pub(crate) fn decode_params(bytes: [u8; 6]) -> KdfParams {
    KdfParams {
        memory_kib: u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
        iterations: u32::from(bytes[4]),
        parallelism: u32::from(bytes[5]),
    }
}

fn mac(key: &[u8; KEY_LEN]) -> HmacSha256 {
    // HMAC accepts a key of any length.
    HmacSha256::new_from_slice(key).expect("HMAC takes any key length")
}

/// The client's proof over the whole exchange (binds the user, both nonces
/// and the salt and parameters the server offered).
pub(crate) fn client_proof(
    key: &[u8; KEY_LEN],
    user: &[u8],
    snonce: &[u8; NONCE_LEN],
    cnonce: &[u8; NONCE_LEN],
    salt: &[u8],
    params: &KdfParams,
) -> [u8; PROOF_LEN] {
    let mut mac = mac(key);
    mac.update(CLIENT_LABEL);
    mac.update(&[u8::try_from(user.len()).unwrap_or(u8::MAX)]);
    mac.update(user);
    mac.update(snonce);
    mac.update(cnonce);
    mac.update(&[u8::try_from(salt.len()).unwrap_or(u8::MAX)]);
    mac.update(salt);
    mac.update(&encode_params(params));
    mac.finalize().into_bytes().into()
}

/// The server's proof (a different label, nonces in the other order), so a
/// client proof can never be reflected back as a server proof.
pub(crate) fn server_proof(
    key: &[u8; KEY_LEN],
    user: &[u8],
    cnonce: &[u8; NONCE_LEN],
    snonce: &[u8; NONCE_LEN],
) -> [u8; PROOF_LEN] {
    let mut mac = mac(key);
    mac.update(SERVER_LABEL);
    mac.update(&[u8::try_from(user.len()).unwrap_or(u8::MAX)]);
    mac.update(user);
    mac.update(cnonce);
    mac.update(snonce);
    mac.finalize().into_bytes().into()
}

/// `HMAC(secret, label || parts...)`, used for the server's decoy answers.
pub(crate) fn decoy_material(secret: &[u8; KEY_LEN], label: &[u8], user: &[u8]) -> [u8; 32] {
    let mut mac = mac(secret);
    mac.update(label);
    mac.update(user);
    mac.finalize().into_bytes().into()
}
