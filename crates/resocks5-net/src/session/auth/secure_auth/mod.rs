//! Password authentication that never puts the password on the wire
//! (feature `secure-auth`): SOCKS5 method [`METHOD`] (`0x80`, the private-use
//! range), a mutual HMAC-SHA256 challenge-response.
//!
//! The server stores, per user, a [`UserSecret`]: a random salt, the
//! [`KdfParams`] and the key `K = Argon2id(password, salt, params)`. It does
//! not store the password. `K` is read in the clear by the server (it has to
//! be, to check a proof). The client derives `K` from the password it was
//! given and proves it holds `K`; neither the password nor `K` is sent.
//!
//! # Wire format (all lengths in bytes, version byte `1`)
//!
//! After the SOCKS5 method selection `[5, 0x80]`:
//!
//! 1. client → server: `1 | ulen | user | cnonce(32)` (`ulen` 1..=255)
//! 2. server → client: `1 | 0 | slen | salt | m_kib(4, BE) | t(1) | p(1) | snonce(32)`
//!    — or `1 | 0xFF` to refuse (never sent for an unknown user: a decoy salt
//!    and parameters are derived from the user name instead, so an unknown user
//!    fails at the proof like a wrong password)
//! 3. client → server: `1 | proof(32)` with
//!    `proof = HMAC-SHA256(K, "resocks5-secure/1 client" | ulen | user | snonce | cnonce | slen | salt | m_kib | t | p)`
//! 4. server → client: `1 | 0 | server_proof(32)` or `1 | 1` (denied), with
//!    `server_proof = HMAC-SHA256(K, "resocks5-secure/1 server" | ulen | user | cnonce | snonce)`
//!
//! The client checks `server_proof` in constant time, so a peer that does not
//! hold `K` cannot pose as the server. Fresh nonces on both sides make a
//! recorded exchange useless for a replay. The SOCKS5 request that follows is
//! not encrypted; only authentication is protected.
//!
//! # What this does and does not give
//!
//! The password and `K` never cross the wire, and the server's decoy answers
//! hide which user names exist. A user still waiting for its first secret is
//! enrolled by the first client that authenticates as it (see the `init`
//! module docs): the password is not sent then either. A passive observer who records one exchange can
//! still try passwords offline (a challenge-response without a PAKE allows that),
//! which the Argon2id cost slows down; use strong passwords. A client refuses
//! parameters weaker than its floor ([`SecureCredentials::with_min_kdf`]), so a
//! man in the middle cannot downgrade the KDF to harvest a cheaply attackable
//! proof.

mod client;
mod init;
mod kdf;
mod server;
#[cfg(test)]
mod tests;
mod wire;

pub use client::{client_authenticate, SecureCredentials};
pub use kdf::{derive_key, KdfParams, UserSecret, KEY_LEN, SALT_LEN};
pub use server::{server_authenticate, DecoyKey, SecretStore, StoredUser};

/// The private-use SOCKS5 authentication method number for this protocol.
pub const METHOD: u8 = 0x80;

/// Protocol version byte of every message.
pub(crate) const VERSION: u8 = 1;
