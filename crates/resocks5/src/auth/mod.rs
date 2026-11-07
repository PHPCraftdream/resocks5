//! Inbound user authentication: secure auth (SOCKS5 method 0x80, see
//! `resocks5_net::secure_auth`). The password never crosses the wire and is
//! never stored: `resocks5.users.ktav` keeps, per user, the Argon2id salt,
//! parameters and the derived key `K` (an Argon2id v19 PHC string, see
//! `secret`), and a login is a mutual HMAC challenge-response over `K`.
//! Hashes written by earlier versions are exactly such strings, so existing
//! accounts keep working; the client derives `K` (Argon2) once per login, the
//! server only computes HMACs.
//!
//! A user stored as `init` is enrolled by its first client: the client sends
//! `K` sealed under an ephemeral X25519 key exchange, the server stores it
//! (once, atomically, also across processes) and from then on the account is
//! a normal one.
//!
//! Clear-text passwords (SOCKS5 UNAME/PASSWD, HTTP Basic) are never accepted
//! from clients. Unknown, disabled and IP-filtered users are answered with a
//! decoy that fails exactly like a wrong password.

pub mod compute_hash;
pub(crate) mod params;
pub mod secret;
pub mod state;
#[cfg(test)]
pub(crate) mod test_support;

pub use compute_hash::compute_hash;
pub use state::AuthState;
