//! Inbound user authentication: ONE stored secret per user verifies BOTH
//! methods. `resocks5.users.ktav` keeps, per user, the Argon2id salt,
//! parameters and the derived key `K` (an Argon2id v19 PHC string, see
//! `secret`).
//!
//! - Secure auth (SOCKS5 method 0x80, HTTP `Resocks5-Secure`, see
//!   `resocks5_net::secure_auth`): a mutual HMAC challenge-response over
//!   `K`. The password never crosses the wire and is never stored.
//! - Clear text (SOCKS5 0x02 RFC 1929 UNAME/PASSWD, HTTP Basic): the
//!   client sends the password, the server derives
//!   Argon2id(password, salt, params) and constant-time compares it to
//!   the stored `K`. Clear text is ALWAYS accepted by default; with
//!   `auth.secure_only: true` only the secure method is served.
//!
//! A user stored as `init` is enrolled by its first successful login over
//! EITHER method: the secret is stored (once, atomically, also across
//! processes) and from then on the account is a normal one.
//!
//! Unknown, disabled and IP-filtered users are answered with a decoy in
//! both paths that fails exactly like a wrong password.

pub mod argon2_config;
pub mod compute_hash;
pub(crate) mod params;
pub mod secret;
pub mod state;
#[cfg(test)]
pub(crate) mod test_support;

pub use argon2_config::Argon2Config;
#[cfg(test)]
pub use compute_hash::compute_hash;
pub use compute_hash::compute_hash_with;
pub use state::AuthState;
