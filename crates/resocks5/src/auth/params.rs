//! Argon2id parameters and the configured `Argon2` instance shared by
//! the hash-creation path (`compute_hash`) and the verify path inside
//! `AuthState`. Centralising them here means changing parameters is a
//! one-line edit that updates both call sites at once — they cannot
//! drift apart.

use argon2::{Algorithm, Argon2, Params, Version};

/// 5 MiB memory cost. See parent module docstring for rationale.
const M_KIB: u32 = 5120;
const T: u32 = 2;
const P: u32 = 1;

pub(in crate::auth) fn argon2_instance() -> Argon2<'static> {
    let params = Params::new(M_KIB, T, P, None).expect("hardcoded Argon2 params are valid");
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
}
