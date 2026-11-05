//! Argon2id parameters and the configured `Argon2` instance shared by
//! the hash-creation path (`compute_hash`) and the verify path inside
//! `AuthState`. Centralising them here means changing parameters is a
//! one-line edit that updates both call sites at once — they cannot
//! drift apart.

use argon2::{Algorithm, Argon2, Params, Version};

/// 19 MiB memory cost — the OWASP minimum for Argon2id. Applies to
/// NEW hashes (CLI and init-claims). Verification reads m/t/p from
/// each PHC string itself, so existing hashes keep verifying with
/// their embedded parameters; there is deliberately no
/// rehash-on-login migration. Peak hashing memory =
/// `verify_slots` × M_KIB ≈ 4 × 19 MiB. See parent module docstring.
const M_KIB: u32 = 19456;
const T: u32 = 2;
const P: u32 = 1;

/// Test-only memory cost: 1 MiB keeps the many hashing tests fast.
/// Verify reads the parameters embedded in each PHC string, so hashes
/// the test instance creates also verify cheaply.
#[cfg(test)]
const TEST_M_KIB: u32 = 1024;

pub(in crate::auth) fn argon2_instance() -> Argon2<'static> {
    #[cfg(test)]
    let m_kib = TEST_M_KIB;
    #[cfg(not(test))]
    let m_kib = M_KIB;
    let params = Params::new(m_kib, T, P, None).expect("hardcoded Argon2 params are valid");
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Policy pin: NEW hashes must use the OWASP minimum (m=19456 KiB,
    /// t=2, p=1). Mutation `M_KIB → 5120` (or lowering T/P) fails here.
    #[test]
    fn production_params_meet_owasp_minimum() {
        assert_eq!(M_KIB, 19456);
        assert_eq!(T, 2);
        assert_eq!(P, 1);
    }
}
