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

fn argon2_with(m_kib: u32) -> Argon2<'static> {
    let params = Params::new(m_kib, T, P, None).expect("hardcoded Argon2 params are valid");
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
}

/// The production instance (also built by the policy test, which test builds
/// of `argon2_instance` bypass for speed).
fn production_argon2() -> Argon2<'static> {
    argon2_with(M_KIB)
}

pub(in crate::auth) fn argon2_instance() -> Argon2<'static> {
    #[cfg(test)]
    {
        argon2_with(TEST_M_KIB)
    }
    #[cfg(not(test))]
    {
        production_argon2()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};

    /// Policy pin: NEW hashes must use the OWASP minimum (m=19456 KiB,
    /// t=2, p=1). Mutation `M_KIB → 5120` (or lowering T/P) fails here.
    #[test]
    fn production_params_meet_owasp_minimum() {
        assert_eq!(M_KIB, 19456);
        assert_eq!(T, 2);
        assert_eq!(P, 1);
    }

    /// The PHC string the production path creates carries the policy, not
    /// just the constants: m=19456,t=2,p=1, Argon2id v19, and it verifies.
    /// One real production-cost hash (19 MiB), deliberately the only one.
    /// Mutation: the production path building its instance from other
    /// parameters (or the test instance leaking into it) fails the match.
    #[test]
    fn production_instance_creates_policy_phc() {
        let salt = SaltString::encode_b64(&[9u8; 16]).unwrap();
        let phc = production_argon2()
            .hash_password(b"policy-check", &salt)
            .unwrap()
            .to_string();
        assert!(
            phc.starts_with("$argon2id$v=19$m=19456,t=2,p=1$"),
            "unexpected PHC prefix: {phc}"
        );
        let parsed = PasswordHash::new(&phc).unwrap();
        assert!(production_argon2()
            .verify_password(b"policy-check", &parsed)
            .is_ok());
    }
}
