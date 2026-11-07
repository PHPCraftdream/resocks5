//! Argon2id cost policy for the secrets this server writes (CLI `user
//! add`/`user set`) and the floor it demands from an init enrollment.
//! Existing secrets keep the parameters stored with them.

use resocks5_net::secure_auth::KdfParams;

/// 19 MiB, 2 passes, 1 lane: the OWASP minimum for Argon2id, equal to the
/// SDK client's default floor (a client refuses anything cheaper).
const PRODUCTION: KdfParams = KdfParams {
    memory_kib: 19456,
    iterations: 2,
    parallelism: 1,
};

/// Test-only cost: keeps the many derivations in tests fast.
#[cfg(test)]
pub(crate) const TEST: KdfParams = KdfParams {
    memory_kib: 64,
    iterations: 1,
    parallelism: 1,
};

/// Parameters for a new secret.
pub(in crate::auth) fn new_secret_params() -> KdfParams {
    #[cfg(test)]
    {
        TEST
    }
    #[cfg(not(test))]
    {
        PRODUCTION
    }
}

/// The cheapest derivation an init enrollment may use.
pub(in crate::auth) fn enrollment_floor() -> KdfParams {
    new_secret_params()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::secret::{encode_secret, parse_secret};
    use resocks5_net::secure_auth::UserSecret;

    /// Policy pin: new secrets use the OWASP minimum, which is exactly the
    /// SDK client's default floor. Mutation: lowering any value (clients
    /// with the default floor would refuse the secret) fails here.
    #[test]
    fn production_params_are_the_owasp_minimum_and_the_client_floor() {
        assert_eq!(
            (
                PRODUCTION.memory_kib,
                PRODUCTION.iterations,
                PRODUCTION.parallelism
            ),
            (19456, 2, 1)
        );
        assert_eq!(PRODUCTION, KdfParams::DEFAULT);
    }

    /// One real production-cost secret (19 MiB), deliberately the only one:
    /// it stores the policy parameters and round-trips. Mutation: building
    /// it from other parameters fails the prefix.
    #[test]
    fn a_production_secret_carries_the_policy() {
        let secret = UserSecret::from_password("policy-check", PRODUCTION).unwrap();
        let stored = encode_secret(&secret);
        assert!(
            stored.starts_with("$argon2id$v=19$m=19456,t=2,p=1$"),
            "unexpected prefix: {stored}"
        );
        assert_eq!(parse_secret(&stored).unwrap().key(), secret.key());
    }
}
