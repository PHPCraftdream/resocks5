//! Argon2id cost policy for the secrets this server writes (CLI `user
//! add`/`user set`) and the floor it demands from an init enrollment.
//! Existing secrets keep the parameters stored with them.

use resocks5_net::secure_auth::KdfParams;

/// The single cost policy for every new secret — deliberately below the
/// OWASP minimum (4 MiB, single pass) — a documented cost trade-off
/// (see SECURITY).
const PRODUCTION: KdfParams = KdfParams::DEFAULT;

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

    /// Policy pin: new secrets use the SDK default cost — one literal
    /// lives in the SDK. Mutation: diverging `PRODUCTION` from
    /// `KdfParams::DEFAULT` fails here.
    #[test]
    fn production_params_are_the_sdk_default() {
        assert_eq!(PRODUCTION, KdfParams::DEFAULT);
        assert_eq!(
            (
                PRODUCTION.memory_kib,
                PRODUCTION.iterations,
                PRODUCTION.parallelism
            ),
            (
                KdfParams::DEFAULT.memory_kib,
                KdfParams::DEFAULT.iterations,
                KdfParams::DEFAULT.parallelism
            )
        );
    }

    /// One real production-cost secret, deliberately the only one: it
    /// stores the policy parameters and round-trips. The prefix pins the
    /// wire format. Mutation: building it from other parameters fails the
    /// prefix.
    #[test]
    fn a_production_secret_carries_the_policy() {
        let secret = UserSecret::from_password("policy-check", PRODUCTION).unwrap();
        let stored = encode_secret(&secret);
        assert!(
            stored.starts_with("$argon2id$v=19$m=4096,t=1,p=1$"),
            "unexpected prefix: {stored}"
        );
        assert_eq!(parse_secret(&stored).unwrap().key(), secret.key());
    }
}
