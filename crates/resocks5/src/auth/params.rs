//! Argon2id cost policy: the default every new secret is created with. The
//! operator tunes it with `auth.argon2`; existing secrets keep the
//! parameters stored with them.

use resocks5_net::secure_auth::KdfParams;

/// The default cost for a new secret: the SDK default (the OWASP minimum,
/// 19 MiB, 2 passes, 1 lane).
pub(crate) const PRODUCTION: KdfParams = KdfParams::DEFAULT;

/// Test-only cost: keeps the many derivations in tests fast.
#[cfg(test)]
pub(crate) const TEST: KdfParams = KdfParams {
    memory_kib: 64,
    iterations: 1,
    parallelism: 1,
};

/// What an unconfigured `auth.argon2` resolves to (test builds: the cheap
/// cost).
pub(crate) fn default_params() -> KdfParams {
    #[cfg(test)]
    {
        TEST
    }
    #[cfg(not(test))]
    {
        PRODUCTION
    }
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
            stored.starts_with("$argon2id$v=19$m=19456,t=2,p=1$"),
            "unexpected prefix: {stored}"
        );
        assert_eq!(parse_secret(&stored).unwrap().key(), secret.key());
    }
}
