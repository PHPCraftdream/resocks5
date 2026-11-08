//! The Argon2id cost policy: the default creation cost, the client floor
//! below it, and the parameters an unknown name is offered.

use super::{DecoyKey, KdfParams, SecureAuthError};

/// The creation default is the OWASP minimum and a client demands nothing
/// beyond the smallest valid cost unless told to, so secrets created with a
/// tuned (cheaper) cost keep working. Mutation: raising the default floor
/// (e.g. to the creation default) fails here.
#[test]
fn the_default_cost_is_the_owasp_minimum_and_no_floor_is_imposed() {
    assert_eq!(
        KdfParams::DEFAULT,
        KdfParams {
            memory_kib: 19456,
            iterations: 2,
            parallelism: 1
        }
    );
    assert!(KdfParams::DEFAULT.at_least(&KdfParams::MIN));
    assert!(KdfParams::DEFAULT.is_in_range() && KdfParams::MIN.is_in_range());
    assert_eq!(
        super::SecureCredentials::new("u", "p").min_kdf(),
        KdfParams::MIN
    );
}

/// A decoy advertises the host's configured cost; `generate` keeps the
/// default and an out-of-range cost is refused up front.
/// Mutation: ignoring the configured parameters (always the default) fails
/// the first assert; skipping the range check fails the last.
#[test]
fn a_decoy_advertises_the_configured_parameters() {
    let tuned = KdfParams {
        memory_kib: 8192,
        iterations: 3,
        parallelism: 2,
    };
    let decoy = DecoyKey::generate_with(tuned).unwrap();
    assert_eq!(decoy.decoy_secret(b"nobody").params, tuned);
    assert_eq!(
        DecoyKey::generate().unwrap().decoy_secret(b"nobody").params,
        KdfParams::DEFAULT
    );
    let bad = KdfParams {
        memory_kib: 1,
        iterations: 1,
        parallelism: 1,
    };
    assert!(matches!(
        DecoyKey::generate_with(bad),
        Err(SecureAuthError::KdfOutOfRange)
    ));
}
