//! Test-only client credentials matching the test-build secret cost.

use resocks5_net::secure_auth::SecureCredentials;

use crate::auth::params::TEST;

/// Secure-auth credentials that accept the cheap test-build secrets.
pub(crate) fn creds(user: &str, password: &str) -> SecureCredentials {
    SecureCredentials::new(user, password).with_min_kdf(TEST)
}

/// Like [`creds`], and willing to enroll an `init` account.
pub(crate) fn enrolling(user: &str, password: &str) -> SecureCredentials {
    creds(user, password)
        .allow_enrollment(true)
        .with_enrollment_kdf(TEST)
}
