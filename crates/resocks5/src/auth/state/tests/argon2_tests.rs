//! The configurable Argon2id cost (`auth.argon2`): the state adopts it as the
//! enrollment floor, refuses an out-of-range section at build time, and stored
//! secrets of any other cost keep verifying.

use super::*;
use crate::auth::compute_hash_with;
use crate::auth::secret::parse_secret;
use crate::auth::Argon2Config;
use resocks5_net::secure_auth::{KdfParams, PasswordCheck, SecretStore as _};

fn state_with(argon2: Argon2Config, users: Vec<User>) -> Result<AuthState> {
    AuthState::build(
        &AuthConfig {
            argon2,
            ..Default::default()
        },
        &UsersConfig { users },
        "/__resocks5_test_never_written__",
    )
}

/// The configured cost is the floor of an init enrollment. Mutation: ignoring
/// the section (always the default cost) fails the equality.
#[test]
fn the_configured_cost_is_the_enrollment_floor() {
    let cost = Argon2Config {
        memory_kib: 128,
        iterations: 2,
        parallelism: 1,
    };
    let state = state_with(cost, Vec::new()).unwrap();
    assert_eq!(state.enrollment_floor, cost.to_params().unwrap());
}

/// An out-of-range section stops the build with a message naming it.
/// Mutation: skipping `to_params` validation lets the server start with a
/// zero or an absurd cost.
#[test]
fn an_out_of_range_section_stops_the_build() {
    for memory_kib in [0, 4_000_000] {
        let error = state_with(
            Argon2Config {
                memory_kib,
                iterations: 2,
                parallelism: 1,
            },
            Vec::new(),
        )
        .err()
        .expect("must refuse");
        assert!(error.to_string().contains("auth.argon2"), "{error}");
    }
}

/// A secret created at a cost other than the configured one still verifies:
/// the cost lives in the stored secret, the configuration only governs NEW
/// ones. Mutation: verifying with the configured parameters instead of the
/// stored ones rejects the correct password.
#[tokio::test]
async fn secrets_of_another_cost_keep_verifying() {
    let old = KdfParams {
        memory_kib: 96,
        iterations: 2,
        parallelism: 1,
    };
    let hash = compute_hash_with("pw", old).unwrap();
    assert_eq!(parse_secret(&hash).unwrap().params, old);
    let user = User {
        name: "alice".into(),
        hash,
        is_enabled: true,
        direct: false,
        allowed_clients: None,
    };
    let state = Arc::new(state_with(Argon2Config::default(), vec![user]).unwrap());
    let store = state.peer_store(Some("127.0.0.1".parse().unwrap()));
    assert!(matches!(
        store.check_password("alice", "pw").await,
        PasswordCheck::Accepted
    ));
    assert!(matches!(
        store.check_password("alice", "other").await,
        PasswordCheck::Rejected
    ));
}
