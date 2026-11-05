//! SEC-03 (timing equalisation) and SEC-05 (fail-closed PHC checks)
//! tests for the verify paths.

use super::*;
use argon2::password_hash::{PasswordHasher, SaltString};
use argon2::{Algorithm, Argon2, Params, Version};

/// A real PHC string built with explicit cheap parameters (m=64 KiB,
/// t=1, p=1) and a fixed 16-byte salt — verification reads m/t/p from
/// the string, so these verify fast and prove the no-migration
/// contract. The params segment renders as `m=64,t=1,p=1`.
fn real_phc(algorithm: Algorithm, version: Version) -> String {
    let salt = SaltString::encode_b64(&[7u8; 16]).unwrap();
    let params = Params::new(64, 1, 1, None).expect("valid params");
    Argon2::new(algorithm, version, params)
        .hash_password(b"sec05-password", &salt)
        .expect("hashing with valid params succeeds")
        .to_string()
}

fn state_with_hash(hash: String) -> AuthState {
    build_state(
        vec![User {
            name: "alice".to_string(),
            hash,
            is_enabled: true,
            direct: false,
            allowed_clients: None,
        }],
        false,
    )
}

// ─── SEC-03: timing-equalised rejection ───────────────────────────────

#[tokio::test]
async fn unknown_name_still_runs_hmac_and_rejects() {
    let state = Arc::new(build_state(vec![make_user("alice", "s3cret", true)], false));
    let before = state.hmac_probe_count();
    assert!(!state.verify_async("carol", "s3cret").await);
    assert_eq!(
        state.hmac_probe_count(),
        before + 1,
        "SEC-03: unknown name must still run the cache-HMAC step"
    );
}

#[tokio::test]
async fn disabled_name_still_runs_hmac_and_rejects() {
    let state = Arc::new(build_state(vec![make_user("bob", "s3cret", false)], false));
    let before = state.hmac_probe_count();
    assert!(!state.verify_async("bob", "s3cret").await);
    assert_eq!(
        state.hmac_probe_count(),
        before + 1,
        "SEC-03: disabled name must still run the cache-HMAC step"
    );
}

#[tokio::test]
async fn known_name_hmac_step_and_results_unchanged() {
    let state = Arc::new(build_state(vec![make_user("alice", "s3cret", true)], false));
    let before = state.hmac_probe_count();
    assert!(state.verify_async("alice", "s3cret").await);
    assert!(!state.verify_async("alice", "wrong").await);
    // true login: HMAC + Argon2 + cache; wrong password: HMAC +
    // cache-miss + Argon2 reject.
    assert_eq!(state.hmac_probe_count(), before + 2);
}

// ─── SEC-05: fail-closed PHC algorithm/version/params checks ─────────
// `argon2::verify_password` takes the algorithm and version FROM the stored
// string, so `argon2_verify` refuses everything but Argon2id v19 itself;
// the foreign-algorithm / old-version rows fail without that explicit check.

#[test]
fn foreign_algorithm_phc_rejected_fail_closed() {
    // Positive control: the Argon2id twin verifies, so the rejections
    // below are about the algorithm contract, not broken fixtures.
    assert!(
        state_with_hash(real_phc(Algorithm::Argon2id, Version::V0x13))
            .verify("alice", "sec05-password")
    );
    assert!(
        !state_with_hash(real_phc(Algorithm::Argon2i, Version::V0x13))
            .verify("alice", "sec05-password")
    );
    assert!(
        !state_with_hash(real_phc(Algorithm::Argon2d, Version::V0x13))
            .verify("alice", "sec05-password")
    );
}

#[test]
fn old_version_phc_rejected_fail_closed() {
    // Positive control: the current-version twin verifies.
    assert!(
        state_with_hash(real_phc(Algorithm::Argon2id, Version::V0x13))
            .verify("alice", "sec05-password")
    );
    assert!(
        !state_with_hash(real_phc(Algorithm::Argon2id, Version::V0x10))
            .verify("alice", "sec05-password")
    );
}

#[test]
fn invalid_params_phc_rejected_fail_closed() {
    let phc = real_phc(Algorithm::Argon2id, Version::V0x13);
    // Unpadded PHC base64 contains no `=`, so `m=64,t=1,p=1` can only
    // be the params segment — replacement is unambiguous.
    for bad in ["m=0,t=1,p=1", "m=7,t=1,p=1", "m=64,t=0,p=1", "m=64,t=1,p=0"] {
        let tampered = phc.replace("m=64,t=1,p=1", bad);
        assert!(
            !state_with_hash(tampered.clone()).verify("alice", "sec05-password"),
            "PHC with params `{bad}` must be rejected"
        );
    }
    // Positive control / no-migration pin: the unmodified PHC verifies
    // TRUE even though its embedded m=64 differs from the instance
    // parameters — verification reads parameters from the string; this
    // also fails if anyone adds a verify-side params floor (forbidden
    // by the no-migration contract). NEVER use a huge m here (e.g.
    // 4294967295): MAX_M_COST is unchecked and verify would attempt a
    // multi-TiB allocation.
    assert!(state_with_hash(phc).verify("alice", "sec05-password"));
}
