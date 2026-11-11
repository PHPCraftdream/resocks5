//! Init enrollment: the first client's secret is stored once, atomically,
//! on top of the current users file.

use super::*;
use crate::auth::secret::parse_secret;
use crate::auth::test_support::enrolling;
use resocks5_net::secure_auth::{derive_key, KdfParams};
use std::path::PathBuf;

fn disk_hash(path: &str, name: &str) -> String {
    let loaded: UsersConfig = ktav::from_file(path).unwrap();
    loaded
        .users
        .into_iter()
        .find(|u| u.name == name)
        .unwrap()
        .hash
}

fn memory_hash(state: &AuthState, name: &str) -> String {
    let users = state.users.read().unwrap();
    users.iter().find(|u| u.name == name).unwrap().hash.clone()
}

fn cleanup(path: &str) {
    let _ = std::fs::remove_file(path);
    let _ = std::fs::remove_file(format!("{path}.lock"));
}

/// The first client sets the secret in memory and on disk; the stored key
/// is the one its password derives, the password itself is not in the
/// file; the same password then logs in and another is denied. Mutation:
/// publishing without persisting, or persisting another key, fails here.
#[tokio::test]
async fn the_first_login_of_an_init_user_stores_its_secret() {
    let password = "bobs-first-password";
    let (state, path) = build_state_with_disk_file(vec![
        make_user("alice", "alice-pw", true),
        make_init_user("bob", true),
    ]);
    let (c, s) = login(&state, &enrolling("bob", password)).await;
    c.unwrap();
    assert_eq!(s.unwrap(), "bob");

    let stored = disk_hash(&path, "bob");
    assert_eq!(memory_hash(&state, "bob"), stored);
    assert!(!std::fs::read_to_string(&path).unwrap().contains(password));
    let secret = parse_secret(&stored).unwrap();
    let expected = derive_key(password.as_bytes(), &secret.salt, &secret.params).unwrap();
    assert_eq!(secret.key(), &*expected);

    let (c, _) = login(&state, &creds("bob", password)).await;
    c.unwrap();
    assert_denied(
        login(&state, &enrolling("bob", "someone-else")).await,
        "a second first login",
    );
    // A server restarted on the file logs bob in as well.
    let restarted = build_state(
        ktav::from_file::<UsersConfig, _>(&path).unwrap().users,
        false,
    );
    let (c, _) = login(&restarted, &creds("bob", password)).await;
    c.unwrap();
    cleanup(&path);
}

/// Of two simultaneous first logins exactly one wins, and the stored
/// secret is the winner's. Mutation: dropping the re-check under
/// `claim_lock` lets both persist.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn of_two_concurrent_first_logins_exactly_one_wins() {
    let (state, path) = build_state_with_disk_file(vec![make_init_user("bob", true)]);
    let first = enrolling("bob", "first-pw-aaaa");
    let second = enrolling("bob", "second-pw-bbbb");
    let (a, b) = tokio::join!(login(&state, &first), login(&state, &second));
    assert_eq!(a.0.is_ok(), a.1.is_ok());
    assert_eq!(b.0.is_ok(), b.1.is_ok());
    let winner = match (a.0.is_ok(), b.0.is_ok()) {
        (true, false) => "first-pw-aaaa",
        (false, true) => "second-pw-bbbb",
        other => panic!("exactly one first login must win: {other:?}"),
    };
    let secret = parse_secret(&disk_hash(&path, "bob")).unwrap();
    let expected = derive_key(winner.as_bytes(), &secret.salt, &secret.params).unwrap();
    assert_eq!(
        secret.key(),
        &*expected,
        "the stored secret is the winner's"
    );
    cleanup(&path);
}

/// An init user filtered out for this peer is neither offered an
/// enrollment nor stored. Mutation: `PeerStore` without the rule lets a
/// stranger claim the account.
#[tokio::test]
async fn a_filtered_peer_cannot_enroll() {
    let user = User {
        allowed_clients: Some("10.1.1.1".into()),
        ..make_init_user("bob", true)
    };
    let (state, path) = build_state_with_disk_file(vec![user]);
    assert_denied(
        login_from(&state, "203.0.113.9", &enrolling("bob", "pw")).await,
        "filtered enrollment",
    );
    assert_eq!(disk_hash(&path, "bob"), INIT_HASH);
    assert_eq!(memory_hash(&state, "bob"), INIT_HASH);
    cleanup(&path);
}

/// A disabled init user is the decoy, and stays unclaimed.
#[tokio::test]
async fn a_disabled_init_user_is_not_claimed() {
    let (state, path) = build_state_with_disk_file(vec![make_init_user("bob", false)]);
    assert_denied(
        login(&state, &enrolling("bob", "pw")).await,
        "disabled init user",
    );
    assert_eq!(disk_hash(&path, "bob"), INIT_HASH);
    cleanup(&path);
}

/// An enrollment derived below the server's floor stores nothing.
/// Mutation: a `PeerStore` that does not hand the floor on accepts it.
#[tokio::test]
async fn an_enrollment_below_the_floor_is_refused() {
    let (state, path) = build_state_with_disk_file(vec![make_init_user("bob", true)]);
    let cheap = KdfParams {
        memory_kib: 32,
        ..crate::auth::params::TEST
    };
    let credentials = creds("bob", "pw")
        .allow_enrollment(true)
        .with_enrollment_kdf(cheap);
    let (_, s) = login(&state, &credentials).await;
    assert_eq!(s, Err(SecureAuthError::KdfTooWeak));
    assert_eq!(disk_hash(&path, "bob"), INIT_HASH);
    cleanup(&path);
}

#[tokio::test]
async fn the_first_claim_creates_a_missing_file_with_every_user() {
    let (state, path) = build_state_persistent(vec![
        make_user("alice", "alice-pw", true),
        make_init_user("bob", true),
    ]);
    assert!(!Path::new(&path).exists());
    let (c, _) = login(&state, &enrolling("bob", "bob-pw")).await;
    c.unwrap();
    let loaded: UsersConfig = ktav::from_file(&path).unwrap();
    assert_eq!(loaded.users.len(), 2, "fallback must carry every user");
    assert!(parse_secret(&disk_hash(&path, "alice")).is_ok());
    assert!(parse_secret(&disk_hash(&path, "bob")).is_ok());
    let (c, _) = login(&state, &creds("alice", "alice-pw")).await;
    c.unwrap();
    cleanup(&path);
}

// ─── cross-process safety: CLI edits vs init-claim ──────────────

/// The claim merges into the on-disk truth, not the stale snapshot: a CLI
/// edit to other users survives.
#[tokio::test]
async fn a_claim_preserves_a_concurrent_cli_edit_to_other_users() {
    let baseline = vec![
        make_user("alice", "alice-pw", true),
        make_init_user("bob", true),
    ];
    let (state, path) = build_state_with_disk_file(baseline.clone());
    let cli_edit = vec![
        User {
            is_enabled: false,
            ..baseline[0].clone()
        },
        make_init_user("bob", true),
        make_init_user("carol", true),
    ];
    ktav::to_file(&UsersConfig { users: cli_edit }, &path).unwrap();

    let (c, _) = login(&state, &enrolling("bob", "bob-pw")).await;
    c.unwrap();
    let loaded: UsersConfig = ktav::from_file(&path).unwrap();
    assert_eq!(loaded.users.len(), 3, "CLI-added user must survive");
    assert!(
        !loaded
            .users
            .iter()
            .find(|u| u.name == "alice")
            .unwrap()
            .is_enabled
    );
    assert_eq!(disk_hash(&path, "carol"), INIT_HASH);
    assert_ne!(disk_hash(&path, "bob"), INIT_HASH);
    cleanup(&path);
}

/// The CLI set a password for the init user meanwhile: the enrollment is
/// denied, the CLI's value stays byte-for-byte and is adopted in memory, so
/// the CLI's password logs in.
#[tokio::test]
async fn a_claim_yields_to_a_cli_password_for_the_same_user() {
    let (state, path) = build_state_with_disk_file(vec![make_init_user("bob", true)]);
    let cli_hash = compute_hash("cli-pw").unwrap();
    ktav::to_file(
        &UsersConfig {
            users: vec![User {
                hash: cli_hash.clone(),
                ..make_init_user("bob", true)
            }],
        },
        &path,
    )
    .unwrap();

    assert_denied(
        login(&state, &enrolling("bob", "claimant-pw")).await,
        "enrollment over a CLI password",
    );
    assert_eq!(disk_hash(&path, "bob"), cli_hash);
    assert_eq!(memory_hash(&state, "bob"), cli_hash);
    let (c, _) = login(&state, &creds("bob", "cli-pw")).await;
    c.unwrap();
    cleanup(&path);
}

/// The CLI removed the user: the claim fails closed and does not resurrect
/// it on disk.
#[tokio::test]
async fn a_claim_fails_when_the_cli_removed_the_user() {
    let baseline = vec![
        make_user("alice", "alice-pw", true),
        make_init_user("bob", true),
    ];
    let (state, path) = build_state_with_disk_file(baseline.clone());
    ktav::to_file(
        &UsersConfig {
            users: vec![baseline[0].clone()],
        },
        &path,
    )
    .unwrap();

    assert_denied(
        login(&state, &enrolling("bob", "pw")).await,
        "claim of a removed user",
    );
    assert_eq!(memory_hash(&state, "bob"), INIT_HASH);
    let loaded: UsersConfig = ktav::from_file(&path).unwrap();
    assert_eq!(loaded.users.len(), 1);
    assert_eq!(loaded.users[0].name, "alice");
    cleanup(&path);
}

/// A persist that fails mid-way (the temp-file slot is a directory) leaves
/// the previous file intact and the sentinel in place for a retry, which
/// then succeeds.
#[tokio::test]
async fn a_failed_write_leaves_the_file_and_the_sentinel() {
    let (state, path) = build_state_with_disk_file(vec![
        make_user("alice", "alice-pw", true),
        make_init_user("bob", true),
    ]);
    let before = std::fs::read_to_string(&path).unwrap();
    let tmp = PathBuf::from(format!("{path}.tmp"));
    std::fs::create_dir(&tmp).unwrap();

    assert_denied(
        login(&state, &enrolling("bob", "pw")).await,
        "claim with a failing write",
    );
    assert_eq!(std::fs::read_to_string(&path).unwrap(), before);
    assert_eq!(memory_hash(&state, "bob"), INIT_HASH);

    std::fs::remove_dir(&tmp).unwrap();
    let (c, _) = login(&state, &enrolling("bob", "pw")).await;
    c.unwrap();
    assert_ne!(disk_hash(&path, "bob"), INIT_HASH);
    cleanup(&path);
}

/// A secret whose stored form would not load again is refused, not
/// persisted: a client may seal a salt of up to 64 bytes, the PHC string
/// holds 48. Mutation: storing it leaves bob with a hash no login can use.
#[tokio::test]
async fn a_secret_that_would_not_load_again_is_not_claimed() {
    use resocks5_net::secure_auth::{UserSecret, KEY_LEN};
    let params = KdfParams {
        memory_kib: 64,
        iterations: 1,
        parallelism: 1,
    };
    let (state, path) = build_state_with_disk_file(vec![make_init_user("bob", true)]);
    let too_long = UserSecret::from_parts(vec![1u8; 49], params, [7u8; KEY_LEN]).unwrap();
    assert!(!state.claim_secret("bob", too_long).await);
    assert_eq!(memory_hash(&state, "bob"), "init");
    assert_eq!(disk_hash(&path, "bob"), "init");

    let longest = UserSecret::from_parts(vec![1u8; 48], params, [7u8; KEY_LEN]).unwrap();
    assert!(state.claim_secret("bob", longest).await);
    assert!(parse_secret(&disk_hash(&path, "bob")).is_ok());
    cleanup(&path);
}
