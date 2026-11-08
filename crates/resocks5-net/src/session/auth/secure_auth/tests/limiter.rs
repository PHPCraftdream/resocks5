//! The derivation limiter and the clear-text half of the one-secret model.
//!
//! Every test here uses a store with its OWN limiter (see `Store`), so the
//! saturation and counting assertions can never be disturbed by a test
//! running beside it.

use std::sync::Arc;
use std::time::Duration;

use super::*;
use crate::secure_auth::DerivationPermit;

/// Take every slot of `limiter` and keep them until the result is dropped.
async fn hold_all(limiter: &DerivationLimiter) -> Vec<DerivationPermit> {
    let mut held = Vec::new();
    for _ in 0..limiter.capacity() {
        held.push(limiter.acquire().await.expect("a free slot"));
    }
    held
}

// ─── check_password: the clear-text half of the one-secret model ─────────

/// When every derivation slot is held, a clear-text check is rejected
/// without deriving, for known and unknown users alike, and succeeds once a
/// slot is free again. Mutation: removing the bounded slot wait (or the
/// limiter) makes the saturated checks take a slot (granted moves) or hang.
#[tokio::test(start_paused = true)]
async fn saturated_limiter_rejects_without_deriving() {
    let store = Store::with("alice", "pw");
    let held = hold_all(&store.1).await;
    let granted = store.1.granted();
    assert_eq!(
        store.check_password("alice", "pw").await,
        PasswordCheck::Rejected
    );
    assert_eq!(
        store.check_password("nobody", "pw").await,
        PasswordCheck::Rejected
    );
    assert_eq!(
        store.1.granted(),
        granted,
        "no slot may be granted while the limiter is saturated"
    );
    drop(held);
    assert_eq!(store.1.available(), store.1.capacity());
    assert_eq!(
        store.check_password("alice", "pw").await,
        PasswordCheck::Accepted
    );
    assert_eq!(store.1.granted(), granted + 1);
}

/// An unknown user costs no derivation; a wrong password for a known user
/// derives exactly once. Mutation: burning a decoy derivation for unknown
/// users (the old behaviour) makes the first `granted` 1.
#[tokio::test(start_paused = true)]
async fn unknown_user_costs_no_derivation() {
    let store = Store::with("alice", "pw");
    assert_eq!(
        store.check_password("nobody", "pw").await,
        PasswordCheck::Rejected
    );
    assert_eq!(
        store.1.granted(),
        0,
        "an unknown user must not trigger any Argon2id work"
    );
    assert_eq!(
        store.check_password("alice", "wrong").await,
        PasswordCheck::Rejected
    );
    assert_eq!(store.1.granted(), 1, "one derivation for a known user");
}

/// A hostile peer's parameters above the ceiling are refused without any
/// Argon2id work; exactly at the ceiling they are in range. Mutation:
/// raising the ceiling back to 1 GiB makes `is_in_range` accept the hostile
/// params.
#[test]
fn kdf_ceiling_refuses_hostile_parameters() {
    let hostile = KdfParams {
        memory_kib: super::super::kdf::MAX_MEMORY_KIB + 8,
        iterations: 1,
        parallelism: 1,
    };
    assert!(!hostile.is_in_range());
    assert!(matches!(
        derive_key(b"pw", &[7u8; 16], &hostile),
        Err(SecureAuthError::KdfOutOfRange)
    ));
    let at_ceiling = KdfParams {
        memory_kib: super::super::kdf::MAX_MEMORY_KIB,
        iterations: 1,
        parallelism: 1,
    };
    assert!(at_ceiling.is_in_range());
}

// ─── flood resilience: the limiter bounds the burn ────────────────────────

/// 500 concurrent wrong-password clear-text checks — enrolled users and
/// unknown names mixed — are all refused, take at most one slot per
/// known-user attempt (unknown names take none), return every slot, and
/// leave the init user untouched. Mutation: giving unknown names a slot makes
/// `granted` exceed the known-user attempts; leaking a slot leaves
/// `available` below `capacity`.
#[tokio::test]
async fn a_flood_of_false_cleartext_logins_is_bounded_and_all_refused() {
    let store = Arc::new(Store::mixed());
    let mut known_attempts = 0u64;
    let mut tasks = Vec::new();
    for i in 0..500 {
        let user = match i % 5 {
            0 | 1 => "nobody",
            _ if i % 2 == 0 => "alice",
            _ => "bob",
        };
        if user != "nobody" {
            known_attempts += 1;
        }
        let store = Arc::clone(&store);
        tasks.push(tokio::spawn(async move {
            store.check_password(user, "wrong").await
        }));
    }
    let run = async {
        let mut verdicts = Vec::new();
        for task in tasks {
            verdicts.push(task.await.unwrap());
        }
        verdicts
    };
    let verdicts = tokio::time::timeout(Duration::from_secs(60), run)
        .await
        .expect("the flood must finish well within the 60 s guard");

    assert_eq!(verdicts.len(), 500);
    for verdict in &verdicts {
        assert_eq!(*verdict, PasswordCheck::Rejected);
    }
    assert!(
        store.1.granted() <= known_attempts,
        "unknown names must take no slot: granted {} > known attempts {known_attempts}",
        store.1.granted()
    );
    assert_eq!(
        store.1.available(),
        store.1.capacity(),
        "every slot is returned"
    );
    assert!(
        store.secret("carol").is_none(),
        "the init user was not part of the flood and stays unclaimed"
    );
}

/// The strong exchange (method 0x80) never touches the derivation limiter:
/// a full mutual login succeeds while every slot of the store's limiter is
/// held. Mutation: gating `server_authenticate`'s verification (or the decoy
/// derivation) on the store's limiter blocks this login.
#[tokio::test(start_paused = true)]
async fn a_secure_auth_login_runs_while_the_limiter_is_saturated() {
    let store = Store::with("alice", "right");
    let held = hold_all(&store.1).await;

    let credentials = creds("alice", "right");
    let (mut client, mut server) = duplex(4096);
    let (client_result, server_result) = tokio::join!(
        client_authenticate(&mut client, &credentials),
        server_authenticate(&mut server, &store, decoy()),
    );
    client_result.expect("the client must not be blocked by the server's limiter");
    assert_eq!(
        server_result.expect("the server must not be blocked by its limiter"),
        "alice"
    );
    drop(held);
}

/// 500 failed secure-auth exchanges — wrong proofs and unknown users — take
/// ZERO server-side derivation slots. Mutation: making the decoy path (or the
/// denial) derive through the store's limiter makes `granted` jump.
#[tokio::test]
async fn failed_secure_exchanges_cost_zero_argon2_derivations() {
    // One credentials object per name: the client key cache collapses the
    // 250 derivations per name into one per distinct salt/params.
    let wrong_alice = Arc::new(creds("alice", "wrong"));
    let ghost = Arc::new(creds("ghost", "pw"));
    let enrolled = Arc::new(Store::with("alice", "right"));
    let empty = Arc::new(Store::empty());

    let run = async {
        let mut tasks = Vec::new();
        for i in 0..500 {
            let known = i % 2 == 0;
            let credentials = Arc::clone(if known { &wrong_alice } else { &ghost });
            let store = Arc::clone(if known { &enrolled } else { &empty });
            tasks.push(tokio::spawn(async move {
                let (mut client, mut server) = duplex(4096);
                tokio::join!(
                    client_authenticate(&mut client, &credentials),
                    server_authenticate(&mut server, &*store, decoy()),
                )
            }));
        }
        let mut results = Vec::new();
        for task in tasks {
            results.push(task.await.unwrap());
        }
        results
    };
    let results = tokio::time::timeout(Duration::from_secs(60), run)
        .await
        .expect("500 failed exchanges must finish well within the 60 s guard");

    for (client, server) in &results {
        assert_eq!(client.as_ref().unwrap_err(), &SecureAuthError::Denied);
        assert_eq!(server.as_ref().unwrap_err(), &SecureAuthError::Denied);
    }
    assert_eq!(enrolled.1.granted(), 0, "no server-side derivation slot");
    assert_eq!(empty.1.granted(), 0, "no server-side derivation slot");
}
