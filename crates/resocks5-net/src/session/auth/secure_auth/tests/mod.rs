//! Behaviour of the secure-auth exchange: both sides over in-memory streams.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt, DuplexStream};

use super::kdf::{derive_key, KdfParams, UserSecret, KEY_LEN};
use super::wire::{client_proof, encode_params, server_proof, NONCE_LEN};
use super::{
    client_authenticate, server_authenticate, DecoyKey, DerivationLimiter, PasswordCheck,
    SecretStore, SecureCredentials, StoredUser,
};
use crate::error::SecureAuthError;

/// Cheap parameters so the tests do not pay for the default Argon2id cost each.
const WEAK: KdfParams = KdfParams {
    memory_kib: 64,
    iterations: 1,
    parallelism: 1,
};

/// A store with its OWN derivation limiter (2 slots), so tests that saturate or
/// count derivations never disturb tests running beside them.
struct Store(Mutex<HashMap<String, StoredUser>>, DerivationLimiter);

impl Store {
    fn with(user: &str, password: &str) -> Self {
        let mut map = HashMap::new();
        map.insert(
            user.to_owned(),
            StoredUser::Secret(UserSecret::from_password(password, WEAK).unwrap()),
        );
        Self(Mutex::new(map), DerivationLimiter::new(2))
    }

    fn init(user: &str) -> Self {
        let mut map = HashMap::new();
        map.insert(user.to_owned(), StoredUser::Init);
        Self(Mutex::new(map), DerivationLimiter::new(2))
    }

    /// An empty store: no users at all (every lookup misses).
    fn empty() -> Self {
        Self(Mutex::new(HashMap::new()), DerivationLimiter::new(2))
    }

    /// Mixed population for flood tests: enrolled "alice", enrolled "bob"
    /// and an unclaimed init user "carol".
    fn mixed() -> Self {
        let mut map = HashMap::new();
        map.insert(
            "alice".to_owned(),
            StoredUser::Secret(UserSecret::from_password("pw", WEAK).unwrap()),
        );
        map.insert(
            "bob".to_owned(),
            StoredUser::Secret(UserSecret::from_password("pw", WEAK).unwrap()),
        );
        map.insert("carol".to_owned(), StoredUser::Init);
        Self(Mutex::new(map), DerivationLimiter::new(2))
    }

    fn secret(&self, user: &str) -> Option<UserSecret> {
        match self.0.lock().unwrap().get(user) {
            Some(StoredUser::Secret(secret)) => Some(secret.clone()),
            _ => None,
        }
    }
}

impl SecretStore for Store {
    async fn lookup(&self, user: &str) -> Option<StoredUser> {
        self.0.lock().unwrap().get(user).cloned()
    }

    async fn claim(&self, user: &str, secret: UserSecret) -> bool {
        let mut map = self.0.lock().unwrap();
        match map.get(user) {
            Some(StoredUser::Init) => {
                map.insert(user.to_owned(), StoredUser::Secret(secret));
                true
            }
            _ => false,
        }
    }

    fn enrollment_floor(&self) -> KdfParams {
        WEAK
    }

    fn derivation_limiter(&self) -> &DerivationLimiter {
        &self.1
    }
}

fn creds(user: &str, password: &str) -> SecureCredentials {
    SecureCredentials::new(user, password).with_min_kdf(WEAK)
}

fn decoy() -> &'static DecoyKey {
    static KEY: std::sync::OnceLock<DecoyKey> = std::sync::OnceLock::new();
    KEY.get_or_init(|| DecoyKey::from_bytes_with([7u8; KEY_LEN], WEAK))
}

/// A client and a server end joined by a relay that records every byte that
/// crosses (both directions) into the returned log.
fn recorded_pair() -> (DuplexStream, DuplexStream, Arc<Mutex<Vec<u8>>>) {
    let (client_end, client_relay) = duplex(4096);
    let (server_relay, server_end) = duplex(4096);
    let log = Arc::new(Mutex::new(Vec::new()));
    let (client_read, client_write) = tokio::io::split(client_relay);
    let (server_read, server_write) = tokio::io::split(server_relay);
    spawn_copy(client_read, server_write, Arc::clone(&log));
    spawn_copy(server_read, client_write, Arc::clone(&log));
    (client_end, server_end, log)
}

fn spawn_copy<R, W>(mut from: R, mut to: W, log: Arc<Mutex<Vec<u8>>>)
where
    R: tokio::io::AsyncRead + Unpin + Send + 'static,
    W: tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    tokio::spawn(async move {
        let mut buf = [0u8; 1024];
        loop {
            match from.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    log.lock().unwrap().extend_from_slice(&buf[..n]);
                    if to.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            }
        }
        let _ = to.shutdown().await;
    });
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && haystack.windows(needle.len()).any(|w| w == needle)
}

/// A correct password authenticates both ways and the server learns the user.
#[tokio::test]
async fn the_right_password_authenticates_both_ways() {
    let store = Store::with("alice", "correct horse battery staple");
    let credentials = creds("alice", "correct horse battery staple");
    let (mut client, mut server) = duplex(4096);
    let (client_result, server_result) = tokio::join!(
        client_authenticate(&mut client, &credentials),
        server_authenticate(&mut server, &store, decoy()),
    );
    client_result.unwrap();
    assert_eq!(server_result.unwrap(), "alice");
}

/// Neither the password nor the derived key ever crosses the wire. Mutation:
/// sending either (or the key inside a proof field) puts it in the log.
#[tokio::test]
async fn neither_the_password_nor_the_key_crosses_the_wire() {
    let password = "p4ssw0rd-never-on-the-wire";
    let store = Store::with("alice", password);
    let key = *store.secret("alice").unwrap().key();
    let salt = store.secret("alice").unwrap().salt;
    let credentials = creds("alice", password);
    let (mut client, mut server, log) = recorded_pair();
    let (client_result, server_result) = tokio::join!(
        client_authenticate(&mut client, &credentials),
        server_authenticate(&mut server, &store, decoy()),
    );
    client_result.unwrap();
    server_result.unwrap();
    let wire = log.lock().unwrap().clone();
    assert!(wire.len() > 100, "the exchange really crossed the relay");
    assert!(
        !contains(&wire, password.as_bytes()),
        "password on the wire"
    );
    assert!(!contains(&wire, &key), "derived key on the wire");
    // The salt is public by design (the client needs it).
    assert!(contains(&wire, &salt));
}

/// A wrong password is denied on both sides.
#[tokio::test]
async fn a_wrong_password_is_denied_on_both_sides() {
    let store = Store::with("alice", "right");
    let credentials = creds("alice", "wrong");
    let (mut client, mut server) = duplex(4096);
    let (client_result, server_result) = tokio::join!(
        client_authenticate(&mut client, &credentials),
        server_authenticate(&mut server, &store, decoy()),
    );
    assert_eq!(client_result.unwrap_err(), SecureAuthError::Denied);
    assert_eq!(server_result.unwrap_err(), SecureAuthError::Denied);
}

/// An unknown user fails exactly like a wrong password, and the offer it gets
/// has the same shape as a known user's (status 0, a salt, parameters, a
/// nonce): the answer does not reveal which names exist. Mutation: refusing an
/// unknown user up front (`0xFF`) is visible in the first reply bytes.
#[tokio::test]
async fn an_unknown_user_looks_like_a_wrong_password() {
    let store = Store::with("alice", "right");
    for (user, expect_known) in [("alice", true), ("mallory", false)] {
        let (mut client, mut server) = duplex(4096);
        let credentials = creds(user, "right");
        let (client_result, server_result) = tokio::join!(
            client_authenticate(&mut client, &credentials),
            server_authenticate(&mut server, &store, decoy()),
        );
        if expect_known {
            client_result.unwrap();
            server_result.unwrap();
        } else {
            assert_eq!(client_result.unwrap_err(), SecureAuthError::Denied);
            assert_eq!(server_result.unwrap_err(), SecureAuthError::Denied);
        }
    }
    // The raw first reply for a known and for an unknown name.
    let mut shapes = Vec::new();
    for user in ["alice", "mallory"] {
        let (mut client, mut server) = duplex(4096);
        let user_bytes = user.as_bytes();
        let mut hello = vec![1, u8::try_from(user_bytes.len()).unwrap()];
        hello.extend_from_slice(user_bytes);
        hello.extend_from_slice(&[9u8; NONCE_LEN]);
        client.write_all(&hello).await.unwrap();
        let task = tokio::spawn({
            let store = Store::with("alice", "right");
            async move { server_authenticate(&mut server, &store, decoy()).await }
        });
        let mut offer = [0u8; 2 + 1 + 16 + 6 + NONCE_LEN];
        client.read_exact(&mut offer).await.unwrap();
        shapes.push((offer[0], offer[1], offer[2]));
        drop(client);
        let _ = task.await;
    }
    assert_eq!(shapes[0].0, shapes[1].0);
    assert_eq!(shapes[0].1, 0);
    assert_eq!(shapes[1].1, 0, "an unknown user is not refused up front");
    assert_eq!(shapes[0].2, shapes[1].2, "same salt length");
}

/// The decoy is stable per name and differs between names.
#[tokio::test]
async fn the_decoy_is_stable_per_name() {
    let key = decoy();
    let a1 = key.decoy_secret(b"mallory");
    let a2 = key.decoy_secret(b"mallory");
    let b = key.decoy_secret(b"trudy");
    assert_eq!(a1.salt, a2.salt);
    assert_eq!(a1.key(), a2.key());
    assert_ne!(a1.salt, b.salt);
    assert_ne!(a1.key(), b.key());
}

/// A peer that does not hold the key cannot pass as the server: the client
/// verifies the server's proof. Mutation: skipping the check accepts it.
#[tokio::test]
async fn a_server_without_the_key_is_rejected() {
    let credentials = creds("alice", "right");
    let (mut client, mut server) = duplex(4096);
    let rogue = tokio::spawn(async move {
        // Reads the hello, offers a salt, accepts ANY proof with a made-up proof.
        let mut head = [0u8; 2];
        server.read_exact(&mut head).await.unwrap();
        let mut rest = vec![0u8; usize::from(head[1]) + NONCE_LEN];
        server.read_exact(&mut rest).await.unwrap();
        let mut offer = vec![1, 0, 16];
        offer.extend_from_slice(&[3u8; 16]);
        offer.extend_from_slice(&encode_params(&WEAK));
        offer.extend_from_slice(&[4u8; NONCE_LEN]);
        server.write_all(&offer).await.unwrap();
        let mut proof = [0u8; 1 + 32];
        server.read_exact(&mut proof).await.unwrap();
        let mut ok = vec![1, 0];
        ok.extend_from_slice(&[0xAA; 32]);
        server.write_all(&ok).await.unwrap();
    });
    let error = client_authenticate(&mut client, &credentials)
        .await
        .unwrap_err();
    assert_eq!(error, SecureAuthError::ServerProofMismatch);
    rogue.await.unwrap();
}

/// Read the client hello, then hand-encode and return the `params` offer (bomb values exceed `encode_params`).
async fn rogue_offer<R>(server: &mut R, params: KdfParams) -> Vec<u8>
where
    R: tokio::io::AsyncRead + Unpin,
{
    let mut head = [0u8; 2];
    server.read_exact(&mut head).await.unwrap();
    let mut rest = vec![0u8; usize::from(head[1]) + NONCE_LEN];
    server.read_exact(&mut rest).await.unwrap();
    let mut offer = vec![1, 0, 16];
    offer.extend([3u8; 16].into_iter().chain(params.memory_kib.to_be_bytes()));
    offer.extend([params.iterations, params.parallelism].map(|v| v as u8));
    offer.extend_from_slice(&[4u8; NONCE_LEN]);
    offer
}

/// A server that offers a cheaper KDF than the client's floor is refused
/// before any key is derived (no downgrade); absurd parameters are refused as
/// out of range (no memory bomb). Mutation: no floor check derives and sends a
/// proof.
#[tokio::test]
async fn a_kdf_downgrade_or_bomb_is_refused_before_any_work() {
    for (params, expected) in [
        (WEAK, SecureAuthError::KdfTooWeak),
        (
            KdfParams {
                memory_kib: u32::MAX,
                iterations: 2,
                parallelism: 1,
            },
            SecureAuthError::KdfOutOfRange,
        ),
        (
            KdfParams {
                memory_kib: super::kdf::KdfParams::DEFAULT.memory_kib,
                iterations: 200,
                parallelism: 1,
            },
            SecureAuthError::KdfOutOfRange,
        ),
    ] {
        // A client that demands the default cost: WEAK is below it.
        let credentials = SecureCredentials::new("alice", "right").with_min_kdf(KdfParams::DEFAULT);
        let (mut client, mut server) = duplex(4096);
        let rogue = tokio::spawn(async move {
            let offer = rogue_offer(&mut server, params).await;
            server.write_all(&offer).await.unwrap();
            // The client must hang up without sending a proof.
            let mut proof = [0u8; 1];
            assert_eq!(server.read(&mut proof).await.unwrap(), 0);
        });
        let error = client_authenticate(&mut client, &credentials)
            .await
            .unwrap_err();
        assert_eq!(error, expected);
        drop(client);
        rogue.await.unwrap();
        assert!(
            !credentials.is_cached(),
            "no key may be derived for refused parameters"
        );
    }
}

/// The client floor is exactly what `with_min_kdf` says: one step below is
/// refused, the floor itself passes. Mutation: an off-by-one boundary (or
/// dropping the floor check) fails one of the rows.
#[tokio::test]
async fn the_client_floor_is_exactly_the_configured_one() {
    const FLOOR: KdfParams = KdfParams {
        memory_kib: 4096,
        iterations: 1,
        parallelism: 1,
    };
    async fn exchange(params: KdfParams, password: &str) -> SecureAuthError {
        let credentials = SecureCredentials::new("alice", password).with_min_kdf(FLOOR);
        let (mut client, mut server) = duplex(4096);
        let rogue = tokio::spawn(async move {
            let offer = rogue_offer(&mut server, params).await;
            server.write_all(&offer).await.unwrap();
            // Accept any proof, reply with a made-up proof of our own.
            let mut proof = [0u8; 1 + 32];
            // A refused offer (below the floor) ends in EOF with no proof.
            if server.read_exact(&mut proof).await.is_err() {
                return;
            }
            let mut ok = vec![1, 0];
            ok.extend_from_slice(&[0xAA; 32]);
            server.write_all(&ok).await.unwrap();
        });
        let error = client_authenticate(&mut client, &credentials)
            .await
            .unwrap_err();
        drop(client);
        rogue.await.unwrap();
        error
    }

    // One step below the floor is refused without any derivation.
    let below = exchange(
        KdfParams {
            memory_kib: FLOOR.memory_kib - 1,
            iterations: 1,
            parallelism: 1,
        },
        "right",
    )
    .await;
    assert_eq!(below, SecureAuthError::KdfTooWeak);

    // Exactly the floor passes it; the bogus salt makes the rogue
    // server's fake proof fail instead.
    let equal = exchange(FLOOR, "right").await;
    assert_eq!(equal, SecureAuthError::ServerProofMismatch);
}

/// A recorded client proof is useless in a new session: the server nonce is
/// fresh. Mutation: a fixed server nonce makes the replay succeed.
#[tokio::test]
async fn a_recorded_proof_cannot_be_replayed() {
    let store = Store::with("alice", "right");
    let credentials = creds("alice", "right");
    // Session 1, recorded.
    let (mut client, mut server, log) = recorded_pair();
    let (c, s) = tokio::join!(
        client_authenticate(&mut client, &credentials),
        server_authenticate(&mut server, &store, decoy()),
    );
    c.unwrap();
    s.unwrap();
    let wire = log.lock().unwrap().clone();
    // message 1 = 2 + 5 + 32 bytes ("alice"); then the offer (3 + 16 + 6 + 32);
    // then message 3 = 1 + 32.
    let hello = wire[..2 + 5 + NONCE_LEN].to_vec();
    let offer_len = 3 + 16 + 6 + NONCE_LEN;
    let proof_msg = wire[2 + 5 + NONCE_LEN + offer_len..][..1 + 32].to_vec();
    // Session 2: replay the recorded hello and proof.
    let (mut attacker, mut server) = duplex(4096);
    let task = tokio::spawn({
        let store = Store::with("alice", "right");
        async move { server_authenticate(&mut server, &store, decoy()).await }
    });
    attacker.write_all(&hello).await.unwrap();
    let mut offer = vec![0u8; offer_len];
    attacker.read_exact(&mut offer).await.unwrap();
    attacker.write_all(&proof_msg).await.unwrap();
    assert_eq!(task.await.unwrap().unwrap_err(), SecureAuthError::Denied);
}

/// The proofs are bound to everything: changing the user, a nonce, the salt or
/// the parameters changes the proof, and a client proof is never a valid
/// server proof. Mutations: leaving a field out of the HMAC input fails its row.
#[test]
fn proofs_bind_every_field() {
    let key = [5u8; KEY_LEN];
    let (sn, cn) = ([1u8; NONCE_LEN], [2u8; NONCE_LEN]);
    let salt = [9u8; 16];
    let base = client_proof(&key, b"alice", &sn, &cn, &salt, &WEAK);
    assert_ne!(base, client_proof(&key, b"alicf", &sn, &cn, &salt, &WEAK));
    assert_ne!(base, client_proof(&key, b"alice", &cn, &cn, &salt, &WEAK));
    assert_ne!(base, client_proof(&key, b"alice", &sn, &sn, &salt, &WEAK));
    assert_ne!(
        base,
        client_proof(&key, b"alice", &sn, &cn, &[8u8; 16], &WEAK)
    );
    let other = KdfParams {
        memory_kib: 65,
        ..WEAK
    };
    assert_ne!(base, client_proof(&key, b"alice", &sn, &cn, &salt, &other));
    assert_ne!(
        base,
        client_proof(&[6u8; KEY_LEN], b"alice", &sn, &cn, &salt, &WEAK)
    );
    assert_ne!(
        base,
        server_proof(&key, b"alice", &cn, &sn),
        "no reflection"
    );
}

/// Malformed first messages are refused with typed errors.
#[tokio::test]
async fn malformed_hellos_are_refused() {
    let store = Store::with("alice", "right");
    for (bytes, expected) in [
        (vec![2u8, 1, b'a'], SecureAuthError::BadVersion),
        (vec![1u8, 0], SecureAuthError::BadLength),
    ] {
        let (mut client, mut server) = duplex(4096);
        client.write_all(&bytes).await.unwrap();
        let error = server_authenticate(&mut server, &store, decoy())
            .await
            .unwrap_err();
        assert_eq!(error, expected);
    }
}

/// The key is derived once and reused: the second exchange reuses the cache.
#[tokio::test]
async fn the_derived_key_is_cached() {
    let store = Store::with("alice", "right");
    let credentials = creds("alice", "right");
    assert!(!credentials.is_cached());
    for _ in 0..2 {
        let (mut client, mut server) = duplex(4096);
        let (c, s) = tokio::join!(
            client_authenticate(&mut client, &credentials),
            server_authenticate(&mut server, &store, decoy()),
        );
        c.unwrap();
        s.unwrap();
        assert!(credentials.is_cached());
    }
}

/// The stored secret is exactly the Argon2id key of the password and its salt,
/// so a client that derives it independently authenticates. Mutation: another
/// KDF or a different salt handling breaks the equality.
#[test]
fn the_stored_key_is_the_argon2id_of_the_password() {
    let secret = UserSecret::from_password("hunter2hunter2", WEAK).unwrap();
    let again = derive_key(b"hunter2hunter2", &secret.salt, &WEAK).unwrap();
    assert_eq!(secret.key(), &*again);
    let other = derive_key(b"hunter3hunter3", &secret.salt, &WEAK).unwrap();
    assert_ne!(secret.key(), &*other);
}

/// Hard limits and bounds of the stored parts.
#[test]
fn parts_are_validated() {
    assert!(UserSecret::from_parts(vec![0; 7], WEAK, [0; KEY_LEN]).is_err());
    assert!(UserSecret::from_parts(vec![0; 65], WEAK, [0; KEY_LEN]).is_err());
    assert!(UserSecret::from_parts(vec![0; 16], WEAK, [0; KEY_LEN]).is_ok());
    let bomb = KdfParams {
        memory_kib: 1 << 21,
        ..WEAK
    };
    assert!(!bomb.is_in_range());
    assert!(UserSecret::from_parts(vec![0; 16], bomb, [0; KEY_LEN]).is_err());
    assert!(derive_key(b"pw", &[0; 16], &bomb).is_err());
    assert!(!KdfParams {
        memory_kib: 7,
        iterations: 1,
        parallelism: 1
    }
    .is_in_range());
}

/// Debug of the credentials, the stored secret and the decoy key prints no
/// secret material.
#[test]
fn debug_prints_nothing_secret() {
    let credentials = creds("alice", "topsecretpw");
    let secret = UserSecret::from_password("topsecretpw", WEAK).unwrap();
    for text in [
        format!("{credentials:?}"),
        format!("{secret:?}"),
        format!("{:?}", decoy()),
    ] {
        assert!(!text.contains("topsecretpw"));
        assert!(!text.contains("alice"));
    }
}

// ─── init: first-time enrollment ─────────────────────────────────────────

fn enrolling(user: &str, password: &str) -> SecureCredentials {
    creds(user, password)
        .allow_enrollment(true)
        .with_enrollment_kdf(WEAK)
}

/// The first client of an `init` user sets the secret; afterwards the same
/// password logs in normally and another one is denied. Mutations: not
/// storing the claimed secret, or storing it but not proving it, fails here.
#[tokio::test]
async fn the_first_client_sets_the_secret() {
    let store = Store::init("bob");
    let first = enrolling("bob", "bobs-first-password");
    let (mut client, mut server) = duplex(4096);
    let (c, s) = tokio::join!(
        client_authenticate(&mut client, &first),
        server_authenticate(&mut server, &store, decoy()),
    );
    c.unwrap();
    assert_eq!(s.unwrap(), "bob");
    let stored = store.secret("bob").expect("the secret was written");
    let expected = derive_key(b"bobs-first-password", &stored.salt, &stored.params).unwrap();
    assert_eq!(
        stored.key(),
        &*expected,
        "the stored key is the password-derived one"
    );

    // A normal login with the same password (a fresh client, no cache).
    let again = creds("bob", "bobs-first-password");
    let (mut client, mut server) = duplex(4096);
    let (c, s) = tokio::join!(
        client_authenticate(&mut client, &again),
        server_authenticate(&mut server, &store, decoy()),
    );
    c.unwrap();
    s.unwrap();
    // Any other password is now denied: the init window is closed.
    let other = enrolling("bob", "someone-else");
    let (mut client, mut server) = duplex(4096);
    let (c, s) = tokio::join!(
        client_authenticate(&mut client, &other),
        server_authenticate(&mut server, &store, decoy()),
    );
    assert_eq!(c.unwrap_err(), SecureAuthError::Denied);
    assert_eq!(s.unwrap_err(), SecureAuthError::Denied);
}

/// During enrollment neither the password nor the key crosses the wire.
/// Mutation: sending the sealed payload unencrypted puts the key in the log.
#[tokio::test]
async fn enrollment_puts_neither_password_nor_key_on_the_wire() {
    let password = "enroll-secret-pw-42";
    let store = Store::init("bob");
    let credentials = enrolling("bob", password);
    let (mut client, mut server, log) = recorded_pair();
    let (c, s) = tokio::join!(
        client_authenticate(&mut client, &credentials),
        server_authenticate(&mut server, &store, decoy()),
    );
    c.unwrap();
    s.unwrap();
    let key = *store.secret("bob").unwrap().key();
    let wire = log.lock().unwrap().clone();
    assert!(wire.len() > 100);
    assert!(
        !contains(&wire, password.as_bytes()),
        "password on the wire"
    );
    assert!(!contains(&wire, &key), "key on the wire");
}

/// A client that was not told to enroll refuses an `init` offer and the
/// server stores nothing. Mutation: enrolling by default (a man in the
/// middle could then pose as an enrolled user's server) passes the exchange.
#[tokio::test]
async fn a_client_enrolls_only_when_told_to() {
    let store = Store::init("bob");
    let credentials = creds("bob", "pw-for-bob");
    let (mut client, mut server) = duplex(4096);
    let server_task = tokio::spawn(async move {
        let result = server_authenticate(&mut server, &store, decoy()).await;
        (result, store.secret("bob").is_none())
    });
    let error = client_authenticate(&mut client, &credentials)
        .await
        .unwrap_err();
    assert_eq!(error, SecureAuthError::EnrollmentNotAllowed);
    drop(client);
    let (result, nothing_stored) = server_task.await.unwrap();
    assert!(result.is_err());
    assert!(
        nothing_stored,
        "no secret may be stored without an enrollment"
    );
}

/// Two first logins at once: exactly one wins, the other is denied, and the
/// stored secret is the winner's. Mutation: a non-atomic claim lets both win.
#[tokio::test]
async fn of_two_concurrent_first_logins_exactly_one_wins() {
    let store = Arc::new(Store::init("bob"));
    let mut tasks = Vec::new();
    for password in ["first-pw-aaaa", "second-pw-bbbb"] {
        let store = Arc::clone(&store);
        tasks.push(tokio::spawn(async move {
            let credentials = enrolling("bob", password);
            let (mut client, mut server) = duplex(4096);
            let (c, s) = tokio::join!(
                client_authenticate(&mut client, &credentials),
                server_authenticate(&mut server, &*store, decoy()),
            );
            (password, c.is_ok(), s.is_ok())
        }));
    }
    let mut winners = Vec::new();
    for task in tasks {
        let (password, client_ok, server_ok) = task.await.unwrap();
        assert_eq!(client_ok, server_ok, "both sides agree on {password}");
        if client_ok {
            winners.push(password);
        }
    }
    assert_eq!(
        winners.len(),
        1,
        "exactly one first login wins: {winners:?}"
    );
    let stored = store.secret("bob").unwrap();
    let expected = derive_key(winners[0].as_bytes(), &stored.salt, &stored.params).unwrap();
    assert_eq!(
        stored.key(),
        &*expected,
        "the stored secret is the winner's"
    );
}

/// A server refuses an enrollment derived more cheaply than its floor.
/// Mutation: no floor check stores a cheap key.
#[tokio::test]
async fn an_enrollment_below_the_floor_is_refused() {
    struct StrictStore(Store);
    impl SecretStore for StrictStore {
        async fn lookup(&self, user: &str) -> Option<StoredUser> {
            self.0.lookup(user).await
        }
        async fn claim(&self, user: &str, secret: UserSecret) -> bool {
            self.0.claim(user, secret).await
        }
        fn enrollment_floor(&self) -> KdfParams {
            KdfParams {
                memory_kib: 128,
                ..WEAK
            }
        }
    }
    let store = StrictStore(Store::init("bob"));
    // WEAK costs 64 KiB, below the 128 KiB floor.
    let credentials = enrolling("bob", "pw-for-bob");
    let (mut client, mut server) = duplex(4096);
    let server_task = tokio::spawn(async move {
        let result = server_authenticate(&mut server, &store, decoy()).await;
        (result, store.0.secret("bob").is_none())
    });
    let _ = client_authenticate(&mut client, &credentials).await;
    drop(client);
    let (result, nothing_stored) = server_task.await.unwrap();
    assert_eq!(result.unwrap_err(), SecureAuthError::KdfTooWeak);
    assert!(nothing_stored);
}

/// A tampered sealed enrollment does not decrypt and nothing is stored; a
/// degenerate (all-zero) public key is refused. Mutation: skipping the AEAD
/// tag check or the contributory check stores attacker-chosen material.
#[tokio::test]
async fn tampered_or_degenerate_enrollments_are_refused() {
    for degenerate in [false, true] {
        let store = Arc::new(Store::init("bob"));
        let (mut attacker, mut server) = duplex(4096);
        let server_task = tokio::spawn({
            let store = Arc::clone(&store);
            async move { server_authenticate(&mut server, &*store, decoy()).await }
        });
        let mut hello = vec![1u8, 3];
        hello.extend_from_slice(b"bob");
        hello.extend_from_slice(&[1u8; NONCE_LEN]);
        attacker.write_all(&hello).await.unwrap();
        let mut offer = [0u8; 2 + 32 + NONCE_LEN];
        attacker.read_exact(&mut offer).await.unwrap();
        assert_eq!(
            &offer[..2],
            &[1, 1],
            "an init user is offered an enrollment"
        );
        let public = if degenerate { [0u8; 32] } else { [9u8; 32] };
        let sealed = [0x55u8; 1 + 16 + 6 + 32 + 16];
        let mut message = vec![1u8];
        message.extend_from_slice(&public);
        message.extend_from_slice(&u16::try_from(sealed.len()).unwrap().to_be_bytes());
        message.extend_from_slice(&sealed);
        attacker.write_all(&message).await.unwrap();
        let error = server_task.await.unwrap().unwrap_err();
        assert_eq!(error, SecureAuthError::Crypto, "degenerate={degenerate}");
        assert!(store.secret("bob").is_none(), "nothing may be stored");
    }
}

mod cost;
mod limiter;
