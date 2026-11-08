//! RFC 1929 / HTTP Basic wire-level strictness, unit-level and fast
//! (feature `secure-auth`).

use super::*;
use std::collections::HashMap;
use std::sync::Mutex;

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;

use crate::error::SecureAuthError;
use crate::secure_auth::{
    client_authenticate, derive_key, server_authenticate, DecoyKey, PasswordCheck, SecretStore,
    SecureCredentials, StoredUser, UserSecret, KEY_LEN,
};

/// Cheap parameters so the tests do not pay the default Argon2id cost.
const WEAK: crate::secure_auth::KdfParams = crate::secure_auth::KdfParams {
    memory_kib: 64,
    iterations: 1,
    parallelism: 1,
};

struct Store(Mutex<HashMap<String, StoredUser>>);

impl Store {
    fn with(user: &str, password: &str) -> Self {
        let mut map = HashMap::new();
        map.insert(
            user.to_owned(),
            StoredUser::Secret(UserSecret::from_password(password, WEAK).unwrap()),
        );
        Self(Mutex::new(map))
    }

    fn init(user: &str) -> Self {
        let mut map = HashMap::new();
        map.insert(user.to_owned(), StoredUser::Init);
        Self(Mutex::new(map))
    }

    fn is_init(&self, user: &str) -> bool {
        matches!(self.0.lock().unwrap().get(user), Some(StoredUser::Init))
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

    fn enrollment_floor(&self) -> crate::secure_auth::KdfParams {
        WEAK
    }
}

fn decoy() -> &'static DecoyKey {
    static KEY: std::sync::OnceLock<DecoyKey> = std::sync::OnceLock::new();
    KEY.get_or_init(|| DecoyKey::from_bytes([7u8; KEY_LEN]))
}

/// Independent closing-refusal oracle (challenge order: secure then Basic).
const CHALLENGE_CLOSE: &[u8] = b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Resocks5-Secure\r\nProxy-Authenticate: Basic realm=\"resocks5\"\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";

fn b64(text: &str) -> String {
    STANDARD.encode(text)
}

const BARE_REQUEST: &[u8] = b"CONNECT h:443 HTTP/1.1\r\nHost: h\r\n\r\n";

/// What `serve_http` reads back for a refused retry: the keep-alive challenge
/// answering the bare probe, then the closing refusal.
fn probe_then_close() -> Vec<u8> {
    [EXPECT_HTTP_407_CHALLENGE, CHALLENGE_CLOSE].concat()
}

fn request_with(value: &str) -> Vec<u8> {
    format!("CONNECT h:443 HTTP/1.1\r\nHost: h\r\nProxy-Authorization: {value}\r\n\r\n")
        .into_bytes()
}

/// Non-interactive SOCKS run: the greeting and the sub-negotiation bytes are
/// buffered up front, so the RFC 1929 answer (if any) ends up after the
/// method selection in the returned bytes.
async fn serve_socks(
    greeting: &[u8],
    subnegotiation: &[u8],
    store: &Store,
) -> (Result<IncomingRequest, ServerError>, Vec<u8>) {
    let mut bytes = greeting.to_vec();
    bytes.extend_from_slice(subnegotiation);
    // A successful login continues into a CONNECT frame; failure rows never
    // reach it, so the trailer is harmless there.
    bytes.extend_from_slice(&socks_request(b"h")[3..]);
    let (mut peer, mut server) = duplex(64 * 1024);
    peer.write_all(&bytes).await.unwrap();
    peer.shutdown().await.unwrap();
    let options = options(soon(), false, true);
    let result = accept_with(&mut server, &options, &AuthMethods::secure(store, decoy())).await;
    drop(server);
    let mut written = Vec::new();
    peer.read_to_end(&mut written).await.unwrap();
    (result, written)
}

/// Non-interactive HTTP run: a bare probe followed by one header-carrying
/// request; returns everything written (challenge bytes included).
async fn serve_http(
    header: &str,
    store: &Store,
) -> (Result<IncomingRequest, ServerError>, Vec<u8>) {
    let bytes = [BARE_REQUEST, request_with(header).as_slice()].concat();
    let (mut peer, mut server) = duplex(64 * 1024);
    peer.write_all(&bytes).await.unwrap();
    peer.shutdown().await.unwrap();
    let options = options(soon(), false, true);
    let result = accept_with(&mut server, &options, &AuthMethods::secure(store, decoy())).await;
    drop(server);
    let mut written = Vec::new();
    peer.read_to_end(&mut written).await.unwrap();
    (result, written)
}

/// The RFC 1929 sub-negotiation is strictly framed: version != 1 fails
/// WITHOUT any status write, zero-length names/passwords and non-UTF-8
/// bytes answer `[1, 1]`, and the extreme legal length 255 works end to end.
/// Mutation: accepting another version, framing an empty field, tolerating
/// invalid UTF-8, or off-by-one on the 1..=255 length bound fails a row.
#[tokio::test]
async fn subnegotiation_framing_is_strict() {
    let greeting = [5, 1, 2];
    // (sub-negotiation bytes, expected status after the selection | None,
    //  expected error kind)
    let name255 = "a".repeat(255);
    let pw255 = "p".repeat(255);
    let mut long_sub = vec![1, 255];
    long_sub.extend_from_slice(name255.as_bytes());
    long_sub.extend_from_slice(&[255]);
    long_sub.extend_from_slice(pw255.as_bytes());
    let rows: Vec<(Vec<u8>, Option<[u8; 2]>)> = vec![
        // Version byte 2: refused without writing any status.
        (vec![2, 1, b'u', 1, b'p'], None),
        (vec![1, 0], Some([1, 1])),                // empty username
        (vec![1, 1, b'u', 0], Some([1, 1])),       // empty password
        (vec![1, 1, 0xFF, 1, b'p'], Some([1, 1])), // non-UTF-8 user
        (vec![1, 1, b'u', 1, 0xFF], Some([1, 1])), // non-UTF-8 password
    ];
    let store = Store::with("u", "p");
    for (sub, status) in &rows {
        let (result, written) = serve_socks(&greeting, sub, &store).await;
        assert!(
            matches!(result, Err(ServerError::Authentication(_))),
            "{sub:?}"
        );
        let mut expected = vec![5, 2];
        if let Some(status) = status {
            expected.extend_from_slice(status);
        }
        assert_eq!(written, expected, "{sub:?}");
    }
    // Length 255 on both fields is legal: the exchange completes.
    let long_store = Store::with(&name255, &pw255);
    let (result, written) = serve_socks(&greeting, &long_sub, &long_store).await;
    let req = result.unwrap();
    assert_eq!(req.auth_method(), AuthMethod::Cleartext);
    assert_eq!(req.username().map(str::len), Some(255));
    assert!(written.ends_with(&[1, 0]));
}

/// HTTP Basic header parsing is strict but case- and blank-tolerant in the
/// scheme token only: lowercase `basic` and extra blanks work, a value
/// without a scheme token or with a TAB separator is refused.
/// Mutation: accepting a bare token, splitting on any whitespace, or
/// case-sensitively matching the scheme fails a row.
#[tokio::test]
async fn basic_header_parsing_is_strict() {
    let good = format!("Basic {}", b64("user:pw"));
    let store = Store::with("user", "pw");
    for (header, want_success) in [
        (format!("basic {}", b64("user:pw")), true), // lowercase scheme
        (format!("Basic   {}", b64("user:pw")), true), // extra blanks
        (good, true),
        (b64("user:pw"), false), // bare token: no scheme
        (format!("Basic\t{}", b64("user:pw")), false), // TAB stays in the token
    ] {
        let (result, written) = serve_http(&header, &store).await;
        if want_success {
            let req = result.unwrap_or_else(|e| panic!("{header:?}: {e}"));
            assert_eq!(req.auth_method(), AuthMethod::Cleartext, "{header:?}");
            assert_eq!(req.username(), Some("user"), "{header:?}");
            assert_eq!(written, EXPECT_HTTP_407_CHALLENGE, "{header:?}");
        } else {
            assert_eq!(written, probe_then_close(), "{header:?}");
            assert!(
                matches!(result, Err(ServerError::Authentication(_))),
                "{header:?}"
            );
        }
    }
}

/// Empty and control-character Basic credentials are refused with the
/// closing 407 and never claim an `Init` user.
/// Mutation: accepting `user:` / `:pw` / control bytes, or claiming the Init
/// user on a rejected row, fails this test.
#[tokio::test]
async fn empty_and_control_rejections_never_claim() {
    for header in [
        format!("Basic {}", b64("user:")),
        format!("Basic {}", b64(":pw")),
        format!("Basic {}", b64("u\u{0}:p")),
    ] {
        let store = Store::init("carol");
        let (result, written) = serve_http(&header, &store).await;
        assert_eq!(written, probe_then_close(), "{header:?}");
        assert!(
            matches!(result, Err(ServerError::Authentication(_))),
            "{header:?}"
        );
        assert!(store.is_init("carol"), "{header:?} claimed a rejected user");
    }
}

// ─── `SecretStore::check_password`: the clear-text half of the one-secret model ─────────

/// The enrolled password is accepted, a wrong one and an unknown user are
/// rejected. Mutation: comparing non-constant-time (or comparing against a
/// wrong stored field) flips one of the verdicts.
#[tokio::test]
async fn check_password_accepts_the_enrolled_password() {
    let store = Store::with("alice", "pw");
    assert_eq!(
        store.check_password("alice", "pw").await,
        PasswordCheck::Accepted
    );
    assert_eq!(
        store.check_password("alice", "wrong").await,
        PasswordCheck::Rejected
    );
    assert_eq!(
        store.check_password("mallory", "pw").await,
        PasswordCheck::Rejected
    );
}

/// The first clear-text login claims an `init` user: it stores a secret that
/// later verifies the same password, the secure-auth exchange then succeeds
/// for it, and a different password is rejected. Mutation: skipping the
/// claim (or storing a secret of another password) fails one of the asserts.
#[tokio::test]
async fn check_password_claims_an_init_user() {
    let store = Store::init("bob");
    assert_eq!(
        store.check_password("bob", "bobs-pw").await,
        PasswordCheck::Claimed
    );
    let stored = store.secret("bob").expect("the secret was written");
    let derived = derive_key(b"bobs-pw", &stored.salt, &stored.params).unwrap();
    assert_eq!(stored.key(), &*derived, "the stored key verifies bobs-pw");
    assert_eq!(
        store.check_password("bob", "other").await,
        PasswordCheck::Rejected
    );
    // A secure-auth login for the claimed user now succeeds.
    let credentials = SecureCredentials::new("bob", "bobs-pw").with_min_kdf(WEAK);
    let (mut client, mut server) = duplex(4096);
    let (c, s) = tokio::join!(
        client_authenticate(&mut client, &credentials),
        server_authenticate(&mut server, &store, decoy()),
    );
    c.unwrap();
    assert_eq!(s.unwrap(), "bob");
}

/// An empty password never claims an account, and an empty user name is
/// always rejected. Mutation: dropping the empty check claims the user (the
/// second assert catches it).
#[tokio::test]
async fn check_password_rejects_empty_credentials() {
    let store = Store::init("alice");
    assert_eq!(
        store.check_password("alice", "").await,
        PasswordCheck::Rejected
    );
    assert!(
        store.secret("alice").is_none(),
        "an empty password must not claim the account"
    );
    assert_eq!(
        store.check_password("", "pw").await,
        PasswordCheck::Rejected
    );
}

/// `try_new` refuses an empty field up front with `BadLength`; a normal pair
/// is fine. Mutation: accepting empty fields fails the first two asserts.
#[test]
fn try_new_refuses_empty_fields() {
    assert_eq!(
        SecureCredentials::try_new("", "pw").unwrap_err(),
        SecureAuthError::BadLength
    );
    assert_eq!(
        SecureCredentials::try_new("u", "").unwrap_err(),
        SecureAuthError::BadLength
    );
    SecureCredentials::try_new("u", "p").unwrap();
}
