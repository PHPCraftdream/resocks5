//! The full negotiation matrix over `accept_with`: SOCKS5 method selection
//! (secure 0x80 over clear text 0x02 over anonymous 0x00) and the HTTP
//! `407` rounds for `Resocks5-Secure` / `Basic` / anonymous (feature
//! `secure-auth`).

use super::*;
use std::collections::HashMap;
use std::sync::Mutex;

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;

use crate::connect::http_connect_handshake;
use crate::error::ConnectError;
use crate::http_auth::MAX_ROUNDS;
use crate::secure_auth::{
    client_authenticate, DecoyKey, SecretStore, SecureCredentials, StoredUser, UserSecret, KEY_LEN,
    METHOD,
};
use crate::types::ProxyConfig;
use crate::SecureAuthError;

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

    fn empty() -> Self {
        Self(Mutex::new(HashMap::new()))
    }

    fn is_init(&self, user: &str) -> bool {
        matches!(self.0.lock().unwrap().get(user), Some(StoredUser::Init))
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

/// Run `accept_with` while `client` drives the peer end; join both.
async fn run<T, F>(
    options: &ServerOptions,
    store: &Store,
    client: impl FnOnce(DuplexStream) -> F,
) -> (Result<IncomingRequest, ServerError>, T)
where
    F: std::future::Future<Output = T>,
{
    let (peer, mut server) = duplex(64 * 1024);
    let decoy = decoy();
    let methods = AuthMethods::secure(store, decoy);
    let server_side = accept_with(&mut server, options, &methods);
    tokio::join!(server_side, client(peer))
}

/// Non-interactive `serve`: write `bytes`, close, read everything written.
async fn serve(
    bytes: &[u8],
    options: &ServerOptions,
    store: &Store,
) -> (Result<IncomingRequest, ServerError>, Vec<u8>) {
    let (mut peer, mut server) = duplex(64 * 1024);
    peer.write_all(bytes).await.unwrap();
    peer.shutdown().await.unwrap();
    let result = accept_with(&mut server, options, &AuthMethods::secure(store, decoy())).await;
    drop(server);
    let mut written = Vec::new();
    peer.read_to_end(&mut written).await.unwrap();
    (result, written)
}

/// The method-selection bytes the server answers a SOCKS5 greeting with,
/// driven interactively (a chosen method keeps the connection open).
async fn selection(offered: &[u8], options: &ServerOptions, store: &Store) -> Vec<u8> {
    let mut greeting = vec![5, u8::try_from(offered.len()).unwrap()];
    greeting.extend_from_slice(offered);
    run(options, store, move |mut peer| async move {
        peer.write_all(&greeting).await.unwrap();
        let mut chosen = [0u8; 2];
        // A refusal closes the stream (read still yields the two bytes); a
        // chosen method stays open until this end drops, failing the server
        // with EOF — the selection bytes are the assertion target either way.
        let _ = peer.read_exact(&mut chosen).await;
        chosen.to_vec()
    })
    .await
    .1
}

/// Independent wire oracles for the closing refusals (never derived from
/// production code).
const CHALLENGE_CLOSE: &[u8] = b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Resocks5-Secure\r\nProxy-Authenticate: Basic realm=\"resocks5\"\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";

fn b64(text: &str) -> String {
    STANDARD.encode(text)
}

const BARE_REQUEST: &[u8] = b"CONNECT h:443 HTTP/1.1\r\nHost: h\r\n\r\n";

fn request_with(value: &str) -> Vec<u8> {
    format!("CONNECT h:443 HTTP/1.1\r\nHost: h\r\nProxy-Authorization: {value}\r\n\r\n")
        .into_bytes()
}

fn secure_proxy(user: &str, password: &str) -> ProxyConfig {
    // `usable_pair` gates the dance, so the clear-text pair is set too; the
    // secure path wins the challenge and the password is never sent.
    let mut proxy = ProxyConfig::http("proxy.test", 1)
        .with_secure_auth(SecureCredentials::new(user, password).with_min_kdf(WEAK));
    proxy.password = Some(password.to_owned());
    proxy
}

/// The SOCKS5 method-selection matrix: the strongest enabled method wins,
/// and a client offering none of the enabled methods gets `[5, 0xFF]`.
/// Mutation: reordering the server's preference (0x02 over 0x80, 0x00 over
/// 0x02, honouring a disabled knob, or choosing from an empty/foreign offer)
/// flips a row's chosen byte or a `[5, 0xFF]` row.
#[tokio::test]
async fn socks_negotiation_matrix() {
    let empty = Store::empty();
    #[rustfmt::skip]
    let rows: &[(&[u8], bool, bool, Option<u8>)] = &[
        // (client offers, allow_anonymous, allow_cleartext, chosen | 0xFF)
        (&[METHOD], false, true, Some(METHOD)),
        (&[METHOD, 0x02], false, true, Some(METHOD)), // secure beats clear text
        (&[0x02], false, true, Some(0x02)),
        (&[0x02], false, false, None), // cleartext disabled
        (&[0x00], true, true, Some(0x00)),
        (&[0x00], true, false, Some(0x00)),
        (&[0x00], false, true, None),
        (&[0x00, 0x02], true, true, Some(0x02)), // 0x02 beats 0x00
        (&[0x02, 0x00], false, true, Some(0x00)),
        (&[], false, true, None),  // empty offer
        (&[], true, true, None),
        (&[0x63], false, true, None), // garbage methods
        (&[0x63], true, true, None),
    ];
    for (offered, anonymous, cleartext, chosen) in rows {
        let opts = options(soon(), *anonymous, *cleartext);
        let got = selection(offered, &opts, &empty).await;
        let want = match chosen {
            Some(m) => vec![5, *m],
            None => vec![5, 0xFF],
        };
        assert_eq!(
            got, want,
            "offers={offered:?} anon={anonymous} ct={cleartext}"
        );
    }
    // secure_only: only 0x80 ever wins, whatever else is offered.
    let opts = options(soon(), false, false).secure_only();
    for (offered, chosen) in [
        (&[METHOD, 0x02] as &[u8], Some(METHOD)),
        (&[0x02], None),
        (&[0x00], None),
    ] {
        let got = selection(offered, &opts, &empty).await;
        let want = match chosen {
            Some(m) => vec![5, m],
            None => vec![5, 0xFF],
        };
        assert_eq!(got, want, "secure_only offers={offered:?}");
    }
}

/// A complete 0x80 exchange with the real client side succeeds and yields a
/// parsed request attributed to the verified user.
/// Mutation: any stage regression (selection, offer, proof, request framing)
/// or a dropped/renamed identity fails this test.
#[tokio::test]
async fn socks_secure_method_completes_end_to_end() {
    let store = Store::with("alice", "pw");
    let opts = options(soon(), false, true);
    let (result, ()) = run(&opts, &store, |mut peer| async move {
        peer.write_all(&[5, 1, METHOD]).await.unwrap();
        let mut chosen = [0; 2];
        peer.read_exact(&mut chosen).await.unwrap();
        assert_eq!(chosen, [5, METHOD]);
        let credentials = SecureCredentials::new("alice", "pw").with_min_kdf(WEAK);
        client_authenticate(&mut peer, &credentials).await.unwrap();
        peer.write_all(&socks_request(b"h")).await.unwrap();
    })
    .await;
    let req = result.unwrap();
    assert_eq!(req.auth_method(), AuthMethod::Secure);
    assert_eq!(req.username(), Some("alice"));
    assert_eq!(req.target(), "h:443");
}

/// A hand-rolled RFC 1929 login over 0x02 succeeds, claims an `Init` user,
/// and the claimed secret then verifies a full 0x80 exchange with the same
/// password (the enrollment floor WEAK keeps it fast).
/// Mutation: skipping the claim, storing a secret at other parameters, or
/// rejecting the claimed user later breaks one of the two phases.
#[tokio::test]
async fn socks_cleartext_completes_and_claims_an_init_user() {
    let store = Store::init("dave");
    let opts = options(soon(), false, true);
    let (result, ()) = run(&opts, &store, |mut peer| async move {
        peer.write_all(&[5, 1, 2]).await.unwrap();
        let mut chosen = [0; 2];
        peer.read_exact(&mut chosen).await.unwrap();
        assert_eq!(chosen, [5, 2]);
        let mut sub = vec![1, 4];
        sub.extend_from_slice(b"dave");
        sub.extend_from_slice(&[8]);
        sub.extend_from_slice(b"daves-pw");
        peer.write_all(&sub).await.unwrap();
        let mut status = [0; 2];
        peer.read_exact(&mut status).await.unwrap();
        assert_eq!(status, [1, 0]);
        peer.write_all(&socks_request(b"h")).await.unwrap();
    })
    .await;
    let req = result.unwrap();
    assert_eq!(req.auth_method(), AuthMethod::Cleartext);
    assert_eq!(req.username(), Some("dave"));

    // The claim enrolled a real secret: the same password now completes 0x80.
    let (result, ()) = run(&opts, &store, |mut peer| async move {
        peer.write_all(&[5, 1, METHOD]).await.unwrap();
        let mut chosen = [0; 2];
        peer.read_exact(&mut chosen).await.unwrap();
        assert_eq!(chosen, [5, METHOD]);
        let credentials = SecureCredentials::new("dave", "daves-pw").with_min_kdf(WEAK);
        client_authenticate(&mut peer, &credentials).await.unwrap();
        peer.write_all(&socks_request(b"h")).await.unwrap();
    })
    .await;
    assert_eq!(result.unwrap().username(), Some("dave"));
}

/// A wrong password over 0x02 and a zero-length password both answer the
/// RFC 1929 failure status and fail the request.
/// Mutation: accepting a wrong password, or answering anything but `[1, 1]`
/// to `plen = 0`, fails a row.
#[tokio::test]
async fn socks_cleartext_wrong_password_and_empty_password_fail() {
    let store = Store::with("alice", "pw");
    for (sub, status) in [
        (
            {
                let mut s = vec![1, 5];
                s.extend_from_slice(b"alice");
                s.extend_from_slice(&[3]);
                s.extend_from_slice(b"bad");
                s
            },
            [1, 1],
        ),
        (
            {
                let mut s = vec![1, 5];
                s.extend_from_slice(b"alice");
                s.extend_from_slice(&[0]); // zero-length password
                s
            },
            [1, 1],
        ),
    ] {
        let opts = options(soon(), false, true);
        let sent = sub.clone();
        let (result, status_read) = run(&opts, &store, move |mut peer| async move {
            peer.write_all(&[5, 1, 2]).await.unwrap();
            let mut chosen = [0; 2];
            peer.read_exact(&mut chosen).await.unwrap();
            assert_eq!(chosen, [5, 2]);
            peer.write_all(&sent).await.unwrap();
            let mut got = [0; 2];
            peer.read_exact(&mut got).await.unwrap();
            got
        })
        .await;
        assert!(
            matches!(result, Err(ServerError::Authentication(_))),
            "{sub:?}"
        );
        assert_eq!(status_read, status, "{sub:?}");
    }
}

/// The HTTP negotiation matrix: no credentials per `allow_anonymous`, then
/// every `Proxy-Authorization` shape per policy, with exact wire oracles.
/// Mutation: serving an anonymous request while disallowed, challenging with
/// the wrong scheme list, accepting/refusing any Basic variant row, or
/// closing/keeping alive the wrong refusal fails a row.
#[tokio::test]
async fn http_negotiation_matrix() {
    enum Outcome {
        /// Authenticated via Basic (true) or served anonymously (false).
        Accept(bool),
        Challenge(&'static [u8]),
        Refuse(&'static [u8]),
    }
    let good = format!("Basic {}", b64("user:pw"));
    let wrong = format!("Basic {}", b64("user:bad"));
    #[rustfmt::skip]
    let rows: Vec<(Option<String>, bool, bool, Outcome)> = vec![
        (None, true, true, Outcome::Accept(false)),
        (None, false, true, Outcome::Challenge(EXPECT_HTTP_407_CHALLENGE)),
        (Some(good.clone()), false, true, Outcome::Accept(true)),
        (Some(wrong), false, true, Outcome::Refuse(CHALLENGE_CLOSE)),
        (Some("Basic !!!".into()), false, true, Outcome::Refuse(CHALLENGE_CLOSE)),
        (Some(format!("Basic {}", b64("nocolon"))), false, true, Outcome::Refuse(CHALLENGE_CLOSE)),
        (Some(format!("Basic {}", b64(":pw"))), false, true, Outcome::Refuse(CHALLENGE_CLOSE)),
        (Some(format!("Basic {}", b64("user:"))), false, true, Outcome::Refuse(CHALLENGE_CLOSE)),
        (Some(format!("Basic {}", b64("u\u{0}:p"))), false, true, Outcome::Refuse(CHALLENGE_CLOSE)),
        (Some("Negotiate a b".into()), false, true, Outcome::Refuse(CHALLENGE_CLOSE)),
        (Some(good.clone()), false, false, Outcome::Refuse(CHALLENGE_CLOSE)), // cleartext off
    ];
    let store = Store::with("user", "pw");
    for (header, anonymous, cleartext, outcome) in &rows {
        let mut bytes = BARE_REQUEST.to_vec();
        if let Some(value) = header {
            bytes.extend(request_with(value));
        }
        let opts = options(soon(), *anonymous, *cleartext);
        let (result, written) = serve(&bytes, &opts, &store).await;
        match outcome {
            Outcome::Accept(via_basic) => {
                let req = result.unwrap_or_else(|e| panic!("{header:?}: {e}"));
                if *via_basic {
                    assert_eq!(req.auth_method(), AuthMethod::Cleartext, "{header:?}");
                    assert_eq!(req.username(), Some("user"), "{header:?}");
                } else {
                    assert_eq!(req.auth_method(), AuthMethod::Anonymous, "{header:?}");
                    assert_eq!(req.username(), None, "{header:?}");
                }
                assert!(written.is_empty(), "{header:?}");
            }
            Outcome::Challenge(oracle) => {
                assert_eq!(written, *oracle, "{header:?}");
                assert!(result.is_err(), "{header:?}");
            }
            Outcome::Refuse(oracle) => {
                assert_eq!(written, *oracle, "{header:?}");
                assert!(
                    matches!(result, Err(ServerError::Authentication(_))),
                    "{header:?}"
                );
            }
        }
    }
    // secure_only challenges without naming Basic; the feature-less `accept`
    // answers every request with the bare closing 407.
    let opts = options(soon(), false, false).secure_only();
    let (result, written) = serve(BARE_REQUEST, &opts, &store).await;
    assert_eq!(written, EXPECT_HTTP_407_SECURE_ONLY);
    assert!(result.is_err());
    let (result, written) = serve(BARE_REQUEST, &anon_options(false), &store).await;
    assert_eq!(written, EXPECT_HTTP_407_BARE_CLOSE);
    assert!(matches!(result, Err(ServerError::Authentication(_))));
    // A disabled clear-text scheme never claims an Init user.
    let init = Store::init("user");
    let opts = options(soon(), false, false);
    let bytes = [BARE_REQUEST, request_with(&good).as_slice()].concat();
    let (result, _) = serve(&bytes, &opts, &init).await;
    assert!(matches!(result, Err(ServerError::Authentication(_))));
    assert!(init.is_init("user"), "clear-text refused but still claimed");
    // Basic claims an Init user once; a different password is then refused.
    let init = Store::init("user");
    let opts = options(soon(), false, true);
    let (result, _) = serve(&bytes, &opts, &init).await;
    let req = result.unwrap();
    assert_eq!(req.username(), Some("user"));
    assert_eq!(req.auth_method(), AuthMethod::Cleartext);
    let second = format!("Basic {}", b64("user:other"));
    let bytes = [BARE_REQUEST, request_with(&second).as_slice()].concat();
    let (result, written) = serve(&bytes, &opts, &init).await;
    assert_eq!(written, CHALLENGE_CLOSE);
    assert!(matches!(result, Err(ServerError::Authentication(_))));
}

/// A client that keeps sending bare CONNECTs is challenged until the round
/// cap, then the connection closes with a final 407.
/// Mutation: raising the cap, dropping it early, or answering a capped round
/// with a keep-alive challenge changes the challenge count or the tail.
#[tokio::test]
async fn http_bare_probes_are_challenged_until_the_round_cap() {
    let store = Store::empty();
    let opts = options(soon(), false, true);
    let mut bytes = Vec::new();
    for _ in 0..MAX_ROUNDS {
        bytes.extend_from_slice(BARE_REQUEST);
    }
    let (result, written) = serve(&bytes, &opts, &store).await;
    assert!(matches!(result, Err(ServerError::Authentication(_))));
    let mut expected = Vec::new();
    for _ in 1..MAX_ROUNDS {
        expected.extend_from_slice(EXPECT_HTTP_407_CHALLENGE);
    }
    expected.extend_from_slice(CHALLENGE_CLOSE);
    assert_eq!(written, expected);
}

/// The full `Resocks5-Secure` HTTP dance with the public client connector:
/// bare probe, challenge, token rounds, and a 200 whose final token the
/// client verifies.
/// Mutation: any round-format, token-encoding, or final-token regression
/// breaks the client handshake or the server identity.
#[tokio::test]
async fn http_secure_rounds_end_to_end() {
    let store = Store::with("erin", "pw");
    let proxy = secure_proxy("erin", "pw");
    let opts = options(soon(), false, true);
    let (mut client, mut server) = duplex(64 * 1024);
    let server_side = async {
        let req = accept_with(&mut server, &opts, &AuthMethods::secure(&store, decoy()))
            .await
            .unwrap();
        assert_eq!(req.auth_method(), AuthMethod::Secure);
        assert_eq!(req.username(), Some("erin"));
        req.reply(&mut server, Reply::Established).await.unwrap();
    };
    let client_side = async {
        http_connect_handshake(&mut client, "target.test:443", &proxy)
            .await
            .unwrap();
    };
    tokio::join!(server_side, client_side);
}

/// A server that answers the successful exchange's 200 with a final token
/// built from the WRONG key is rejected by the client with
/// `SecureAuthError::ServerProofMismatch`.
/// Mutation: skipping the client's final-token verification (or matching any
/// token, not the proven one) turns this test into a success.
#[tokio::test]
async fn http_tampered_final_token_fails_the_client() {
    let store = Store::with("erin", "pw");
    let proxy = secure_proxy("erin", "pw");
    let opts = options(soon(), false, true);
    let (mut client, mut server) = duplex(64 * 1024);
    let server_side = async move {
        accept_with(&mut server, &opts, &AuthMethods::secure(&store, decoy()))
            .await
            .unwrap();
        // Hand-written 200 whose token the store's key cannot verify.
        let head = format!(
            "HTTP/1.1 200 Connection Established\r\nProxy-Authenticate: {}\r\n\r\n",
            crate::http_auth::encode_token(crate::http_auth::SECURE, &[0xAA; 32])
        );
        server.write_all(head.as_bytes()).await.unwrap();
    };
    let client_side = async {
        let error = http_connect_handshake(&mut client, "target.test:443", &proxy)
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            ConnectError::SecureAuth(SecureAuthError::ServerProofMismatch)
        ));
    };
    tokio::join!(server_side, client_side);
}

/// The secure-only challenge names exactly one scheme and nothing else
/// (moved here from `io_failures.rs`: naming schemes needs `accept_with`).
/// Mutation: advertising Basic alongside the strong scheme (or dropping the
/// strong scheme) changes the bytes or the contains-assertions.
#[tokio::test]
async fn secure_only_challenge_names_only_the_secure_scheme() {
    let store = Store::empty();
    let opts = options(soon(), false, false).secure_only();
    let (result, written) = serve(BARE_REQUEST, &opts, &store).await;
    let text = String::from_utf8(written).unwrap();
    assert!(text.contains("Proxy-Authenticate: Resocks5-Secure"));
    assert!(!text.contains("Basic"));
    assert_eq!(text.as_bytes(), EXPECT_HTTP_407_SECURE_ONLY);
    assert!(result.is_err());
}
