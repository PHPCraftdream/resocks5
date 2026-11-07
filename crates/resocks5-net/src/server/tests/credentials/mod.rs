//! Credentials retention, hand-off, redaction, and optional zeroizing tests.

use super::*;

/// SOCKS5 method-2 accept over a fresh duplex; returns the result and the
/// server's full wire output ([method selection, auth result]).
async fn socks_password_accept(
    user: &[u8],
    password: &[u8],
    verified: bool,
    retain: bool,
    calls: &Arc<AtomicUsize>,
) -> (Result<IncomingRequest, ServerError>, Vec<u8>) {
    let (mut peer, mut server) = duplex(4096);
    let mut frame = vec![5, 1, 2];
    frame.push(1);
    frame.push(u8::try_from(user.len()).unwrap());
    frame.extend_from_slice(user);
    frame.push(u8::try_from(password.len()).unwrap());
    frame.extend_from_slice(password);
    frame.extend_from_slice(&[5, 1, 0, 1, 127, 0, 0, 1, 0, 80]); // CONNECT
    peer.write_all(&frame).await.unwrap();
    let expected_user = String::from_utf8(user.to_vec()).unwrap();
    let expected_password = String::from_utf8(password.to_vec()).unwrap();
    let opts = options(false, true);
    let opts = if retain {
        opts.retain_credentials(true)
    } else {
        opts
    };
    let counted = Arc::clone(calls);
    let result = accept(&mut server, &opts, move |c| async move {
        assert_eq!(c.username(), expected_user);
        assert_eq!(c.password(), expected_password);
        counted.fetch_add(1, Ordering::SeqCst);
        verified
    })
    .await;
    drop(server);
    let mut response = Vec::new();
    peer.read_to_end(&mut response).await.unwrap();
    (result, response)
}

/// HTTP Basic accept over a fresh duplex, with an optional appended pipeline;
/// returns the result and the server's full wire output (the 407 bytes on failure).
async fn http_basic_accept(
    user: &str,
    password: &str,
    pipeline: &[u8],
    verified: bool,
    retain: bool,
    calls: &Arc<AtomicUsize>,
) -> (Result<IncomingRequest, ServerError>, Vec<u8>) {
    let token = general_purpose::STANDARD.encode(format!("{user}:{password}"));
    let mut frame = format!("CONNECT h:443 HTTP/1.1\r\nProxy-Authorization: Basic {token}\r\n\r\n")
        .into_bytes();
    frame.extend_from_slice(pipeline);
    let (mut peer, mut server) = duplex(4096);
    peer.write_all(&frame).await.unwrap();
    let opts = options(false, true);
    let opts = if retain {
        opts.retain_credentials(true)
    } else {
        opts
    };
    let counted = Arc::clone(calls);
    let result = accept(&mut server, &opts, move |c| async move {
        assert_eq!(c.username(), user);
        assert_eq!(c.password(), password);
        counted.fetch_add(1, Ordering::SeqCst);
        verified
    })
    .await;
    drop(server);
    let mut response = Vec::new();
    peer.read_to_end(&mut response).await.unwrap();
    (result, response)
}

/// Without retention the request carries no credentials, but the username survives.
#[tokio::test]
async fn retain_off_default_keeps_no_credentials() {
    timeout(Duration::from_secs(10), async {
        let calls = Arc::new(AtomicUsize::new(0));
        let (result, _) =
            socks_password_accept(b"plain-user", b"plain-pass", true, false, &calls).await;
        let mut req = result.expect("socks request ok");
        assert!(req.credentials.is_none());
        assert!(req.take_credentials().is_none());
        assert_eq!(req.username(), Some("plain-user"));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        drop(req);

        let calls = Arc::new(AtomicUsize::new(0));
        let (result, _) =
            http_basic_accept("plain-user", "plain-pass", b"", true, false, &calls).await;
        let mut req = result.expect("http request ok");
        assert!(req.credentials.is_none());
        assert!(req.take_credentials().is_none());
        assert_eq!(req.username(), Some("plain-user"));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    })
    .await
    .expect("bounded retain_off_default_keeps_no_credentials");
}

/// With retention the exact submitted bytes come back once, then are gone.
#[tokio::test]
async fn retain_on_hands_back_exact_submitted_credentials() {
    timeout(Duration::from_secs(10), async {
        let calls = Arc::new(AtomicUsize::new(0));
        let (result, _) =
            socks_password_accept("üser-✓".as_bytes(), "päss".as_bytes(), true, true, &calls).await;
        let mut req = result.expect("socks request ok");
        let creds = req.take_credentials().expect("retained credentials");
        assert_eq!(creds.username(), "üser-✓");
        assert_eq!(creds.password(), "päss");
        assert!(req.take_credentials().is_none());
        assert_eq!(req.username(), Some("üser-✓"));
        assert_eq!(req.take_username(), Some("üser-✓".to_owned()));
        assert_eq!(req.take_username(), None);
        let (user, password) = creds.into_parts();
        assert_eq!(user, "üser-✓".to_owned());
        assert_eq!(password, "päss".to_owned());
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        let calls = Arc::new(AtomicUsize::new(0));
        let (result, _) =
            http_basic_accept("colon-user", "pass:with:colons", b"", true, true, &calls).await;
        let mut req = result.expect("http request ok");
        let creds = req.take_credentials().expect("retained credentials");
        assert_eq!(creds.username(), "colon-user");
        assert_eq!(creds.password(), "pass:with:colons");
        assert!(req.take_credentials().is_none());
        assert_eq!(req.username(), Some("colon-user"));
        assert_eq!(req.take_username(), Some("colon-user".to_owned()));
        assert_eq!(req.take_username(), None);
        let (user, password) = creds.into_parts();
        assert_eq!(user, "colon-user".to_owned());
        assert_eq!(password, "pass:with:colons".to_owned());
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    })
    .await
    .expect("bounded retain_on_hands_back_exact_submitted_credentials");
}

/// Anonymous acceptance and failed authentication never retain credentials.
#[tokio::test]
async fn retain_on_anonymous_and_failed_auth_hold_no_credentials() {
    timeout(Duration::from_secs(10), async {
        // (a) Anonymous HTTP with retention on.
        let (mut peer, mut server) = duplex(4096);
        peer.write_all(b"CONNECT h:443 HTTP/1.1\r\n\r\n")
            .await
            .unwrap();
        let calls = Arc::new(AtomicUsize::new(0));
        let counted = Arc::clone(&calls);
        let result = accept(
            &mut server,
            &options(true, false).retain_credentials(true),
            move |_| async move {
                counted.fetch_add(1, Ordering::SeqCst);
                true
            },
        )
        .await;
        drop(server);
        let mut response = Vec::new();
        peer.read_to_end(&mut response).await.unwrap();
        let mut req = result.expect("anonymous http ok");
        assert!(req.take_credentials().is_none());
        assert_eq!(req.username(), None);
        assert_eq!(calls.load(Ordering::SeqCst), 0);

        // (b) SOCKS wrong password.
        let calls = Arc::new(AtomicUsize::new(0));
        let (result, response) =
            socks_password_accept(b"right-user", b"wrong-pass", false, true, &calls).await;
        assert!(matches!(result, Err(ServerError::Authentication(_))));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(response, [5, 2, 1, 1]);

        // (c) HTTP wrong password.
        let calls = Arc::new(AtomicUsize::new(0));
        let (result, response) =
            http_basic_accept("right-user", "wrong-pass", b"", false, true, &calls).await;
        assert!(matches!(result, Err(ServerError::Authentication(_))));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(response, EXPECT_HTTP_407);
    })
    .await
    .expect("bounded retain_on_anonymous_and_failed_auth_hold_no_credentials");
}

/// Anonymous SOCKS5 (method 0) with retention on holds nothing anywhere.
#[tokio::test]
async fn anonymous_socks5_retention_holds_no_credentials() {
    timeout(Duration::from_secs(10), async {
        let (mut peer, mut server) = duplex(4096);
        peer.write_all(&socks_request(b"h")).await.unwrap();
        let calls = Arc::new(AtomicUsize::new(0));
        let counted = Arc::clone(&calls);
        let result = accept(
            &mut server,
            &options(true, false).retain_credentials(true),
            move |_| async move {
                counted.fetch_add(1, Ordering::SeqCst);
                true
            },
        )
        .await;
        drop(server);
        let mut response = Vec::new();
        peer.read_to_end(&mut response).await.unwrap();
        assert_eq!(response, [5, 0]);
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        let mut req = result.expect("anonymous socks ok");
        assert!(req.take_credentials().is_none());
        assert_eq!(req.username(), None);
        assert_eq!(req.take_username(), None);
    })
    .await
    .expect("bounded anonymous socks retention");
}

/// `take_username` yields once and never disturbs retained credentials.
#[tokio::test]
async fn take_username_hands_back_once_and_stays_independent() {
    timeout(Duration::from_secs(10), async {
        // (a) Retention on: username and credentials are independent.
        let calls = Arc::new(AtomicUsize::new(0));
        let (result, _) = socks_password_accept(b"user-x", b"user-pass", true, true, &calls).await;
        let mut req = result.expect("socks request ok");
        assert_eq!(req.take_username(), Some("user-x".to_owned()));
        assert_eq!(req.username(), None);
        assert_eq!(req.take_username(), None);
        let creds = req.take_credentials().expect("credentials independent");
        let (user, password) = creds.into_parts();
        assert_eq!(user, "user-x".to_owned());
        assert_eq!(password, "user-pass".to_owned());

        // (b) Retention off: only the username is available.
        let (result, _) = socks_password_accept(b"user-x", b"user-pass", true, false, &calls).await;
        let mut req = result.expect("socks request ok");
        assert_eq!(req.take_username(), Some("user-x".to_owned()));
        assert!(req.take_credentials().is_none());
        assert_eq!(req.take_username(), None);

        // (c) Anonymous: no username at all.
        let (mut peer, mut server) = duplex(4096);
        peer.write_all(b"CONNECT h:443 HTTP/1.1\r\n\r\n")
            .await
            .unwrap();
        let result = accept(&mut server, &options(true, false), |_| async move { true }).await;
        drop(server);
        let mut response = Vec::new();
        peer.read_to_end(&mut response).await.unwrap();
        let mut req = result.expect("anonymous http ok");
        assert_eq!(req.take_username(), None);

        // (d) Empty HTTP username.
        let token = general_purpose::STANDARD.encode(":pw");
        let frame = format!("CONNECT h:443 HTTP/1.1\r\nProxy-Authorization: Basic {token}\r\n\r\n");
        let (mut peer, mut server) = duplex(4096);
        peer.write_all(frame.as_bytes()).await.unwrap();
        let result = accept(&mut server, &options(false, true), |c| async move {
            assert_eq!(c.username(), "");
            assert_eq!(c.password(), "pw");
            true
        })
        .await;
        drop(server);
        let mut response = Vec::new();
        peer.read_to_end(&mut response).await.unwrap();
        let mut req = result.expect("empty-username http ok");
        assert_eq!(req.username(), Some(""));
        assert_eq!(req.take_username(), Some("".to_owned()));
        assert_eq!(req.take_username(), None);

        // (e) HTTP with retention on: username and credentials independent.
        let calls = Arc::new(AtomicUsize::new(0));
        let (result, _) = http_basic_accept("user-x", "user-pass", b"", true, true, &calls).await;
        let mut req = result.expect("http request ok");
        assert_eq!(req.take_username(), Some("user-x".to_owned()));
        assert_eq!(req.username(), None);
        assert_eq!(req.take_username(), None);
        let creds = req.take_credentials().expect("credentials independent");
        let (user, password) = creds.into_parts();
        assert_eq!(user, "user-x".to_owned());
        assert_eq!(password, "user-pass".to_owned());

        // (f) HTTP with retention off: only the username is available.
        let calls = Arc::new(AtomicUsize::new(0));
        let (result, _) = http_basic_accept("user-x", "user-pass", b"", true, false, &calls).await;
        let mut req = result.expect("http request ok");
        assert_eq!(req.take_username(), Some("user-x".to_owned()));
        assert_eq!(req.take_username(), None);
        assert!(req.take_credentials().is_none());
    })
    .await
    .expect("bounded take_username_hands_back_once_and_stays_independent");
}

/// Credentials redact themselves in Debug and hand back exact owned parts.
#[test]
fn credentials_into_parts_and_debug_redaction() {
    let c = Credentials::new("u5".to_owned(), "p5".to_owned());
    assert_eq!(
        format!("{c:?}"),
        "Credentials { username: [REDACTED], password: [REDACTED] }"
    );
    let (user, password) = c.into_parts();
    assert_eq!(user, "u5".to_owned());
    assert_eq!(password, "p5".to_owned());
}

/// The request Debug shows shapes, never secrets, before and after hand-off.
#[tokio::test]
async fn incoming_request_debug_hides_secrets_and_shows_shapes() {
    timeout(Duration::from_secs(10), async {
        let calls = Arc::new(AtomicUsize::new(0));
        let (result, _) = http_basic_accept(
            "cred-user-7",
            "cred-secret-9",
            b"PIPE-SECRET-3",
            true,
            true,
            &calls,
        )
        .await;
        let mut req = result.expect("http request ok");
        assert_eq!(req.pipeline(), b"PIPE-SECRET-3");
        let debug = format!("{req:?}");
        assert!(!debug.contains("cred-user-7"));
        assert!(!debug.contains("cred-secret-9"));
        assert!(!debug.contains("PIPE-SECRET-3"));
        assert!(debug.contains("pipeline_len"));
        assert!(debug.contains("has_username: true"));
        assert!(debug.contains("has_credentials: true"));
        assert!(req.take_credentials().is_some());
        let debug = format!("{req:?}");
        assert!(debug.contains("has_credentials: false"));
    })
    .await
    .expect("bounded incoming_request_debug_hides_secrets_and_shows_shapes");
}

/// Authentication failures stay secret-free on the wire and in error text.
#[tokio::test]
async fn auth_failures_stay_secret_free_on_wire_and_in_text() {
    timeout(Duration::from_secs(10), async {
        let user = "leak-user-4";
        let password = "leak-pass-5";

        // (a) SOCKS wrong password.
        let calls = Arc::new(AtomicUsize::new(0));
        let (result, response) =
            socks_password_accept(user.as_bytes(), password.as_bytes(), false, true, &calls).await;
        let err = result.unwrap_err();
        assert!(matches!(err, ServerError::Authentication(_)));
        assert!(!format!("{err}").contains(user));
        assert!(!format!("{err}").contains(password));
        assert!(!format!("{err:?}").contains(user));
        assert!(!format!("{err:?}").contains(password));
        assert_eq!(response, [5, 2, 1, 1]);

        // (b) HTTP wrong password.
        let (result, response) = http_basic_accept(user, password, b"", false, true, &calls).await;
        let err = result.unwrap_err();
        assert!(matches!(err, ServerError::Authentication(_)));
        assert!(!format!("{err}").contains(user));
        assert!(!format!("{err}").contains(password));
        assert!(!format!("{err:?}").contains(user));
        assert!(!format!("{err:?}").contains(password));
        assert_eq!(response, EXPECT_HTTP_407);

        // (c) Malformed SOCKS5 sub-negotiations (all four shapes).
        let leaked_user = b"leak-user-4";
        let leaked_password = b"leak-pass-5";
        let shapes: [(&str, Vec<u8>); 4] = [
            (
                "zero-length username",
                [&[5u8, 1, 2][..], &[1, 0, 11][..], &leaked_password[..]].concat(),
            ),
            (
                "zero-length password",
                [&[5u8, 1, 2][..], &[1, 11][..], &leaked_user[..], &[0][..]].concat(),
            ),
            (
                "invalid UTF-8 username",
                [
                    &[5u8, 1, 2][..],
                    &[1, 12][..],
                    &leaked_user[..],
                    &[0xFF][..],
                    &[11][..],
                    &leaked_password[..],
                ]
                .concat(),
            ),
            (
                "invalid UTF-8 password",
                [
                    &[5u8, 1, 2][..],
                    &[1, 11][..],
                    &leaked_user[..],
                    &[12][..],
                    &leaked_password[..],
                    &[0xFF][..],
                ]
                .concat(),
            ),
        ];
        for (shape, frame) in shapes {
            let (mut peer, mut server) = duplex(4096);
            peer.write_all(&frame).await.unwrap();
            let calls = Arc::new(AtomicUsize::new(0));
            let counted = Arc::clone(&calls);
            let result = accept(&mut server, &options(false, true), move |_| async move {
                counted.fetch_add(1, Ordering::SeqCst);
                false
            })
            .await;
            drop(server);
            let mut response = Vec::new();
            peer.read_to_end(&mut response).await.unwrap();
            assert_eq!(
                calls.load(Ordering::SeqCst),
                0,
                "{shape}: must be rejected before authentication"
            );
            let err = result.unwrap_err();
            assert!(matches!(err, ServerError::Authentication(_)), "{shape}");
            for rendering in [format!("{err}"), format!("{err:?}")] {
                assert!(!rendering.contains("leak-user-4"), "{shape}: {rendering}");
                assert!(!rendering.contains("leak-pass-5"), "{shape}: {rendering}");
                assert!(!rendering.contains("\u{fffd}"), "{shape}: {rendering}");
                assert!(!rendering.contains("\\u{fffd}"), "{shape}: {rendering}");
                assert!(!rendering.contains("\\xff"), "{shape}: {rendering}");
            }
            assert_eq!(response, [5, 2, 1, 1], "{shape}");
        }
    })
    .await
    .expect("bounded auth_failures_stay_secret_free_on_wire_and_in_text");
}

/// The builder defaults off, chains, copies, and preserves deadline semantics.
#[tokio::test]
async fn retain_credentials_builder_defaults_chain_and_copies() {
    timeout(Duration::from_secs(10), async {
        // White-box: default off.
        assert!(!options(false, true).retain_credentials);

        let opts = options(false, true).retain_credentials(true);
        assert!(opts.retain_credentials);
        assert!(!opts.anonymous);
        assert!(opts.password);

        // Copy semantics: reading through both after the copy compiles only for Copy.
        let copy = opts;
        assert!(copy.retain_credentials);
        assert!(!copy.anonymous);
        assert!(copy.password);
        assert!(opts.retain_credentials);

        // Deadline semantics unchanged: an expired deadline refuses before auth.
        let expired = ServerOptions::new(Instant::now(), true, true).retain_credentials(true);
        let (mut peer, mut server) = duplex(4096);
        peer.write_all(b"CONNECT h:443 HTTP/1.1\r\n\r\n")
            .await
            .unwrap();
        let result = accept(&mut server, &expired, |_| async move { true }).await;
        drop(server);
        let mut response = Vec::new();
        peer.read_to_end(&mut response).await.unwrap();
        assert!(matches!(result, Err(ServerError::Deadline)));
    })
    .await
    .expect("bounded retain_credentials_builder_defaults_chain_and_copies");
}

#[cfg(feature = "zeroize")]
mod drop_lifecycle;

/// Wiping clears credential and request secrets; the pipeline is preserved.
#[cfg(feature = "zeroize")]
#[tokio::test]
async fn zeroize_wipes_credentials_and_requests() {
    timeout(Duration::from_secs(10), async {
        // (a) Credentials wipe.
        let mut c = Credentials::new("wipe-user-1".to_owned(), "wipe-pass-2".to_owned());
        c.wipe();
        assert_eq!(c.username(), "");
        assert_eq!(c.password(), "");

        // (b) Request wipe clears identity, keeps the pipeline.
        let mut req = IncomingRequest {
            auth: crate::server::AuthMethod::Anonymous,
            #[cfg(feature = "gssapi")]
            gss: None,
            protocol: Protocol::Http,
            target: "h:1".into(),
            username: Some("wipe-user-1".to_owned()),
            username_raw: None,
            credentials: Some(Credentials::new(
                "wipe-user-1".to_owned(),
                "wipe-pass-2".to_owned(),
            )),
            pipeline: b"KEEP".to_vec(),
        };
        req.wipe();
        assert_eq!(req.username(), Some(""));
        let creds = req.take_credentials().expect("credentials kept");
        let (user, password) = creds.into_parts();
        assert_eq!(user, "");
        assert_eq!(password, "");
        assert_eq!(req.pipeline(), b"KEEP");

        // (c) A partially drained request still drops without panicking.
        let mut req = IncomingRequest {
            auth: crate::server::AuthMethod::Anonymous,
            #[cfg(feature = "gssapi")]
            gss: None,
            protocol: Protocol::Http,
            target: "h:2".into(),
            username: Some("wipe-user-1".to_owned()),
            username_raw: None,
            credentials: Some(Credentials::new(
                "wipe-user-1".to_owned(),
                "wipe-pass-2".to_owned(),
            )),
            pipeline: b"KEEP".to_vec(),
        };
        assert!(req.take_username().is_some());
        assert!(req.take_credentials().is_some());
    })
    .await
    .expect("bounded zeroize_wipes_credentials_and_requests");
}

// ---- Reply wire pins (folded from tests/replies.rs) ----

const _: () = {
    fn assert_reply_traits<T: Copy + Eq + std::fmt::Debug>() {}
    let _ = assert_reply_traits::<Reply>;
};

/// Drain one host reply from a duplex, after a clean flush and writer drop.
async fn reply_wire(protocol: Protocol, reply: Reply) -> Vec<u8> {
    let req = IncomingRequest {
        auth: crate::server::AuthMethod::Anonymous,
        #[cfg(feature = "gssapi")]
        gss: None,
        username_raw: None,
        credentials: None,
        protocol,
        target: "h:1".into(),
        username: None,
        pipeline: Vec::new(),
    };
    // Capacity must hold the longest reply (the 74-byte 503 head) so the
    // pre-read write can always complete.
    let (mut peer, mut stream) = duplex(4096);
    req.reply(&mut stream, reply).await.unwrap();
    drop(stream);
    let mut received = Vec::new();
    peer.read_to_end(&mut received).await.unwrap();
    received
}

/// Independent wire oracles for every (reply, SOCKS5 bytes, HTTP bytes) pair.
fn reply_rows() -> [(Reply, &'static [u8], &'static [u8]); 8] {
    [
        (
            Reply::Established,
            &[5, 0, 0, 1, 0, 0, 0, 0, 0, 0],
            b"HTTP/1.1 200 Connection Established\r\n\r\n",
        ),
        (
            Reply::Forbidden,
            &[5, 2, 0, 1, 0, 0, 0, 0, 0, 0],
            EXPECT_HTTP_403,
        ),
        (
            Reply::UpstreamUnavailable,
            &[5, 4, 0, 1, 0, 0, 0, 0, 0, 0],
            EXPECT_HTTP_502,
        ),
        (
            Reply::ConnectionRefused,
            &[5, 5, 0, 1, 0, 0, 0, 0, 0, 0],
            EXPECT_HTTP_502,
        ),
        (
            Reply::NetworkUnreachable,
            &[5, 3, 0, 1, 0, 0, 0, 0, 0, 0],
            EXPECT_HTTP_502,
        ),
        (
            Reply::TimedOut,
            &[5, 6, 0, 1, 0, 0, 0, 0, 0, 0],
            EXPECT_HTTP_504,
        ),
        (
            Reply::GeneralFailure,
            &[5, 1, 0, 1, 0, 0, 0, 0, 0, 0],
            EXPECT_HTTP_502,
        ),
        (
            Reply::Overloaded,
            &[5, 1, 0, 1, 0, 0, 0, 0, 0, 0],
            EXPECT_HTTP_503,
        ),
    ]
}

#[tokio::test]
async fn every_protocol_reply_pair_writes_exact_wire_bytes() {
    timeout(Duration::from_secs(10), async {
        for (reply, socks_bytes, http_bytes) in reply_rows() {
            for (protocol, expected) in [
                (Protocol::Socks5, socks_bytes),
                (Protocol::Http, http_bytes),
            ] {
                assert_eq!(reply_wire(protocol, reply).await, expected);
            }
        }
    })
    .await
    .expect("bounded full reply-table pins");
}

#[tokio::test]
async fn reply_flush_delivers_the_whole_message_for_every_pair() {
    timeout(Duration::from_secs(10), async {
        for (reply, socks_bytes, http_bytes) in reply_rows() {
            for (protocol, expected) in [
                (Protocol::Socks5, socks_bytes),
                (Protocol::Http, http_bytes),
            ] {
                let req = IncomingRequest {
                    auth: crate::server::AuthMethod::Anonymous,
                    #[cfg(feature = "gssapi")]
                    gss: None,
                    username_raw: None,
                    credentials: None,
                    protocol,
                    target: "h:1".into(),
                    username: None,
                    pipeline: Vec::new(),
                };
                let delivered = Arc::new(Mutex::new(Vec::new()));
                let mut stream = flush_deliverer(delivered.clone());
                req.reply(&mut stream, reply).await.unwrap();
                // Only poll_flush publishes staged bytes: if IncomingRequest::reply
                // skipped its flush, `delivered` would stay empty and this fails.
                assert_eq!(&*delivered.lock().expect("test delivered buffer"), expected);
                assert!(
                    stream.staged.is_empty(),
                    "flush must move every staged byte"
                );
            }
        }
    })
    .await
    .expect("bounded flush-delivery pins");
}

#[tokio::test]
async fn http_error_replies_are_complete_well_formed_heads() {
    timeout(Duration::from_secs(10), async {
        for (reply, code, reason) in [
            (Reply::Forbidden, "403", "Forbidden"),
            (Reply::UpstreamUnavailable, "502", "Bad Gateway"),
            (Reply::ConnectionRefused, "502", "Bad Gateway"),
            (Reply::NetworkUnreachable, "502", "Bad Gateway"),
            (Reply::TimedOut, "504", "Gateway Timeout"),
            (Reply::GeneralFailure, "502", "Bad Gateway"),
            (Reply::Overloaded, "503", "Service Unavailable"),
        ] {
            let bytes = reply_wire(Protocol::Http, reply).await;
            let text = std::str::from_utf8(&bytes).unwrap();
            assert_eq!(text.matches("\r\n\r\n").count(), 1);
            let end = text.find("\r\n\r\n").unwrap();
            assert_eq!(end + 4, text.len(), "no body after the empty head");
            let lines: Vec<&str> = text[..end].split("\r\n").collect();
            assert_eq!(lines[0], format!("HTTP/1.1 {code} {reason}"));
            assert_eq!(&lines[1..], ["Connection: close", "Content-Length: 0"]);
        }
    })
    .await
    .expect("bounded HTTP head shape pins");
}

/// An unknown status must degrade to a well-formed 500 head, never panic.
/// Mutation: restoring the old `_ => unreachable!(...)` arm makes the
/// unknown-status calls panic and fails this test.
#[test]
fn http_error_unknown_status_falls_back_to_a_500_head() {
    const FALLBACK_500: &[u8] =
        b"HTTP/1.1 500 Internal Server Error\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";
    assert_eq!(http_error(418), FALLBACK_500);
    assert_eq!(http_error(0), FALLBACK_500);
    assert_eq!(http_error(599), FALLBACK_500);
    // Known statuses keep their independently pinned heads.
    assert_eq!(http_error(407), EXPECT_HTTP_407);
    assert_eq!(http_error(503), EXPECT_HTTP_503);
}

#[tokio::test]
async fn timed_out_reply_is_a_504_head_distinct_from_502() {
    timeout(Duration::from_secs(10), async {
        let head_504 = reply_wire(Protocol::Http, Reply::TimedOut).await;
        let head_502 = reply_wire(Protocol::Http, Reply::UpstreamUnavailable).await;
        assert_ne!(head_504, head_502);
        let text = std::str::from_utf8(&head_504).unwrap();
        let status = text.split("\r\n").next().unwrap();
        let parts: Vec<&str> = status.split(' ').collect();
        assert_eq!(parts[0], "HTTP/1.1");
        assert_eq!(parts[1].parse::<u16>().unwrap(), 504);
        assert_eq!(parts[2..].join(" "), "Gateway Timeout");
    })
    .await
    .expect("bounded 504 distinctness pin");
}

#[tokio::test]
async fn socks_replies_are_exactly_ten_bytes_with_rfc1928_shape() {
    timeout(Duration::from_secs(10), async {
        for (reply, rep) in [
            (Reply::Established, 0),
            (Reply::Forbidden, 2),
            (Reply::UpstreamUnavailable, 4),
            (Reply::ConnectionRefused, 5),
            (Reply::NetworkUnreachable, 3),
            (Reply::TimedOut, 6),
            (Reply::GeneralFailure, 1),
            (Reply::Overloaded, 1),
        ] {
            let bytes = reply_wire(Protocol::Socks5, reply).await;
            assert_eq!(bytes.len(), 10);
            assert_eq!((bytes[0], bytes[2], bytes[3]), (5, 0, 1));
            assert_eq!(bytes[1], rep);
            assert_eq!(&bytes[4..], &[0; 6]);
        }
    })
    .await
    .expect("bounded SOCKS reply shape pins");
}

#[tokio::test]
async fn reply_writes_drain_through_a_four_byte_duplex_with_a_concurrent_reader() {
    timeout(Duration::from_secs(10), async {
        for (protocol, reply, expected) in [
            (
                Protocol::Socks5,
                Reply::Established,
                &[5, 0, 0, 1, 0, 0, 0, 0, 0, 0][..],
            ),
            (
                Protocol::Socks5,
                Reply::TimedOut,
                &[5, 6, 0, 1, 0, 0, 0, 0, 0, 0][..],
            ),
            (
                Protocol::Http,
                Reply::Established,
                b"HTTP/1.1 200 Connection Established\r\n\r\n".as_slice(),
            ),
            (Protocol::Http, Reply::TimedOut, EXPECT_HTTP_504),
        ] {
            let req = IncomingRequest {
                auth: crate::server::AuthMethod::Anonymous,
                #[cfg(feature = "gssapi")]
                gss: None,
                username_raw: None,
                credentials: None,
                protocol,
                target: "h:1".into(),
                username: None,
                pipeline: Vec::new(),
            };
            let (mut peer, mut stream) = duplex(4);
            let reader = tokio::spawn(async move {
                let mut received = Vec::new();
                peer.read_to_end(&mut received).await.unwrap();
                received
            });
            req.reply(&mut stream, reply).await.unwrap();
            drop(stream);
            let received = reader.await.unwrap();
            assert_eq!(received, expected);
        }
    })
    .await
    .expect("bounded partial-write drain through a tiny pipe");
}

#[tokio::test]
async fn reply_to_closed_peer_fails_with_io_error() {
    timeout(Duration::from_secs(10), async {
        for protocol in [Protocol::Socks5, Protocol::Http] {
            for reply in [
                Reply::Established,
                Reply::Forbidden,
                Reply::UpstreamUnavailable,
                Reply::ConnectionRefused,
                Reply::NetworkUnreachable,
                Reply::TimedOut,
                Reply::GeneralFailure,
                Reply::Overloaded,
            ] {
                let req = IncomingRequest {
        auth: crate::server::AuthMethod::Anonymous,
        #[cfg(feature = "gssapi")]
        gss: None,
                    username_raw: None,
                    credentials: None,
                    protocol,
                    target: "h:1".into(),
                    username: None,
                    pipeline: Vec::new(),
                };
                let (_peer, mut stream) = duplex(1024);
                drop(_peer);
                let result = req.reply(&mut stream, reply).await;
                assert!(
                    matches!(result, Err(ServerError::Io(ref error)) if error.kind() == io::ErrorKind::BrokenPipe)
                );
            }
        }
    })
    .await
    .expect("bounded closed-peer reply failures");
}

#[tokio::test]
async fn accept_then_error_replies_reach_the_scripted_client() {
    timeout(Duration::from_secs(10), async {
        for reply in [
            Reply::TimedOut,
            Reply::ConnectionRefused,
            Reply::NetworkUnreachable,
        ] {
            let rep_of = |reply| match reply {
                Reply::TimedOut => 6u8,
                Reply::ConnectionRefused => 5,
                Reply::NetworkUnreachable => 3,
                _ => unreachable!("unexpected test reply"),
            };
            let mut expected = vec![5, 0, 5, rep_of(reply), 0, 1, 0, 0, 0, 0, 0, 0];
            let opts = options(true, false);
            let (mut peer, mut stream) = duplex(1024);
            peer.write_all(&socks_request(b"h")).await.unwrap();
            let req = accept(&mut stream, &opts, |_| async { true })
                .await
                .unwrap();
            assert_eq!(req.protocol(), Protocol::Socks5);
            req.reply(&mut stream, reply).await.unwrap();
            drop(stream);
            let mut response = Vec::new();
            peer.read_to_end(&mut response).await.unwrap();
            assert_eq!(response, expected);

            expected = EXPECT_HTTP_502.to_vec();
            if reply == Reply::TimedOut {
                expected = EXPECT_HTTP_504.to_vec();
            }
            let (mut peer, mut stream) = duplex(1024);
            peer.write_all(b"CONNECT h:1 HTTP/1.1\r\nHost: h:1\r\n\r\n")
                .await
                .unwrap();
            let req = accept(&mut stream, &opts, |_| async { true })
                .await
                .unwrap();
            assert_eq!(req.protocol(), Protocol::Http);
            req.reply(&mut stream, reply).await.unwrap();
            drop(stream);
            let mut response = Vec::new();
            peer.read_to_end(&mut response).await.unwrap();
            assert_eq!(response, expected);
        }
    })
    .await
    .expect("bounded handshake-level error replies");
}

/// The retained Basic payload (the whole `user:pass` text) is wiped with the
/// rest of the credentials. Mutation: leaving it out of `wipe` keeps the text.
#[cfg(feature = "zeroize")]
#[test]
fn zeroize_wipes_the_basic_payload() {
    let mut c = Credentials::with_basic_payload(
        "wipe-user".to_owned(),
        "wipe-pass".to_owned(),
        "wipe-user:wipe-pass".to_owned(),
    );
    assert_eq!(c.basic_payload(), Some("wipe-user:wipe-pass"));
    c.wipe();
    assert_eq!(c.basic_payload(), None);
}
