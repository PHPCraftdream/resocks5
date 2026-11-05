//! Raw-bytes SOCKS5 credential tests (RFC 1929 UNAME/PASSWD beyond UTF-8).

use super::*;

/// The helper itself must produce the RFC 1929 layout.
#[test]
fn subneg_matches_rfc1929_layout() {
    assert_eq!(subneg(b"ab", b"c"), [1, 2, b'a', b'b', 1, b'c']);
    assert_eq!(subneg(b"", b"x"), [1, 0, 1, b'x']);
    assert_eq!(subneg(b"x", b""), [1, 1, b'x', 0]);
    let long = [b'x'; 255];
    assert_eq!(subneg(&long, b"")[..2], [1, 255]);
    // VER + ULEN + PLEN are 3 framing bytes: 3 + 255 = 258.
    assert_eq!(subneg(&long, b"").len(), 258);
    assert_eq!(subneg(b"", &long).len(), 258);
    // "üser-✓" is 9 UTF-8 bytes; "päss" is 5.
    assert_eq!(subneg("üser-✓".as_bytes(), b"")[1], 9);
    assert_eq!(subneg(b"", "päss".as_bytes())[2], 5);
}

/// SOCKS5 method-2 accept with explicit byte frames; `verify` runs inside the
/// authentication closure and its verdict decides acceptance. Returns the result
/// and the server's full wire output.
async fn socks_raw_accept(
    frame_tail: &[u8], // everything after the [5, 1, 2] greeting
    opts: ServerOptions,
    verify: impl FnOnce(&Credentials) -> bool + Send + 'static,
    calls: &Arc<AtomicUsize>,
) -> (Result<IncomingRequest, ServerError>, Vec<u8>) {
    let (mut peer, mut server) = duplex(4096);
    let mut frame = vec![5, 1, 2];
    frame.extend_from_slice(frame_tail);
    peer.write_all(&frame).await.unwrap();
    let counted = Arc::clone(calls);
    let result = accept(&mut server, &opts, move |c| {
        let verdict = verify(&c);
        counted.fetch_add(1, Ordering::SeqCst);
        async move { verdict }
    })
    .await;
    drop(server);
    let mut response = Vec::new();
    peer.read_to_end(&mut response).await.unwrap();
    (result, response)
}

/// The CONNECT request appended after a successful sub-negotiation.
const CONNECT_IPV4: &[u8] = &[5, 1, 0, 1, 127, 0, 0, 1, 0, 80];

/// With the raw flag off, non-UTF-8 fields are rejected with pinned texts.
#[tokio::test]
async fn raw_off_rejects_invalid_utf8_fields_with_pinned_texts() {
    timeout(Duration::from_secs(10), async {
        // (i) username-only invalid.
        let calls = Arc::new(AtomicUsize::new(0));
        let tail = subneg(b"ab\xff", b"p");
        let (result, response) =
            socks_raw_accept(&tail, options(false, true), move |_| false, &calls).await;
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        let err = result.unwrap_err();
        assert!(matches!(err, ServerError::Authentication(_)));
        assert_eq!(format!("{err}"), "Invalid UTF-8 in username");
        assert_eq!(response, [5, 2, 1, 1]);

        // (ii) password-only invalid.
        let calls = Arc::new(AtomicUsize::new(0));
        let tail = subneg(b"u", b"p\xff");
        let (result, response) =
            socks_raw_accept(&tail, options(false, true), move |_| false, &calls).await;
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        let err = result.unwrap_err();
        assert!(matches!(err, ServerError::Authentication(_)));
        assert_eq!(format!("{err}"), "Invalid UTF-8 in password");
        assert_eq!(response, [5, 2, 1, 1]);
    })
    .await
    .expect("bounded raw_off_rejects_invalid_utf8_fields_with_pinned_texts");
}

/// With the raw flag on, non-UTF-8 fields are accepted and exposed as raw bytes.
#[tokio::test]
async fn raw_on_accepts_non_utf8_fields_and_exposes_raw_bytes() {
    timeout(Duration::from_secs(10), async {
        let opts = options(false, true).raw_credentials(true);

        // (i) username-only invalid.
        let calls = Arc::new(AtomicUsize::new(0));
        let tail = [subneg(b"ab\xff", b"p").as_slice(), CONNECT_IPV4].concat();
        let (result, response) = socks_raw_accept(
            &tail,
            opts,
            |c| {
                assert!(!c.is_utf8());
                assert_eq!(c.username_bytes(), b"ab\xff".as_slice());
                assert_eq!(c.password_bytes(), b"p".as_slice());
                assert_eq!(c.username(), String::from_utf8_lossy(b"ab\xff"));
                assert_eq!(c.password(), "p");
                true
            },
            &calls,
        )
        .await;
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(response, [5, 2, 1, 0]);
        assert_eq!(result.expect("accepted").target(), "127.0.0.1:80");

        // (ii) password-only invalid.
        let calls = Arc::new(AtomicUsize::new(0));
        let tail = [subneg(b"u", b"p\xff").as_slice(), CONNECT_IPV4].concat();
        let (result, response) = socks_raw_accept(
            &tail,
            opts,
            |c| {
                assert!(!c.is_utf8());
                assert_eq!(c.username_bytes(), b"u".as_slice());
                assert_eq!(c.password_bytes(), b"p\xff".as_slice());
                assert_eq!(c.username(), "u");
                assert_eq!(c.password(), String::from_utf8_lossy(b"p\xff"));
                true
            },
            &calls,
        )
        .await;
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(response, [5, 2, 1, 0]);
        assert_eq!(result.expect("accepted").target(), "127.0.0.1:80");

        // (iii) both invalid.
        let calls = Arc::new(AtomicUsize::new(0));
        let tail = [subneg(b"u\xff", b"p\xff").as_slice(), CONNECT_IPV4].concat();
        let (result, response) = socks_raw_accept(
            &tail,
            opts,
            |c| {
                assert!(!c.is_utf8());
                assert_eq!(c.username_bytes(), b"u\xff".as_slice());
                assert_eq!(c.password_bytes(), b"p\xff".as_slice());
                true
            },
            &calls,
        )
        .await;
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(response, [5, 2, 1, 0]);
        assert_eq!(result.expect("accepted").target(), "127.0.0.1:80");
    })
    .await
    .expect("bounded raw_on_accepts_non_utf8_fields_and_exposes_raw_bytes");
}

/// A multibyte character split across the 255-byte boundary still reassembles.
#[tokio::test]
async fn raw_on_reassembles_multibyte_split_across_the_255_byte_boundary() {
    timeout(Duration::from_secs(10), async {
        let mut full = vec![b'a'; 254];
        full.extend_from_slice("€".as_bytes()); // 0xE2 0x82 0xAC straddles byte 255
        full.extend_from_slice(&[b'b'; 43]);
        assert_eq!(full.len(), 300);
        assert_eq!(full[..255].len(), 255);
        assert_eq!(full[255..].len(), 45);
        assert!(String::from_utf8(full[..255].to_vec()).is_err());
        assert!(String::from_utf8(full[255..].to_vec()).is_err());
        assert!(String::from_utf8(full.clone()).is_ok());

        let full_for_closure = full.clone();
        let tail = [subneg(&full[..255], &full[255..]).as_slice(), CONNECT_IPV4].concat();

        // Flag on: split fields are accepted and join back into the original bytes.
        let calls = Arc::new(AtomicUsize::new(0));
        let (result, response) = socks_raw_accept(
            &tail,
            options(false, true).raw_credentials(true),
            move |c| {
                let full = &full_for_closure;
                assert!(!c.is_utf8());
                assert_eq!(c.username_bytes(), &full[..255]);
                assert_eq!(c.password_bytes(), &full[255..]);
                assert_eq!(c.username(), String::from_utf8_lossy(&full[..255]));
                let joined = [c.username_bytes(), c.password_bytes()].concat();
                assert_eq!(joined, *full);
                assert!(String::from_utf8(joined.clone()).is_ok());
                true
            },
            &calls,
        )
        .await;
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(response, [5, 2, 1, 0]);
        let req = result.expect("accepted");
        assert_eq!(req.target(), "127.0.0.1:80");
        assert_eq!(req.username_bytes(), Some(&full[..255]));

        // Flag off: the same tail is rejected with the pinned username text.
        let calls = Arc::new(AtomicUsize::new(0));
        let (result, response) =
            socks_raw_accept(&tail, options(false, true), move |_| false, &calls).await;
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        let err = result.unwrap_err();
        assert_eq!(format!("{err}"), "Invalid UTF-8 in username");
        assert_eq!(response, [5, 2, 1, 1]);
    })
    .await
    .expect("bounded raw_on_reassembles_multibyte_split_across_the_255_byte_boundary");
}

/// Valid UTF-8 fields stay byte-identical with the raw flag on.
#[tokio::test]
async fn raw_on_valid_utf8_fields_stay_byte_identical() {
    timeout(Duration::from_secs(10), async {
        let calls = Arc::new(AtomicUsize::new(0));
        let tail = [
            subneg("üser-✓".as_bytes(), "päss".as_bytes()).as_slice(),
            CONNECT_IPV4,
        ]
        .concat();
        let (result, response) = socks_raw_accept(
            &tail,
            options(false, true).raw_credentials(true),
            |c| {
                assert!(c.is_utf8());
                assert_eq!(c.username_bytes(), "üser-✓".as_bytes());
                assert_eq!(c.password_bytes(), "päss".as_bytes());
                assert_eq!(c.username(), "üser-✓");
                assert!(!c.username().contains('\u{fffd}'));
                true
            },
            &calls,
        )
        .await;
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(response, [5, 2, 1, 0]);
        let req = result.expect("accepted");
        assert_eq!(req.username(), Some("üser-✓"));
        assert_eq!(req.username_bytes(), Some("üser-✓".as_bytes()));
    })
    .await
    .expect("bounded raw_on_valid_utf8_fields_stay_byte_identical");
}

/// The raw flag never widens the RFC 1929 length limits.
#[tokio::test]
async fn raw_on_keeps_rfc1929_length_limits() {
    timeout(Duration::from_secs(10), async {
        // (a) 255-byte raw UNAME is accepted.
        let long_user = [&[b'u'; 254][..], &[0xFF][..]].concat();
        assert_eq!(long_user.len(), 255);
        let calls = Arc::new(AtomicUsize::new(0));
        let long_for_closure = long_user.clone();
        let tail = [subneg(&long_user, b"p").as_slice(), CONNECT_IPV4].concat();
        let (result, response) = socks_raw_accept(
            &tail,
            options(false, true).raw_credentials(true),
            move |c| {
                assert_eq!(c.username_bytes(), long_for_closure.as_slice());
                assert_eq!(c.username_bytes().len(), 255);
                assert!(!c.is_utf8());
                true
            },
            &calls,
        )
        .await;
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(response, [5, 2, 1, 0]);
        result.expect("accepted");

        // (b) 255-byte raw PASSWD is accepted.
        let long_pass = [&[b'p'; 254][..], &[0xFF][..]].concat();
        assert_eq!(long_pass.len(), 255);
        let calls = Arc::new(AtomicUsize::new(0));
        let long_for_closure = long_pass.clone();
        let tail = [subneg(b"u", &long_pass).as_slice(), CONNECT_IPV4].concat();
        let (result, response) = socks_raw_accept(
            &tail,
            options(false, true).raw_credentials(true),
            move |c| {
                assert_eq!(c.password_bytes(), long_for_closure.as_slice());
                assert_eq!(c.password_bytes().len(), 255);
                assert!(!c.is_utf8());
                true
            },
            &calls,
        )
        .await;
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(response, [5, 2, 1, 0]);
        result.expect("accepted");

        // (c)+(d) Zero-length UNAME and PASSWD stay rejected under both flags.
        for raw in [false, true] {
            for (shape, tail) in [
                ("zero-length username", subneg(b"", b"p")),
                ("zero-length password", subneg(b"u", b"")),
            ] {
                let calls = Arc::new(AtomicUsize::new(0));
                let opts = if raw {
                    options(false, true).raw_credentials(true)
                } else {
                    options(false, true)
                };
                let (result, response) =
                    socks_raw_accept(&tail, opts, move |_| false, &calls).await;
                assert_eq!(
                    calls.load(Ordering::SeqCst),
                    0,
                    "{shape}: must be rejected before authentication"
                );
                let err = result.unwrap_err();
                assert!(matches!(err, ServerError::Authentication(_)), "{shape}");
                assert_eq!(response, [5, 2, 1, 1], "{shape}");
            }
        }
    })
    .await
    .expect("bounded raw_on_keeps_rfc1929_length_limits");
}

/// HTTP Basic still 407s on a non-UTF-8 payload regardless of the raw flag.
#[tokio::test]
async fn http_basic_still_407_on_non_utf8_payload_regardless_of_raw_flag() {
    timeout(Duration::from_secs(10), async {
        for raw in [false, true] {
            let frame = [
                b"CONNECT h:443 HTTP/1.1\r\nProxy-Authorization: Basic ".as_slice(),
                general_purpose::STANDARD
                    .encode([0xFFu8, 0xFE, b':', b'p'])
                    .as_bytes(),
                b"\r\n\r\n".as_slice(),
            ]
            .concat();
            let (mut peer, mut server) = duplex(4096);
            peer.write_all(&frame).await.unwrap();
            let calls = Arc::new(AtomicUsize::new(0));
            let counted = Arc::clone(&calls);
            let opts = options(false, true).raw_credentials(raw);
            let result = accept(&mut server, &opts, move |_| async move {
                counted.fetch_add(1, Ordering::SeqCst);
                true
            })
            .await;
            drop(server);
            let mut response = Vec::new();
            peer.read_to_end(&mut response).await.unwrap();
            assert_eq!(calls.load(Ordering::SeqCst), 0);
            assert_eq!(response, EXPECT_HTTP_407);
            assert!(matches!(result, Err(ServerError::Authentication(_))));
        }
    })
    .await
    .expect("bounded http_basic_still_407_on_non_utf8_payload_regardless_of_raw_flag");
}

/// `IncomingRequest::username_bytes` tracks identity across raw, UTF-8, and anonymous.
#[tokio::test]
async fn incoming_request_username_bytes_tracks_identity() {
    timeout(Duration::from_secs(10), async {
        // (a) Raw username with retention.
        let calls = Arc::new(AtomicUsize::new(0));
        let tail = [subneg(b"ab\xff", b"p").as_slice(), CONNECT_IPV4].concat();
        let (result, _) = socks_raw_accept(
            &tail,
            options(false, true)
                .retain_credentials(true)
                .raw_credentials(true),
            |c| {
                assert!(!c.is_utf8());
                assert_eq!(c.username_bytes(), b"ab\xff".as_slice());
                true
            },
            &calls,
        )
        .await;
        let mut req = result.expect("accepted");
        assert_eq!(req.username_bytes(), Some(b"ab\xff".as_slice()));
        assert_eq!(req.username(), Some("ab\u{fffd}"));
        let creds = req.take_credentials().expect("retained");
        assert_eq!(creds.username_bytes(), b"ab\xff");
        assert!(!creds.is_utf8());
        assert!(req.take_username().is_some());
        assert_eq!(req.username_bytes(), None);

        // (b) Valid UTF-8 username.
        let calls = Arc::new(AtomicUsize::new(0));
        let tail = [
            subneg("üser-✓".as_bytes(), "päss".as_bytes()).as_slice(),
            CONNECT_IPV4,
        ]
        .concat();
        let (result, _) = socks_raw_accept(
            &tail,
            options(false, true).raw_credentials(true),
            move |_| true,
            &calls,
        )
        .await;
        let req = result.expect("accepted");
        assert_eq!(req.username_bytes(), Some("üser-✓".as_bytes()));

        // (c) Anonymous: no username bytes at all.
        let (mut peer, mut server) = duplex(4096);
        peer.write_all(&socks_request(b"h")).await.unwrap();
        let calls = Arc::new(AtomicUsize::new(0));
        let counted = Arc::clone(&calls);
        let result = accept(
            &mut server,
            &options(true, false).raw_credentials(true),
            move |_| async move {
                counted.fetch_add(1, Ordering::SeqCst);
                true
            },
        )
        .await;
        drop(server);
        let mut response = Vec::new();
        peer.read_to_end(&mut response).await.unwrap();
        let req = result.expect("accepted");
        assert_eq!(req.username_bytes(), None);
        assert_eq!(req.username(), None);
        assert_eq!(response, [5, 0]);
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    })
    .await
    .expect("bounded incoming_request_username_bytes_tracks_identity");
}

/// Failed raw authentication never leaks the raw bytes in errors or Debug.
#[tokio::test]
async fn raw_failed_auth_errors_and_debugs_stay_secret_free() {
    timeout(Duration::from_secs(10), async {
        let calls = Arc::new(AtomicUsize::new(0));
        let tail = subneg(b"leak-raw-1\xff", b"leak-pass-2");
        let (result, response) = socks_raw_accept(
            &tail,
            options(false, true).raw_credentials(true),
            move |_| false,
            &calls,
        )
        .await;
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(response, [5, 2, 1, 1]);
        let err = result.unwrap_err();
        assert!(matches!(err, ServerError::Authentication(_)));
        for text in [format!("{err}"), format!("{err:?}")] {
            assert!(!text.contains("leak-raw-1"));
            assert!(!text.contains("leak-pass-2"));
            assert!(!text.contains('\u{fffd}'));
            assert!(!text.contains("\\u{fffd}"));
            assert!(!text.contains("\\xff"));
        }

        let c = Credentials::with_raw(
            "leak-raw-1".to_owned(),
            "leak-pass-2".to_owned(),
            Some(b"leak-raw-1\xff".to_vec()),
            None,
        );
        assert_eq!(
            format!("{c:?}"),
            "Credentials { username: [REDACTED], password: [REDACTED] }"
        );

        let req = IncomingRequest {
            protocol: Protocol::Http,
            target: "h:1".into(),
            username: Some("leak-raw-1\u{fffd}".to_owned()),
            username_raw: Some(b"leak-raw-1\xff".to_vec()),
            credentials: Some(Credentials::with_raw(
                "leak-raw-1".to_owned(),
                "leak-pass-2".to_owned(),
                Some(b"leak-raw-1\xff".to_vec()),
                None,
            )),
            pipeline: b"PIPE".to_vec(),
        };
        let debug = format!("{req:?}");
        assert!(!debug.contains("leak-raw-1"));
        assert!(!debug.contains("leak-pass-2"));
    })
    .await
    .expect("bounded raw_failed_auth_errors_and_debugs_stay_secret_free");
}

/// The builder defaults off, chains, copies, and preserves deadline semantics.
#[tokio::test]
async fn raw_credentials_builder_defaults_chain_copy_and_deadline() {
    timeout(Duration::from_secs(10), async {
        // White-box: default off.
        assert!(!options(false, true).raw_credentials);

        let opts = options(false, true)
            .retain_credentials(true)
            .raw_credentials(true);
        assert!(opts.raw_credentials);
        assert!(opts.retain_credentials);
        assert!(!opts.anonymous);
        assert!(opts.password);

        // Copy semantics: reading through both compiles only for Copy.
        let copy = opts;
        assert!(copy.raw_credentials);
        assert!(copy.retain_credentials);
        assert!(opts.raw_credentials);
        assert!(opts.retain_credentials);

        // Deadline semantics unchanged: an expired deadline refuses before auth.
        let expired = ServerOptions::new(Instant::now(), true, true)
            .retain_credentials(true)
            .raw_credentials(true);
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
    .expect("bounded raw_credentials_builder_defaults_chain_copy_and_deadline");
}

/// Wiping clears the raw byte vectors alongside the text fields.
#[cfg(feature = "zeroize")]
#[tokio::test]
async fn raw_zeroize_wipes_raw_byte_vectors() {
    timeout(Duration::from_secs(10), async {
        let mut c = Credentials::with_raw(
            "raw-u".to_owned(),
            "raw-p".to_owned(),
            Some(b"raw-u\xff".to_vec()),
            Some(b"raw-p".to_vec()),
        );
        c.wipe();
        // The zeroized raw vectors are dropped (empty), so the byte accessors
        // fall back to the wiped text: observable without private fields.
        assert!(c.username_bytes().is_empty());
        assert!(c.password_bytes().is_empty());
        assert_eq!(c.username(), "");
        assert_eq!(c.password(), "");
        let (username_raw, password_raw) = c.raw_parts();
        assert!(username_raw.is_none() || username_raw.expect("present").is_empty());
        assert!(password_raw.is_none() || password_raw.expect("present").is_empty());

        let mut req = IncomingRequest {
            protocol: Protocol::Http,
            target: "h:2".into(),
            username: Some("raw-u".to_owned()),
            username_raw: Some(b"raw-req\xff".to_vec()),
            credentials: None,
            pipeline: b"KEEP".to_vec(),
        };
        req.wipe();
        assert!(req.username_raw.as_ref().expect("kept").is_empty());
    })
    .await
    .expect("bounded raw_zeroize_wipes_raw_byte_vectors");
}

/// `take_username` must wipe the raw identity bytes before they are freed:
/// the witness records what its `Drop` sees, so the assertion reads live
/// memory only. Mutation: removing the in-place wipe inside `discard_wiped`
/// lets the buffer arrive at `Drop` unwiped and fails the all-zero assertion.
#[cfg(feature = "zeroize")]
#[test]
fn take_username_zeroizes_raw_bytes_before_free() {
    // A Vec stand-in whose Drop records the bytes it still held (and how
    // often it dropped); `discard_wiped` wipes through `Zeroize` first.
    struct Witness {
        bytes: Vec<u8>,
        observed: std::rc::Rc<std::cell::RefCell<(usize, Vec<u8>)>>,
    }
    impl zeroize::Zeroize for Witness {
        // Overwrite in place and keep the length: `Vec::zeroize` would also
        // clear it, leaving the witness nothing to observe.
        fn zeroize(&mut self) {
            self.bytes.iter_mut().for_each(|b| *b = 0);
        }
    }
    impl Drop for Witness {
        fn drop(&mut self) {
            let mut seen = self.observed.borrow_mut();
            seen.0 += 1;
            seen.1 = self.bytes.clone();
        }
    }

    let observed = std::rc::Rc::new(std::cell::RefCell::new((0usize, Vec::new())));
    let mut slot = Some(Witness {
        bytes: b"raw-secret".to_vec(),
        observed: std::rc::Rc::clone(&observed),
    });
    discard_wiped(&mut slot);
    assert!(slot.is_none());
    let seen = observed.borrow().clone();
    assert_eq!(seen.0, 1, "the witness must drop exactly once");
    assert_eq!(seen.1.len(), 10, "the witness must capture the buffer");
    assert!(seen.1.iter().all(|&b| b == 0), "bytes must arrive zeroized");

    // An already-empty slot is a no-op: no second drop, nothing wiped.
    discard_wiped(&mut slot);
    assert!(slot.is_none());
    assert_eq!(observed.borrow().0, 1, "an empty slot must drop nothing");
}

/// The extracted decode helper returns the exact pair for valid and invalid
/// UTF-8: text-only for a valid field, lossy text plus the exact submitted
/// bytes for a non-UTF-8 field. Mutation: any regression that drops or
/// corrupts the raw bytes (or mangles the lossy text) fails these assertions.
#[test]
fn decode_raw_field_returns_exact_pairs() {
    assert_eq!(
        decode_raw_field(b"plain".to_vec()),
        ("plain".to_owned(), None)
    );
    let (text, raw) = decode_raw_field(b"ab\xff".to_vec());
    assert_eq!(text, "ab\u{fffd}");
    assert_eq!(raw.as_deref(), Some(b"ab\xff".as_slice()));
}

/// The helper consumes the buffer: a valid field becomes the text in place and
/// an invalid one comes back as the very same allocation, neither is copied.
/// Mutation: going back to `String::from_utf8(raw.clone())` / cloning the
/// bytes changes the data pointer and fails both assertions.
#[test]
fn decode_raw_field_does_not_copy_the_buffer() {
    let raw = b"plain-field".to_vec();
    let ptr = raw.as_ptr();
    let (text, kept) = decode_raw_field(raw);
    assert_eq!(text.as_ptr(), ptr, "valid UTF-8 must convert in place");
    assert!(kept.is_none());

    let raw = b"ab\xffcd".to_vec();
    let ptr = raw.as_ptr();
    let (_, kept) = decode_raw_field(raw);
    let kept = kept.expect("invalid UTF-8 keeps the bytes");
    assert_eq!(
        kept.as_ptr(),
        ptr,
        "the exact bytes must come back without a clone"
    );
}

/// `drop_secret` must wipe rejected credential bytes before they are freed:
/// the witness records what its `Drop` sees, so the assertion reads live
/// memory only. Mutation: dropping without the in-place wipe lets the buffer
/// arrive at `Drop` unwiped and fails the all-zero assertion.
#[cfg(feature = "zeroize")]
#[test]
fn drop_secret_zeroizes_rejected_bytes_before_free() {
    struct Witness {
        bytes: Vec<u8>,
        observed: std::rc::Rc<std::cell::RefCell<(usize, Vec<u8>)>>,
    }
    impl zeroize::Zeroize for Witness {
        // Overwrite in place and keep the length: a wholesale `Vec::zeroize`
        // would also clear the length, leaving nothing to observe.
        fn zeroize(&mut self) {
            self.bytes.iter_mut().for_each(|b| *b = 0);
        }
    }
    impl Drop for Witness {
        fn drop(&mut self) {
            let mut seen = self.observed.borrow_mut();
            seen.0 += 1;
            seen.1 = self.bytes.clone();
        }
    }

    let observed = std::rc::Rc::new(std::cell::RefCell::new((0usize, Vec::new())));
    drop_secret(Witness {
        bytes: b"rejected-secret".to_vec(),
        observed: std::rc::Rc::clone(&observed),
    });
    let seen = observed.borrow().clone();
    assert_eq!(seen.0, 1, "the witness must drop exactly once");
    assert_eq!(seen.1.len(), 15, "the witness must capture the buffer");
    assert!(seen.1.iter().all(|&b| b == 0), "bytes must arrive zeroized");
}
