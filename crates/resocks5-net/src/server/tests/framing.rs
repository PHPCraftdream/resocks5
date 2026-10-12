//! Framing, authentication, and header-handling tests.

use super::*;

#[tokio::test]
async fn same_listener_accepts_both_protocols_without_early_success() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = async {
        for expected in [Protocol::Socks5, Protocol::Http] {
            let (mut stream, _) = listener.accept().await.unwrap();
            let req = accept(&mut stream, &options(true, false), |_| async {
                panic!("anonymous callback")
            })
            .await
            .unwrap();
            assert_eq!(req.protocol(), expected);
            assert_eq!(req.target(), "unresolved.invalid:443");
            assert_eq!(req.username(), None);
            // Parsing emits only method selection, never a tunnel success reply.
            req.reply(&mut stream, Reply::Forbidden).await.unwrap();
        }
    };
    let client = async {
        for bytes in [
            socks_request(b"unresolved.invalid"),
            b"CONNECT unresolved.invalid:443 HTTP/1.1\r\n\r\n".to_vec(),
        ] {
            let socks = bytes[0] == 5;
            let mut stream = tokio::net::TcpStream::connect(address).await.unwrap();
            stream.write_all(&bytes).await.unwrap();
            let mut reply = Vec::new();
            stream.read_to_end(&mut reply).await.unwrap();
            if socks {
                assert_eq!(reply, [5, 0, 5, 2, 0, 1, 0, 0, 0, 0, 0, 0]);
            } else {
                assert_eq!(reply, EXPECT_HTTP_403);
            }
        }
    };
    timeout(Duration::from_secs(10), async {
        tokio::join!(server, client);
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn authentication_policy_matrix_and_method_preference() {
    for anonymous in [false, true] {
        for password in [false, true] {
            for supplied in [false, true] {
                let http = if supplied {
                    b"CONNECT h:0 HTTP/x\r\nProxy-Authorization: bAsIc dTpwOm0=\r\n\r\n".as_slice()
                } else {
                    b"CONNECT h:0 HTTP/x\r\n\r\n".as_slice()
                };
                let (result, reply, calls) = parse(http, anonymous, password, true).await;
                let allowed = if supplied { password } else { anonymous };
                assert_eq!(result.is_ok(), allowed);
                assert_eq!(calls, usize::from(supplied && password));
                if allowed {
                    assert!(reply.is_empty());
                    assert_eq!(result.unwrap().username(), supplied.then_some("u"));
                } else {
                    assert_eq!(reply, EXPECT_HTTP_407);
                }
            }
            let mut socks = vec![5, 2, 0, 2];
            if password {
                socks.extend_from_slice(&[1, 1, b'u', 1, b'p']);
            }
            socks.extend_from_slice(&socks_request(b"h")[3..]);
            let (result, reply, calls) = parse(&socks, anonymous, password, true).await;
            assert_eq!(result.is_ok(), anonymous || password);
            assert_eq!(calls, usize::from(password));
            if password {
                assert_eq!(reply, [5, 2, 1, 0]);
                assert_eq!(result.unwrap().username(), Some("u"));
            } else if anonymous {
                assert_eq!(reply, [5, 0]);
            } else {
                assert_eq!(reply, [5, 255]);
            }
        }
    }
    let (result, reply, calls) = parse(&[5, 1, 2, 1, 1, b'u', 1, b'p'], true, true, false).await;
    assert!(matches!(result, Err(ServerError::Authentication(_))));
    assert_eq!(reply, [5, 2, 1, 1]);
    assert_eq!(calls, 1);
    let (result, reply, _) = parse(
        b"CONNECT h:1 HTTP/1.1\r\nProxy-Authorization: Basic dTpw\r\n\r\n",
        true,
        true,
        false,
    )
    .await;
    assert!(matches!(result, Err(ServerError::Authentication(_))));
    assert_eq!(reply, EXPECT_HTTP_407); // Optional credentials never fall back to anonymous.
}

#[tokio::test]
async fn basic_uses_first_header_first_colon_and_redacts_credentials() {
    let (mut peer, mut stream) = duplex(1024);
    peer.write_all(b"CONNECT h:443 HTTP/anything\r\n Proxy-Authorization : Basic dTpwOm0=\r\nProxy-Authorization: Bearer ignored\r\n\r\n").await.unwrap();
    let req = accept(
        &mut stream,
        &options(true, true),
        |credentials| async move {
            assert_eq!(credentials.username(), "u");
            assert_eq!(credentials.password(), "p:m");
            let debug = format!("{credentials:?}");
            assert!(!debug.contains("p:m"));
            true
        },
    )
    .await
    .unwrap();
    assert_eq!(req.username(), Some("u"));
    for value in [
        "Bearer private-token",
        "Basic !!!",
        "Basic /w==",
        "Basic dQ==",
        "Basic\tdTpw",
    ] {
        let bytes = format!("CONNECT h:443 HTTP/1.1\r\nProxy-Authorization: {value}\r\n\r\n");
        let (result, reply, calls) = parse(bytes.as_bytes(), true, true, true).await;
        let error = result.unwrap_err();
        assert!(!error.to_string().contains("private-token"));
        assert_eq!(reply, EXPECT_HTTP_407);
        assert_eq!(calls, 0);
    }
    let (result, _, _) = parse(
        b"CONNECT h:443 HTTP/x\r\nProxy-Authorization: Basic OnA=\r\n\r\n",
        false,
        true,
        true,
    )
    .await;
    assert_eq!(result.unwrap().username(), Some("")); // Verified empty identity is not anonymous.
}

#[tokio::test]
async fn malformed_targets_frames_and_legacy_rsv_behavior() {
    timeout(Duration::from_secs(10), async {
        for target in [
            ":443", "h:", "h:65536", "h:-1", "[h]:443", "[::1]", "a\0b:443", "a\nb:443",
        ] {
            let bytes = format!("CONNECT {target} HTTP/1.1\r\n\r\n");
            let (result, reply, calls) = parse(bytes.as_bytes(), true, false, true).await;
            assert!(matches!(result, Err(ServerError::Protocol(_))));
            assert_eq!(reply, EXPECT_HTTP_400);
            assert_eq!(calls, 0);
        }
        for target in ["h:0", "[::1]:443", "2001:db8::1:443", "not-a-dns-name!:443"] {
            let bytes = format!("CONNECT {target} HTTP/x\r\n\r\n");
            assert_eq!(
                parse(bytes.as_bytes(), true, false, true)
                    .await
                    .0
                    .unwrap()
                    .target(),
                target
            );
        }
        for domain in [b"".as_slice(), b"a\0b", b"a:b", b"a b"] {
            let (result, reply, _) = parse(&socks_request(domain), true, false, true).await;
            assert!(matches!(result, Err(ServerError::Protocol(_))));
            assert_eq!(reply, [5, 0, 5, 4, 0, 1, 0, 0, 0, 0, 0, 0]);
        }
        for (header, expected) in [
            ([4, 1, 0, 1], vec![5, 0]),
            ([5, 2, 0, 1], vec![5, 0, 5, 7, 0, 1, 0, 0, 0, 0, 0, 0]),
            ([5, 1, 0, 9], vec![5, 0, 5, 8, 0, 1, 0, 0, 0, 0, 0, 0]),
        ] {
            let mut bytes = vec![5, 1, 0];
            bytes.extend_from_slice(&header);
            let (result, reply, _) = parse(&bytes, true, false, true).await;
            assert!(matches!(result, Err(ServerError::Protocol(_))));
            assert_eq!(reply, expected);
        }
        let mut bytes = socks_request(b"h");
        bytes[5] = 99;
        assert!(parse(&bytes, true, false, true).await.0.is_ok());
        assert!(matches!(
            parse(&[5, 1, 0, 5], true, false, true).await.0,
            Err(ServerError::Io(_))
        ));
        assert!(matches!(
            parse(&[0xff], true, false, true).await.0,
            Err(ServerError::Protocol(_))
        ));
        assert!(matches!(
            parse(&[], true, false, true).await.0,
            Err(ServerError::Closed)
        ));
        assert_eq!(
            parse(b"GET h:1 HTTP/x\r\n\r\n", true, false, true).await.1,
            EXPECT_HTTP_501
        );
    })
    .await
    .expect("bounded malformed framing table");
}

#[tokio::test]
async fn malformed_socks_credentials_do_not_invoke_authentication() {
    for frame in [
        vec![1, 0],
        vec![1, 1, b'u', 0],
        vec![1, 1, 255, 1, b'p'],
        vec![1, 1, b'u', 1, 255],
    ] {
        let mut bytes = vec![5, 1, 2];
        bytes.extend(frame);
        let (result, reply, calls) = parse(&bytes, false, true, true).await;
        assert!(matches!(result, Err(ServerError::Authentication(_))));
        assert_eq!(reply, [5, 2, 1, 1]);
        assert_eq!(calls, 0);
    }
    let (result, reply, _) = parse(&[5, 1, 2, 2, 1], false, true, true).await;
    assert!(matches!(result, Err(ServerError::Authentication(_))));
    assert_eq!(reply, [5, 2]);
}

#[tokio::test]
async fn delimiter_limit_and_unused_obs_text_are_preserved() {
    let mut bytes = b"CONNECT h:443 HTTP/1.1\r\nX-Opaque: \xff\r\nX: ".to_vec();
    bytes.resize(EXPECT_HEADER_LIMIT - 4, b'a');
    bytes.extend_from_slice(b"\r\n\r\n");
    assert!(parse(&bytes, true, false, true).await.0.is_ok());
    bytes.insert(EXPECT_HEADER_LIMIT - 4, b'a');
    let (result, reply, _) = parse(&bytes, true, false, true).await;
    assert!(matches!(result, Err(ServerError::HeaderTooLarge)));
    assert_eq!(reply, EXPECT_HTTP_431);
    for (bytes, status) in [
        (
            b"CONNECT h:1 HTTP/x\r\nProxy-Authorization: Basic \xff\r\n\r\n".as_slice(),
            407,
        ),
        (b"CONNECT \xff:1 HTTP/x\r\n\r\n".as_slice(), 400),
    ] {
        let expected = match status {
            400 => EXPECT_HTTP_400,
            407 => EXPECT_HTTP_407,
            _ => panic!("unexpected test status"),
        };
        assert_eq!(parse(bytes, true, true, true).await.1, expected);
    }
}

#[tokio::test]
async fn fragmented_headers_and_tls_binary_pipeline_are_lossless() {
    let payload: Vec<u8> = [
        vec![0x16, 3, 1, 0, 255],
        (0..=255).cycle().take(8192).collect(),
    ]
    .concat();
    for socks in [false, true] {
        let (mut peer, mut stream) = duplex(64);
        let frame = if socks {
            socks_request(b"h")
        } else {
            b"CONNECT h:443 HTTP/x\r\nX: \xff\r\n\r\n".to_vec()
        };
        let expected = payload.clone();
        let writer = async {
            for byte in frame {
                peer.write_all(&[byte]).await.unwrap();
            }
            peer.write_all(&payload).await.unwrap();
            peer.shutdown().await.unwrap();
        };
        let reader = async {
            let mut req = accept(&mut stream, &options(true, false), |_| async { false })
                .await
                .unwrap();
            let mut received = req.take_pipeline();
            assert!(req.take_pipeline().is_empty());
            if socks {
                assert!(received.is_empty());
            }
            stream.read_to_end(&mut received).await.unwrap();
            assert_eq!(received, expected);
        };
        timeout(Duration::from_secs(5), async {
            tokio::join!(writer, reader);
        })
        .await
        .unwrap();
    }
    // Buffered binary bytes are explicitly owned, not lost with a temporary reader.
    let mut bytes = b"CONNECT h:443 HTTP/x\r\n\r\n".to_vec();
    bytes.extend_from_slice(&payload[..100]);
    let req = parse(&bytes, true, false, true).await.0.unwrap();
    assert_eq!(req.pipeline(), &payload[..100]);
}

#[tokio::test(start_paused = true)]
async fn expired_deadline_never_polls_auth_or_consumes_stream() {
    let (mut peer, mut stream) = duplex(1024);
    let frame = b"CONNECT h:443 HTTP/x\r\nProxy-Authorization: Basic dTpw\r\n\r\n";
    peer.write_all(frame).await.unwrap();
    let opts = ServerOptions::new(Instant::now(), false, true);
    assert!(matches!(
        accept(&mut stream, &opts, |_| async {
            panic!("expired auth polled")
        })
        .await,
        Err(ServerError::Deadline)
    ));
    let mut untouched = vec![0; frame.len()];
    stream.read_exact(&mut untouched).await.unwrap();
    assert_eq!(untouched, frame);
}

#[tokio::test(start_paused = true)]
async fn stalled_frame_spends_one_absolute_deadline() {
    let (mut peer, mut stream) = duplex(64);
    peer.write_all(&[5]).await.unwrap();
    let start = Instant::now();
    let opts = ServerOptions::new(start + Duration::from_secs(1), true, false);
    assert!(matches!(
        accept(&mut stream, &opts, |_| async { false }).await,
        Err(ServerError::Deadline)
    ));
    assert_eq!(start.elapsed(), Duration::from_secs(1));
    drop(stream); // Terminal: never resume partially consumed framing.
}

#[tokio::test(start_paused = true)]
async fn auth_deadline_cancels_future_but_admitted_side_effect_can_finish() {
    let (mut peer, mut stream) = duplex(1024);
    peer.write_all(b"CONNECT h:443 HTTP/x\r\nProxy-Authorization: Basic dTpw\r\n\r\n")
        .await
        .unwrap();
    let (started_tx, started_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let (finished_tx, finished_rx) = tokio::sync::oneshot::channel();
    let effects = Arc::new(AtomicUsize::new(0));
    let effect = effects.clone();
    let slots = Arc::new(tokio::sync::Semaphore::new(1));
    let owned_slots = slots.clone();
    let opts = ServerOptions::new(Instant::now() + Duration::from_secs(1), false, true);
    let handshake = accept(&mut stream, &opts, move |_| async move {
        let permit = owned_slots.acquire_owned().await.unwrap();
        let work = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            release_rx.recv().unwrap();
            effect.fetch_add(1, Ordering::SeqCst);
            finished_tx.send(()).unwrap();
            true
        });
        started_tx.send(()).unwrap();
        // Cancellation intentionally leaves admitted blocking work running.
        work.await.unwrap()
    });
    tokio::pin!(handshake);
    tokio::select! {
        result = &mut handshake => panic!("handshake ended before admission: {result:?}"),
        result = started_rx => result.unwrap(),
    }
    tokio::time::advance(Duration::from_secs(1)).await;
    assert!(matches!(handshake.await, Err(ServerError::Deadline)));
    assert_eq!(effects.load(Ordering::SeqCst), 0);
    assert_eq!(slots.available_permits(), 0);
    release_tx.send(()).unwrap();
    finished_rx.await.unwrap();
    // Completion notification precedes closure drop; acquire observes actual permit release.
    let _released = slots.acquire().await.unwrap();
    assert_eq!(effects.load(Ordering::SeqCst), 1);
}

#[tokio::test(start_paused = true)]
async fn late_first_byte_does_not_renew_handshake_budget() {
    let (mut peer, mut stream) = duplex(64);
    let start = Instant::now();
    let opts = ServerOptions::new(start + Duration::from_secs(1), true, false);
    let reader = async {
        assert!(matches!(
            accept(&mut stream, &opts, |_| async { false }).await,
            Err(ServerError::Deadline)
        ));
        assert_eq!(start.elapsed(), Duration::from_secs(1));
    };
    let writer = async {
        tokio::time::sleep(Duration::from_millis(900)).await;
        peer.write_all(&[5]).await.unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
    };
    tokio::join!(reader, writer);
}

// Compile-only consumer witness: conditional Send, with owned closure credentials.
#[allow(dead_code)]
fn public_future_is_send() {
    fn send<F: Future + Send>(_: F) {}
    let (_, mut stream) = duplex(64);
    let opts = options(true, true);
    send(accept(&mut stream, &opts, |credentials| async move {
        credentials.username() == "user" && credentials.password() == "password"
    }));
}

#[tokio::test]
async fn host_replies_map_to_existing_wire_codes() {
    timeout(Duration::from_secs(10), async {
        for socks in [false, true] {
            for (reply, code, http) in [
                (
                    Reply::Established,
                    0,
                    b"HTTP/1.1 200 Connection Established\r\n\r\n".as_slice(),
                ),
                (Reply::Forbidden, 2, EXPECT_HTTP_403),
                (Reply::UpstreamUnavailable, 4, EXPECT_HTTP_502),
                (Reply::GeneralFailure, 1, EXPECT_HTTP_502),
                (Reply::Overloaded, 1, EXPECT_HTTP_503),
            ] {
                let bytes = if socks {
                    socks_request(b"h")
                } else {
                    b"CONNECT h:443 HTTP/x\r\n\r\n".to_vec()
                };
                let req = parse(&bytes, true, false, true).await.0.unwrap();
                let (mut peer, stream) = duplex(1024);
                let mut stream = BufWriter::new(stream);
                let socks_reply = [5, code, 0, 1, 0, 0, 0, 0, 0, 0];
                let expected = if socks { socks_reply.as_slice() } else { http };
                let mut response = vec![0; expected.len()];
                let (result, read) = tokio::join!(
                    req.reply(&mut stream, reply),
                    peer.read_exact(&mut response),
                );
                result.unwrap();
                read.unwrap();
                assert_eq!(response, expected);
                assert!(stream.buffer().is_empty());
                // No host extra-write, manual flush, shutdown or drop made this visible.
                drop(stream);
                let mut trailing = Vec::new();
                peer.read_to_end(&mut trailing).await.unwrap();
                assert!(trailing.is_empty());
            }
        }
    })
    .await
    .expect("bounded buffered final replies");
}

#[tokio::test]
async fn buffered_socks_peer_waits_for_each_handshake_reply() {
    timeout(Duration::from_secs(10), async {
        for password in [false, true] {
            let (mut peer, stream) = duplex(64);
            let mut stream = BufWriter::new(stream);
            let opts = options(!password, password);
            let client = async {
                let method = if password { 2 } else { 0 };
                for byte in [5, 1, method] {
                    peer.write_all(&[byte]).await.unwrap();
                }
                let mut response = [0; 2];
                peer.read_exact(&mut response).await.unwrap();
                assert_eq!(response, [5, method]);
                if password {
                    peer.write_all(&[1, 1, b'u', 1, b'p']).await.unwrap();
                    peer.read_exact(&mut response).await.unwrap();
                    assert_eq!(response, [1, 0]);
                }
                peer.write_all(&socks_request(b"h")[3..]).await.unwrap();
            };
            let (result, ()) = tokio::join!(accept(&mut stream, &opts, |_| async { true }), client);
            let req = result.unwrap();
            assert_eq!(req.target(), "h:443");
            assert_eq!(req.username(), password.then_some("u"));
            assert!(stream.buffer().is_empty());
        }
    })
    .await
    .expect("bounded staged buffered handshake");
}

/// cancel-safe: NO — enclosing safety timeout drops both in-place futures and
/// disposable streams. No spawned tasks, manual flush, shutdown or early drop.
pub(super) async fn buffered_failure(
    bytes: &[u8],
    anonymous: bool,
    password: bool,
    verified: bool,
    expected: &[u8],
) -> (ServerError, usize) {
    let (mut peer, stream) = duplex(64 * 1024);
    let mut stream = BufWriter::new(stream);
    peer.write_all(bytes).await.unwrap();
    let calls = AtomicUsize::new(0);
    let opts = options(anonymous, password);
    let mut response = vec![0; expected.len()];
    let (result, read) = tokio::join!(
        accept(&mut stream, &opts, |_| async {
            calls.fetch_add(1, Ordering::SeqCst);
            verified
        }),
        peer.read_exact(&mut response),
    );
    read.unwrap();
    assert_eq!(response, expected);
    assert!(stream.buffer().is_empty());
    (result.unwrap_err(), calls.load(Ordering::SeqCst))
}

#[tokio::test]
async fn buffered_socks_failure_replies_are_visible_before_drop() {
    timeout(Duration::from_secs(10), async {
        for greeting in [vec![5, 0], vec![5, 1, 99]] {
            let (error, calls) = buffered_failure(&greeting, true, true, true, &[5, 255]).await;
            assert!(matches!(error, ServerError::Authentication(_)));
            assert_eq!(calls, 0);
        }
        for (frame, verified, expected_calls) in [
            (vec![1, 0], true, 0),
            (vec![1, 1, b'u', 0], true, 0),
            (vec![1, 1, 255, 1, b'p'], true, 0),
            (vec![1, 1, b'u', 1, 255], true, 0),
            (vec![1, 1, b'u', 1, b'p'], false, 1),
        ] {
            let mut bytes = vec![5, 1, 2];
            bytes.extend(frame);
            let (error, calls) =
                buffered_failure(&bytes, false, true, verified, &[5, 2, 1, 1]).await;
            assert!(matches!(error, ServerError::Authentication(_)));
            assert_eq!(calls, expected_calls);
        }
        for domain in [b"".as_slice(), b"a\0b", b"a:b", b"a b"] {
            let (error, calls) = buffered_failure(
                &socks_request(domain),
                true,
                false,
                true,
                &[5, 0, 5, 4, 0, 1, 0, 0, 0, 0, 0, 0],
            )
            .await;
            assert!(matches!(error, ServerError::Protocol(_)));
            assert_eq!(calls, 0);
        }
    })
    .await
    .expect("bounded buffered SOCKS failures");
}

#[tokio::test]
async fn buffered_canonical_refusals_after_both_auth_methods_are_terminal() {
    timeout(Duration::from_secs(10), async {
        for password in [false, true] {
            for (header, expected) in [
                ([5, 2, 0, 1], [5, 7, 0, 1, 0, 0, 0, 0, 0, 0]),
                ([5, 3, 0, 1], [5, 7, 0, 1, 0, 0, 0, 0, 0, 0]),
                ([5, 1, 0, 9], [5, 8, 0, 1, 0, 0, 0, 0, 0, 0]),
            ] {
                let (mut peer, stream) = duplex(1024);
                let mut stream = BufWriter::new(stream);
                let opts = options(!password, password);
                let calls = AtomicUsize::new(0);
                let client = async {
                    let method = if password { 2 } else { 0 };
                    peer.write_all(&[5, 1, method]).await.unwrap();
                    let mut response = [0; 2];
                    peer.read_exact(&mut response).await.unwrap();
                    assert_eq!(response, [5, method]);
                    if password {
                        peer.write_all(&[1, 1, b'u', 1, b'p']).await.unwrap();
                        peer.read_exact(&mut response).await.unwrap();
                        assert_eq!(response, [1, 0]);
                    }
                    let mut bytes = header.to_vec();
                    // A later valid request cannot rescue the rejected frame.
                    bytes.extend_from_slice(&socks_request(b"later")[3..]);
                    peer.write_all(&bytes).await.unwrap();
                    let mut refusal = [0; 10];
                    peer.read_exact(&mut refusal).await.unwrap();
                    assert_eq!(refusal, expected);
                };
                let (result, ()) = tokio::join!(
                    accept(&mut stream, &opts, |_| async {
                        calls.fetch_add(1, Ordering::SeqCst);
                        true
                    }),
                    client,
                );
                assert!(matches!(result, Err(ServerError::Protocol(_))));
                assert_eq!(calls.load(Ordering::SeqCst), usize::from(password));
                assert!(stream.buffer().is_empty());
                drop(stream); // Terminal: never retry accept.
                let mut extra = Vec::new();
                peer.read_to_end(&mut extra).await.unwrap();
                assert!(extra.is_empty());
            }
        }
    })
    .await
    .expect("bounded canonical refusals, including partial-frame mutations");
}

#[tokio::test]
async fn buffered_wrong_versions_remain_terminal_without_failure_reply() {
    timeout(Duration::from_secs(10), async {
        for (bytes, password, expected) in [
            (vec![5, 1, 0, 4, 1, 0, 1], false, &[5, 0][..]),
            (vec![5, 1, 2, 2, 1], true, &[5, 2][..]),
            (
                vec![5, 1, 2, 1, 1, b'u', 1, b'p', 4, 1, 0, 1],
                true,
                &[5, 2, 1, 0][..],
            ),
        ] {
            let (mut peer, inner) = duplex(1024);
            let mut stream = BufWriter::new(inner);
            peer.write_all(&bytes).await.unwrap();
            let opts = options(!password, password);
            let mut response = vec![0; expected.len()];
            let (result, read) = tokio::join!(
                accept(&mut stream, &opts, |_| async { true }),
                peer.read_exact(&mut response),
            );
            assert!(matches!(
                result,
                Err(ServerError::Protocol(_) | ServerError::Authentication(_))
            ));
            read.unwrap();
            assert_eq!(response, expected);
            assert!(stream.buffer().is_empty());
            drop(stream);
            let mut extra = Vec::new();
            peer.read_to_end(&mut extra).await.unwrap();
            assert!(extra.is_empty());
        }
    })
    .await
    .expect("bounded wrong-version no-response contract");
}
