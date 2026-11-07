//! Framing, authentication, and header-handling tests.

use super::*;

#[tokio::test]
async fn same_listener_accepts_both_protocols_without_early_success() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = async {
        for expected in [Protocol::Socks5, Protocol::Http] {
            let (mut stream, _) = listener.accept().await.unwrap();
            let req = accept(&mut stream, &options(true, false)).await.unwrap();
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
async fn authentication_policy_matrix_never_selects_a_password_method() {
    for anonymous in [false, true] {
        for users in [false, true] {
            for supplied in [false, true] {
                let http = if supplied {
                    b"CONNECT h:0 HTTP/x\r\nProxy-Authorization: bAsIc dTpwOm0=\r\n\r\n".as_slice()
                } else {
                    b"CONNECT h:0 HTTP/x\r\n\r\n".as_slice()
                };
                let (result, reply) = parse(http, anonymous, users).await;
                // Credentials never fall back to anonymous: any header is a 407.
                let allowed = !supplied && anonymous;
                assert_eq!(result.is_ok(), allowed);
                if allowed {
                    assert!(reply.is_empty());
                    assert_eq!(result.unwrap().username(), None);
                } else {
                    assert_eq!(reply, EXPECT_HTTP_407);
                }
            }
            // A client offering "none" and "username/password": only "none" is
            // ever selected, whatever users exist.
            let mut socks = vec![5, 2, 0, 2];
            socks.extend_from_slice(&socks_request(b"h")[3..]);
            let (result, reply) = parse(&socks, anonymous, users).await;
            assert_eq!(result.is_ok(), anonymous);
            if anonymous {
                assert_eq!(reply, [5, 0]);
                assert_eq!(result.unwrap().username(), None);
            } else {
                assert_eq!(reply, [5, 255]);
            }
            // A client offering only "username/password" is refused outright.
            let (result, reply) = parse(&[5, 1, 2, 1, 1, b'u', 1, b'p'], anonymous, users).await;
            assert!(matches!(result, Err(ServerError::Authentication(_))));
            assert_eq!(reply, [5, 255]);
        }
    }
}

/// Every `Proxy-Authorization` shape is a 407 and never authenticates, and the
/// submitted token never appears in the error text.
/// Mutation: parsing any scheme (Basic, Bearer, padding-tolerant base64, a TAB
/// separator) would accept a row here or echo its token.
#[tokio::test]
async fn every_proxy_authorization_shape_is_a_407_without_echo() {
    timeout(Duration::from_secs(10), async {
        for value in [
            "Basic dTpwOm0=",
            "bAsIc dTpwOm0=",
            "Basic dTpwYQ",
            "Basic\tdTpwOm0=",
            "Basic !!!",
            "Basic /w==",
            "Basic dQ==",
            "Bearer private-token",
        ] {
            let bytes = format!("CONNECT h:443 HTTP/1.1\r\nProxy-Authorization: {value}\r\n\r\n");
            for anonymous in [false, true] {
                let (result, reply) = parse(bytes.as_bytes(), anonymous, true).await;
                let error = result.unwrap_err();
                assert!(matches!(error, ServerError::Authentication(_)), "{value}");
                let text = error.to_string();
                assert!(!text.contains("private-token"), "{value}");
                assert!(!text.contains("dTpw"), "{value}");
                assert_eq!(reply, EXPECT_HTTP_407, "{value}");
            }
        }
        // The first header wins and a padded header name is still the header.
        let bytes = b"CONNECT h:443 HTTP/anything\r\n Proxy-Authorization : Basic dTpwOm0=\r\nProxy-Authorization: Bearer ignored\r\n\r\n";
        let (result, reply) = parse(bytes, true, true).await;
        assert!(matches!(result, Err(ServerError::Authentication(_))));
        assert_eq!(reply, EXPECT_HTTP_407);
    })
    .await
    .expect("bounded proxy-authorization rows");
}
#[tokio::test]
async fn malformed_targets_frames_and_legacy_rsv_behavior() {
    timeout(Duration::from_secs(10), async {
        for target in [
            ":443", "h:", "h:65536", "h:-1", "[h]:443", "[::1]", "a\0b:443", "a\nb:443",
        ] {
            let bytes = format!("CONNECT {target} HTTP/1.1\r\n\r\n");
            let (result, reply) = parse(bytes.as_bytes(), true, false).await;
            assert!(matches!(result, Err(ServerError::Protocol(_))));
            assert_eq!(reply, EXPECT_HTTP_400);
        }
        for target in ["h:0", "[::1]:443", "2001:db8::1:443", "not-a-dns-name!:443"] {
            let bytes = format!("CONNECT {target} HTTP/x\r\n\r\n");
            assert_eq!(
                parse(bytes.as_bytes(), true, false)
                    .await
                    .0
                    .unwrap()
                    .target(),
                target
            );
        }
        for domain in [b"".as_slice(), b"a\0b", b"a:b", b"a b"] {
            let (result, reply) = parse(&socks_request(domain), true, false).await;
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
            let (result, reply) = parse(&bytes, true, false).await;
            assert!(matches!(result, Err(ServerError::Protocol(_))));
            assert_eq!(reply, expected);
        }
        let mut bytes = socks_request(b"h");
        bytes[5] = 99;
        assert!(parse(&bytes, true, false).await.0.is_ok());
        assert!(matches!(
            parse(&[5, 1, 0, 5], true, false).await.0,
            Err(ServerError::Io(_))
        ));
        assert!(matches!(
            parse(&[0xff], true, false).await.0,
            Err(ServerError::Protocol(_))
        ));
        assert!(matches!(
            parse(&[], true, false).await.0,
            Err(ServerError::Closed)
        ));
        assert_eq!(
            parse(b"GET h:1 HTTP/x\r\n\r\n", true, false).await.1,
            EXPECT_HTTP_501
        );
    })
    .await
    .expect("bounded malformed framing table");
}

/// DT-08 pin: the permissive target grammar is intentional. SOCKS5
/// DOMAINNAME and non-strict HTTP CONNECT accept `@`, `/`, `%` in the host
/// (the check is only control/whitespace bytes plus the host:port split);
/// strict HTTP mode is the stricter grammar and rejects the same shapes.
/// Mutation: adding RFC authority-host grammar (or `@`/`/`/`%` bans) to the
/// permissive path makes every row here fail.
#[tokio::test]
async fn permissive_targets_accept_at_slash_percent_in_host() {
    timeout(Duration::from_secs(10), async {
        for domain in ["a@b", "a/b", "a%41b", "@bad.example", "ex%zzample"] {
            let bytes = socks_request(domain.as_bytes());
            let (result, reply) = parse(&bytes, true, false).await;
            let req = result.unwrap_or_else(|error| panic!("domain {domain:?} rejected: {error}"));
            assert_eq!(req.target(), &format!("{domain}:443"), "{domain}");
            assert_eq!(reply, [5, 0], "{domain}");
        }
        for target in [
            "user@example.com:443",
            "example.com/path:443",
            "ex%zzample.com:443",
        ] {
            let bytes = format!("CONNECT {target} HTTP/1.1\r\nHost: h\r\n\r\n");
            let (result, reply) = parse(bytes.as_bytes(), true, false).await;
            let req = result.unwrap_or_else(|error| panic!("target {target:?} rejected: {error}"));
            assert_eq!(req.target(), target);
            assert!(reply.is_empty(), "{target}");
        }
    })
    .await
    .expect("bounded permissive host character pins");
}

#[tokio::test]
async fn socks5_username_password_frames_are_never_read() {
    // Whatever follows a greeting that offers only method 2 is never read as
    // credentials: the server answers "no acceptable method" and stops.
    for frame in [
        vec![1, 0],
        vec![1, 1, b'u', 0],
        vec![1, 1, 255, 1, b'p'],
        vec![1, 1, b'u', 1, 255],
    ] {
        let mut bytes = vec![5, 1, 2];
        bytes.extend(frame);
        let (result, reply) = parse(&bytes, false, true).await;
        assert!(matches!(result, Err(ServerError::Authentication(_))));
        assert_eq!(reply, [5, 255]);
    }
    let (result, reply) = parse(&[5, 1, 2, 2, 1], false, true).await;
    assert!(matches!(result, Err(ServerError::Authentication(_))));
    assert_eq!(reply, [5, 255]);
}
#[tokio::test]
async fn delimiter_limit_and_unused_obs_text_are_preserved() {
    let mut bytes = b"CONNECT h:443 HTTP/1.1\r\nX-Opaque: \xff\r\nX: ".to_vec();
    bytes.resize(EXPECT_HEADER_LIMIT - 4, b'a');
    bytes.extend_from_slice(b"\r\n\r\n");
    assert!(parse(&bytes, true, false).await.0.is_ok());
    bytes.insert(EXPECT_HEADER_LIMIT - 4, b'a');
    let (result, reply) = parse(&bytes, true, false).await;
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
        assert_eq!(parse(bytes, true, true).await.1, expected);
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
            let mut req = accept(&mut stream, &options(true, false)).await.unwrap();
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
    let req = parse(&bytes, true, false).await.0.unwrap();
    assert_eq!(req.pipeline(), &payload[..100]);
}

#[tokio::test(start_paused = true)]
async fn expired_deadline_never_consumes_the_stream() {
    let (mut peer, mut stream) = duplex(1024);
    let frame = b"CONNECT h:443 HTTP/x\r\n\r\n";
    peer.write_all(frame).await.unwrap();
    let opts = ServerOptions::new(Instant::now(), true, true);
    assert!(matches!(
        accept(&mut stream, &opts).await,
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
        accept(&mut stream, &opts).await,
        Err(ServerError::Deadline)
    ));
    assert_eq!(start.elapsed(), Duration::from_secs(1));
    drop(stream); // Terminal: never resume partially consumed framing.
}

#[tokio::test(start_paused = true)]
async fn late_first_byte_does_not_renew_handshake_budget() {
    let (mut peer, mut stream) = duplex(64);
    let start = Instant::now();
    let opts = ServerOptions::new(start + Duration::from_secs(1), true, false);
    let reader = async {
        assert!(matches!(
            accept(&mut stream, &opts).await,
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

// Compile-only consumer witness: conditional Send.
#[allow(dead_code)]
fn public_future_is_send() {
    fn send<F: Future + Send>(_: F) {}
    let (_, mut stream) = duplex(64);
    let opts = options(true, true);
    send(accept(&mut stream, &opts));
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
                let req = parse(&bytes, true, false).await.0.unwrap();
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
        let (mut peer, stream) = duplex(64);
        let mut stream = BufWriter::new(stream);
        let opts = options(true, false);
        let client = async {
            for byte in [5, 1, 0] {
                peer.write_all(&[byte]).await.unwrap();
            }
            let mut response = [0; 2];
            peer.read_exact(&mut response).await.unwrap();
            assert_eq!(response, [5, 0]);
            peer.write_all(&socks_request(b"h")[3..]).await.unwrap();
        };
        let (result, ()) = tokio::join!(accept(&mut stream, &opts), client);
        let req = result.unwrap();
        assert_eq!(req.target(), "h:443");
        assert_eq!(req.username(), None);
        assert!(stream.buffer().is_empty());
    })
    .await
    .expect("bounded staged buffered handshake");
}

/// cancel-safe: NO — enclosing safety timeout drops both in-place futures and
/// disposable streams. No spawned tasks, manual flush, shutdown or early drop.
pub(super) async fn buffered_failure(
    bytes: &[u8],
    anonymous: bool,
    users: bool,
    expected: &[u8],
) -> ServerError {
    let (mut peer, stream) = duplex(64 * 1024);
    let mut stream = BufWriter::new(stream);
    peer.write_all(bytes).await.unwrap();
    let opts = options(anonymous, users);
    let mut response = vec![0; expected.len()];
    let (result, read) = tokio::join!(accept(&mut stream, &opts), peer.read_exact(&mut response),);
    read.unwrap();
    assert_eq!(response, expected);
    assert!(stream.buffer().is_empty());
    result.unwrap_err()
}

#[tokio::test]
async fn buffered_socks_failure_replies_are_visible_before_drop() {
    timeout(Duration::from_secs(10), async {
        for greeting in [vec![5, 0], vec![5, 1, 99]] {
            let error = buffered_failure(&greeting, false, true, &[5, 255]).await;
            assert!(matches!(error, ServerError::Authentication(_)));
        }
        // A password-method greeting is refused, whatever follows it.
        for frame in [
            vec![1, 0],
            vec![1, 1, b'u', 0],
            vec![1, 1, 255, 1, b'p'],
            vec![1, 1, b'u', 1, 255],
            vec![1, 1, b'u', 1, b'p'],
        ] {
            let mut bytes = vec![5, 1, 2];
            bytes.extend(frame);
            let error = buffered_failure(&bytes, true, true, &[5, 255]).await;
            assert!(matches!(error, ServerError::Authentication(_)));
        }
        for domain in [b"".as_slice(), b"a\0b", b"a:b", b"a b"] {
            let error = buffered_failure(
                &socks_request(domain),
                true,
                false,
                &[5, 0, 5, 4, 0, 1, 0, 0, 0, 0, 0, 0],
            )
            .await;
            assert!(matches!(error, ServerError::Protocol(_)));
        }
    })
    .await
    .expect("bounded buffered SOCKS failures");
}

#[tokio::test]
async fn buffered_canonical_refusals_after_the_greeting_are_terminal() {
    timeout(Duration::from_secs(10), async {
        for (header, expected) in [
            ([5, 2, 0, 1], [5, 7, 0, 1, 0, 0, 0, 0, 0, 0]),
            ([5, 3, 0, 1], [5, 7, 0, 1, 0, 0, 0, 0, 0, 0]),
            ([5, 1, 0, 9], [5, 8, 0, 1, 0, 0, 0, 0, 0, 0]),
        ] {
            let (mut peer, stream) = duplex(1024);
            let mut stream = BufWriter::new(stream);
            let opts = options(true, false);
            let client = async {
                peer.write_all(&[5, 1, 0]).await.unwrap();
                let mut response = [0; 2];
                peer.read_exact(&mut response).await.unwrap();
                assert_eq!(response, [5, 0]);
                let mut bytes = header.to_vec();
                // A later valid request cannot rescue the rejected frame.
                bytes.extend_from_slice(&socks_request(b"later")[3..]);
                peer.write_all(&bytes).await.unwrap();
                let mut refusal = [0; 10];
                peer.read_exact(&mut refusal).await.unwrap();
                assert_eq!(refusal, expected);
            };
            let (result, ()) = tokio::join!(accept(&mut stream, &opts), client);
            assert!(matches!(result, Err(ServerError::Protocol(_))));
            assert!(stream.buffer().is_empty());
            drop(stream); // Terminal: never retry accept.
            let mut extra = Vec::new();
            peer.read_to_end(&mut extra).await.unwrap();
            assert!(extra.is_empty());
        }
    })
    .await
    .expect("bounded canonical refusals, including partial-frame mutations");
}

#[tokio::test]
async fn buffered_wrong_versions_remain_terminal_without_failure_reply() {
    timeout(Duration::from_secs(10), async {
        for (bytes, anonymous, expected) in [
            (vec![5, 1, 0, 4, 1, 0, 1], true, &[5, 0][..]),
            (vec![5, 1, 2, 2, 1], false, &[5, 255][..]),
        ] {
            let (mut peer, inner) = duplex(1024);
            let mut stream = BufWriter::new(inner);
            peer.write_all(&bytes).await.unwrap();
            let opts = options(anonymous, true);
            let mut response = vec![0; expected.len()];
            let (result, read) =
                tokio::join!(accept(&mut stream, &opts), peer.read_exact(&mut response),);
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
