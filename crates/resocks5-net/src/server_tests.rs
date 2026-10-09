use super::*;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use std::time::Duration;
use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt};

// Independent boundary oracle: changing the production limit must fail these tests.
const EXPECT_HEADER_LIMIT: usize = 16_384;

// Independent wire oracles: never derive expected replies from production encoders.
const EXPECT_HTTP_400: &[u8] =
    b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";
const EXPECT_HTTP_403: &[u8] =
    b"HTTP/1.1 403 Forbidden\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";
const EXPECT_HTTP_407: &[u8] = b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"resocks5\", charset=\"UTF-8\"\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";
const EXPECT_HTTP_431: &[u8] = b"HTTP/1.1 431 Request Header Fields Too Large\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";
const EXPECT_HTTP_501: &[u8] =
    b"HTTP/1.1 501 Not Implemented\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";
const EXPECT_HTTP_502: &[u8] =
    b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";
const EXPECT_HTTP_503: &[u8] =
    b"HTTP/1.1 503 Service Unavailable\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";

fn options(anonymous: bool, password: bool) -> ServerOptions {
    ServerOptions::new(Instant::now() + Duration::from_secs(5), anonymous, password)
}

fn socks_request(domain: &[u8]) -> Vec<u8> {
    let mut bytes = vec![5, 1, 0, 5, 1, 0, 3];
    bytes.push(u8::try_from(domain.len()).unwrap());
    bytes.extend_from_slice(domain);
    bytes.extend_from_slice(&443u16.to_be_bytes());
    bytes
}

async fn parse(
    bytes: &[u8],
    anonymous: bool,
    password: bool,
    verified: bool,
) -> (Result<IncomingRequest, ServerError>, Vec<u8>, usize) {
    let (mut peer, mut server) = duplex(64 * 1024);
    peer.write_all(bytes).await.unwrap();
    peer.shutdown().await.unwrap();
    let calls = Arc::new(AtomicUsize::new(0));
    let count = calls.clone();
    let result = accept(
        &mut server,
        &options(anonymous, password),
        move |_| async move {
            count.fetch_add(1, Ordering::SeqCst);
            verified
        },
    )
    .await;
    drop(server);
    let mut response = Vec::new();
    peer.read_to_end(&mut response).await.unwrap();
    (result, response, calls.load(Ordering::SeqCst))
}

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
    for header in [[4, 1, 0, 1], [5, 2, 0, 1], [5, 1, 0, 9]] {
        let mut bytes = vec![5, 1, 0];
        bytes.extend_from_slice(&header);
        let (result, reply, _) = parse(&bytes, true, false, true).await;
        assert!(matches!(result, Err(ServerError::Protocol(_))));
        assert_eq!(reply, [5, 0]);
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
    for socks in [false, true] {
        for reply in [
            Reply::Established,
            Reply::Forbidden,
            Reply::UpstreamUnavailable,
            Reply::GeneralFailure,
            Reply::Overloaded,
        ] {
            let bytes = if socks {
                socks_request(b"h")
            } else {
                b"CONNECT h:443 HTTP/x\r\n\r\n".to_vec()
            };
            let req = parse(&bytes, true, false, true).await.0.unwrap();
            let (mut peer, mut stream) = duplex(1024);
            req.reply(&mut stream, reply).await.unwrap();
            drop(stream);
            let mut response = Vec::new();
            peer.read_to_end(&mut response).await.unwrap();
            let code = match reply {
                Reply::Established => 0,
                Reply::Forbidden => 2,
                Reply::UpstreamUnavailable => 4,
                Reply::GeneralFailure => 1,
                Reply::Overloaded => 1,
            };
            if socks {
                assert_eq!(response, [5, code, 0, 1, 0, 0, 0, 0, 0, 0]);
            } else {
                let expected = match reply {
                    Reply::Established => b"HTTP/1.1 200 Connection Established\r\n\r\n".as_slice(),
                    Reply::Forbidden => EXPECT_HTTP_403,
                    Reply::UpstreamUnavailable => EXPECT_HTTP_502,
                    Reply::GeneralFailure => EXPECT_HTTP_502,
                    Reply::Overloaded => EXPECT_HTTP_503,
                };
                assert_eq!(response, expected);
            }
        }
    }
}

// Migrated parser-only application regressions: framing stays in the library.
#[tokio::test]
async fn socks_ip_targets_keep_canonical_spelling() {
    let mut ipv6 = vec![5, 1, 0, 5, 1, 0, 4];
    ipv6.extend_from_slice(&std::net::Ipv6Addr::LOCALHOST.octets());
    ipv6.extend_from_slice(&443u16.to_be_bytes());
    assert_eq!(
        parse(&ipv6, true, false, true).await.0.unwrap().target(),
        "[::1]:443"
    );
    let ipv4 = [5, 1, 0, 5, 1, 0, 1, 1, 2, 3, 4, 1, 187];
    assert_eq!(
        parse(&ipv4, true, false, true).await.0.unwrap().target(),
        "1.2.3.4:443"
    );
}

#[tokio::test]
async fn thousands_of_header_lines_are_still_fully_scanned() {
    let mut bytes = b"CONNECT example.com:443 HTTP/1.1\r\n".to_vec();
    bytes.extend_from_slice(&b"X:\r\n".repeat(4000));
    let mut with_auth = bytes.clone();
    with_auth.extend_from_slice(b"Proxy-Authorization: Basic dXNlcjpwYXNz\r\n\r\n");
    let (result, response, calls) = parse(&with_auth, true, false, true).await;
    assert!(matches!(result, Err(ServerError::Authentication(_))));
    assert_eq!(response, EXPECT_HTTP_407);
    assert_eq!(calls, 0);
    bytes.extend_from_slice(b"\r\n");
    let (result, response, _) = parse(&bytes, true, false, true).await;
    assert_eq!(result.unwrap().target(), "example.com:443");
    assert!(response.is_empty());
}

#[tokio::test]
async fn proxy_auth_challenge_declares_utf8_charset() {
    let (_, response, _) = parse(
        b"CONNECT h:443 HTTP/x\r\nProxy-Authorization: Bearer token\r\n\r\n",
        true,
        false,
        true,
    )
    .await;
    assert!(String::from_utf8(response)
        .unwrap()
        .contains("Proxy-Authenticate: Basic realm=\"resocks5\", charset=\"UTF-8\""));
}

#[tokio::test]
async fn socks_single_method_offers_and_no_match_rows() {
    for anonymous in [false, true] {
        for password in [false, true] {
            for offered in [0, 2, 99] {
                let supported = (offered == 0 && anonymous) || (offered == 2 && password);
                let mut bytes = vec![5, 1, offered];
                if offered == 2 && supported {
                    bytes.extend_from_slice(&[1, 1, b'u', 1, b'p']);
                }
                bytes.extend_from_slice(&socks_request(b"h")[3..]);
                let (result, response, calls) = parse(&bytes, anonymous, password, true).await;
                assert_eq!(result.is_ok(), supported);
                assert_eq!(calls, usize::from(supported && offered == 2));
                let expected = if !supported {
                    vec![5, 255]
                } else if offered == 2 {
                    vec![5, 2, 1, 0]
                } else {
                    vec![5, 0]
                };
                assert_eq!(response, expected);
            }
        }
    }
    let (result, response, calls) = parse(&[5, 0], true, true, true).await;
    assert!(matches!(result, Err(ServerError::Authentication(_))));
    assert_eq!(response, [5, 255]);
    assert_eq!(calls, 0);
}

#[tokio::test]
async fn maximum_valid_headers_do_not_count_binary_payload() {
    let mut bytes = b"CONNECT h:443 HTTP/x\r\nX: ".to_vec();
    bytes.resize(EXPECT_HEADER_LIMIT - 4, b'a');
    bytes.extend_from_slice(b"\r\n\r\n");
    let payload: Vec<u8> = (0..=255).cycle().take(4096).collect();
    bytes.extend_from_slice(&payload);
    let (mut peer, mut stream) = duplex(64 * 1024);
    peer.write_all(&bytes).await.unwrap();
    peer.shutdown().await.unwrap();
    let mut req = accept(&mut stream, &options(true, false), |_| async {
        panic!("anonymous auth")
    })
    .await
    .unwrap();
    let mut received = req.take_pipeline();
    assert!(
        !received.is_empty(),
        "header-boundary read must preserve its over-read"
    );
    stream.read_to_end(&mut received).await.unwrap();
    assert_eq!(received, payload);
}

#[tokio::test]
async fn fragmented_obs_headers_reach_the_real_auth_field() {
    let bytes = b"CONNECT h:443 HTTP/x\r\nX-Opaque: \xff\xfe\r\ncolonless\r\n Proxy-Authorization : Basic dTpw\r\n\r\n";
    let (mut peer, mut stream) = duplex(8);
    let writer = async {
        for byte in bytes {
            peer.write_all(&[*byte]).await.unwrap();
        }
    };
    let reader = async {
        let req = accept(
            &mut stream,
            &options(false, true),
            |credentials| async move {
                assert_eq!(credentials.username(), "u");
                assert_eq!(credentials.password(), "p");
                true
            },
        )
        .await
        .unwrap();
        assert_eq!(req.username(), Some("u"));
        assert_eq!(req.target(), "h:443");
    };
    timeout(Duration::from_secs(5), async {
        tokio::join!(writer, reader);
    })
    .await
    .unwrap();
}
