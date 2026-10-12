//! Buffered-reply visibility, flush-fault, and cancellation tests.

use super::framing::buffered_failure;
use super::*;

#[tokio::test]
async fn buffered_http_failure_paths_are_visible_before_drop() {
    timeout(Duration::from_secs(10), async {
        for (bytes, anonymous, password, verified, expected, calls) in [
            (
                b"CONNECT \xff:1 HTTP/x\r\n\r\n".as_slice(),
                true,
                true,
                true,
                EXPECT_HTTP_400,
                0,
            ),
            (
                b"CONNECT h:1 broken\r\n\r\n".as_slice(),
                true,
                true,
                true,
                EXPECT_HTTP_400,
                0,
            ),
            (
                b"GET h:1 HTTP/x\r\n\r\n".as_slice(),
                true,
                true,
                true,
                EXPECT_HTTP_501,
                0,
            ),
            (
                b"CONNECT a\0b:1 HTTP/x\r\n\r\n".as_slice(),
                true,
                true,
                true,
                EXPECT_HTTP_400,
                0,
            ),
            (
                b"CONNECT :1 HTTP/x\r\n\r\n".as_slice(),
                true,
                true,
                true,
                EXPECT_HTTP_400,
                0,
            ),
            (
                b"CONNECT h:1 HTTP/x\r\nProxy-Authorization: \xff\r\n\r\n".as_slice(),
                true,
                true,
                true,
                EXPECT_HTTP_407,
                0,
            ),
            (
                b"CONNECT h:1 HTTP/x\r\nProxy-Authorization: Bearer token\r\n\r\n".as_slice(),
                true,
                true,
                true,
                EXPECT_HTTP_407,
                0,
            ),
            (
                b"CONNECT h:1 HTTP/x\r\nProxy-Authorization: Basic !!!\r\n\r\n".as_slice(),
                true,
                true,
                true,
                EXPECT_HTTP_407,
                0,
            ),
            (
                b"CONNECT h:1 HTTP/x\r\nProxy-Authorization: Basic /w==\r\n\r\n".as_slice(),
                true,
                true,
                true,
                EXPECT_HTTP_407,
                0,
            ),
            (
                b"CONNECT h:1 HTTP/x\r\nProxy-Authorization: Basic dQ==\r\n\r\n".as_slice(),
                true,
                true,
                true,
                EXPECT_HTTP_407,
                0,
            ),
            (
                b"CONNECT h:1 HTTP/x\r\nProxy-Authorization: Basic dTpw\r\n\r\n".as_slice(),
                true,
                false,
                true,
                EXPECT_HTTP_407,
                0,
            ),
            (
                b"CONNECT h:1 HTTP/x\r\nProxy-Authorization: Basic dTpw\r\n\r\n".as_slice(),
                true,
                true,
                false,
                EXPECT_HTTP_407,
                1,
            ),
            (
                b"CONNECT h:1 HTTP/x\r\n\r\n".as_slice(),
                false,
                true,
                true,
                EXPECT_HTTP_407,
                0,
            ),
        ] {
            let (error, actual_calls) =
                buffered_failure(bytes, anonymous, password, verified, expected).await;
            assert!(matches!(
                error,
                ServerError::Protocol(_) | ServerError::Authentication(_)
            ));
            assert_eq!(actual_calls, calls);
        }
        for delimiter in [false, true] {
            let mut bytes = b"CONNECT h:1 HTTP/x\r\nX: ".to_vec();
            bytes.resize(EXPECT_HEADER_LIMIT - 3, b'a');
            if delimiter {
                bytes.extend_from_slice(b"\r\n\r\n");
            } else {
                bytes.extend_from_slice(b"aaaa");
            }
            let (error, calls) = buffered_failure(&bytes, true, true, true, EXPECT_HTTP_431).await;
            assert!(matches!(error, ServerError::HeaderTooLarge));
            assert_eq!(calls, 0);
        }
    })
    .await
    .expect("bounded buffered HTTP failures");
}

// Transport fault injection only: wire visibility is tested with real BufWriter above.
struct FlushFault {
    inner: DuplexStream,
    writes: Vec<u8>,
    write_calls: usize,
    flush_calls: usize,
    fault_at: usize,
    fail_write: bool,
    stall: bool,
    first_flush_delay: Option<Pin<Box<tokio::time::Sleep>>>,
}

impl AsyncRead for FlushFault {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for FlushFault {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.write_calls += 1;
        if self.fail_write && self.write_calls == self.fault_at {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "injected write failure",
            )));
        }
        self.writes.extend_from_slice(bytes);
        Poll::Ready(Ok(bytes.len()))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let Some(delay) = &mut self.first_flush_delay {
            if delay.as_mut().poll(cx).is_pending() {
                return Poll::Pending;
            }
            self.first_flush_delay = None;
        }
        // Count completed flushes once; the fault remains persistent on repoll.
        if !self.fail_write && self.flush_calls + 1 == self.fault_at {
            if self.stall {
                // Permanently stalled by design; the owning timeout is the wake source.
                return Poll::Pending;
            }
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "injected flush failure",
            )));
        }
        self.flush_calls += 1;
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

fn flush_fault(inner: DuplexStream, fault_at: usize, fail_write: bool, stall: bool) -> FlushFault {
    FlushFault {
        inner,
        writes: Vec::new(),
        write_calls: 0,
        flush_calls: 0,
        fault_at,
        fail_write,
        stall,
        first_flush_delay: None,
    }
}

#[tokio::test]
async fn reply_write_and_flush_errors_propagate_without_replay() {
    timeout(Duration::from_secs(10), async {
        for fail_write in [false, true] {
            for (bytes, anonymous, password, verified, fault_at) in [
                (vec![5, 1, 0], true, false, true, 1),
                (vec![5, 0], true, true, true, 1),
                (vec![5, 1, 2, 1, 1, b'u', 1, b'p'], false, true, true, 2),
                (vec![5, 1, 2, 1, 1, b'u', 1, b'p'], false, true, false, 2),
                (vec![5, 1, 2, 1, 0], false, true, true, 2),
                (socks_request(b"a b"), true, false, true, 2),
                (vec![5, 1, 0, 5, 2, 0, 1], true, false, true, 2),
                (vec![5, 1, 0, 5, 1, 0, 9], true, false, true, 2),
                (b"GET h:1 HTTP/x\r\n\r\n".to_vec(), true, false, true, 1),
                (b"CONNECT h:1 HTTP/x\r\n\r\n".to_vec(), false, true, true, 1),
            ] {
                let (mut peer, inner) = duplex(1024);
                peer.write_all(&bytes).await.unwrap();
                let mut stream = flush_fault(inner, fault_at, fail_write, false);
                let result = accept(&mut stream, &options(anonymous, password), |_| async { verified }).await;
                assert!(matches!(result, Err(ServerError::Io(ref error)) if error.kind() == io::ErrorKind::BrokenPipe));
                assert_eq!(stream.write_calls, fault_at);
                assert_eq!(stream.flush_calls, fault_at - 1);
                drop(stream); // No replay after transport failure.
            }
            for protocol in [Protocol::Socks5, Protocol::Http] {
                for reply in [Reply::Established, Reply::Forbidden, Reply::UpstreamUnavailable, Reply::GeneralFailure, Reply::Overloaded] {
                    let req = IncomingRequest {
                        protocol, target: "h:1".into(), username: None, pipeline: Vec::new(),
                    };
                    let (_peer, inner) = duplex(64);
                    let mut stream = flush_fault(inner, 1, fail_write, false);
                    let result = req.reply(&mut stream, reply).await;
                    assert!(matches!(result, Err(ServerError::Io(ref error)) if error.kind() == io::ErrorKind::BrokenPipe));
                    assert_eq!(stream.write_calls, 1);
                    assert_eq!(stream.flush_calls, 0);
                }
            }
        }
    }).await.expect("bounded reply transport faults");
}

#[tokio::test(start_paused = true)]
async fn stalled_handshake_and_error_flushes_share_absolute_deadline() {
    timeout(Duration::from_secs(10), async {
        for (bytes, anonymous, password, verified, fault_at) in [
            (vec![5, 1, 0], true, false, true, 1),
            (vec![5, 0], true, true, true, 1),
            (vec![5, 1, 2, 1, 1, b'u', 1, b'p'], false, true, true, 2),
            (vec![5, 1, 2, 1, 1, b'u', 1, b'p'], false, true, false, 2),
            (vec![5, 1, 2, 1, 0], false, true, true, 2),
            (socks_request(b"a b"), true, false, true, 2),
            (vec![5, 1, 0, 5, 2, 0, 1], true, false, true, 2),
            (vec![5, 1, 0, 5, 1, 0, 9], true, false, true, 2),
            (b"GET h:1 HTTP/x\r\n\r\n".to_vec(), true, false, true, 1),
        ] {
            let (mut peer, inner) = duplex(1024);
            peer.write_all(&bytes).await.unwrap();
            let mut stream = flush_fault(inner, fault_at, false, true);
            let start = Instant::now();
            if fault_at == 2 {
                stream.first_flush_delay =
                    Some(Box::pin(tokio::time::sleep(Duration::from_millis(900))));
            }
            let opts = ServerOptions::new(start + Duration::from_secs(1), anonymous, password);
            let result = accept(&mut stream, &opts, |_| async { verified }).await;
            assert!(matches!(result, Err(ServerError::Deadline)));
            assert_eq!(start.elapsed(), Duration::from_secs(1));
            assert_eq!(stream.write_calls, fault_at);
            assert_eq!(stream.flush_calls, fault_at - 1);
            drop(stream);
        }
    })
    .await
    .expect("bounded absolute flush deadlines");
}

#[tokio::test(start_paused = true)]
async fn external_cancellation_during_accept_flush_is_terminal() {
    timeout(Duration::from_secs(10), async {
        let (mut peer, inner) = duplex(64);
        peer.write_all(&[5, 1, 0, 5, 1, 0, 1, 127, 0, 0, 1, 0, 80])
            .await
            .unwrap();
        let mut stream = flush_fault(inner, 1, false, true);
        let calls = AtomicUsize::new(0);
        let opts = options(true, false);
        let result = timeout(
            Duration::from_secs(1),
            accept(&mut stream, &opts, |_| async {
                calls.fetch_add(1, Ordering::SeqCst);
                true
            }),
        )
        .await;
        assert!(result.is_err());
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert_eq!(stream.writes, [5, 0]);
        assert_eq!(stream.write_calls, 1);
        assert_eq!(stream.flush_calls, 0);
        drop(stream); // The queued valid CONNECT is never parsed after cancellation.
    })
    .await
    .expect("bounded external accept cancellation");
}

#[tokio::test(start_paused = true)]
async fn host_budget_cancels_final_flush_without_replay() {
    timeout(Duration::from_secs(10), async {
        for protocol in [Protocol::Socks5, Protocol::Http] {
            let req = IncomingRequest {
                protocol,
                target: "h:1".into(),
                username: None,
                pipeline: Vec::new(),
            };
            let (_peer, inner) = duplex(64);
            let mut stream = flush_fault(inner, 1, false, true);
            let start = Instant::now();
            let result = timeout(
                Duration::from_secs(2),
                req.reply(&mut stream, Reply::Established),
            )
            .await;
            assert!(result.is_err());
            assert_eq!(start.elapsed(), Duration::from_secs(2));
            assert_eq!(stream.write_calls, 1);
            assert_eq!(stream.flush_calls, 0);
            let expected = match protocol {
                Protocol::Socks5 => &[5, 0, 0, 1, 0, 0, 0, 0, 0, 0][..],
                Protocol::Http => &b"HTTP/1.1 200 Connection Established\r\n\r\n"[..],
            };
            assert_eq!(stream.writes, expected);
            drop(stream); // Host owns the budget and terminal disposal; never retry.
        }
    })
    .await
    .expect("bounded host final-reply cancellation");
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
