//! Prefix-then-stream wrapper tests (library-level).

use super::*;
use std::future::poll_fn;

/// Panics if polled while armed; used to prove the prefix never reaches the inner.
struct AssertNotPolled<R> {
    inner: R,
    armed: bool,
}

impl<R: AsyncRead + Unpin> AsyncRead for AssertNotPolled<R> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        assert!(!self.armed, "inner polled while prefix bytes remain");
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<R> AssertNotPolled<R> {
    fn disarm(&mut self) {
        self.armed = false;
    }
}

/// Counts flush and shutdown calls, forwarding everything else.
struct CountingIo<S> {
    inner: S,
    flushes: usize,
    shutdowns: usize,
}

impl<S> CountingIo<S> {
    fn new(inner: S) -> Self {
        Self {
            inner,
            flushes: 0,
            shutdowns: 0,
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for CountingIo<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for CountingIo<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        match Pin::new(&mut this.inner).poll_flush(cx) {
            Poll::Ready(Ok(())) => {
                this.flushes += 1;
                Poll::Ready(Ok(()))
            }
            other => other,
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        match Pin::new(&mut this.inner).poll_shutdown(cx) {
            Poll::Ready(Ok(())) => {
                this.shutdowns += 1;
                Poll::Ready(Ok(()))
            }
            other => other,
        }
    }
}

/// Inner that reports vectored support and records write paths.
struct VectoredInner {
    vectored_calls: usize,
    plain_calls: usize,
}

impl AsyncWrite for VectoredInner {
    fn is_write_vectored(&self) -> bool {
        true
    }

    fn poll_write(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.plain_calls += 1;
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let total: usize = bufs.iter().map(|b| b.len()).sum();
        self.vectored_calls += 1;
        Poll::Ready(Ok(total))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

/// Inner whose first read poll returns an error.
struct ErrorInner;

impl AsyncRead for ErrorInner {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Poll::Ready(Err(io::Error::new(
            io::ErrorKind::BrokenPipe,
            "inner read failure",
        )))
    }
}

// Case 1: the prefix is served before the inner; an empty prefix is fully transparent.
#[tokio::test]
async fn prefix_serves_before_inner_and_empty_prefix_is_transparent() {
    timeout(Duration::from_secs(10), async {
        // (a) prefix bytes first, then whatever the peer wrote.
        let (mut peer, server) = duplex(64);
        peer.write_all(b"CD").await.unwrap();
        let reader = async {
            let mut prefixed = Prefixed::new(b"AB".to_vec(), server);
            let mut got = Vec::new();
            prefixed.read_to_end(&mut got).await.unwrap();
            got
        };
        let releaser = async {
            // Dropping the peer provides the EOF that ends `read_to_end`.
            drop(peer);
        };
        let (got, ()) = tokio::join!(reader, releaser);
        assert_eq!(got, *b"ABCD");

        // (b) an empty prefix must not intercept or inject anything.
        let (mut peer, server) = duplex(64);
        peer.write_all(b"INNER").await.unwrap();
        let reader = async {
            let mut prefixed = Prefixed::new(Vec::new(), server);
            let mut got = Vec::new();
            prefixed.read_to_end(&mut got).await.unwrap();
            got
        };
        let releaser = async {
            drop(peer);
        };
        let (got, ()) = tokio::join!(reader, releaser);
        assert_eq!(got, *b"INNER");
    })
    .await
    .expect("bounded prefix/empty-prefix read");
}

// Case 2: a read never mixes prefix and inner bytes, and the inner is never polled
// while prefix bytes remain (the wrapper's armed assert is the oracle).
#[tokio::test]
async fn reads_never_mix_prefix_and_inner_and_never_poll_inner_early() {
    timeout(Duration::from_secs(10), async {
        for k in [1usize, 2, 3, 7] {
            let (mut peer, server) = duplex(64);
            peer.write_all(b"abcdefghij").await.unwrap();
            drop(peer);
            let mut prefixed = Prefixed::new(
                b"0123456789".to_vec(),
                AssertNotPolled {
                    inner: server,
                    armed: true,
                },
            );
            let mut got = Vec::new();
            loop {
                let mut buf = vec![0u8; k];
                let n = prefixed.read(&mut buf).await.unwrap();
                if n == 0 {
                    break;
                }
                got.extend_from_slice(&buf[..n]);
                if prefixed.prefix_remaining().is_empty() {
                    // The prefix is fully served; only now may the inner be polled.
                    prefixed.get_mut().disarm();
                }
            }
            assert_eq!(got, *b"0123456789abcdefghij");
        }
    })
    .await
    .expect("bounded never-mix read loop");
}

// Case 3: a zero-capacity ReadBuf completes without consuming any prefix byte.
#[tokio::test]
async fn zero_capacity_readbuf_consumes_nothing() {
    timeout(Duration::from_secs(10), async {
        let (peer, server) = duplex(64);
        drop(peer); // EOF inner
        let mut prefixed = Prefixed::new(b"AB".to_vec(), server);
        poll_fn(|cx| {
            let mut empty: [u8; 0] = [];
            let mut buf = ReadBuf::new(&mut empty);
            match Pin::new(&mut prefixed).poll_read(cx, &mut buf) {
                Poll::Ready(Ok(())) => {
                    assert!(buf.filled().is_empty());
                    Poll::Ready(())
                }
                other => panic!("zero-capacity read did not complete: {other:?}"),
            }
        })
        .await;
        assert_eq!(prefixed.prefix_remaining(), b"AB");
        let mut buf = [0u8; 2];
        prefixed.read_exact(&mut buf).await.unwrap();
        assert_eq!(buf, *b"AB");
    })
    .await
    .expect("bounded zero-capacity read");
}

// Case 4: EOF comes only from the inner, after the prefix is served.
#[tokio::test]
async fn eof_comes_only_from_inner_after_the_prefix() {
    timeout(Duration::from_secs(10), async {
        // (a) prefix then EOF.
        let (peer, server) = duplex(64);
        drop(peer);
        let mut prefixed = Prefixed::new(b"XY".to_vec(), server);
        let mut buf = [0u8; 5];
        assert_eq!(prefixed.read(&mut buf).await.unwrap(), 2);
        assert_eq!(prefixed.read(&mut buf).await.unwrap(), 0);

        // (b) empty prefix: the FIRST read is EOF.
        let (peer, server) = duplex(64);
        drop(peer);
        let mut prefixed = Prefixed::new(Vec::new(), server);
        assert_eq!(prefixed.read(&mut buf).await.unwrap(), 0);

        // (c) while any prefix byte remains, a read returns prefix bytes, never 0.
        let (peer, server) = duplex(64);
        drop(peer);
        let mut prefixed = Prefixed::new(b"XY".to_vec(), server);
        let mut one = [0u8; 1];
        assert_eq!(prefixed.read(&mut one).await.unwrap(), 1);
        assert_eq!(prefixed.read(&mut one).await.unwrap(), 1);
        assert_eq!(prefixed.read(&mut one).await.unwrap(), 0);
    })
    .await
    .expect("bounded prefix-then-EOF reads");
}

// Case 5: inner read errors surface only after the prefix is drained.
#[tokio::test]
async fn inner_read_errors_surface_only_after_the_prefix() {
    timeout(Duration::from_secs(10), async {
        // (a) prefix first, then the inner's error.
        let mut prefixed = Prefixed::new(b"AB".to_vec(), ErrorInner);
        let mut buf = [0u8; 5];
        assert_eq!(prefixed.read(&mut buf).await.unwrap(), 2);
        let err = prefixed.read(&mut buf).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::BrokenPipe);

        // (b) empty prefix: the very first read is the error.
        let mut prefixed = Prefixed::new(Vec::new(), ErrorInner);
        let err = prefixed.read(&mut buf).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::BrokenPipe);
    })
    .await
    .expect("bounded error-after-prefix reads");
}

// Case 6: once the prefix is drained, reads pend until the inner has data.
#[tokio::test(start_paused = true)]
async fn drained_prefix_reads_pend_until_inner_data_arrives() {
    timeout(Duration::from_secs(10), async {
        let (mut peer, server) = duplex(64);
        let writer = async {
            tokio::time::sleep(Duration::from_millis(900)).await;
            peer.write_all(b"DATA").await.unwrap();
        };
        let reader = async {
            let mut prefixed = Prefixed::new(Vec::new(), server);
            let mut buf = [0u8; 4];
            prefixed.read_exact(&mut buf).await.unwrap();
            buf
        };
        let (buf, ()) = tokio::join!(reader, writer);
        assert_eq!(buf, *b"DATA");
    })
    .await
    .expect("bounded pending-after-prefix read");
}

// Case 7: dropped and cancelled reads lose no prefix bytes.
#[tokio::test(start_paused = true)]
async fn dropped_and_cancelled_reads_lose_no_prefix_bytes() {
    timeout(Duration::from_secs(10), async {
        // (a) a dropped 2-byte read consumed exactly those 2 bytes.
        let (mut peer, server) = duplex(64);
        let mut prefixed = Prefixed::new(b"ABC".to_vec(), server);
        poll_fn(|cx| {
            let mut buf = [0u8; 2];
            let mut rbuf = ReadBuf::new(&mut buf);
            match Pin::new(&mut prefixed).poll_read(cx, &mut rbuf) {
                Poll::Ready(Ok(())) => {
                    assert_eq!(rbuf.filled(), b"AB");
                    Poll::Ready(())
                }
                other => panic!("prefix read did not complete: {other:?}"),
            }
        })
        .await;
        assert_eq!(prefixed.prefix_remaining(), b"C");
        // `async move` drops `peer` after the write, so `read_to_end` sees EOF.
        let writer = async move {
            tokio::time::sleep(Duration::from_millis(900)).await;
            peer.write_all(b"DE").await.unwrap();
        };
        let reader = async {
            let mut got = Vec::new();
            prefixed.read_to_end(&mut got).await.unwrap();
            got
        };
        let (got, ()) = tokio::join!(reader, writer);
        assert_eq!(got, *b"CDE"); // exactly one delivery of ABCDE

        // (b) a cancelled read on the drained prefix loses nothing.
        let (mut peer, server) = duplex(64);
        let mut prefixed = Prefixed::new(b"AB".to_vec(), server);
        let mut buf = [0u8; 2];
        prefixed.read_exact(&mut buf).await.unwrap();
        assert!(prefixed.prefix_remaining().is_empty());
        assert!(timeout(Duration::from_millis(500), async {
            prefixed.read(&mut [0u8; 4]).await
        })
        .await
        .is_err());
        let writer = async {
            tokio::time::sleep(Duration::from_millis(900)).await;
            peer.write_all(b"XY").await.unwrap();
        };
        let reader = async {
            let mut buf = [0u8; 2];
            prefixed.read_exact(&mut buf).await.unwrap();
            buf
        };
        let (buf, ()) = tokio::join!(reader, writer);
        assert_eq!(buf, *b"XY");
    })
    .await
    .expect("bounded cancellation-safety reads");
}

// Case 8: writes (plain, vectored), flush, and shutdown pass through to the inner,
// independent of prefix state.
#[tokio::test]
async fn writes_flush_shutdown_and_vectored_pass_through_to_inner() {
    timeout(Duration::from_secs(10), async {
        // (a) a write BEFORE any read reaches the peer.
        let (mut peer, server) = duplex(64);
        let mut prefixed = Prefixed::new(b"AB".to_vec(), CountingIo::new(server));
        prefixed.write_all(b"OUT").await.unwrap();
        let mut got = [0u8; 3];
        peer.read_exact(&mut got).await.unwrap();
        assert_eq!(got, *b"OUT");

        // (b) a write after reading one prefix byte still reaches the peer.
        let mut one = [0u8; 1];
        prefixed.read_exact(&mut one).await.unwrap();
        assert_eq!(one, *b"A");
        prefixed.write_all(b"OUT2").await.unwrap();
        let mut got = [0u8; 4];
        peer.read_exact(&mut got).await.unwrap();
        assert_eq!(got, *b"OUT2");

        // (c) flush and shutdown are forwarded and counted.
        prefixed.flush().await.unwrap();
        assert_eq!(prefixed.get_ref().flushes, 1);
        prefixed.shutdown().await.unwrap();
        assert_eq!(prefixed.get_ref().shutdowns, 1);
        let mut rest = Vec::new();
        peer.read_to_end(&mut rest).await.unwrap();
        assert!(rest.is_empty());

        // (d) vectored writes pass through even while prefix bytes remain.
        let mut prefixed = Prefixed::new(
            b"P".to_vec(),
            VectoredInner {
                vectored_calls: 0,
                plain_calls: 0,
            },
        );
        assert!(prefixed.is_write_vectored());
        let n = prefixed
            .write_vectored(&[io::IoSlice::new(b"AA"), io::IoSlice::new(b"BBB")])
            .await
            .unwrap();
        assert_eq!(n, 5);
        assert_eq!(prefixed.get_ref().vectored_calls, 1);
        assert_eq!(prefixed.get_ref().plain_calls, 0);
    })
    .await
    .expect("bounded write pass-through");
}

// Case 9: accessors track the prefix position and reach the wrapped stream.
#[tokio::test]
async fn accessors_track_prefix_and_reach_the_inner() {
    timeout(Duration::from_secs(10), async {
        let (mut peer, server) = duplex(64);
        peer.write_all(b"DATA").await.unwrap();
        let mut prefixed = Prefixed::new(b"XYZ".to_vec(), server);
        prefixed.read_exact(&mut [0u8; 1]).await.unwrap();
        assert_eq!(prefixed.prefix_remaining(), b"YZ");
        prefixed.get_mut().write_all(b"Q").await.unwrap();
        let mut sent = [0u8; 1];
        peer.read_exact(&mut sent).await.unwrap();
        assert_eq!(sent, *b"Q"); // `get_mut` reaches the wrapped stream's peer
        let (rest, mut inner) = prefixed.into_parts();
        assert_eq!(rest, b"YZ");
        let mut got = [0u8; 4];
        inner.read_exact(&mut got).await.unwrap();
        assert_eq!(got, *b"DATA");

        // `into_inner` drops the unserved prefix entirely.
        let (mut peer, server) = duplex(64);
        peer.write_all(b"DATA").await.unwrap();
        let mut inner = Prefixed::new(b"DROPME".to_vec(), server).into_inner();
        let mut got = [0u8; 4];
        inner.read_exact(&mut got).await.unwrap();
        assert_eq!(got, *b"DATA");
    })
    .await
    .expect("bounded accessor usage");
}

// Case 10: a 100 KiB prefix reads back exactly, byte for byte, in small buffers.
#[tokio::test]
async fn hundred_kib_prefix_reads_exactly_with_small_buffers() {
    timeout(Duration::from_secs(10), async {
        let prefix: Vec<u8> = (0u8..=255).cycle().take(100 * 1024).collect();
        let (peer, server) = duplex(64);
        drop(peer); // EOF inner
        let mut prefixed = Prefixed::new(prefix, server);
        let mut got = Vec::new();
        loop {
            let mut buf = [0u8; 7];
            let n = prefixed.read(&mut buf).await.unwrap();
            if n == 0 {
                break;
            }
            got.extend_from_slice(&buf[..n]);
        }
        assert_eq!(got.len(), 102400);
        let expected: Vec<u8> = (0u8..=255).cycle().take(100 * 1024).collect();
        assert_eq!(got, expected);
    })
    .await
    .expect("bounded 100 KiB prefix read");
}

// Case 11: Debug renders lengths only, never prefix bytes.
#[tokio::test]
async fn debug_never_shows_prefix_bytes_only_lengths() {
    timeout(Duration::from_secs(10), async {
        let (peer, server) = duplex(64);
        drop(peer);
        let mut prefixed = Prefixed::new(b"SECRET-PIPELINE".to_vec(), server);
        let s = format!("{prefixed:?}");
        assert!(!s.contains("SECRET"));
        assert!(!s.contains("83, 69, 67, 82, 69, 84"));
        assert!(!s.contains("\\x53\\x45\\x43\\x52\\x45\\x54"));
        assert!(s.contains("prefix_len: 15"), "{s}");
        assert!(s.contains("prefix_pos: 0"), "{s}");
        prefixed.read_exact(&mut [0u8; 1]).await.unwrap();
        let s = format!("{prefixed:?}");
        assert!(s.contains("prefix_len: 15"), "{s}");
        assert!(s.contains("prefix_pos: 1"), "{s}");
    })
    .await
    .expect("bounded debug rendering");
}

// Case 12: `into_prefixed` streams the pipeline and payload end to end, for
// both HTTP and SOCKS5 handshakes.
#[tokio::test]
async fn into_prefixed_streams_pipeline_and_payload_end_to_end() {
    timeout(Duration::from_secs(10), async {
        // (a) HTTP: the over-read pipeline is served by the wrapper.
        let (mut client, mut server) = duplex(1024);
        let server_side = async {
            let req = accept(&mut server, &anon_options(true)).await.unwrap();
            assert_eq!(req.protocol(), Protocol::Http);
            assert_eq!(req.pipeline(), b"EARLY");
            req.reply(&mut server, Reply::Established).await.unwrap();
            let mut p = req.into_prefixed(server);
            assert_eq!(p.prefix_remaining(), b"EARLY");
            let mut buf = [0u8; 10];
            p.read_exact(&mut buf).await.unwrap();
            assert_eq!(buf, *b"EARLYLATER");
            p.write_all(b"HOSTDATA").await.unwrap();
        };
        let client_side = async {
            // One write: the header block plus the early pipeline byte.
            client
                .write_all(b"CONNECT h:443 HTTP/1.1\r\nHost: h:443\r\n\r\nEARLY")
                .await
                .unwrap();
            let mut reply = [0u8; 39];
            client.read_exact(&mut reply).await.unwrap();
            client.write_all(b"LATER").await.unwrap();
            let mut buf = [0u8; 8];
            client.read_exact(&mut buf).await.unwrap();
            assert_eq!(buf, *b"HOSTDATA");
        };
        tokio::join!(server_side, client_side);

        // (b) SOCKS5: no pipeline; the wrapper is transparent.
        let (mut client, mut server) = duplex(1024);
        let server_side = async {
            let req = accept(&mut server, &anon_options(true)).await.unwrap();
            assert!(req.pipeline().is_empty());
            let mut p = req.into_prefixed(server);
            assert!(p.prefix_remaining().is_empty());
            let mut buf = [0u8; 7];
            p.read_exact(&mut buf).await.unwrap();
            assert_eq!(buf, *b"PAYLOAD");
            p.write_all(b"ACK").await.unwrap();
        };
        let client_side = async {
            client.write_all(&socks_request(b"h")).await.unwrap();
            let mut reply = [0u8; 2];
            client.read_exact(&mut reply).await.unwrap();
            assert_eq!(reply, [5, 0]);
            client.write_all(b"PAYLOAD").await.unwrap();
            let mut buf = [0u8; 3];
            client.read_exact(&mut buf).await.unwrap();
            assert_eq!(buf, *b"ACK");
        };
        tokio::join!(server_side, client_side);
    })
    .await
    .expect("bounded end-to-end into_prefixed streams");
}

// Case 13: `take_pipeline` and `pipeline` keep their behavior now that
// `into_prefixed` exists.
#[test]
fn take_pipeline_and_pipeline_survive_into_prefixed_addition() {
    // `tests/framing.rs` still covers accept-level pipeline regression (unchanged).
    let mut req = IncomingRequest {
        auth: crate::server::AuthMethod::Anonymous,
        protocol: Protocol::Http,
        target: "h:1".into(),
        username: None,
        auth_info: None,
        pipeline: b"PIP".to_vec(),
    };
    assert_eq!(req.pipeline(), b"PIP");
    assert_eq!(req.take_pipeline(), b"PIP");
    assert!(req.take_pipeline().is_empty());

    let (peer, server) = duplex(64);
    drop(peer);
    let req = IncomingRequest {
        auth: crate::server::AuthMethod::Anonymous,
        protocol: Protocol::Http,
        target: "h:1".into(),
        username: None,
        auth_info: None,
        pipeline: b"REST".to_vec(),
    };
    let prefixed = req.into_prefixed(server);
    assert_eq!(prefixed.prefix_remaining(), b"REST");
}
