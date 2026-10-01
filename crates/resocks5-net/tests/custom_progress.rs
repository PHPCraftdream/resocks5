//! SDK-C: custom progress instrumentation through the public API.
//!
//! Proves a third-party `AsyncWrite` wrapper — written WITHOUT any
//! crate-private access, reporting confirmed bytes via
//! [`FlushProgress::report_confirmed`] — can keep the bounded helpers
//! (`send_possibly_fragmented`) alive across a slow drain, and that a
//! wrapper which does NOT report stalls exactly like an
//! uninstrumented stack. All timing is paused virtual time.

use std::collections::VecDeque;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use resocks5_net::connect::send_possibly_fragmented;
use resocks5_net::connect::tls_fragment::{FragmentSpec, SendProgress};
use resocks5_net::progress::FlushProgress;
use tokio::io::AsyncWrite;

/// Raw transport double: accepts at most `per_poll` bytes per
/// successful `poll_write`, then goes silent for `interval` of
/// (virtual) time. Mirrors the crate-internal `DripTransport`.
struct DripTransport {
    accepted: Vec<u8>,
    per_poll: usize,
    interval: Duration,
    // ZERO so the very first write is immediate.
    cooldown: Pin<Box<tokio::time::Sleep>>,
}

impl DripTransport {
    fn new(per_poll: usize, interval: Duration) -> Self {
        Self {
            accepted: Vec::new(),
            per_poll,
            interval,
            cooldown: Box::pin(tokio::time::sleep(Duration::ZERO)),
        }
    }
}

impl AsyncWrite for DripTransport {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        if this.cooldown.as_mut().poll(cx).is_pending() {
            return Poll::Pending;
        }
        let n = buf.len().min(this.per_poll);
        this.accepted.extend_from_slice(&buf[..n]);
        let deadline = tokio::time::Instant::now() + this.interval;
        this.cooldown.as_mut().reset(deadline);
        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        self.poll_flush(cx)
    }
}

/// The third-party buffering look-alike under test: `poll_write`
/// accepts the whole payload into a queue (tokio-rustls-style), and
/// `poll_flush` drains it to the inner transport `piece` bytes per
/// drip wake, reporting each accepted piece via the PUBLIC API
/// (`report_confirmed`) when `instrument: true`.
struct CustomBuffer<W> {
    instrument: bool,
    piece: usize,
    pending: VecDeque<u8>,
    /// Bytes reported through the public API (0 when not instrumented).
    reported: u64,
    inner: W,
}

impl<W> CustomBuffer<W> {
    fn new(piece: usize, instrument: bool, inner: W) -> Self {
        Self {
            instrument,
            piece,
            pending: VecDeque::new(),
            reported: 0,
            inner,
        }
    }
}

impl<W: AsyncWrite + Unpin> AsyncWrite for CustomBuffer<W> {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        this.pending.extend(buf.iter().copied());
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        loop {
            if this.pending.is_empty() {
                return Pin::new(&mut this.inner).poll_flush(cx);
            }
            let contiguous = this.pending.make_contiguous();
            let take = this.piece.min(contiguous.len());
            let written = match Pin::new(&mut this.inner).poll_write(cx, &contiguous[..take]) {
                Poll::Ready(Ok(n)) => n,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            };
            this.pending.drain(..written);
            if this.instrument {
                // THE public-API contract: only bytes the transport
                // actually accepted are progress. `current()` must
                // see the ambient scope installed by the bounded
                // helper — assert that, since the whole point of this
                // test is that no handle had to be passed in.
                let ambient =
                    FlushProgress::current().expect("bounded helper must install the scope");
                ambient.record(written as u64);
                this.reported += written as u64;
            }
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        self.poll_flush(cx)
    }
}

fn hello() -> Vec<u8> {
    // Minimal TLS ClientHello prefix so the fragmented path runs.
    let mut data = vec![0x16, 0x03, 0x01, 0x00, 0x10, 0x01];
    data.extend_from_slice(&[0x5A; 2000]);
    data
}

/// (1) A custom wrapper reporting via the public API keeps a bounded
/// fragmented send alive across a slow drain: the transport accepts
/// 8 bytes per 200 ms drip, so the final flush stays Pending for
/// ~50 s of virtual time — 50 renewals past the 1 s idle window.
#[tokio::test(start_paused = true)]
async fn custom_reporting_wrapper_completes_bounded_send_over_slow_drain() {
    let data = hello();
    let drip = DripTransport::new(8, Duration::from_millis(200));
    let mut w = CustomBuffer::new(8, true, drip);

    let cfg = FragmentSpec {
        enabled: true,
        fragment_size: 512,
        delay_ms: 0,
    };
    let start = tokio::time::Instant::now();
    let outcome = send_possibly_fragmented(&mut w, &data, &cfg, Duration::from_secs(1))
        .await
        .unwrap();
    assert_eq!(outcome, SendProgress::Completed);
    assert!(
        start.elapsed() >= Duration::from_secs(2),
        "the drain must have ridden many idle-window renewals: {:?}",
        start.elapsed()
    );
    // The wrapper really reported through the public API, byte for byte.
    assert_eq!(w.reported, data.len() as u64);
    // Byte-for-byte: the transport received the whole payload once.
    assert_eq!(w.inner.accepted, data);
}

/// (2) Negative control: the IDENTICAL wrapper without reporting
/// stalls after one idle window — the counter's renewal logic rides
/// ONLY reported bytes, and none are reported.
#[tokio::test(start_paused = true)]
async fn identical_wrapper_without_reporting_stalls() {
    let data = hello();
    let mut w = CustomBuffer::new(8, false, DripTransport::new(8, Duration::from_millis(200)));

    let cfg = FragmentSpec {
        enabled: true,
        fragment_size: 512,
        delay_ms: 0,
    };
    let start = tokio::time::Instant::now();
    let outcome = send_possibly_fragmented(&mut w, &data, &cfg, Duration::from_secs(1))
        .await
        .unwrap();
    assert_eq!(outcome, SendProgress::Stalled);
    assert!(
        start.elapsed() >= Duration::from_secs(1) && start.elapsed() < Duration::from_secs(2),
        "one idle window only, not the ~50 s drain: {:?}",
        start.elapsed()
    );
    assert_eq!(w.reported, 0);
    assert!(w.inner.accepted.len() < data.len());
}

/// (3) `record(0)` is a no-op and never counts as progress: a wrapper
/// that dutifully reports a zero-byte "piece" every poll still stalls
/// after exactly one window. Also checks the direct sink API.
#[tokio::test(start_paused = true)]
async fn zero_byte_reports_are_not_progress() {
    struct ZeroReporter<W> {
        pending: VecDeque<u8>,
        inner: W,
    }
    impl<W: AsyncWrite + Unpin> AsyncWrite for ZeroReporter<W> {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            let this = self.get_mut();
            this.pending.extend(buf.iter().copied());
            Poll::Ready(Ok(buf.len()))
        }
        fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            let this = self.get_mut();
            loop {
                if this.pending.is_empty() {
                    return Pin::new(&mut this.inner).poll_flush(cx);
                }
                let contiguous = this.pending.make_contiguous();
                let written = match Pin::new(&mut this.inner)
                    .poll_write(cx, &contiguous[..1.min(contiguous.len())])
                {
                    Poll::Ready(Ok(n)) => n,
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => return Poll::Pending,
                };
                this.pending.drain(..written);
                // VIOLATION under test: reporting zero as if it were
                // progress. It must change nothing.
                if let Some(p) = FlushProgress::current() {
                    p.record(0);
                }
                FlushProgress::report_confirmed(0);
            }
        }
        fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            self.poll_flush(cx)
        }
    }

    let data = hello();
    let mut w = ZeroReporter {
        pending: VecDeque::new(),
        inner: DripTransport::new(1, Duration::from_millis(200)),
    };

    let cfg = FragmentSpec {
        enabled: true,
        fragment_size: 512,
        delay_ms: 0,
    };
    let start = tokio::time::Instant::now();
    let outcome = send_possibly_fragmented(&mut w, &data, &cfg, Duration::from_secs(1))
        .await
        .unwrap();
    assert_eq!(outcome, SendProgress::Stalled);
    assert!(
        start.elapsed() >= Duration::from_secs(1) && start.elapsed() < Duration::from_secs(2),
        "zero-byte reports must not renew the idle window: {:?}",
        start.elapsed()
    );

    // Direct sink API: record(0) never moves the total.
    let sink = FlushProgress::new();
    sink.record(0);
    assert_eq!(sink.total(), 0);
    sink.record(7);
    assert_eq!(sink.total(), 7);
}
