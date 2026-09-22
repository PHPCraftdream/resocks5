//! Bidirectional copy with activity tracking and bounded teardown.

use std::future::poll_fn;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use crate::progress::{confirmed_scope, FlushProgress};
use tokio::io::{copy_bidirectional_with_sizes, AsyncRead, AsyncWrite, ReadBuf};
use tokio::time::Instant;

/// Forward bytes until both directions reach EOF, a timeout fires, or I/O fails.
/// Half-closes are propagated while the other direction continues to flow.
///
/// `idle` measures time since the last successful read or write in either
/// direction. Progress confirmed inside a wrapping TLS/buffering stack — a
/// `ProgressReportingWriter` below the tracked stream, reported through the
/// tunnel's shared `FlushProgress` — counts as activity too: bytes moved
/// inside the wrapper while the outer write/flush/shutdown is still
/// unresolved are activity, not idleness. `max_lifetime` also bounds
/// stalled writes
/// and shutdowns.
/// A zero duration disables the corresponding deadline. On timeout, shutdown
/// is attempted once on each stream before dropping both; teardown never waits
/// indefinitely for a peer to accept buffered data.
///
/// cancel-safe: NO — cancellation can discard buffered bytes. Both owned
/// streams and their permits are dropped; the transfer must not be resumed.
pub async fn tunnel_with_timeouts<A, B>(
    a: A,
    b: B,
    idle: Duration,
    max_lifetime: Duration,
) -> io::Result<()>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    let activity = Activity {
        epoch: Instant::now(),
        nanos: AtomicU64::new(0),
    };
    let confirmed = FlushProgress::new();
    let mut a = Tracked {
        inner: a,
        activity: &activity,
        confirmed: &confirmed,
    };
    let mut b = Tracked {
        inner: b,
        activity: &activity,
        confirmed: &confirmed,
    };
    confirmed_scope(confirmed.clone(), async {
        {
            let transfer = copy_bidirectional_with_sizes(&mut a, &mut b, 16 * 1024, 16 * 1024);
            let lifetime = tokio::time::sleep(max_lifetime);
            let idle_timer = tokio::time::sleep(idle);
            tokio::pin!(transfer, lifetime, idle_timer);
            loop {
                tokio::select! {
                    biased;
                    _ = &mut lifetime, if !max_lifetime.is_zero() => break,
                    _ = &mut idle_timer, if !idle.is_zero() => {
                        let last = activity.epoch + Duration::from_nanos(activity.nanos.load(Ordering::Relaxed));
                        let deadline = last + idle;
                        if Instant::now() >= deadline {
                            break;
                        }
                        idle_timer.as_mut().reset(deadline);
                    }
                    result = &mut transfer => return result.map(|_| ()),
                }
            }
        }
        poll_fn(|cx| {
            let _ = Pin::new(&mut a.inner).poll_shutdown(cx);
            let _ = Pin::new(&mut b.inner).poll_shutdown(cx);
            Poll::Ready(())
        })
        .await;
        Ok(())
    })
    .await
}

struct Activity {
    epoch: Instant,
    nanos: AtomicU64,
}

impl Activity {
    fn record(&self) {
        let nanos = u64::try_from(self.epoch.elapsed().as_nanos()).unwrap_or(u64::MAX);
        // Both wrappers are polled by one task; no other state is published.
        self.nanos.store(nanos, Ordering::Relaxed);
    }
}

struct Tracked<'a, S> {
    inner: S,
    activity: &'a Activity,
    confirmed: &'a FlushProgress,
}

impl<S: AsyncRead + Unpin> AsyncRead for Tracked<'_, S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        let result = Pin::new(&mut self.inner).poll_read(cx, buf);
        if matches!(result, Poll::Ready(Ok(()))) && buf.filled().len() > before {
            self.activity.record();
        }
        result
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Tracked<'_, S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let confirmed_before = self.confirmed.total();
        let result = Pin::new(&mut self.inner).poll_write(cx, buf);
        if matches!(result, Poll::Ready(Ok(n)) if n > 0)
            || self.confirmed.total() > confirmed_before
        {
            self.activity.record();
        }
        result
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let confirmed_before = self.confirmed.total();
        let result = Pin::new(&mut self.inner).poll_flush(cx);
        if self.confirmed.total() > confirmed_before {
            self.activity.record();
        }
        result
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let confirmed_before = self.confirmed.total();
        let result = Pin::new(&mut self.inner).poll_shutdown(cx);
        if self.confirmed.total() > confirmed_before {
            self.activity.record();
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::progress::ProgressReportingWriter;
    use std::future::Future;
    use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt};

    #[tokio::test(start_paused = true)]
    async fn blocked_write_still_allows_reverse_traffic() {
        let (mut client, client_inner) = duplex(64);
        let (mut proxy, proxy_inner) = duplex(1);
        client.write_all(b"request").await.unwrap();
        let task = tokio::spawn(tunnel_with_timeouts(
            client_inner,
            proxy_inner,
            Duration::from_secs(60),
            Duration::from_secs(60),
        ));
        let mut byte = [0];
        proxy.read_exact(&mut byte).await.unwrap();
        assert_eq!(byte, *b"r");
        proxy.write_all(b"R").await.unwrap();
        let received =
            tokio::time::timeout(Duration::from_secs(1), client.read_exact(&mut byte)).await;
        drop(client);
        drop(proxy);
        let _ = task.await.unwrap();
        received
            .expect("reverse traffic stalled behind a blocked write")
            .unwrap();
        assert_eq!(byte, *b"R");
    }

    async fn check_blocked_write_deadline(idle: Duration, lifetime: Duration) {
        let (mut client, client_inner) = duplex(64);
        let (_proxy, proxy_inner) = duplex(1);
        client.write_all(b"request").await.unwrap();
        tokio::time::timeout(
            Duration::from_secs(6),
            tunnel_with_timeouts(client_inner, proxy_inner, idle, lifetime),
        )
        .await
        .expect("blocked write bypassed the tunnel deadline")
        .unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn idle_deadline_covers_blocked_writes() {
        check_blocked_write_deadline(Duration::from_secs(5), Duration::from_secs(60)).await;
    }

    #[tokio::test(start_paused = true)]
    async fn lifetime_deadline_covers_blocked_writes() {
        check_blocked_write_deadline(Duration::from_secs(60), Duration::from_secs(5)).await;
    }

    /// Helper: build two pairs of in-memory pipes representing the
    /// client side and the proxy side of the tunnel, plus the "outer"
    /// endpoints a test can read/write to drive the proxy.
    fn pair() -> (
        tokio::io::DuplexStream,
        tokio::io::DuplexStream,
        tokio::io::DuplexStream,
        tokio::io::DuplexStream,
    ) {
        let (client_outer, client_inner) = duplex(64 * 1024);
        let (proxy_outer, proxy_inner) = duplex(64 * 1024);
        (client_outer, client_inner, proxy_outer, proxy_inner)
    }

    #[tokio::test]
    async fn data_flows_both_ways_until_eof() {
        let (mut client_outer, client_inner, mut proxy_outer, proxy_inner) = pair();
        let task = tokio::spawn(tunnel_with_timeouts(
            client_inner,
            proxy_inner,
            Duration::from_secs(5),
            Duration::from_secs(60),
        ));

        // Client → proxy.
        client_outer.write_all(b"hello").await.unwrap();
        let mut buf = [0u8; 5];
        proxy_outer.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"hello");

        // Proxy → client.
        proxy_outer.write_all(b"world").await.unwrap();
        let mut buf = [0u8; 5];
        client_outer.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"world");

        // Close client side → tunnel should propagate close and exit.
        drop(client_outer);
        // Proxy will see EOF on its read side after the client→proxy
        // shutdown is forwarded.
        let mut tail = Vec::new();
        let _ = proxy_outer.read_to_end(&mut tail).await;
        drop(proxy_outer);

        let res = task.await.unwrap();
        assert!(res.is_ok());
    }

    #[tokio::test(start_paused = true)]
    async fn idle_timeout_closes_silent_tunnel() {
        let (client_outer, client_inner, proxy_outer, proxy_inner) = pair();
        let start = Instant::now();
        let task = tokio::spawn(tunnel_with_timeouts(
            client_inner,
            proxy_inner,
            Duration::from_millis(100), // idle
            Duration::from_secs(60),    // lifetime — won't fire
        ));

        // Neither side writes anything → idle must fire.
        let res = task.await.unwrap();
        assert!(res.is_ok());
        let elapsed = start.elapsed();
        assert!(
            elapsed >= Duration::from_millis(100),
            "fired too early: {:?}",
            elapsed
        );
        assert!(
            elapsed < Duration::from_secs(2),
            "took too long: {:?}",
            elapsed
        );

        drop(client_outer);
        drop(proxy_outer);
    }

    #[tokio::test(start_paused = true)]
    async fn idle_does_not_fire_while_data_flows() {
        let (mut client_outer, client_inner, mut proxy_outer, proxy_inner) = pair();
        let task = tokio::spawn(tunnel_with_timeouts(
            client_inner,
            proxy_inner,
            Duration::from_millis(150), // idle
            Duration::from_secs(60),
        ));

        // Drip a byte every 50 ms — well under the idle threshold —
        // for 500 ms, then close.
        let mut got = Vec::new();
        for i in 0u8..10 {
            client_outer.write_all(&[i]).await.unwrap();
            got.push(proxy_outer.read_u8().await.unwrap());
            tokio::time::advance(Duration::from_millis(50)).await;
        }
        assert_eq!(got, (0..10u8).collect::<Vec<_>>());

        // Now close — tunnel must end gracefully, NOT via idle (we
        // were active throughout).
        drop(client_outer);
        let mut tail = Vec::new();
        let _ = proxy_outer.read_to_end(&mut tail).await;
        drop(proxy_outer);
        let res = task.await.unwrap();
        assert!(res.is_ok());
    }

    #[tokio::test(start_paused = true)]
    async fn max_lifetime_caps_tunnel() {
        let (client_outer, client_inner, proxy_outer, proxy_inner) = pair();
        let start = Instant::now();
        let task = tokio::spawn(tunnel_with_timeouts(
            client_inner,
            proxy_inner,
            Duration::from_secs(60),    // idle — would not fire first
            Duration::from_millis(120), // lifetime — fires
        ));

        let res = task.await.unwrap();
        assert!(res.is_ok());
        let elapsed = start.elapsed();
        assert!(
            elapsed >= Duration::from_millis(120),
            "fired too early: {:?}",
            elapsed
        );
        assert!(
            elapsed < Duration::from_secs(2),
            "took too long: {:?}",
            elapsed
        );

        drop(client_outer);
        drop(proxy_outer);
    }

    #[tokio::test(start_paused = true)]
    async fn zero_deadlines_allow_a_long_lived_tunnel() {
        let (mut client, client_inner, mut proxy, proxy_inner) = pair();
        let task = tokio::spawn(tunnel_with_timeouts(
            client_inner,
            proxy_inner,
            Duration::ZERO,
            Duration::ZERO,
        ));
        tokio::time::advance(Duration::from_secs(3600)).await;
        assert!(!task.is_finished());
        client.write_all(b"x").await.unwrap();
        assert_eq!(proxy.read_u8().await.unwrap(), b'x');
        drop(client);
        drop(proxy);
        task.await.unwrap().unwrap();
    }

    struct PendingShutdown {
        inner: tokio::io::DuplexStream,
        dropped: std::sync::Arc<std::sync::atomic::AtomicBool>,
    }

    impl Drop for PendingShutdown {
        fn drop(&mut self) {
            self.dropped.store(true, Ordering::Relaxed);
        }
    }

    impl AsyncRead for PendingShutdown {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Pin::new(&mut self.inner).poll_read(cx, buf)
        }
    }

    impl AsyncWrite for PendingShutdown {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            Pin::new(&mut self.inner).poll_write(cx, buf)
        }
        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.inner).poll_flush(cx)
        }
        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Pending
        }
    }

    #[tokio::test(start_paused = true)]
    async fn timeout_drops_stream_even_when_shutdown_stalls() {
        let (_client, client_inner, _proxy, proxy_inner) = pair();
        let dropped = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let stream = PendingShutdown {
            inner: client_inner,
            dropped: dropped.clone(),
        };
        tokio::time::timeout(
            Duration::from_secs(2),
            tunnel_with_timeouts(
                stream,
                proxy_inner,
                Duration::from_secs(1),
                Duration::from_secs(60),
            ),
        )
        .await
        .expect("shutdown bypassed the deadline")
        .unwrap();
        assert!(dropped.load(Ordering::Relaxed));
    }

    #[tokio::test]
    async fn one_sided_close_propagates_shutdown_then_other_eof_exits() {
        // Client writes a bit then closes. Tunnel forwards the bytes
        // and the FIN; once the proxy also closes (no further data
        // either way) the tunnel should exit cleanly.
        let (mut client_outer, client_inner, mut proxy_outer, proxy_inner) = pair();
        let task = tokio::spawn(tunnel_with_timeouts(
            client_inner,
            proxy_inner,
            Duration::from_secs(5),
            Duration::from_secs(60),
        ));

        client_outer.write_all(b"bye").await.unwrap();
        drop(client_outer);

        // Proxy sees the data and then EOF (because tunnel called
        // `shutdown()` on the proxy-side write half).
        let mut got = Vec::new();
        proxy_outer.read_to_end(&mut got).await.unwrap();
        assert_eq!(got, b"bye");

        // Proxy itself closes. Tunnel sees EOF on the proxy→client
        // direction too, both legs done → exit Ok.
        drop(proxy_outer);

        let res = task.await.unwrap();
        assert!(res.is_ok(), "tunnel returned {:?}", res);
    }

    #[tokio::test]
    async fn write_failure_after_peer_drop_terminates_tunnel() {
        // If one peer drops while the other is still trying to push
        // bytes through, our forwarder will hit EPIPE relaying that
        // data — the tunnel must terminate (rather than hang) on
        // such errors. We don't assert Ok vs Err: both are legitimate
        // outcomes depending on which branch of the select fires
        // first (clean shutdown vs broken-pipe write).
        let (client_outer, client_inner, mut proxy_outer, proxy_inner) = pair();
        let task = tokio::spawn(tunnel_with_timeouts(
            client_inner,
            proxy_inner,
            Duration::from_secs(5),
            Duration::from_secs(60),
        ));

        drop(client_outer); // both halves of client side are gone
        let _ = proxy_outer.write_all(b"orphan").await; // may fail or succeed-then-EPIPE
        drop(proxy_outer);

        // The important property: the task terminates instead of
        // hanging forever.
        let _ = task.await.unwrap();
    }

    /// Raw transport below everything else: accepts at most `per_poll`
    /// bytes per successful poll_write, then goes silent for `interval`
    /// of (virtual) time before becoming writable again. Unlike the
    /// send-path DripWriter it never stalls permanently. Every accepted
    /// byte is appended into the shared `log` so the test can verify the
    /// exact payload reached the wire; the mutex is locked only
    /// synchronously, never across an await. `poll_flush` and
    /// `poll_shutdown` are instantly ready.
    struct LoggingDripTransport {
        /// Every byte the transport has accepted so far.
        log: std::sync::Arc<std::sync::Mutex<Vec<u8>>>,
        per_poll: usize,
        interval: Duration,
        // Created with Duration::ZERO so the very first write is
        // immediate; reset to `interval` after every accepted write.
        cooldown: std::pin::Pin<Box<tokio::time::Sleep>>,
    }

    impl LoggingDripTransport {
        fn new(
            per_poll: usize,
            interval: Duration,
            log: std::sync::Arc<std::sync::Mutex<Vec<u8>>>,
        ) -> Self {
            Self {
                log,
                per_poll,
                interval,
                cooldown: Box::pin(tokio::time::sleep(Duration::ZERO)),
            }
        }
    }

    // All fields are Unpin, so get_mut() is enough to drive the writer.
    impl tokio::io::AsyncWrite for LoggingDripTransport {
        fn poll_write(
            self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &[u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            let this = self.get_mut();
            if this.cooldown.as_mut().poll(cx).is_pending() {
                // Still inside the silent window after the last drip.
                return std::task::Poll::Pending;
            }
            let n = buf.len().min(this.per_poll);
            this.log.lock().unwrap().extend_from_slice(&buf[..n]);
            let deadline = tokio::time::Instant::now() + this.interval;
            this.cooldown.as_mut().reset(deadline);
            std::task::Poll::Ready(Ok(n))
        }

        fn poll_flush(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }

        fn poll_shutdown(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }
    }

    /// The TLS/buffering look-alike the tunnel is talking to: its
    /// poll_write accepts the whole plaintext into an internal queue
    /// without touching the transport (mimicking tokio-rustls buffering
    /// records), and only poll_flush/poll_shutdown drain that queue into
    /// the wrapped transport `piece` bytes per accepted write — so the
    /// outer flush stays unresolved for the whole drain while real
    /// writes happen underneath the `ProgressReportingWriter`. The read
    /// leg is immediate EOF, so only the write leg keeps the tunnel busy.
    struct BufferedTlsUpstream {
        pending: std::collections::VecDeque<u8>,
        piece: usize,
        transport: ProgressReportingWriter<LoggingDripTransport>,
    }

    impl BufferedTlsUpstream {
        fn new(
            piece: usize,
            interval: Duration,
            log: std::sync::Arc<std::sync::Mutex<Vec<u8>>>,
        ) -> Self {
            Self {
                pending: std::collections::VecDeque::new(),
                piece,
                transport: ProgressReportingWriter::new(LoggingDripTransport::new(
                    piece, interval, log,
                )),
            }
        }

        // Shared drain step: pushes at most one `piece` of `pending`
        // into the transport per poll; once the queue runs dry, delegates
        // the flush inward. All fields are Unpin, so get_mut() is enough.
        fn poll_drain(
            &mut self,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            loop {
                if self.pending.is_empty() {
                    return std::pin::Pin::new(&mut self.transport).poll_flush(cx);
                }
                // VecDeque has no range Index impl: normalise the layout
                // into one contiguous slice and peek at most `piece`
                // bytes off the front; only a successful poll_write
                // drains them for real.
                let contiguous = self.pending.make_contiguous();
                let take = self.piece.min(contiguous.len());
                match std::pin::Pin::new(&mut self.transport).poll_write(cx, &contiguous[..take]) {
                    std::task::Poll::Ready(Ok(n)) => {
                        self.pending.drain(..n);
                    }
                    std::task::Poll::Ready(Err(e)) => return std::task::Poll::Ready(Err(e)),
                    std::task::Poll::Pending => return std::task::Poll::Pending,
                }
            }
        }
    }

    impl tokio::io::AsyncRead for BufferedTlsUpstream {
        fn poll_read(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
            _buf: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            // Immediate EOF: nothing is ever readable from the upstream,
            // so its read leg finishes instantly.
            std::task::Poll::Ready(Ok(()))
        }
    }

    impl tokio::io::AsyncWrite for BufferedTlsUpstream {
        fn poll_write(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
            buf: &[u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            // Accept the whole plaintext without transmitting — the TLS
            // layer has the bytes, the wire does not (yet).
            let this = self.get_mut();
            this.pending.extend(buf.iter().copied());
            std::task::Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(
            self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            self.get_mut().poll_drain(cx)
        }

        fn poll_shutdown(
            self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            // Shutdown drives the same drain to completion first; the
            // final Ready(Ok(())) is the drain's own ready state.
            self.get_mut().poll_drain(cx)
        }
    }

    /// R7-02 end-to-end: the upstream is a TLS/buffered look-alike that
    /// accepts the whole 2000-byte payload on poll_write and only
    /// transmits it 8 bytes every 200 ms during flush — ~50 s of virtual
    /// time, dozens of windows past the 1 s idle deadline. The bytes
    /// moving underneath are confirmed through the tunnel's shared
    /// FlushProgress, Tracked::poll_flush records them as activity, and
    /// the tunnel must stay alive until the drain finishes and exit Ok
    /// with the transport holding the exact payload. Without the fix the
    /// idle timer fires at 1 s (last activity was the initial poll_write)
    /// and the tunnel tears down mid-drain around ~1 s.
    #[tokio::test(start_paused = true)]
    async fn idle_spares_tunnel_while_tls_flush_drains_slowly() {
        let payload = vec![0xC3; 2000];
        let log = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));

        let (mut client, client_inner) = duplex(4096);
        client.write_all(&payload).await.unwrap();
        drop(client); // EOF: the client→upstream leg can finish

        let upstream = BufferedTlsUpstream::new(8, Duration::from_millis(200), log.clone());
        let start = tokio::time::Instant::now();
        let res = tunnel_with_timeouts(
            client_inner,
            upstream,
            Duration::from_secs(1), // idle
            Duration::ZERO,         // lifetime disabled
        )
        .await;
        res.expect("tunnel must not error");
        assert!(
            start.elapsed() >= Duration::from_millis(2000),
            "tunnel must survive past the idle window while the TLS flush drains: {:?}",
            start.elapsed()
        );
        assert_eq!(&*log.lock().unwrap(), &payload);
    }

    /// P2-03 raw transport for the write-phase doubles: accepts at most
    /// `per_poll` bytes per successful poll_write, then goes silent for
    /// `interval` of (virtual) time. `stalling_after` makes it refuse
    /// forever (Pending, no waker — re-polls come only from the
    /// caller's own timers) once that many bytes have been accepted in
    /// total. Every accepted byte is appended into the shared `log` so
    /// the test can verify the exact wire content after the tunnel
    /// consumed the stream.
    struct GatedTransport {
        log: std::sync::Arc<std::sync::Mutex<Vec<u8>>>,
        per_poll: usize,
        interval: Duration,
        cooldown: std::pin::Pin<Box<tokio::time::Sleep>>,
        stall_after: Option<usize>,
    }

    impl GatedTransport {
        fn new(
            per_poll: usize,
            interval: Duration,
            log: std::sync::Arc<std::sync::Mutex<Vec<u8>>>,
        ) -> Self {
            Self {
                log,
                per_poll,
                interval,
                cooldown: Box::pin(tokio::time::sleep(Duration::ZERO)),
                stall_after: None,
            }
        }

        fn stalling_after(mut self, n: usize) -> Self {
            self.stall_after = Some(n);
            self
        }
    }

    // All fields are Unpin, so get_mut() is enough to drive it.
    impl AsyncWrite for GatedTransport {
        fn poll_write(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            let this = self.get_mut();
            if let Some(quota) = this.stall_after {
                if this.log.lock().unwrap().len() >= quota {
                    // Quota reached: silent forever, no waker
                    // registered — only the caller's timers re-poll.
                    return Poll::Pending;
                }
            }
            if this.cooldown.as_mut().poll(cx).is_pending() {
                return Poll::Pending;
            }
            let n = buf.len().min(this.per_poll);
            this.log.lock().unwrap().extend_from_slice(&buf[..n]);
            let deadline = tokio::time::Instant::now() + this.interval;
            this.cooldown.as_mut().reset(deadline);
            Poll::Ready(Ok(n))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    /// P2-03 TLS look-alike for the WRITE phase: its poll_write, when
    /// asked to accept NEW plaintext while previously accepted bytes
    /// are still in flight, first pushes one `piece` of the old bytes
    /// into the transport (confirmed progress below the
    /// `ProgressReportingWriter`) and then returns Pending WITHOUT
    /// consuming any of the new bytes — the tokio-rustls
    /// `(0, would_block)` shape. New bytes are buffered — never put on
    /// the wire directly — and only once the buffer has fully drained,
    /// at most `accept_per_poll` per Ready, so the copy loop keeps
    /// re-invoking poll_write while earlier bytes are still draining.
    /// Flush and shutdown drive any remaining buffer into the
    /// transport. The read leg is immediate EOF.
    struct DrainingTlsPeer<W> {
        pending: std::collections::VecDeque<u8>,
        accept_per_poll: usize,
        piece: usize,
        transport: W,
    }

    impl<W: AsyncWrite + Unpin> DrainingTlsPeer<W> {
        fn new(accept_per_poll: usize, piece: usize, transport: W) -> Self {
            Self {
                pending: std::collections::VecDeque::new(),
                accept_per_poll,
                piece,
                transport,
            }
        }

        // Loop until the buffer is fully drained or the transport
        // blocks, then delegate the flush inward.
        fn poll_drain(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            while !self.pending.is_empty() {
                let contiguous = self.pending.make_contiguous();
                let take = self.piece.min(contiguous.len());
                match Pin::new(&mut self.transport).poll_write(cx, &contiguous[..take]) {
                    Poll::Ready(Ok(n)) => {
                        self.pending.drain(..n);
                    }
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => return Poll::Pending,
                }
            }
            Pin::new(&mut self.transport).poll_flush(cx)
        }
    }

    impl<W: AsyncWrite + Unpin> AsyncRead for DrainingTlsPeer<W> {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            // Immediate EOF: the upstream's read leg never blocks the
            // tunnel; only the write leg keeps it busy.
            Poll::Ready(Ok(()))
        }
    }

    impl<W: AsyncWrite + Unpin> AsyncWrite for DrainingTlsPeer<W> {
        fn poll_write(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            let this = self.get_mut();
            // Refuse new plaintext while anything is in flight: drain
            // toward the transport only while it accepts, and accept
            // new bytes only once the buffer has fully drained.
            while !this.pending.is_empty() {
                let contiguous = this.pending.make_contiguous();
                let take = this.piece.min(contiguous.len());
                match Pin::new(&mut this.transport).poll_write(cx, &contiguous[..take]) {
                    Poll::Ready(Ok(n)) => {
                        this.pending.drain(..n);
                    }
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    // Old bytes still in flight: the new ones are not
                    // even looked at (the `(0, would_block)` shape).
                    Poll::Pending => return Poll::Pending,
                }
            }
            let n = buf.len().min(this.accept_per_poll);
            this.pending.extend(&buf[..n]);
            Poll::Ready(Ok(n))
        }

        fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            self.get_mut().poll_drain(cx)
        }

        fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            self.get_mut().poll_drain(cx)
        }
    }

    /// P2-03 end-to-end for the tunnel's own idle tracking: the
    /// upstream's poll_write keeps refusing new plaintext (Pending)
    /// while it drains previously accepted bytes to the wire 2 bytes
    /// every 400 ms. Those drains are confirmed through the tunnel's
    /// shared FlushProgress, and with the fix Tracked::poll_write
    /// records them as activity, so the tunnel survives its 1 s idle
    /// deadline (the Ready-writes alone land ~1.6 s apart) and exits Ok
    /// with the exact 30-byte payload on the wire. Before the fix the
    /// idle timer fired at 1 s and tore the tunnel down mid-drain with
    /// only the drained prefix on the wire.
    #[tokio::test(start_paused = true)]
    async fn idle_spares_tunnel_while_tls_write_drains_slowly() {
        let payload: Vec<u8> = (0u8..30).collect();
        let log = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let (mut client, client_inner) = duplex(4096);
        client.write_all(&payload).await.unwrap();
        drop(client); // EOF: the client→upstream leg can finish

        let upstream = DrainingTlsPeer::new(
            10,
            2,
            ProgressReportingWriter::new(GatedTransport::new(
                2,
                Duration::from_millis(400),
                log.clone(),
            )),
        );
        let start = tokio::time::Instant::now();
        let res = tunnel_with_timeouts(
            client_inner,
            upstream,
            Duration::from_secs(1), // idle
            Duration::ZERO,         // lifetime disabled
        )
        .await;
        res.expect("tunnel must not error");
        assert!(
            start.elapsed() >= Duration::from_millis(3000),
            "tunnel must survive past the idle window while the write phase drains: {:?}",
            start.elapsed()
        );
        assert_eq!(&*log.lock().unwrap(), &payload);
    }

    /// P2-03 negative control: once the confirmed progress stops (the
    /// transport hit its 2-byte quota and goes silent, Pending without
    /// a waker), bare Pending from poll_write must NOT keep the tunnel
    /// alive — it dies at the idle deadline with exactly the drained
    /// prefix on the wire and nothing beyond it.
    #[tokio::test(start_paused = true)]
    async fn tunnel_write_phase_stalls_when_confirmed_progress_stops() {
        let payload: Vec<u8> = (0u8..30).collect();
        let log = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let (mut client, client_inner) = duplex(4096);
        client.write_all(&payload).await.unwrap();
        drop(client);

        let upstream = DrainingTlsPeer::new(
            10,
            2,
            ProgressReportingWriter::new(
                GatedTransport::new(2, Duration::from_millis(400), log.clone()).stalling_after(2),
            ),
        );
        let start = tokio::time::Instant::now();
        let res = tunnel_with_timeouts(
            client_inner,
            upstream,
            Duration::from_secs(1),
            Duration::ZERO,
        )
        .await;
        res.expect("idle teardown must be clean");
        assert!(
            start.elapsed() >= Duration::from_secs(1)
                && start.elapsed() < Duration::from_millis(1500),
            "must die at the first idle deadline, not ride bare Pending: {:?}",
            start.elapsed()
        );
        assert_eq!(&*log.lock().unwrap(), &payload[..2]);
    }

    /// P2-03 backward compatibility: without a ProgressReportingWriter
    /// in the stack nothing reports progress, so the write-phase drains
    /// count for nothing and the old idle behavior stands — the tunnel
    /// dies at the first idle deadline even though the wire kept
    /// moving underneath.
    #[tokio::test(start_paused = true)]
    async fn uninstrumented_tunnel_write_drains_do_not_count() {
        let payload: Vec<u8> = (0u8..30).collect();
        let log = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let (mut client, client_inner) = duplex(4096);
        client.write_all(&payload).await.unwrap();
        drop(client);

        let upstream = DrainingTlsPeer::new(
            10,
            2,
            GatedTransport::new(2, Duration::from_millis(400), log.clone()),
        );
        let start = tokio::time::Instant::now();
        let res = tunnel_with_timeouts(
            client_inner,
            upstream,
            Duration::from_secs(1),
            Duration::ZERO,
        )
        .await;
        res.expect("idle teardown must be clean");
        assert!(
            start.elapsed() >= Duration::from_secs(1)
                && start.elapsed() < Duration::from_millis(1500),
            "uninstrumented drains must keep the single idle window: {:?}",
            start.elapsed()
        );
        assert_eq!(&*log.lock().unwrap(), &payload[..6]);
    }
}
