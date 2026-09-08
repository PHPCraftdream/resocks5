//! Bidirectional copy with activity tracking and bounded teardown.

use std::future::poll_fn;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::{copy_bidirectional_with_sizes, AsyncRead, AsyncWrite, ReadBuf};
use tokio::time::Instant;

/// Forward bytes until both directions reach EOF, a timeout fires, or I/O fails.
/// Half-closes are propagated while the other direction continues to flow.
///
/// `idle` measures time since the last successful read or write in either
/// direction. `max_lifetime` also bounds stalled writes and shutdowns.
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
    let mut a = Tracked {
        inner: a,
        activity: &activity,
    };
    let mut b = Tracked {
        inner: b,
        activity: &activity,
    };
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
        let result = Pin::new(&mut self.inner).poll_write(cx, buf);
        if matches!(result, Poll::Ready(Ok(n)) if n > 0) {
            self.activity.record();
        }
        result
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
}
