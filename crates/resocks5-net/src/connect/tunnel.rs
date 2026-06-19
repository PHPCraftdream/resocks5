//! Idle- and lifetime-bounded bidirectional copy between two streams.
//!
//! Replaces `tokio::io::copy_bidirectional` because that one has no
//! activity tracking — a misbehaving peer that holds the TCP open but
//! never sends a byte would keep the per-upstream permit busy until
//! `tunnel_max_lifetime_sec` (30 min). With explicit idle tracking we
//! tear the tunnel down within `tunnel_idle_timeout_sec` (60 s) of
//! silence, sending FIN to both peers so they can clean up too.

use std::io;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Forward bytes between `a` and `b` until either side closes, both
/// timeouts fire, or an I/O error happens. Sends `shutdown()` on the
/// opposite write half whenever one direction reaches EOF or a
/// timeout fires, so peers see a clean FIN rather than a half-open
/// zombie connection.
///
/// `idle` is the per-iteration deadline: if `select!` doesn't make
/// any read progress within this duration the tunnel is closed.
/// `max_lifetime` is a hard cap independent of activity.
///
/// Both streams are consumed by value so that the function owns the
/// drop-order and any wrapper resources (e.g. a per-upstream permit
/// inside `UpstreamStream`) are released before this returns.
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
    let (mut a_r, mut a_w) = tokio::io::split(a);
    let (mut b_r, mut b_w) = tokio::io::split(b);

    let mut buf_ab = vec![0u8; 16 * 1024];
    let mut buf_ba = vec![0u8; 16 * 1024];
    let mut ab_open = true; // a → b direction still flowing
    let mut ba_open = true; // b → a direction still flowing

    // Hard lifetime deadline is a single sleep, pinned so we can poll
    // it across multiple iterations of the select loop.
    let lifetime = tokio::time::sleep(max_lifetime);
    tokio::pin!(lifetime);

    while ab_open || ba_open {
        // Per-iteration idle sleep — freshly created each loop so its
        // deadline is "now + idle". When this branch fires, neither
        // read side has produced any data in the past `idle` window.
        tokio::select! {
            // ── a → b ────────────────────────────────────────────
            res = a_r.read(&mut buf_ab), if ab_open => {
                let n = res?;
                if n == 0 {
                    // EOF from a — tell b we won't send any more.
                    let _ = b_w.shutdown().await;
                    ab_open = false;
                } else {
                    // write_all is NOT cancel-safe; the surrounding
                    // select has already picked this branch, so we
                    // run write_all to completion here without risk
                    // of an `idle` cancellation tearing it up mid-way.
                    b_w.write_all(&buf_ab[..n]).await?;
                }
            }

            // ── b → a ────────────────────────────────────────────
            res = b_r.read(&mut buf_ba), if ba_open => {
                let n = res?;
                if n == 0 {
                    let _ = a_w.shutdown().await;
                    ba_open = false;
                } else {
                    a_w.write_all(&buf_ba[..n]).await?;
                }
            }

            // ── Idle watchdog ───────────────────────────────────
            _ = tokio::time::sleep(idle) => {
                // No read progress for `idle` seconds. Send FIN on
                // both directions still open so the peers don't sit
                // in CLOSE_WAIT.
                let _ = a_w.shutdown().await;
                let _ = b_w.shutdown().await;
                return Ok(());
            }

            // ── Hard lifetime cap ───────────────────────────────
            _ = &mut lifetime => {
                let _ = a_w.shutdown().await;
                let _ = b_w.shutdown().await;
                return Ok(());
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt};

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

    #[tokio::test]
    async fn idle_timeout_closes_silent_tunnel() {
        let (client_outer, client_inner, proxy_outer, proxy_inner) = pair();
        let start = std::time::Instant::now();
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

    #[tokio::test]
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
        for i in 0u8..10 {
            client_outer.write_all(&[i]).await.unwrap();
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        // Read what the proxy side received.
        let mut got = vec![0u8; 10];
        proxy_outer.read_exact(&mut got).await.unwrap();
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

    #[tokio::test]
    async fn max_lifetime_caps_tunnel() {
        let (client_outer, client_inner, proxy_outer, proxy_inner) = pair();
        let start = std::time::Instant::now();
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
