//! Per-tunnel accounting for the log: bytes each way, how and when it ended.

use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::logger::Logger;

/// Who and what a tunnel serves, for its log lines.
pub(crate) struct TunnelLabel<'a> {
    pub logger: &'a Logger,
    pub target: &'a str,
    pub client: Option<&'a str>,
}

/// Bytes moved through a [`Counted`] stream, readable after it is gone.
#[derive(Clone, Default)]
pub(crate) struct Counters {
    sent: Arc<AtomicU64>,
    received: Arc<AtomicU64>,
    /// An I/O call on the upstream stream returned an error.
    upstream_failed: Arc<AtomicBool>,
}

impl Counters {
    pub(crate) fn sent(&self) -> u64 {
        self.sent.load(Ordering::Relaxed)
    }

    pub(crate) fn received(&self) -> u64 {
        self.received.load(Ordering::Relaxed)
    }

    /// Which end broke the tunnel: the upstream stream reported an I/O error,
    /// otherwise the error came from the client's side.
    pub(crate) fn failed_side(&self) -> &'static str {
        if self.upstream_failed.load(Ordering::Relaxed) {
            "upstream"
        } else {
            "client"
        }
    }

    fn note<T>(&self, poll: &Poll<io::Result<T>>) {
        if matches!(poll, Poll::Ready(Err(_))) {
            self.upstream_failed.store(true, Ordering::Relaxed);
        }
    }
}

/// The upstream side of a tunnel, counting bytes written to it (sent) and
/// read from it (received).
pub(crate) struct Counted<S> {
    inner: S,
    counters: Counters,
}

pub(crate) fn counted<S>(inner: S) -> (Counted<S>, Counters) {
    let counters = Counters::default();
    (
        Counted {
            inner,
            counters: counters.clone(),
        },
        counters,
    )
}

impl<S: AsyncRead + Unpin> AsyncRead for Counted<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        let poll = Pin::new(&mut self.inner).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = poll {
            let n = (buf.filled().len() - before) as u64;
            self.counters.received.fetch_add(n, Ordering::Relaxed);
        }
        self.counters.note(&poll);
        poll
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Counted<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let poll = Pin::new(&mut self.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(n)) = poll {
            self.counters.sent.fetch_add(n as u64, Ordering::Relaxed);
        }
        self.counters.note(&poll);
        poll
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let poll = Pin::new(&mut self.inner).poll_flush(cx);
        self.counters.note(&poll);
        poll
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let poll = Pin::new(&mut self.inner).poll_shutdown(cx);
        self.counters.note(&poll);
        poll
    }
}

/// Log a finished tunnel: one `log.tunnels` line for every tunnel (a failed
/// one names the side that broke it, `client` or `upstream`), plus a
/// `log.proxy_failures` warning when the upstream never sent a byte back
/// although the client did send — the signature of a tunnel that "opened
/// but does not work".
pub(crate) fn report(
    label: &TunnelLabel<'_>,
    result: &anyhow::Result<&'static str>,
    counters: &Counters,
    elapsed: Duration,
) {
    let sent = counters.sent();
    let received = counters.received();
    let secs = elapsed.as_secs_f64();
    let ctag = match label.client {
        Some(user) => format!(" [client={user}]"),
        None => " [client=anon]".to_string(),
    };
    let end = match result {
        Ok(end) => (*end).to_string(),
        Err(e) => format!("failed on {} side: {e}", counters.failed_side()),
    };
    label.logger.tunnel(|| {
        format!(
            "Tunnel {} {} after {:.1}s: sent {} B, received {} B{}",
            label.target, end, secs, sent, received, ctag
        )
    });
    if received == 0 && sent > 0 {
        label.logger.proxy_failure(|| {
            format!(
                "Tunnel {}: upstream sent nothing back (sent {} B, {} after {:.1}s){}",
                label.target, sent, end, secs, ctag
            )
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn counts_both_directions() {
        let (a, mut b) = duplex(64);
        let (mut a, counters) = counted(a);
        a.write_all(b"hello").await.unwrap();
        let mut buf = [0u8; 5];
        b.read_exact(&mut buf).await.unwrap();
        b.write_all(b"abc").await.unwrap();
        let mut back = [0u8; 3];
        a.read_exact(&mut back).await.unwrap();
        assert_eq!(counters.sent(), 5);
        assert_eq!(counters.received(), 3);
    }

    /// A stream whose every call fails like a reset connection.
    struct Reset;

    fn reset() -> io::Error {
        io::Error::from(io::ErrorKind::ConnectionReset)
    }

    impl AsyncRead for Reset {
        fn poll_read(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            _: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Ready(Err(reset()))
        }
    }

    impl AsyncWrite for Reset {
        fn poll_write(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            _: &[u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Ready(Err(reset()))
        }
        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Err(reset()))
        }
        fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Err(reset()))
        }
    }

    fn tunnel_lines(result: anyhow::Result<&'static str>, counters: &Counters) -> Vec<String> {
        let (tx, mut rx) = tokio::sync::mpsc::channel(8);
        let logger = Logger::new(
            tx,
            crate::logger::LogConfig {
                tunnels: true,
                ..crate::logger::LogConfig::default()
            },
        );
        let label = TunnelLabel {
            logger: &logger,
            target: "t.example:443",
            client: Some("alice"),
        };
        report(&label, &result, counters, Duration::from_secs(2));
        let mut lines = Vec::new();
        while let Ok(crate::logger::ELog::Log(text) | crate::logger::ELog::Error(text)) =
            rx.try_recv()
        {
            lines.push(text);
        }
        lines
    }

    #[tokio::test]
    async fn every_upstream_call_that_errors_marks_the_upstream_side() {
        for call in 0..4 {
            let (mut up, counters) = counted(Reset);
            assert_eq!(counters.failed_side(), "client", "nothing failed yet");
            let _ = match call {
                0 => up.read(&mut [0u8; 4]).await.map(|_| ()),
                1 => up.write(b"x").await.map(|_| ()),
                2 => up.flush().await,
                _ => up.shutdown().await,
            };
            assert_eq!(counters.failed_side(), "upstream", "call {call}");
        }
    }

    #[tokio::test]
    async fn successful_calls_leave_the_side_unmarked() {
        let (a, mut b) = duplex(64);
        let (mut a, counters) = counted(a);
        a.write_all(b"hi").await.unwrap();
        a.flush().await.unwrap();
        let mut buf = [0u8; 2];
        b.read_exact(&mut buf).await.unwrap();
        assert_eq!(counters.failed_side(), "client");
    }

    #[tokio::test]
    async fn a_failed_tunnel_names_the_upstream_side() {
        let (mut up, counters) = counted(Reset);
        let _ = up.read(&mut [0u8; 4]).await;
        let lines = tunnel_lines(Err(anyhow::anyhow!("reset")), &counters);
        assert_eq!(lines.len(), 1, "{lines:?}");
        assert!(
            lines[0].contains("failed on upstream side: reset after 2.0s"),
            "{}",
            lines[0]
        );
        assert!(lines[0].ends_with("[client=alice]"), "{}", lines[0]);
    }

    #[tokio::test]
    async fn a_failure_the_upstream_never_saw_is_the_clients() {
        let (_up, counters) = counted(Reset);
        let lines = tunnel_lines(Err(anyhow::anyhow!("reset")), &counters);
        assert!(
            lines[0].contains("failed on client side: reset"),
            "{}",
            lines[0]
        );
    }

    #[tokio::test]
    async fn a_clean_end_keeps_its_plain_wording() {
        let (_up, counters) = counted(Reset);
        let lines = tunnel_lines(Ok("closed"), &counters);
        assert!(
            lines[0].contains("t.example:443 closed after 2.0s"),
            "{}",
            lines[0]
        );
    }
}
