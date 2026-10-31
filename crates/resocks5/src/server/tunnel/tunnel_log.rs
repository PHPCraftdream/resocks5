//! Per-tunnel accounting for the log: bytes each way, how and when it ended.

use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
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
}

impl Counters {
    pub(crate) fn sent(&self) -> u64 {
        self.sent.load(Ordering::Relaxed)
    }

    pub(crate) fn received(&self) -> u64 {
        self.received.load(Ordering::Relaxed)
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
        poll
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// Log a finished tunnel: one `log.tunnels` line for every tunnel, plus a
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
        Err(e) => format!("failed: {e}"),
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
}
