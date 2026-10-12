use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll};

use crate::progress::FlushProgress;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::time::Instant;

pub(super) struct Bytes {
    pub(super) a_to_b: AtomicU64,
    pub(super) b_to_a: AtomicU64,
}

pub(super) struct Activity {
    pub(super) epoch: Instant,
    pub(super) nanos: AtomicU64,
}

impl Activity {
    fn record(&self) {
        let nanos = u64::try_from(self.epoch.elapsed().as_nanos()).unwrap_or(u64::MAX);
        // Both wrappers are polled by one task; no other state is published.
        self.nanos.store(nanos, Ordering::Relaxed);
    }
}

pub(super) struct Tracked<'a, S> {
    pub(super) inner: S,
    pub(super) activity: &'a Activity,
    pub(super) confirmed: &'a FlushProgress,
    /// Bytes this (destination) side has confirmed written.
    pub(super) forwarded: &'a AtomicU64,
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
        if let Poll::Ready(Ok(n)) = &result {
            if *n > 0 {
                self.forwarded.fetch_add(*n as u64, Ordering::Relaxed);
            }
        }
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
