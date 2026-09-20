//! Confirmed-write-progress plumbing shared by the TLS and pool layers.
//!
//! Generic `AsyncWrite` instrumentation with zero TLS-specific logic,
//! kept in a dependency-free top-level module so `connect` and `pool`
//! can both depend on it without forming a module cycle. Three pieces:
//!
//! - [`FlushProgress`] — the monotonic counter sink progress is
//!   reported into;
//! - `CONFIRMED_WRITE_PROGRESS` — the task-local carrying the sink for
//!   the current task, installed with `confirmed_scope`;
//! - [`ProgressReportingWriter`] — an `AsyncWrite` wrapper that reports
//!   every accepted byte into the enclosing scope.

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Confirmed write progress reported by a writer stack below the layer
/// that buffers.
///
/// This is an instrumentation sink, not a synchronization primitive:
/// only a successful `poll_write` of `n > 0` bytes by a
/// [`ProgressReportingWriter`] advances the counter. A bare task wake or
/// an unresolved `Pending` never moves it, so "the counter advanced"
/// always means "real bytes were handed to the transport underneath".
/// `total()` is monotonic.
#[derive(Debug, Clone, Default)]
pub struct FlushProgress {
    counter: Arc<AtomicU64>,
}

impl FlushProgress {
    /// Creates an empty sink — zero bytes confirmed so far.
    pub fn new() -> Self {
        Self {
            counter: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Total number of bytes confirmed written underneath the buffering
    /// layer so far.
    pub fn total(&self) -> u64 {
        self.counter.load(Ordering::Relaxed)
    }

    fn record(&self, n: usize) {
        if n == 0 {
            return;
        }
        self.counter.fetch_add(n as u64, Ordering::Relaxed);
    }
}

tokio::task_local! {
    pub(crate) static CONFIRMED_WRITE_PROGRESS: FlushProgress;
}

/// Run `f` with `progress` installed as the confirmed-write sink for
/// anything polled underneath (i.e. any [`ProgressReportingWriter`]).
pub(crate) fn confirmed_scope<F: Future>(
    progress: FlushProgress,
    f: F,
) -> impl Future<Output = F::Output> {
    CONFIRMED_WRITE_PROGRESS.scope(progress, f)
}

/// `AsyncWrite` wrapper that reports every successful write of `n > 0`
/// bytes into the enclosing `CONFIRMED_WRITE_PROGRESS` scope, if any.
///
/// Meant to sit BELOW a buffering/TLS layer, around the raw transport:
/// wrap the socket, wrap the buffering layer on top. Outside a
/// `confirmed_scope` the wrapper is a pure pass-through (reporting is
/// silently skipped).
pub struct ProgressReportingWriter<W> {
    inner: W,
}

impl<W> ProgressReportingWriter<W> {
    /// Wraps `inner` so its writes get reported into the enclosing
    /// confirmed-progress scope.
    pub fn new(inner: W) -> Self {
        Self { inner }
    }

    /// Unwraps back to the inner writer.
    pub fn into_inner(self) -> W {
        self.inner
    }

    /// Borrows the inner writer — for `&self`-only reach-through such as
    /// socket options on the transport underneath a TLS layer.
    pub fn get_ref(&self) -> &W {
        &self.inner
    }
}

impl<W: AsyncWrite + Unpin> AsyncWrite for ProgressReportingWriter<W> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let result = Pin::new(&mut self.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(n)) = &result {
            let _ = CONFIRMED_WRITE_PROGRESS.try_with(|p| p.record(*n));
        }
        result
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let result = Pin::new(&mut self.inner).poll_write_vectored(cx, bufs);
        if let Poll::Ready(Ok(n)) = &result {
            let _ = CONFIRMED_WRITE_PROGRESS.try_with(|p| p.record(*n));
        }
        result
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// Reads pass straight through: the wrapper instruments writes only.
impl<W: AsyncRead + Unpin> AsyncRead for ProgressReportingWriter<W> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}
