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
//!
//! # Custom writer stacks
//!
//! A third-party wrapper (its own TLS layer, compression, buffering)
//! participates with the public API alone, no crate-private items:
//! inside its `poll_write`/`poll_flush`, once bytes are confirmed to
//! have left the wrapper toward the real transport, call
//! [`FlushProgress::report_confirmed`] (or `try_with`-style
//! [`FlushProgress::current`] first if it wants to check whether any
//! scope is active at all). The bounded helpers
//! (`send_possibly_fragmented`, the bounded flush in the TLS fragment
//! path, `tunnel_with_timeouts`) install the ambient scope themselves,
//! so a wrapper nested under them is picked up automatically. See the
//! example on [`FlushProgress`].

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
/// only bytes CONFIRMED to have left a writer stack toward the real
/// transport advance the counter. A bare task wake or an unresolved
/// `Pending` never moves it, so "the counter advanced" always means
/// "real bytes were handed to the transport underneath". `total()` is
/// monotonic.
///
/// # Reporting from a custom wrapper
///
/// A writer stack that buffers below its own layer reports progress
/// through the ambient scope — the one the bounded helpers install —
/// using [`FlushProgress::report_confirmed`]:
///
/// ```
/// use std::pin::Pin;
/// use std::task::{Context, Poll};
/// use resocks5_net::progress::FlushProgress;
///
/// /// A buffering look-alike: accepts whole writes into a queue and
/// /// drains it to the inner transport on flush. Every piece the
/// /// inner transport ACCEPTS is confirmed progress and is reported.
/// struct MyBuffer<W> {
///     pending: std::collections::VecDeque<u8>,
///     inner: W,
/// }
///
/// impl<W: tokio::io::AsyncWrite + Unpin> tokio::io::AsyncWrite
///     for MyBuffer<W>
/// {
///     fn poll_write(
///         mut self: Pin<&mut Self>,
///         _cx: &mut Context<'_>,
///         buf: &[u8],
///     ) -> Poll<std::io::Result<usize>> {
///         self.pending.extend(buf.iter().copied());
///         Poll::Ready(Ok(buf.len()))
///     }
///
///     fn poll_flush(
///         mut self: Pin<&mut Self>,
///         cx: &mut Context<'_>,
///     ) -> Poll<std::io::Result<()>> {
///         // Drain as much as the transport accepts right now ...
///         while !self.pending.is_empty() {
///             let MyBuffer { pending, inner } = &mut *self;
///             let contiguous = pending.make_contiguous();
///             let written = match Pin::new(inner).poll_write(cx, contiguous) {
///                 Poll::Ready(Ok(n)) => n,
///                 Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
///                 Poll::Pending => return Poll::Pending,
///             };
///             self.pending.drain(..written);
///             // ... and report ONLY those accepted bytes. Bare
///             // wakeups and Pending are NOT progress — reporting
///             // them would falsely renew the bounded helpers'
///             // idle windows and defeat the stall detection.
///             FlushProgress::report_confirmed(written as u64);
///         }
///         Pin::new(&mut self.inner).poll_flush(cx)
///     }
///
///     fn poll_shutdown(
///         mut self: Pin<&mut Self>,
///         cx: &mut Context<'_>,
///     ) -> Poll<std::io::Result<()>> {
///         self.poll_flush(cx)
///     }
/// }
///
/// // Outside any bounded helper's scope, reporting is a silent no-op:
/// FlushProgress::report_confirmed(64);
/// ```
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

    /// Reports `n` bytes confirmed to have reached the real transport
    /// underneath the reporting layer.
    ///
    /// Contract: call this ONLY for bytes that verifiably left the
    /// reporting wrapper toward the transport (the transport accepted
    /// them via `poll_write`). A bare task wake, an unresolved
    /// `Pending`, or a zero-byte result is NOT progress and must not
    /// be reported — [`record`](Self::record)(0) is a no-op, and any
    /// other inflation falsely renews the bounded helpers' idle
    /// windows, defeating their stall detection.
    pub fn record(&self, n: u64) {
        if n == 0 {
            return;
        }
        self.counter.fetch_add(n, Ordering::Relaxed);
        #[cfg(feature = "test-instrumentation")]
        CONFIRMED_WRITE_PROGRESS_TOTAL.fetch_add(n, Ordering::Relaxed);
    }

    /// The ambient confirmed-progress sink of the current task, if the
    /// code being polled runs underneath one of the crate's bounded
    /// helpers (`send_possibly_fragmented`, the bounded flush in the
    /// TLS fragment path, `tunnel_with_timeouts`).
    ///
    /// Custom writer wrappers use this (or the shortcut
    /// [`FlushProgress::report_confirmed`]) to report confirmed bytes
    /// without the sink being threaded through their constructors.
    /// Returns `None` outside any scope; reporting into `None` is a
    /// silent no-op either way.
    pub fn current() -> Option<Self> {
        CONFIRMED_WRITE_PROGRESS.try_with(|p| p.clone()).ok()
    }

    /// Reports `n` confirmed bytes into the ambient scope of the
    /// current task, if any; a silent no-op outside one.
    ///
    /// Same contract as [`FlushProgress::record`]: only bytes the
    /// transport underneath actually accepted; zero is a no-op.
    pub fn report_confirmed(n: u64) {
        let _ = CONFIRMED_WRITE_PROGRESS.try_with(|p| p.record(n));
    }
}

/// Test-only process-global total of every byte ever reported into any
/// [`FlushProgress`] (enabled by the crate's `test-instrumentation`
/// feature, which the `resocks5` dev-dependencies turn on).
///
/// Cumulative, monotonic, and shared by every instance in the process:
/// compare deltas, never absolutes, and treat a delta as a LOWER bound
/// on a single chain's confirmed traffic — concurrently running tests
/// can only inflate it.
#[cfg(feature = "test-instrumentation")]
pub static CONFIRMED_WRITE_PROGRESS_TOTAL: AtomicU64 = AtomicU64::new(0);

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
/// bytes into the enclosing `CONFIRMED_WRITE_PROGRESS` scope, if any —
/// via the public [`FlushProgress::report_confirmed`] API.
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
            FlushProgress::report_confirmed(*n as u64);
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
            FlushProgress::report_confirmed(*n as u64);
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
