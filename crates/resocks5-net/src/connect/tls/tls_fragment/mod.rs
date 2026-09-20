//! TLS ClientHello fragmentation for per-segment SNI-based DPI evasion.
//!
//! See `docs/ARCHITECTURE.md` for the threat model and limits.

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};

/// Parameters controlling TLS ClientHello fragmentation.
///
/// This is the library-level counterpart of the application's
/// `TlsFragmentConfig`: the binary converts its parsed config into a
/// `FragmentSpec` at the call site, keeping this crate free of any
/// config-file format concerns.
#[derive(Debug, Clone, Copy)]
pub struct FragmentSpec {
    /// Master switch. When false all traffic is forwarded as-is.
    pub enabled: bool,
    /// Bytes per fragment. Splitting at ≤ 40 bytes typically puts the
    /// SNI field (offset ~45–80 into the record) in a later fragment.
    pub fragment_size: usize,
    /// Milliseconds to wait between consecutive fragments. Zero sends
    /// all fragments back-to-back.
    pub delay_ms: u64,
}

/// Outcome of matching a possibly-truncated byte prefix against the
/// ClientHello signature.
///
/// A single TCP read may deliver fewer than the 6 bytes the private
/// ClientHello matcher needs, so deciding from one read misclassifies
/// split ClientHellos as ordinary traffic. The third state lets a caller
/// accumulate across reads until the signature is confirmed or ruled
/// out (see [`classify_client_hello`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientHelloMatch {
    /// `data` begins with a TLS ClientHello record.
    ClientHello,
    /// `data` is definitively not a ClientHello: a later read cannot
    /// change bytes already inspected.
    Other,
    /// Fewer than 6 bytes, all consistent with a ClientHello prefix —
    /// more bytes are needed to decide.
    Indeterminate,
}

/// Outcome of a send whose individual writes are bounded by an idle
/// window.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SendProgress {
    /// Every byte of the payload was written and flushed.
    Completed,
    /// A chunk write did not complete within the idle window, or the
    /// final flush stopped making confirmed progress for one idle
    /// window. A partial prefix may already be on the wire — the writer
    /// must be closed, never driven again with the same payload.
    Stalled,
}

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

/// Match `data` against the ClientHello signature
/// (`0x16 0x03 .. .. .. 0x01`), tolerating truncation. See the private
/// signature matcher below for the signature rationale and
/// [`ClientHelloMatch`] for why the third state exists.
pub fn classify_client_hello(data: &[u8]) -> ClientHelloMatch {
    if data.is_empty() {
        return ClientHelloMatch::Indeterminate;
    }
    if data[0] != 0x16 {
        return ClientHelloMatch::Other;
    }
    if data.len() < 2 {
        return ClientHelloMatch::Indeterminate;
    }
    if data[1] != 0x03 {
        return ClientHelloMatch::Other;
    }
    if data.len() < 6 {
        return ClientHelloMatch::Indeterminate;
    }
    if data[5] == 0x01 {
        ClientHelloMatch::ClientHello
    } else {
        ClientHelloMatch::Other
    }
}

/// Returns true if `data` begins with a TLS ClientHello record.
/// Signature: 6 bytes — 5-byte record header + 1-byte handshake type:
///
///   byte 0      0x16            content type = Handshake
///   byte 1      0x03            legacy record major version
///   bytes 2..5  any             legacy minor version + record length
///   byte 5      0x01            handshake type = ClientHello
///
/// Tighter than just `0x16 0x03` (false positive ~1/2^16): a random
/// binary stream won't start with these exact bytes by accident in any
/// practical traffic.
fn is_tls_client_hello(data: &[u8]) -> bool {
    matches!(classify_client_hello(data), ClientHelloMatch::ClientHello)
}

/// Write `data` to `writer`.
///
/// If `cfg.enabled` and `data` looks like a TLS ClientHello, the slice
/// is split into chunks of at most `cfg.fragment_size` bytes. Each
/// chunk is written and flushed individually so Nagle's algorithm
/// (already disabled by the caller via `TCP_NODELAY`) cannot merge them
/// back into a single TCP segment. An optional `cfg.delay_ms` pause is
/// inserted between fragments to defeat stateful DPI reassembly windows.
///
/// If `cfg.enabled` is false, or the data is not a TLS ClientHello, the
/// whole slice is written in one call — no overhead on the hot path.
///
/// `idle` measures write inactivity, not write duration: each
/// individual write attempt gets a fresh idle window, and a window
/// that expires without a single accepted byte ends the send with
/// [`SendProgress::Stalled`]. A backpressured writer that keeps
/// accepting bytes — however slowly — never trips the bound, so a
/// paced send stays alive no matter how long the whole send takes.
/// The configured inter-fragment pause (`FragmentSpec::delay_ms`) is
/// deliberate pacing: it elapses between chunks, outside the
/// per-write loop, and never counts as inactivity. `Duration::ZERO`
/// disables the bound entirely.
///
/// cancel-safe: NO — cancellation (or a [`SendProgress::Stalled`]
/// outcome) can leave a prefix of `data` on the wire; close the writer,
/// never re-send from the start of `data`.
pub async fn send_possibly_fragmented<W>(
    writer: &mut W,
    data: &[u8],
    cfg: &FragmentSpec,
    idle: Duration,
) -> anyhow::Result<SendProgress>
where
    W: AsyncWriteExt + Unpin,
{
    if !cfg.enabled || !is_tls_client_hello(data) {
        return write_progress_bounded(writer, data, idle).await;
    }
    let chunk_size = cfg.fragment_size.max(1);
    for chunk in data.chunks(chunk_size) {
        if write_progress_bounded(writer, chunk, idle).await? == SendProgress::Stalled {
            return Ok(SendProgress::Stalled);
        }
        if cfg.delay_ms > 0 {
            tokio::time::sleep(Duration::from_millis(cfg.delay_ms)).await;
        }
    }
    Ok(SendProgress::Completed)
}

/// Write `buf` in full and flush it, bounded by `idle`.
///
/// `idle` measures write inactivity, not write duration: the buffer is
/// driven one `poll_write` at a time and every individual write attempt
/// gets a fresh idle window. A writer that keeps accepting bytes —
/// however slowly — therefore never trips the bound, while a writer
/// that stops accepting bytes entirely is reported as
/// [`SendProgress::Stalled`] after one idle window of total silence. A
/// successful write of zero bytes is an error (`WriteZero`), matching
/// `write_all`'s own contract.
///
/// When the bound fires, the write is abandoned mid-flight: whatever
/// prefix was accepted stays on the wire and the caller must treat the
/// writer as terminal. The final flush is bounded by the same idle
/// window, renewed whenever the writer stack underneath a
/// [`ProgressReportingWriter`] confirms additional bytes reached the
/// transport — a buffered/TLS writer that keeps draining underneath is
/// not `Stalled` merely for taking longer than one window in total.
async fn write_progress_bounded<W>(
    writer: &mut W,
    buf: &[u8],
    idle: Duration,
) -> anyhow::Result<SendProgress>
where
    W: AsyncWriteExt + Unpin,
{
    if idle.is_zero() {
        writer.write_all(buf).await?;
        writer.flush().await?;
        return Ok(SendProgress::Completed);
    }
    let progress = FlushProgress::new();
    confirmed_scope(progress.clone(), async {
        let mut written = 0;
        while written < buf.len() {
            let n = match tokio::time::timeout(idle, writer.write(&buf[written..])).await {
                Ok(status) => status?,
                Err(_) => return Ok(SendProgress::Stalled),
            };
            if n == 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::WriteZero,
                    "failed to write whole buffer",
                )
                .into());
            }
            written += n;
        }
        flush_bounded_by_confirmed_progress(writer, idle, &progress).await
    })
    .await
}

/// Bound `writer.flush()` by idle windows renewed only by confirmed
/// write progress.
///
/// The flush future is pinned once and NEVER restarted: each
/// `timeout(idle, ..)` wraps it by reference, so a window expiry drops
/// only the timeout wrapper and the in-flight flush state underneath
/// survives. If a window expires but [`FlushProgress::total`] advanced
/// during it — real bytes reached the transport below a buffering/TLS
/// layer while the outer flush was still unresolved — the window is
/// renewed, so a slowly-draining writer is never disconnected for
/// taking longer than one idle window in total. If a window expires
/// with no confirmed progress, the flush is abandoned with
/// [`SendProgress::Stalled`]. A bare wake or a plain `Pending` never
/// renews the window: only reported bytes do. A writer stack without a
/// [`ProgressReportingWriter`] underneath reports nothing and therefore
/// keeps the old single-idle-window flush behavior.
async fn flush_bounded_by_confirmed_progress<W: AsyncWriteExt + Unpin>(
    writer: &mut W,
    idle: Duration,
    progress: &FlushProgress,
) -> anyhow::Result<SendProgress> {
    let mut flush = std::pin::pin!(writer.flush());
    loop {
        let confirmed_before = progress.total();
        match tokio::time::timeout(idle, &mut flush).await {
            Ok(status) => {
                status?;
                return Ok(SendProgress::Completed);
            }
            Err(_) => {
                if progress.total() > confirmed_before {
                    continue;
                }
                return Ok(SendProgress::Stalled);
            }
        }
    }
}

#[cfg(test)]
mod tests;
