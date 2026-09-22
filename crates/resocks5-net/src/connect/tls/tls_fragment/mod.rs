//! TLS ClientHello fragmentation for per-segment SNI-based DPI evasion.
//!
//! See `docs/ARCHITECTURE.md` for the threat model and limits.

use std::time::Duration;

use tokio::io::AsyncWriteExt;

use crate::progress::{confirmed_scope, FlushProgress};

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
    /// A chunk write or the final flush stopped making confirmed
    /// progress for one idle window. A partial prefix may already be on
    /// the wire — the writer must be closed, never driven again with
    /// the same payload.
    Stalled,
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
/// individual write attempt is bounded by idle windows, and a window
/// that expires without the writer stack accepting new bytes or
/// confirming progress underneath ends the send with
/// [`SendProgress::Stalled`]. A backpressured writer that keeps
/// accepting bytes — or keeps draining previously accepted bytes to
/// the transport below a
/// [`ProgressReportingWriter`](crate::progress::ProgressReportingWriter)
/// — however slowly, never trips the bound, so a paced send stays
/// alive no matter how long the whole send takes.
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
/// driven one `poll_write` attempt at a time, each attempt bounded by
/// idle windows. A writer that keeps accepting bytes — however slowly —
/// therefore never trips the bound, and neither does a writer stack
/// that keeps draining previously accepted bytes to the transport
/// below a
/// [`ProgressReportingWriter`](crate::progress::ProgressReportingWriter)
/// while still refusing the new bytes this call offers; a writer that
/// does neither for one full idle window is reported as
/// [`SendProgress::Stalled`]. A successful write of zero bytes is an
/// error (`WriteZero`), matching `write_all`'s own contract.
///
/// When the bound fires, the write is abandoned mid-flight: whatever
/// prefix was accepted stays on the wire and the caller must treat the
/// writer as terminal. The final flush is bounded by the same idle
/// window, renewed whenever the writer stack underneath a
/// [`ProgressReportingWriter`](crate::progress::ProgressReportingWriter)
/// confirms additional bytes reached the
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
            let attempt =
                write_bounded_by_confirmed_progress(writer, &buf[written..], idle, &progress)
                    .await?;
            let n = match attempt {
                Some(n) => n,
                None => return Ok(SendProgress::Stalled),
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

/// Bound one `writer.write(buf)` attempt by idle windows renewed only
/// by confirmed write progress, never restarting the attempt.
///
/// The write future is pinned once and polled across window renewals —
/// NEVER recreated: re-offering `buf` from scratch after a window
/// expiry could duplicate bytes the writer stack already consumed from
/// the first attempt. Each `timeout(idle, ..)` wraps the pinned future
/// by reference, so an expiry drops only the timeout wrapper and the
/// in-flight write state underneath survives. If a window expires but
/// [`FlushProgress::total`](crate::progress::FlushProgress::total) advanced
/// during it — a buffering/TLS layer moved previously accepted bytes to
/// the transport while still refusing the new plaintext this attempt
/// offers (tokio-rustls' `(0, would_block)` shape) — the window is
/// renewed and the same future keeps being polled. If a window expires
/// with no confirmed progress, the attempt is abandoned and `None` is
/// returned. A bare wake or a plain `Pending` never renews the window:
/// only reported bytes do. A writer stack without a
/// [`ProgressReportingWriter`](crate::progress::ProgressReportingWriter)
/// underneath reports nothing and therefore keeps the old
/// single-idle-window write behavior.
///
/// cancel-safe: NO — dropping this mid-attempt abandons a partially
/// accepted write exactly like the unbounded form; the caller treats
/// the writer as terminal.
async fn write_bounded_by_confirmed_progress<W: AsyncWriteExt + Unpin>(
    writer: &mut W,
    buf: &[u8],
    idle: Duration,
    progress: &FlushProgress,
) -> anyhow::Result<Option<usize>> {
    let mut write = std::pin::pin!(writer.write(buf));
    loop {
        let confirmed_before = progress.total();
        match tokio::time::timeout(idle, &mut write).await {
            Ok(status) => {
                let n = status?;
                return Ok(Some(n));
            }
            Err(_) => {
                if progress.total() > confirmed_before {
                    continue;
                }
                return Ok(None);
            }
        }
    }
}

/// Bound `writer.flush()` by idle windows renewed only by confirmed
/// write progress.
///
/// The flush future is pinned once and NEVER restarted: each
/// `timeout(idle, ..)` wraps it by reference, so a window expiry drops
/// only the timeout wrapper and the in-flight flush state underneath
/// survives. If a window expires but
/// [`FlushProgress::total`](crate::progress::FlushProgress::total) advanced
/// during it — real bytes reached the transport below a buffering/TLS
/// layer while the outer flush was still unresolved — the window is
/// renewed, so a slowly-draining writer is never disconnected for
/// taking longer than one idle window in total. If a window expires
/// with no confirmed progress, the flush is abandoned with
/// [`SendProgress::Stalled`]. A bare wake or a plain `Pending` never
/// renews the window: only reported bytes do. A writer stack without a
/// [`ProgressReportingWriter`](crate::progress::ProgressReportingWriter)
/// underneath reports nothing and therefore
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
