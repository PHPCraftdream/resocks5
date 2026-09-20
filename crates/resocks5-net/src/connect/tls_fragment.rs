//! TLS ClientHello fragmentation for per-segment SNI-based DPI evasion.
//!
//! See `docs/ARCHITECTURE.md` for the threat model and limits.

use std::time::Duration;

use tokio::io::AsyncWriteExt;

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
    /// A chunk write did not complete within the idle window. A partial
    /// prefix may already be on the wire — the writer must be closed,
    /// never driven again with the same payload.
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
/// writer as terminal. The final flush is bounded by the same window.
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
    match tokio::time::timeout(idle, writer.flush()).await {
        Ok(status) => {
            status?;
            Ok(SendProgress::Completed)
        }
        Err(_) => Ok(SendProgress::Stalled),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::future::Future;
    use tokio::io::AsyncReadExt;

    fn ch(hs_type: u8) -> Vec<u8> {
        // Synthesises a 6-byte TLS Handshake-record prefix:
        //   0x16 content-type, 0x03 0x01 version, 0x00 0x10 length, hs_type
        vec![0x16, 0x03, 0x01, 0x00, 0x10, hs_type]
    }

    #[test]
    fn detects_minimal_client_hello() {
        assert!(is_tls_client_hello(&ch(0x01)));
    }

    #[test]
    fn detects_client_hello_with_trailing_bytes() {
        let mut data = ch(0x01);
        data.extend_from_slice(&[0xAA; 200]);
        assert!(is_tls_client_hello(&data));
    }

    #[test]
    fn detects_tls_1_0_through_1_3() {
        // The legacy record version byte 1 is 0x03 for every TLS
        // version; byte 2 varies (0x01 = 1.0, 0x02 = 1.1, 0x03 = 1.2,
        // and TLS 1.3 keeps 0x03 for compatibility). Our check ignores
        // byte 2, so all of these match.
        for minor in [0x01, 0x02, 0x03, 0x04] {
            let data = [0x16, 0x03, minor, 0x00, 0x10, 0x01];
            assert!(is_tls_client_hello(&data), "minor={:02x}", minor);
        }
    }

    #[test]
    fn rejects_server_hello() {
        // 0x02 = ServerHello handshake type — sent by servers, never by clients.
        assert!(!is_tls_client_hello(&ch(0x02)));
    }

    #[test]
    fn rejects_alert_record() {
        // 0x15 = TLS Alert content type.
        assert!(!is_tls_client_hello(&[0x15, 0x03, 0x01, 0x00, 0x02, 0x01]));
    }

    #[test]
    fn rejects_application_data() {
        // 0x17 = TLS ApplicationData.
        assert!(!is_tls_client_hello(&[0x17, 0x03, 0x03, 0x00, 0x10, 0x01]));
    }

    #[test]
    fn rejects_change_cipher_spec() {
        // 0x14 = ChangeCipherSpec.
        assert!(!is_tls_client_hello(&[0x14, 0x03, 0x03, 0x00, 0x01, 0x01]));
    }

    #[test]
    fn rejects_wrong_legacy_version_byte() {
        // 0x02 instead of 0x03 in the major-version slot.
        assert!(!is_tls_client_hello(&[0x16, 0x02, 0x01, 0x00, 0x10, 0x01]));
    }

    #[test]
    fn rejects_short_buffer() {
        // Need at least 6 bytes to inspect the handshake-type byte.
        assert!(!is_tls_client_hello(&[]));
        assert!(!is_tls_client_hello(&[0x16]));
        assert!(!is_tls_client_hello(&[0x16, 0x03]));
        assert!(!is_tls_client_hello(&[0x16, 0x03, 0x01, 0x00, 0x10]));
    }

    #[test]
    fn rejects_random_binary_starting_0x16_0x03() {
        // This previously was a false positive of the old 2-byte
        // signature. With the handshake-type check at byte 5 it's a
        // miss unless byte 5 happens to also be 0x01.
        let data = [0x16, 0x03, 0x99, 0x99, 0x99, 0xFF];
        assert!(!is_tls_client_hello(&data));
    }

    #[test]
    fn classify_agrees_with_is_tls_client_hello() {
        let cases: Vec<Vec<u8>> = vec![
            ch(0x01),
            ch(0x02),
            vec![],
            vec![0x16],
            vec![0x16, 0x03],
            vec![0x16, 0x03, 0x01],
            vec![0x16, 0x03, 0x01, 0x00],
            vec![0x16, 0x03, 0x01, 0x00, 0x10],
            vec![0x15, 0x03, 0x01, 0x00, 0x02, 0x01],
            vec![0x17, 0x03, 0x03, 0x00, 0x10, 0x01],
            vec![0x14, 0x03, 0x03, 0x00, 0x01, 0x01],
            vec![0x16, 0x02, 0x01, 0x00, 0x10, 0x01],
            vec![0x16, 0x03, 0x99, 0x99, 0x99, 0xFF],
        ];
        for data in &cases {
            assert_eq!(
                classify_client_hello(data) == ClientHelloMatch::ClientHello,
                is_tls_client_hello(data),
                "mismatch for {data:?}"
            );
        }
    }

    #[test]
    fn classify_reports_indeterminate_for_partial_signatures() {
        // The exact R21 defect: a 5-byte first segment of a ClientHello.
        assert_eq!(classify_client_hello(&[]), ClientHelloMatch::Indeterminate);
        assert_eq!(
            classify_client_hello(&[0x16]),
            ClientHelloMatch::Indeterminate
        );
        assert_eq!(
            classify_client_hello(&[0x16, 0x03]),
            ClientHelloMatch::Indeterminate
        );
        assert_eq!(
            classify_client_hello(&[0x16, 0x03, 0x01, 0x00, 0x10]),
            ClientHelloMatch::Indeterminate
        );
    }

    #[test]
    fn classify_rules_out_non_hello_prefixes_before_six_bytes() {
        assert_eq!(classify_client_hello(&[0x17]), ClientHelloMatch::Other);
        assert_eq!(
            classify_client_hello(&[0x16, 0x02]),
            ClientHelloMatch::Other
        );
        assert_eq!(classify_client_hello(b"GET"), ClientHelloMatch::Other);
    }

    #[tokio::test]
    async fn send_fragmented_splits_into_chunks_when_enabled_and_hello() {
        let cfg = FragmentSpec {
            enabled: true,
            fragment_size: 3,
            delay_ms: 0,
        };
        let mut hello = ch(0x01);
        hello.extend_from_slice(&[0xCD; 10]);
        let original = hello.clone();

        // We pipe the writes into a Vec via Cursor — but we can't tell
        // chunk boundaries from a single contiguous buffer. So we wrap
        // it in a flush-counting writer.
        struct FlushCounter {
            buf: Vec<u8>,
            flushes: usize,
        }
        impl tokio::io::AsyncWrite for FlushCounter {
            fn poll_write(
                mut self: std::pin::Pin<&mut Self>,
                _cx: &mut std::task::Context<'_>,
                data: &[u8],
            ) -> std::task::Poll<std::io::Result<usize>> {
                self.buf.extend_from_slice(data);
                std::task::Poll::Ready(Ok(data.len()))
            }
            fn poll_flush(
                mut self: std::pin::Pin<&mut Self>,
                _cx: &mut std::task::Context<'_>,
            ) -> std::task::Poll<std::io::Result<()>> {
                self.flushes += 1;
                std::task::Poll::Ready(Ok(()))
            }
            fn poll_shutdown(
                self: std::pin::Pin<&mut Self>,
                _cx: &mut std::task::Context<'_>,
            ) -> std::task::Poll<std::io::Result<()>> {
                std::task::Poll::Ready(Ok(()))
            }
        }

        let mut w = FlushCounter {
            buf: Vec::new(),
            flushes: 0,
        };
        send_possibly_fragmented(&mut w, &hello, &cfg, Duration::ZERO)
            .await
            .unwrap();

        // Bytes arrive in order, byte-for-byte identical to the input.
        assert_eq!(w.buf, original);
        // 16 bytes / 3 bytes-per-chunk = 6 chunks (5 full + 1 partial),
        // and each is flushed individually so Nagle can't merge them.
        let expected_chunks = original.len().div_ceil(cfg.fragment_size);
        assert_eq!(w.flushes, expected_chunks);
    }

    #[tokio::test]
    async fn send_fragmented_passes_through_when_disabled() {
        let cfg = FragmentSpec {
            enabled: false,
            fragment_size: 3,
            delay_ms: 0,
        };
        let mut hello = ch(0x01);
        hello.extend_from_slice(&[0xCD; 10]);

        let mut buf: Vec<u8> = Vec::new();
        send_possibly_fragmented(&mut buf, &hello, &cfg, Duration::ZERO)
            .await
            .unwrap();
        assert_eq!(buf, hello);
    }

    #[tokio::test]
    async fn send_fragmented_passes_through_when_not_client_hello() {
        let cfg = FragmentSpec {
            enabled: true,
            fragment_size: 3,
            delay_ms: 0,
        };
        // Application data — fragmentation skipped, single write.
        let data = [0x17, 0x03, 0x03, 0x00, 0x10, 0x99, 0xAA, 0xBB];
        let mut buf: Vec<u8> = Vec::new();
        send_possibly_fragmented(&mut buf, &data, &cfg, Duration::ZERO)
            .await
            .unwrap();
        assert_eq!(buf, data);
    }

    /// R5-03: twenty 1-byte chunks paced 100 ms apart take ~2 s in
    /// total — far past the 150 ms idle bound — yet every individual
    /// write completes instantly. The send must complete: the bound is
    /// per write, and the pacing pause is not inactivity.
    #[tokio::test(start_paused = true)]
    async fn steady_fragment_progress_never_trips_the_per_write_idle() {
        let cfg = FragmentSpec {
            enabled: true,
            fragment_size: 1,
            delay_ms: 100,
        };
        let mut data = ch(0x01);
        data.extend_from_slice(&[0xDD; 14]); // 20 chunks in total

        let (mut writer, mut reader) = tokio::io::duplex(64);
        let start = tokio::time::Instant::now();
        let outcome =
            send_possibly_fragmented(&mut writer, &data, &cfg, Duration::from_millis(150))
                .await
                .unwrap();
        assert_eq!(outcome, SendProgress::Completed);
        assert!(
            start.elapsed() >= Duration::from_millis(100 * data.len() as u64),
            "pacing pauses must actually elapse: {:?}",
            start.elapsed()
        );
        drop(writer);
        let mut got = Vec::new();
        reader.read_to_end(&mut got).await.unwrap();
        assert_eq!(got, data);
    }

    /// A write that genuinely stops (peer never drains the 1-byte
    /// duplex) must end with `Stalled` — not an error, not a hang —
    /// after roughly the idle window.
    #[tokio::test(start_paused = true)]
    async fn stalled_fragment_write_reports_stalled() {
        let cfg = FragmentSpec {
            enabled: true,
            fragment_size: 2,
            delay_ms: 0,
        };
        let hello = ch(0x01);
        // Keep the read half alive: dropping it would surface as a
        // broken-pipe error instead of a stalled write.
        let (_keep_alive, mut writer) = tokio::io::duplex(1);

        let start = tokio::time::Instant::now();
        let outcome =
            send_possibly_fragmented(&mut writer, &hello, &cfg, Duration::from_millis(100))
                .await
                .unwrap();
        assert_eq!(outcome, SendProgress::Stalled);
        assert!(
            start.elapsed() >= Duration::from_millis(100),
            "stall must be bounded, not instant: {:?}",
            start.elapsed()
        );
    }

    /// The pass-through single write (not a ClientHello) is bounded by
    /// the same idle window as fragmented chunks.
    #[tokio::test(start_paused = true)]
    async fn stalled_passthrough_write_is_also_bounded() {
        let cfg = FragmentSpec {
            enabled: true,
            fragment_size: 3,
            delay_ms: 0,
        };
        let data = b"GET /index HTTP/1.1"; // not a ClientHello
        let (_keep_alive, mut writer) = tokio::io::duplex(1);

        let outcome = send_possibly_fragmented(&mut writer, data, &cfg, Duration::from_millis(100))
            .await
            .unwrap();
        assert_eq!(outcome, SendProgress::Stalled);
    }

    /// A mock writer under backpressure: accepts at most `per_poll`
    /// bytes per successful poll_write, then goes silent for `interval`
    /// of (virtual) time before becoming writable again.
    /// `stalling_after` makes it go silent forever once that many bytes
    /// have been accepted in total.
    struct DripWriter {
        /// Every byte the writer has accepted so far.
        accepted: Vec<u8>,
        per_poll: usize,
        interval: Duration,
        // Created with Duration::ZERO so the very first write is
        // immediate; reset to `interval` after every accepted write.
        cooldown: std::pin::Pin<Box<tokio::time::Sleep>>,
        stall_after: Option<usize>,
    }

    impl DripWriter {
        fn new(per_poll: usize, interval: Duration) -> Self {
            Self {
                accepted: Vec::new(),
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

    // All fields are Unpin, so get_mut() is enough to drive the writer.
    impl tokio::io::AsyncWrite for DripWriter {
        fn poll_write(
            self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &[u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            let this = self.get_mut();
            if let Some(quota) = this.stall_after {
                if this.accepted.len() >= quota {
                    // Quota reached: silent forever from here on.
                    return std::task::Poll::Pending;
                }
            }
            if this.cooldown.as_mut().poll(cx).is_pending() {
                // Still inside the silent window after the last drip.
                return std::task::Poll::Pending;
            }
            let n = buf.len().min(this.per_poll);
            this.accepted.extend_from_slice(&buf[..n]);
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

    /// R6-02: steady partial progress under backpressure must NOT trip
    /// idle. The writer accepts 8 bytes per poll_write and then stays
    /// silent for 200 ms, so 64 bytes take 8 drips: the first lands
    /// immediately and each of the other 7 after 200 ms of silence —
    /// 1400 ms in total. That outlasts the 1 s idle window, which is
    /// exactly what the old single write_all+flush timeout got wrong;
    /// fresh per-attempt windows keep the send alive.
    #[tokio::test(start_paused = true)]
    async fn steady_drip_progress_under_backpressure_never_trips_idle() {
        let data = vec![0xAA; 64];
        let mut w = DripWriter::new(8, Duration::from_millis(200));

        let start = tokio::time::Instant::now();
        let outcome = write_progress_bounded(&mut w, &data, Duration::from_secs(1))
            .await
            .unwrap();
        assert_eq!(outcome, SendProgress::Completed);
        // 8 drips of 8 bytes each.
        assert_eq!(w.accepted, data);
        assert!(
            start.elapsed() >= Duration::from_millis(1400),
            "7 of the 8 drips must pay their 200 ms silence: {:?}",
            start.elapsed()
        );
    }

    /// R6-02: a write that stops making ANY progress still trips idle.
    /// The first attempt lands 8 bytes immediately and the writer then
    /// never accepts another byte, so the send must end as `Stalled`
    /// after one full 1 s idle window of total silence past the last
    /// accepted byte.
    #[tokio::test(start_paused = true)]
    async fn silent_drip_writer_still_trips_idle() {
        let data = vec![0xAA; 64];
        let mut w = DripWriter::new(8, Duration::from_millis(200)).stalling_after(8);

        let start = tokio::time::Instant::now();
        let outcome = write_progress_bounded(&mut w, &data, Duration::from_secs(1))
            .await
            .unwrap();
        assert_eq!(outcome, SendProgress::Stalled);
        assert_eq!(w.accepted.len(), 8);
        assert!(
            start.elapsed() >= Duration::from_secs(1),
            "the stall must pay the full idle window: {:?}",
            start.elapsed()
        );
    }

    /// A successful poll_write of zero bytes is WriteZero, matching
    /// write_all's contract.
    #[tokio::test]
    async fn zero_byte_poll_write_is_write_zero_error() {
        struct ZeroWriter;
        impl tokio::io::AsyncWrite for ZeroWriter {
            fn poll_write(
                self: std::pin::Pin<&mut Self>,
                _cx: &mut std::task::Context<'_>,
                _buf: &[u8],
            ) -> std::task::Poll<std::io::Result<usize>> {
                std::task::Poll::Ready(Ok(0))
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

        let mut w = ZeroWriter;
        let err = write_progress_bounded(&mut w, b"payload", Duration::from_secs(1))
            .await
            .unwrap_err();
        let io_err = err.downcast_ref::<std::io::Error>().expect("io error");
        assert_eq!(io_err.kind(), std::io::ErrorKind::WriteZero);
    }
}
