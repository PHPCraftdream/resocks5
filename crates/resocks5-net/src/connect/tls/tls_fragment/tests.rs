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
    let outcome = send_possibly_fragmented(&mut writer, &data, &cfg, Duration::from_millis(150))
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
    let outcome = send_possibly_fragmented(&mut writer, &hello, &cfg, Duration::from_millis(100))
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
/// fresh per-attempt windows keep the send alive. R7-05: the 64
/// payload bytes are position-distinct so the accepted-sequence
/// check below cannot be fooled by a repeated prefix.
#[tokio::test(start_paused = true)]
async fn steady_drip_progress_under_backpressure_never_trips_idle() {
    // R7-05: position-distinct bytes — a uniform payload would let
    // a repeated prefix (or any reordering) reconstruct the very
    // same `accepted` sequence and slip past the content check
    // below with correct total count and timing.
    let data: Vec<u8> = (0u8..64).collect();
    let mut w = DripWriter::new(8, Duration::from_millis(200));

    let start = tokio::time::Instant::now();
    let outcome = write_progress_bounded(&mut w, &data, Duration::from_secs(1))
        .await
        .unwrap();
    assert_eq!(outcome, SendProgress::Completed);
    // 8 drips of 8 bytes each — and every drip must carry the NEXT
    // slice of the payload: a repeated prefix, a reordering, or a
    // dropped byte is corruption even when the total length, the
    // drip count, and the timing all look correct.
    assert_eq!(
        w.accepted, data,
        "accepted bytes must reconstruct the payload exactly"
    );
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
/// accepted byte. R7-05: what stopped must also be exactly the
/// first 8 bytes of a position-distinct payload — a mid-chunk stop
/// leaves a prefix of the payload on the wire, never other bytes.
#[tokio::test(start_paused = true)]
async fn silent_drip_writer_still_trips_idle() {
    let data: Vec<u8> = (0u8..64).collect();
    let mut w = DripWriter::new(8, Duration::from_millis(200)).stalling_after(8);

    let start = tokio::time::Instant::now();
    let outcome = write_progress_bounded(&mut w, &data, Duration::from_secs(1))
        .await
        .unwrap();
    assert_eq!(outcome, SendProgress::Stalled);
    assert_eq!(w.accepted.len(), 8);
    assert_eq!(
        w.accepted,
        &data[..8],
        "the stalled send must have accepted exactly the first 8 payload bytes"
    );
    assert!(
        start.elapsed() >= Duration::from_secs(1),
        "the stall must pay the full idle window: {:?}",
        start.elapsed()
    );
}

/// The raw transport below everything else: DripWriter-style, it
/// accepts at most `per_poll` bytes per successful poll_write and
/// then goes silent for `interval` of (virtual) time before becoming
/// writable again. Unlike DripWriter it never stalls permanently;
/// `poll_flush`/`poll_shutdown` are instantly ready.
struct DripTransport {
    /// Every byte the transport has accepted so far.
    accepted: Vec<u8>,
    per_poll: usize,
    interval: Duration,
    // Created with Duration::ZERO so the very first write is
    // immediate; reset to `interval` after every accepted write.
    cooldown: std::pin::Pin<Box<tokio::time::Sleep>>,
}

impl DripTransport {
    fn new(per_poll: usize, interval: Duration) -> Self {
        Self {
            accepted: Vec::new(),
            per_poll,
            interval,
            cooldown: Box::pin(tokio::time::sleep(Duration::ZERO)),
        }
    }
}

// All fields are Unpin, so get_mut() is enough to drive the writer.
impl tokio::io::AsyncWrite for DripTransport {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        let this = self.get_mut();
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

/// The TLS/buffering layer look-alike: `poll_write` accepts the
/// whole payload into an internal queue without touching the inner
/// writer (mimicking tokio-rustls buffering plaintext), and only
/// `poll_flush` drains that queue to the inner writer `piece` bytes
/// per drip wake — so the outer flush stays Pending for the whole
/// drain while real progress happens underneath.
struct BufferedAcceptor<W> {
    piece: usize,
    pending: std::collections::VecDeque<u8>,
    inner: W,
}

impl<W> BufferedAcceptor<W> {
    fn new(piece: usize, inner: W) -> Self {
        Self {
            piece,
            pending: std::collections::VecDeque::new(),
            inner,
        }
    }

    fn into_inner(self) -> W {
        self.inner
    }

    // Shared drain step: pushes at most one `piece` of `pending`
    // into the inner writer per poll; once the queue runs dry,
    // delegates the flush inward. All fields are Unpin, so get_mut()
    // is enough.
    fn poll_flush_step(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>>
    where
        W: tokio::io::AsyncWrite + Unpin,
    {
        loop {
            if self.pending.is_empty() {
                return std::pin::Pin::new(&mut self.inner).poll_flush(cx);
            }
            // Peek at most `piece` bytes off the front of the queue
            // (layout-normalised into one contiguous slice); only on
            // a successful poll_write are they drained off the front.
            let contiguous = self.pending.make_contiguous();
            let take = self.piece.min(contiguous.len());
            let written =
                match std::pin::Pin::new(&mut self.inner).poll_write(cx, &contiguous[..take]) {
                    std::task::Poll::Ready(Ok(n)) => n,
                    std::task::Poll::Ready(Err(e)) => return std::task::Poll::Ready(Err(e)),
                    std::task::Poll::Pending => return std::task::Poll::Pending,
                };
            self.pending.drain(..written);
        }
    }
}

impl<W: tokio::io::AsyncWrite + Unpin> tokio::io::AsyncWrite for BufferedAcceptor<W> {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        this.pending.extend(buf.iter().copied());
        std::task::Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        self.get_mut().poll_flush_step(cx)
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        // Shutdown drives the pending drain to completion first; the
        // final Ready(Ok(())) is the drain's own ready state.
        self.get_mut().poll_flush_step(cx)
    }
}

/// R7-02: a buffered/TLS writer that accepts the whole payload on
/// poll_write and then drains it to the transport 8 bytes every
/// 200 ms keeps the outer flush Pending for ~50 s of virtual time —
/// 50 windows past the 1 s idle. With confirmed progress reported
/// underneath, the flush must complete instead of being killed as
/// Stalled.
#[tokio::test(start_paused = true)]
async fn flush_draining_slowly_completes_when_progress_is_confirmed() {
    let data = vec![0x5A; 2000];
    let drip = DripTransport::new(8, Duration::from_millis(200));
    let mut w = BufferedAcceptor::new(8, ProgressReportingWriter::new(drip));

    let start = tokio::time::Instant::now();
    let outcome = write_progress_bounded(&mut w, &data, Duration::from_secs(1))
        .await
        .unwrap();
    assert_eq!(outcome, SendProgress::Completed);
    assert!(
        start.elapsed() >= Duration::from_millis(2000),
        "the drain must actually run past the idle window: {:?}",
        start.elapsed()
    );
    // Byte-for-byte: the transport received the whole payload.
    assert_eq!(w.into_inner().into_inner().accepted, data);
}

/// R7-02: bare waker activity proves nothing — only accepted bytes do.
/// This writer accepts the payload on poll_write, then its poll_flush
/// returns Pending forever, calling `cx.wake_by_ref()` for the first
/// handful of polls (a burst of wakeups with zero bytes underneath) and
/// plain waker-less Pending after that. The counter never moves, so the
/// flush must Stall after ONE idle window, not ride forever.
#[tokio::test(start_paused = true)]
async fn bare_wakes_or_pending_without_progress_still_stall() {
    struct BareWakeFlusher {
        accepted: Vec<u8>,
        wakes_left: usize,
    }
    impl tokio::io::AsyncWrite for BareWakeFlusher {
        fn poll_write(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
            buf: &[u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            let this = self.get_mut();
            this.accepted.extend_from_slice(buf);
            std::task::Poll::Ready(Ok(buf.len()))
        }
        fn poll_flush(
            self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            let this = self.get_mut();
            if this.wakes_left > 0 {
                this.wakes_left -= 1;
                cx.waker().wake_by_ref();
            }
            std::task::Poll::Pending
        }
        fn poll_shutdown(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }
    }

    let mut w = BareWakeFlusher {
        accepted: Vec::new(),
        wakes_left: 1000,
    };
    let start = tokio::time::Instant::now();
    let outcome = write_progress_bounded(&mut w, b"payload", Duration::from_secs(1))
        .await
        .unwrap();
    assert_eq!(outcome, SendProgress::Stalled);
    assert!(
        w.wakes_left < 1000,
        "bare wakes must actually have happened"
    );
    assert!(
        start.elapsed() >= Duration::from_secs(1) && start.elapsed() < Duration::from_secs(2),
        "must stall after exactly one idle window, not be renewed: {:?}",
        start.elapsed()
    );
}

/// R7-02 backward compatibility: without a ProgressReportingWriter in
/// the stack, nothing reports progress, so a flush that would drain
/// longer than idle still ends as Stalled after ONE window — the old
/// behavior — instead of being renewed for the whole drain.
#[tokio::test(start_paused = true)]
async fn uninstrumented_flush_keeps_single_idle_window() {
    let data = vec![0x5A; 2000];
    let mut w = BufferedAcceptor::new(8, DripTransport::new(8, Duration::from_millis(200)));

    let start = tokio::time::Instant::now();
    let outcome = write_progress_bounded(&mut w, &data, Duration::from_secs(1))
        .await
        .unwrap();
    assert_eq!(outcome, SendProgress::Stalled);
    assert!(
        start.elapsed() >= Duration::from_secs(1) && start.elapsed() < Duration::from_secs(2),
        "one idle window only, not the ~50 s drain: {:?}",
        start.elapsed()
    );
    assert!(w.into_inner().accepted.len() < data.len());
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
