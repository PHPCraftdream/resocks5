use super::*;

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
    assert_eq!(err.kind(), std::io::ErrorKind::WriteZero);
}

/// The raw transport for the P2-03 write-phase doubles: accepts at
/// most `per_poll` bytes per successful poll_write, then goes silent
/// for `interval` of (virtual) time. `stalling_after` makes it refuse
/// forever (Pending, no waker — re-polls come only from the caller's
/// idle windows) once that many bytes have been accepted in total.
/// Every accepted byte lands in `accepted` for exact-wire checks.
struct GatedTransport {
    accepted: Vec<u8>,
    per_poll: usize,
    interval: Duration,
    // Created with Duration::ZERO so the very first write is
    // immediate; reset to `interval` after every accepted write.
    cooldown: std::pin::Pin<Box<tokio::time::Sleep>>,
    stall_after: Option<usize>,
}

impl GatedTransport {
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

// All fields are Unpin, so get_mut() is enough to drive it.
impl tokio::io::AsyncWrite for GatedTransport {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        if let Some(quota) = this.stall_after {
            if this.accepted.len() >= quota {
                // Quota reached: silent forever, and no waker is
                // registered — only the caller's idle windows re-poll.
                return std::task::Poll::Pending;
            }
        }
        if this.cooldown.as_mut().poll(cx).is_pending() {
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

/// P2-03 test double: a buffering writer that mimics tokio-rustls'
/// `(0, would_block)` poll_write — when previously accepted bytes are
/// still in flight, a write attempt for NEW plaintext first drains
/// toward the transport (one `piece` per call; each accepted piece is
/// confirmed progress below the `ProgressReportingWriter` when
/// instrumented) and then returns Pending WITHOUT consuming any of the
/// new bytes. New bytes are buffered — never put on the wire directly
/// — and only once the buffer has fully drained, at most
/// `accept_per_poll` per Ready, so the caller's write loop keeps being
/// re-invoked while earlier bytes are still draining. `wakes_left`
/// emits that many progress-free `wake_by_ref()` calls on the Pending
/// path, for the bare-wake negative control.
struct DrainingBuffer<W> {
    pending: std::collections::VecDeque<u8>,
    accept_per_poll: usize,
    piece: usize,
    /// Total NEW bytes accepted into the buffer (never onto the wire
    /// directly).
    accepted_total: usize,
    wakes_left: usize,
    transport: W,
}

impl<W: tokio::io::AsyncWrite + Unpin> DrainingBuffer<W> {
    fn new(accept_per_poll: usize, piece: usize, transport: W) -> Self {
        Self {
            pending: std::collections::VecDeque::new(),
            accept_per_poll,
            piece,
            accepted_total: 0,
            wakes_left: 0,
            transport,
        }
    }

    fn with_bare_wakes(mut self, n: usize) -> Self {
        self.wakes_left = n;
        self
    }

    fn transport(&self) -> &W {
        &self.transport
    }

    fn into_transport(self) -> W {
        self.transport
    }

    fn accepted_total(&self) -> usize {
        self.accepted_total
    }

    // Drain toward the transport while it accepts; Ok(true) means the
    // buffer has fully drained, Ok(false) that old bytes are still in
    // flight. All fields are Unpin, so &mut self is enough.
    fn poll_pending(&mut self, cx: &mut std::task::Context<'_>) -> std::io::Result<bool> {
        while !self.pending.is_empty() {
            let contiguous = self.pending.make_contiguous();
            let take = self.piece.min(contiguous.len());
            match std::pin::Pin::new(&mut self.transport).poll_write(cx, &contiguous[..take]) {
                std::task::Poll::Ready(Ok(n)) => {
                    self.pending.drain(..n);
                }
                std::task::Poll::Ready(Err(e)) => return Err(e),
                std::task::Poll::Pending => {
                    if self.wakes_left > 0 {
                        self.wakes_left -= 1;
                        cx.waker().wake_by_ref();
                    }
                    return Ok(false);
                }
            }
        }
        Ok(true)
    }
}

impl<W: tokio::io::AsyncWrite + Unpin> tokio::io::AsyncWrite for DrainingBuffer<W> {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        // Refuse new plaintext while anything is in flight: drain one
        // piece per call (the transport gates each piece behind its
        // cooldown) and accept only from a fully drained buffer.
        match this.poll_pending(cx) {
            Ok(true) => {}
            Ok(false) => return std::task::Poll::Pending,
            Err(e) => return std::task::Poll::Ready(Err(e)),
        }
        let n = buf.len().min(this.accept_per_poll);
        this.pending.extend(&buf[..n]);
        this.accepted_total += n;
        std::task::Poll::Ready(Ok(n))
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let this = self.get_mut();
        match this.poll_pending(cx) {
            Ok(true) => std::pin::Pin::new(&mut this.transport).poll_flush(cx),
            Ok(false) => std::task::Poll::Pending,
            Err(e) => std::task::Poll::Ready(Err(e)),
        }
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let this = self.get_mut();
        match this.poll_pending(cx) {
            Ok(true) => std::pin::Pin::new(&mut this.transport).poll_flush(cx),
            Ok(false) => std::task::Poll::Pending,
            Err(e) => std::task::Poll::Ready(Err(e)),
        }
    }
}

/// P2-03 release gate (write phase): the double's poll_write keeps
/// refusing NEW plaintext (Pending) while it drains previously
/// accepted bytes into the transport one 2-byte piece per second —
/// confirmed progress below the ProgressReportingWriter renews the
/// caller's idle window, so a 40-byte payload whose write attempts go
/// Pending completes after ~14 s of virtual drain, ten idle-window
/// renewals past the 1.5 s idle. The old single-timeout write loop
/// returned Stalled at the first window (~1.5 s) with 2 bytes on the
/// wire. Payload bytes are position-distinct, so byte-for-byte wire
/// equality also rules out duplication or reordering from any
/// re-polled attempt.
#[tokio::test(start_paused = true)]
async fn write_phase_survives_on_confirmed_drain_progress() {
    let data: Vec<u8> = (0u8..40).collect();
    let mut w = DrainingBuffer::new(
        10,
        2,
        ProgressReportingWriter::new(GatedTransport::new(2, Duration::from_secs(1))),
    );
    let start = tokio::time::Instant::now();
    let outcome = write_progress_bounded(&mut w, &data, Duration::from_millis(1500))
        .await
        .unwrap();
    assert_eq!(outcome, SendProgress::Completed);
    assert!(
        start.elapsed() >= Duration::from_secs(6),
        "the send must have ridden many idle-window renewals: {:?}",
        start.elapsed()
    );
    // Byte-for-byte: the transport received the whole payload exactly
    // once, in order — no duplication from any re-polled attempt.
    assert_eq!(w.into_transport().into_inner().accepted, data);
}

/// P2-03 (write phase): renewals ride ONLY confirmed progress. The
/// transport drains happily for 6 bytes (renewals at 1.5 s and 3 s),
/// then hits its quota and poll_write goes silent WITHOUT progress —
/// the send must end as Stalled at the first progress-free window
/// (4.5 s), not ride on. The abandoned attempt must not have
/// duplicated anything: the wire holds exactly the drained prefix, no
/// byte beyond it was ever accepted by the transport, and the buffer's
/// stranded tail (accepted_new stays 10) was never re-offered.
#[tokio::test(start_paused = true)]
async fn write_phase_stalls_once_confirmed_progress_stops() {
    let data: Vec<u8> = (0u8..40).collect();
    let mut w = DrainingBuffer::new(
        10,
        2,
        ProgressReportingWriter::new(
            GatedTransport::new(2, Duration::from_secs(1)).stalling_after(6),
        ),
    );
    let start = tokio::time::Instant::now();
    let outcome = write_progress_bounded(&mut w, &data, Duration::from_millis(1500))
        .await
        .unwrap();
    assert_eq!(outcome, SendProgress::Stalled);
    assert!(
        start.elapsed() >= Duration::from_millis(4500)
            && start.elapsed() < Duration::from_millis(6000),
        "must renew on progress, then stall at the first progress-free window: {:?}",
        start.elapsed()
    );
    // Wire: exactly the drained prefix — no duplicates, no reordering,
    // nothing beyond the consumed frontier.
    assert_eq!(w.transport().get_ref().accepted, &data[..6]);
    // The double accepted only the first slice; the rest was never
    // re-offered after abandonment.
    assert_eq!(w.accepted_total(), 10);
}

/// P2-03 (write phase): bare wakeups and plain Pending prove nothing.
/// The transport never accepts anything (quota 0) and the double fires
/// 1000 progress-free wake_by_ref() calls from its Pending path — the
/// counter never moves, so the send must stall after exactly ONE idle
/// window.
#[tokio::test(start_paused = true)]
async fn write_phase_bare_wakes_without_progress_still_stall() {
    let data: Vec<u8> = (0u8..40).collect();
    let mut w = DrainingBuffer::new(
        10,
        2,
        ProgressReportingWriter::new(
            GatedTransport::new(2, Duration::from_secs(1)).stalling_after(0),
        ),
    )
    .with_bare_wakes(1000);
    let start = tokio::time::Instant::now();
    let outcome = write_progress_bounded(&mut w, &data, Duration::from_millis(1500))
        .await
        .unwrap();
    assert_eq!(outcome, SendProgress::Stalled);
    assert!(
        w.wakes_left < 1000,
        "bare wakes must actually have happened"
    );
    assert!(
        w.transport().get_ref().accepted.is_empty(),
        "no byte may reach the transport without room"
    );
    assert!(
        start.elapsed() >= Duration::from_millis(1500)
            && start.elapsed() < Duration::from_millis(2500),
        "must stall after exactly one idle window: {:?}",
        start.elapsed()
    );
}

/// P2-03 backward compatibility (write phase): without a
/// ProgressReportingWriter in the stack nothing reports progress, so
/// even a genuinely-draining write phase keeps the old single idle
/// window: two pieces reached the wire (the transport's cooldown
/// starts ready, so one lands immediately), the window expired with
/// no confirmed delta, Stalled.
#[tokio::test(start_paused = true)]
async fn uninstrumented_write_phase_keeps_single_idle_window() {
    let data: Vec<u8> = (0u8..40).collect();
    let mut w = DrainingBuffer::new(10, 2, GatedTransport::new(2, Duration::from_secs(1)));
    let start = tokio::time::Instant::now();
    let outcome = write_progress_bounded(&mut w, &data, Duration::from_millis(1500))
        .await
        .unwrap();
    assert_eq!(outcome, SendProgress::Stalled);
    assert!(
        start.elapsed() >= Duration::from_millis(1500)
            && start.elapsed() < Duration::from_millis(2500),
        "uninstrumented drains must keep the single idle window: {:?}",
        start.elapsed()
    );
    assert_eq!(w.into_transport().accepted, &data[..4]);
}
