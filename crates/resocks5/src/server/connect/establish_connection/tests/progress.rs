//! P2-02 release gate: slow-drain resilience for HTTPS gate chains.
//!
//! The false-idle protection (`send_possibly_fragmented` /
//! `flush_bounded_by_confirmed_progress`) renews its idle window ONLY
//! from confirmed write progress reported below the buffering layer.
//! The direct HTTPS connector instruments its raw transport, but the
//! gate dialer did not: nothing in a gate chain incremented
//! `FlushProgress`, so a congested flush longer than one idle window
//! was killed as `Stalled` even though the gate socket kept moving
//! bytes. These tests pin the fixed behaviour and prove it is not
//! vacuous:
//!
//! - one positive case per HTTPS-involving combo (HTTP→HTTPS,
//!   HTTPS→HTTP, HTTPS→HTTPS): a ClientHello-shaped payload is sent
//!   fragmented through the REAL `use_gate` chain against a stub that
//!   drip-reads the single gate socket slowly, and it must complete
//!   byte-for-byte. The progress oracle is the INSTANCE-SCOPED
//!   `ProgressScopeProbe` (`test-instrumentation`), not the
//!   process-global counter: the global accumulates across the whole
//!   process, so any concurrent test can inflate a delta into a false
//!   pass. A decoy control drives the point home: a second writer's
//!   confirmed bytes move the global but never the observed instance;
//! - a strict counterfactual pair over a controlled writer stack,
//!   both legs IDENTICAL in idle window, payload, fragmenting, drip
//!   transport and probe, differing ONLY in whether the buffering
//!   wrapper reports confirmed progress. One pending flush outlasts
//!   the idle window: with reports the send completes; without them
//!   it stalls after exactly one window with a truncated prefix. The
//!   pair runs on paused virtual time: on the real loopback a
//!   congested 60 KiB fragment flush (~0.6 s at the drip rate below)
//!   and the Windows ~64 KiB acceptance-burst spacing fall in the
//!   same range, so no single idle window can separate two
//!   real-socket legs;
//! - a dead-transport control on the instrumented chain: a stub that
//!   never reads must still stall bounded — instrumentation must not
//!   weaken the zero-progress timeout.
//!
//! Discriminator arithmetic (why the unreporting leg of the
//! controlled pair cannot pass): every 512-byte fragment is accepted
//! by the wrapper's `poll_write` atomically, and its flush drains the
//! fragment through the drip transport at 8 bytes per 200 ms — ~12.8 s
//! per fragment against the 1 s idle window — so without reports the
//! first fragment's flush stalls after exactly one window.

use std::collections::VecDeque;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::{AsyncWrite, AsyncWriteExt};
use tokio::time::{timeout, Instant};

use resocks5_net::connect::tls_fragment::SendProgress;
use resocks5_net::connect::{connect_chain, send_possibly_fragmented, FragmentSpec};
use resocks5_net::pool::{AnyUpstream, ProxyPool};
use resocks5_net::progress::{FlushProgress, ProgressScopeProbe, CONFIRMED_WRITE_PROGRESS_TOTAL};
use resocks5_net::types::{ProxyConfig, ProxyProtocol};

use socket2::SockRef;

use super::tests_matrix::{
    spawn_draining_stub, stub_config, stub_tls_connector, CollectedPayload, Drain,
};

/// Handshake budget per hop, as in the matrix tests.
const HANDSHAKE: Duration = Duration::from_secs(5);
/// Idle window of the POSITIVE slow-drain cases: comfortably above the
/// confirmed-progress event spacing on every supported platform —
/// per-drip on unix, quantized to ~64 KiB kernel bursts (well under
/// 1 s at the drip rate below) on Windows loopback — so a congested
/// fragment flush is always renewed within one window. 5 s matches the
/// direct-path E2E precedent in resocks5-net's `upstream_tls` tests
/// and leaves headroom for scheduler stalls under concurrent load.
const IDLE: Duration = Duration::from_millis(5000);
/// Strict idle window of the dead-transport control: the zero-progress
/// timeout must stay prompt — a stalled send ends within a couple of
/// windows, not after the generous positive window.
const IDLE_STRICT: Duration = Duration::from_millis(250);
/// Drip pacing of the stub: ≈100 KiB/s, and an acceptance event every
/// drip (40 ms) keeps every write window of the instrumented chain
/// comfortably inside `IDLE`.
const DRIP_CHUNK: usize = 4 * 1024;
const DRIP_DELAY: Duration = Duration::from_millis(40);
/// Fragment size below rustls' 64 KiB accept cap, so each `write()`
/// call accepts a whole fragment and returns `Ready` even
/// mid-congestion (tokio-rustls' `(n, would_block) → Ready(n)`): these
/// tests deliberately never depend on the write-phase Pending
/// accounting that P2-03 owns — see docs/reviews/REVIEW-2026-09-21-weekly-release.md.
const FRAGMENT: usize = 60 * 1024;
/// Positives: the repo's established 1.5 MiB — large enough to
/// congest any supported loopback, quick enough to drain.
const PAYLOAD_LEN: usize = 1_572_864;
/// Dead control: beyond any plausible auto-tuned kernel buffer
/// ceiling, so a stall cannot degenerate into buffer absorption.
const CONTROL_LEN: usize = 20_000_000;
/// Decoy writer's payload: completes in one poll, big enough to be an
/// unmistakable pollution of the process-global counter.
const DECOY_LEN: usize = 4096;
/// Strict-counterfactual pair (paused virtual time), IDENTICAL for
/// both legs: the drip transport accepts 8 bytes per 200 ms, so every
/// 512-byte fragment drains in ~12.8 s — one pending flush far past
/// the 1 s idle window.
const PAIR_PIECE: usize = 8;
const PAIR_DRIP: Duration = Duration::from_millis(200);
const PAIR_IDLE: Duration = Duration::from_secs(1);
const PAIR_FRAGMENT: usize = 512;
/// ClientHello-shaped like the real-chain payloads: 6-byte prefix +
/// 2000 pattern bytes = 4 fragments (512×3 + 470).
const PAIR_PAYLOAD_LEN: usize = 2006;

/// ClientHello-shaped, position-distinct payload: `classify_client_hello`
/// routes it through the production fragmented-send path, and a
/// truncated or reordered transfer cannot masquerade as the payload.
fn gate_payload(len: usize) -> Vec<u8> {
    let mut payload = Vec::with_capacity(len);
    payload.extend_from_slice(&[0x16, 0x03, 0x01, 0x3E, 0x80, 0x01]);
    payload.extend((0..len as u64 - 6).map(|i| (i * 7 % 251) as u8));
    payload
}

fn slow_drain() -> (Drain, CollectedPayload) {
    let collected: CollectedPayload = Arc::new(Mutex::new(Vec::new()));
    (
        Drain::Slow {
            chunk: DRIP_CHUNK,
            delay: DRIP_DELAY,
            collected: Arc::clone(&collected),
        },
        collected,
    )
}

fn fragment_spec() -> FragmentSpec {
    FragmentSpec {
        enabled: true,
        fragment_size: FRAGMENT,
        delay_ms: 0,
    }
}

/// The REAL production gate construction: `use_gate` over a drip-paced
/// protocol stub, for the given hop protocols. Also proves the socket
/// reach-through (`as_tcp`, `set_nodelay`) still digs through the TLS
/// layers AND the new progress-reporting base to the gate socket.
async fn connect_instrumented(
    gate_proto: ProxyProtocol,
    inner_proto: ProxyProtocol,
    drain: Drain,
) -> anyhow::Result<(AnyUpstream, CollectedPayload)> {
    let collected: CollectedPayload = match &drain {
        Drain::Slow { collected, .. } => Arc::clone(collected),
        _ => Arc::new(Mutex::new(Vec::new())),
    };
    let (addr, _log, _collector) = spawn_draining_stub(gate_proto, inner_proto, drain).await;
    let gate = stub_config(addr, gate_proto, true);
    let inner = stub_config(addr, inner_proto, false);
    let pool = ProxyPool::new(Default::default(), Duration::from_secs(2), 4);
    let connector = stub_tls_connector();

    let chain = ProxyConfig::chain([Arc::new(gate.clone()), Arc::new(inner.clone())])
        .expect("valid gate chain");
    let upstream = connect_chain(
        &chain,
        "example.com:443",
        &pool,
        HANDSHAKE,
        Some(&connector),
    )
    .await?;

    let tcp = upstream
        .as_tcp()
        .expect("gate chain exposes its real socket");
    tcp.set_nodelay(true)
        .expect("set_nodelay reaches the socket");
    assert!(tcp.nodelay().expect("nodelay readback"));
    upstream
        .set_nodelay(true)
        .expect("AnyUpstream::set_nodelay");
    // Client send-buffer shrink, best-effort (the resocks5-net TLS
    // tests' proven recipe): a tiny send buffer makes every drip
    // produce fresh kernel acceptance events — left at its large
    // default, a Windows send buffer never hits WSAEWOULDBLOCK,
    // write-readiness is not re-armed, and `poll_write` sleeps past
    // drips the wire is actually serving. The oversized payloads
    // remain the guaranteed backstop.
    let _ = SockRef::from(tcp).set_send_buffer_size(2048);

    Ok((upstream, collected))
}

/// One positive slow-drain case: the send must ride the ≈15 s drip
/// (far past one idle window) and the stub must receive every payload
/// byte in order. The progress oracle is the INSTANCE-SCOPED probe:
/// exactly what THIS send confirmed below the first TLS hop —
/// concurrent tests cannot inflate it. A decoy writer then proves the
/// oracle's isolation: its confirmed bytes move the process-global
/// (the old, pollutable oracle) but never the observed chain instance.
async fn slow_drain_case(gate_proto: ProxyProtocol, inner_proto: ProxyProtocol) {
    let (drain, _) = slow_drain();
    let (upstream, collected) = connect_instrumented(gate_proto, inner_proto, drain)
        .await
        .expect("instrumented gate chain");

    let payload = gate_payload(PAYLOAD_LEN);
    let mut probe = ProgressScopeProbe::new(upstream);
    let start = Instant::now();
    let outcome = send_possibly_fragmented(&mut probe, &payload, &fragment_spec(), IDLE)
        .await
        .expect("bounded send must not error");
    let elapsed = start.elapsed();
    let chain_confirmed = probe.confirmed_total();

    assert_eq!(
        outcome,
        SendProgress::Completed,
        "confirmed progress below the first TLS hop must renew the window, \
         got {outcome:?} after {elapsed:?}"
    );
    assert!(
        elapsed >= Duration::from_secs(8),
        "the send must ride the ≈15 s drip, not collapse into kernel buffers: {elapsed:?}"
    );
    // The fix's core claim, proven live: the REAL gate chain's raw
    // transport confirmed at least every payload byte during THIS send.
    assert!(
        chain_confirmed as usize >= payload.len(),
        "instrumentation must be live in the real gate chain: \
         confirmed {chain_confirmed} < payload {}",
        payload.len()
    );

    // Decoy control: a second, independent instrumented writer. Its
    // bytes land byte-exact in ITS instance and demonstrably in the
    // process-global, but must NOT appear in the observed chain
    // instance — under the old global oracle this pollution was
    // invisible, and a decoy alone could satisfy the delta.
    let global_before_decoy = CONFIRMED_WRITE_PROGRESS_TOTAL.load(Ordering::Relaxed);
    let decoy_payload = gate_payload(DECOY_LEN);
    let mut decoy = ProgressScopeProbe::new(PieceBuffer::new(true, DECOY_LEN, VecSink::default()));
    let decoy_outcome =
        send_possibly_fragmented(&mut decoy, &decoy_payload, &fragment_spec(), IDLE)
            .await
            .expect("bounded decoy send must not error");
    assert_eq!(decoy_outcome, SendProgress::Completed);
    assert_eq!(
        decoy.confirmed_total(),
        DECOY_LEN as u64,
        "the decoy's bytes must land in its own instance, byte-exact"
    );
    assert_eq!(
        probe.confirmed_total(),
        chain_confirmed,
        "the decoy's progress must not count toward the observed chain"
    );
    assert!(
        CONFIRMED_WRITE_PROGRESS_TOTAL.load(Ordering::Relaxed) - global_before_decoy
            >= DECOY_LEN as u64,
        "the decoy must pollute the process-global: that pollution is \
         what the instance oracle replaces"
    );
    assert_eq!(
        decoy.into_inner().inner.accepted.len(),
        DECOY_LEN,
        "the decoy's sink must have taken the whole payload"
    );

    // close_notify so the stub's drip loop sees a clean EOF.
    let mut upstream = probe.into_inner();
    upstream.shutdown().await.expect("clean close");

    // The stub may still be drip-draining the last kilobytes out of
    // the kernel buffer; wait (bounded) until every byte has been read
    // back, then compare byte-for-byte.
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let len = collected.lock().unwrap().len();
        if len == payload.len() {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "stub never received the full payload: {len} of {}",
            payload.len()
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let got = collected.lock().unwrap().clone();
    assert_eq!(
        got, payload,
        "byte-for-byte through {gate_proto:?}→{inner_proto:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn slow_drain_http_gate_https_inner_completes_byte_for_byte() {
    timeout(
        Duration::from_secs(45),
        slow_drain_case(ProxyProtocol::Http, ProxyProtocol::Https),
    )
    .await
    .expect("HTTP→HTTPS slow drain must not hang");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn slow_drain_https_gate_http_inner_completes_byte_for_byte() {
    timeout(
        Duration::from_secs(45),
        slow_drain_case(ProxyProtocol::Https, ProxyProtocol::Http),
    )
    .await
    .expect("HTTPS→HTTP slow drain must not hang");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn slow_drain_https_gate_https_inner_completes_byte_for_byte() {
    timeout(
        Duration::from_secs(45),
        slow_drain_case(ProxyProtocol::Https, ProxyProtocol::Https),
    )
    .await
    .expect("HTTPS→HTTPS slow drain must not hang");
}

/// Shared construction of the strict counterfactual pair: the ONLY
/// difference between the legs is the `instrument` flag.
fn pair_stack(instrument: bool) -> PieceBuffer<PacedSink> {
    PieceBuffer::new(
        instrument,
        PAIR_PIECE,
        PacedSink::new(PAIR_PIECE, PAIR_DRIP),
    )
}

fn pair_spec() -> FragmentSpec {
    FragmentSpec {
        enabled: true,
        fragment_size: PAIR_FRAGMENT,
        delay_ms: 0,
    }
}

/// Positive leg of the strict counterfactual: the wrapper reports
/// every drip-accepted piece, so each fragment's ~12.8 s flush — one
/// pending flush far past the 1 s idle window — is renewed and the
/// whole send completes. Identical in every parameter to the negative
/// leg except the reports.
#[tokio::test(start_paused = true)]
async fn controlled_pair_with_reports_completes_past_one_idle_window() {
    let data = gate_payload(PAIR_PAYLOAD_LEN);
    let mut probe = ProgressScopeProbe::new(pair_stack(true));
    let start = Instant::now();
    let outcome = send_possibly_fragmented(&mut probe, &data, &pair_spec(), PAIR_IDLE)
        .await
        .expect("bounded send must not error");
    let elapsed = start.elapsed();

    assert_eq!(outcome, SendProgress::Completed);
    assert!(
        elapsed >= Duration::from_secs(40) && elapsed <= Duration::from_secs(60),
        "the flush must have ridden the ~50 s drip via renewals: {elapsed:?}"
    );
    // Instance-scoped oracle, exact: the reporting wrapper is the ONLY
    // reporter under this send's scopes, so the accumulator must count
    // exactly every payload byte.
    assert_eq!(
        probe.confirmed_total(),
        data.len() as u64,
        "the reporting wrapper must confirm exactly the payload"
    );
    let stack = probe.into_inner();
    assert_eq!(stack.inner.accepted, data, "byte-for-byte through the drip");
}

/// Negative leg: the IDENTICAL stack with reporting switched off.
/// Nothing is reported, so the first fragment's flush — one pending
/// flush far longer than the idle window — stalls after exactly one
/// window, with a truncated prefix on the transport and exactly zero
/// confirmed bytes.
#[tokio::test(start_paused = true)]
async fn controlled_pair_without_reports_stalls_after_one_idle_window() {
    let data = gate_payload(PAIR_PAYLOAD_LEN);
    let mut probe = ProgressScopeProbe::new(pair_stack(false));
    let start = Instant::now();
    let outcome = send_possibly_fragmented(&mut probe, &data, &pair_spec(), PAIR_IDLE)
        .await
        .expect("bounded send must not error");
    let elapsed = start.elapsed();

    assert_eq!(outcome, SendProgress::Stalled);
    assert!(
        elapsed >= PAIR_IDLE && elapsed < PAIR_IDLE * 2,
        "exactly one idle window, not the ~50 s drip: {elapsed:?}"
    );
    assert_eq!(
        probe.confirmed_total(),
        0,
        "the unreporting wrapper must not confirm ANY byte"
    );
    let stack = probe.into_inner();
    assert!(
        stack.inner.accepted.len() < data.len(),
        "the stalled flush must leave the payload truncated"
    );
}

/// Zero-progress timeout preserved on the instrumented chain: a stub
/// that completes the handshakes and then never reads congests the
/// transport with zero confirmed progress — the reporting writer has
/// nothing to report — so the send must still end as `Stalled`
/// promptly instead of riding forever.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dead_gate_transport_still_stalls_bounded() {
    timeout(Duration::from_secs(30), async {
        let (upstream, _collected) =
            connect_instrumented(ProxyProtocol::Https, ProxyProtocol::Http, Drain::Dead)
                .await
                .expect("instrumented gate chain");

        let payload = gate_payload(CONTROL_LEN);
        let mut probe = ProgressScopeProbe::new(upstream);
        let start = Instant::now();
        let outcome = send_possibly_fragmented(&mut probe, &payload, &fragment_spec(), IDLE_STRICT)
            .await
            .expect("bounded send must not error");
        let elapsed = start.elapsed();

        assert_eq!(
            outcome,
            SendProgress::Stalled,
            "a never-reading peer must stall the send, got {outcome:?} after {elapsed:?}"
        );
        assert!(
            elapsed >= IDLE_STRICT && elapsed <= Duration::from_secs(15),
            "zero progress must time out within a window past congestion: {elapsed:?}"
        );
        // Confirmed progress must stay confirmation-driven: on a dead
        // transport only the initial kernel send-buffer absorption is
        // ever accepted — never anything payload-sized. A reporter
        // that inflated Pending/wakeups into progress would blow
        // through this bound.
        assert!(
            probe.confirmed_total() < payload.len() as u64,
            "a dead transport must not confirm payload-sized progress: {}",
            probe.confirmed_total()
        );
    })
    .await
    .expect("dead-transport control must not hang");
}

/// Buffering look-alike shared by the decoy control and the strict
/// counterfactual pair: `poll_write` accepts whole writes into a
/// queue; `poll_flush` drains `piece` bytes per poll to the inner
/// transport and — only when `instrument` is on — reports each
/// accepted piece via the public API. `instrument` is the pair's sole
/// difference.
struct PieceBuffer<W> {
    instrument: bool,
    piece: usize,
    pending: VecDeque<u8>,
    inner: W,
}

impl<W> PieceBuffer<W> {
    fn new(instrument: bool, piece: usize, inner: W) -> Self {
        Self {
            instrument,
            piece,
            pending: VecDeque::new(),
            inner,
        }
    }
}

impl<W: AsyncWrite + Unpin> AsyncWrite for PieceBuffer<W> {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        this.pending.extend(buf.iter().copied());
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        while !this.pending.is_empty() {
            let piece = this.piece;
            let contiguous = this.pending.make_contiguous();
            let take = piece.min(contiguous.len());
            let written = match Pin::new(&mut this.inner).poll_write(cx, &contiguous[..take]) {
                // Ok(0) accepts nothing: `drain(..0)` would leave the
                // buffer untouched and this loop would spin forever.
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(std::io::ErrorKind::WriteZero.into()));
                }
                Poll::Ready(Ok(n)) => n,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            };
            this.pending.drain(..written);
            if this.instrument {
                // Only bytes the transport ACCEPTED are progress.
                FlushProgress::report_confirmed(written as u64);
            }
        }
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        self.poll_flush(cx)
    }
}

/// Raw transport double for the counterfactual pair: accepts at most
/// `piece` bytes per successful `poll_write`, then refuses for one
/// `drip` of (virtual) time — the flush underneath stays Pending far
/// longer than the idle window, by design.
struct PacedSink {
    accepted: Vec<u8>,
    piece: usize,
    drip: Duration,
    // ZERO so the very first write is immediate.
    cooldown: Pin<Box<tokio::time::Sleep>>,
}

impl PacedSink {
    fn new(piece: usize, drip: Duration) -> Self {
        Self {
            accepted: Vec::new(),
            piece,
            drip,
            cooldown: Box::pin(tokio::time::sleep(Duration::ZERO)),
        }
    }
}

impl AsyncWrite for PacedSink {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        if this.cooldown.as_mut().poll(cx).is_pending() {
            return Poll::Pending;
        }
        let n = buf.len().min(this.piece);
        this.accepted.extend_from_slice(&buf[..n]);
        let deadline = tokio::time::Instant::now() + this.drip;
        this.cooldown.as_mut().reset(deadline);
        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        self.poll_flush(cx)
    }
}

/// Terminal sink of the decoy stack: accepts everything.
#[derive(Default)]
struct VecSink {
    accepted: Vec<u8>,
}

impl AsyncWrite for VecSink {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        self.get_mut().accepted.extend_from_slice(buf);
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        self.poll_flush(cx)
    }
}
