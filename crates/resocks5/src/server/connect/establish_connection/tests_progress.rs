//! P2-02 release gate: slow-drain resilience for HTTPS gate chains.
//!
//! The false-idle protection (`send_possibly_fragmented` /
//! `flush_bounded_by_confirmed_progress`) renews its idle window ONLY
//! from confirmed write progress reported below the buffering layer.
//! The direct HTTPS connector instruments its raw transport, but the
//! gate dialer did not: nothing in a gate chain incremented
//! `FlushProgress`, so a congested flush longer than one idle window
//! was killed as `Stalled` even though the gate socket kept moving
//! bytes. These tests pin the fixed behaviour per HTTPS gate variant
//! and prove they are not vacuous:
//!
//! - one positive case per HTTPS-involving combo (HTTP→HTTPS,
//!   HTTPS→HTTP, HTTPS→HTTPS): a ClientHello-shaped payload is sent
//!   fragmented through the REAL `use_gate` chain against a stub that
//!   drip-reads the single gate socket slowly, and it must complete
//!   byte-for-byte;
//! - a negative control built with the PRE-FIX construction (the raw
//!   gate transport boxed WITHOUT `ProgressReportingWriter`, via the
//!   very `tunnel_hop` calls `use_gate` makes): identical scenario,
//!   and it must LOSE — stall after roughly one idle window with the
//!   payload truncated;
//! - a dead-transport control on the instrumented chain: a stub that
//!   never reads must still stall bounded — instrumentation must not
//!   weaken the zero-progress timeout.
//!
//! Platform note: Windows loopback quantizes kernel write acceptance
//! (and therefore confirmed-progress events) into ~MSS-sized bursts
//! spaced well under [`IDLE`] at the drip rate below, while unix
//! delivers them per drip. A congested fragment flush exceeds
//! [`IDLE_STRICT`] on every platform, which is why the negative
//! control uses the strict window while the positives ride the
//! generous one.
//!
//! Discriminator arithmetic (why the negative control cannot pass):
//! rustls 0.23 caps its outgoing ciphertext buffer at 64 KiB
//! (`DEFAULT_BUFFER_LIMIT`), so a 60 KiB fragment is accepted by
//! `poll_write` atomically and its `flush` drains ≈61-72 KiB of
//! ciphertext through the congested socket. At the drip rate of
//! 4 KiB / 40 ms (≈100 KiB/s) a congested flush takes ≈0.6-0.7 s —
//! roughly two to three idle windows (250 ms) — so the uninstrumented
//! chain stalls on the first congested fragment while the instrumented
//! one is renewed by every drip. The payloads (1.5 MiB positive,
//! 20 MiB controls) far exceed any supported platform's loopback
//! socket buffering, so congestion never depends on OS buffer-size
//! hints being honoured.

use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::AsyncWriteExt;
use tokio::time::{timeout, Instant};

use resocks5_net::connect::tls_fragment::SendProgress;
use resocks5_net::connect::{send_possibly_fragmented, FragmentSpec};
use resocks5_net::pool::{AnyUpstream, ProxyPool};
use resocks5_net::progress::CONFIRMED_WRITE_PROGRESS_TOTAL;
use resocks5_net::types::ProxyProtocol;

use socket2::SockRef;

use super::dial::{tunnel_hop, use_gate};
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
/// Strict idle window of the negative/dead controls: a congested
/// 60 KiB-fragment flush (≈61 KiB of ciphertext at ≈100 KiB/s ≈ 0.6 s,
/// longer still where kernel acceptance is burst-quantized) exceeds it
/// on every platform, so an uninstrumented chain must stall — that is
/// the non-vacuity proof — while the zero-progress timeout stays
/// prompt.
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
/// accounting that P2-03 owns — see docs/REVIEW-2026-09-21-weekly-release.md.
const FRAGMENT: usize = 60 * 1024;
/// Positives: the repo's established 1.5 MiB — large enough to
/// congest any supported loopback, quick enough to drain.
const PAYLOAD_LEN: usize = 1_572_864;
/// Controls: beyond any plausible auto-tuned kernel buffer ceiling, so
/// a stall cannot degenerate into buffer absorption.
const CONTROL_LEN: usize = 20_000_000;

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

    let upstream = use_gate(
        "example.com:443",
        &gate,
        &inner,
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
/// byte in order.
async fn slow_drain_case(gate_proto: ProxyProtocol, inner_proto: ProxyProtocol) {
    let (drain, _) = slow_drain();
    let (mut upstream, collected) = connect_instrumented(gate_proto, inner_proto, drain)
        .await
        .expect("instrumented gate chain");

    let payload = gate_payload(PAYLOAD_LEN);
    let progress_before = CONFIRMED_WRITE_PROGRESS_TOTAL.load(Ordering::Relaxed);
    let start = Instant::now();
    let outcome = send_possibly_fragmented(&mut upstream, &payload, &fragment_spec(), IDLE)
        .await
        .expect("bounded send must not error");
    let elapsed = start.elapsed();

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
    // transport reported at least every payload byte into
    // FlushProgress while the outer flush was unresolved.
    let progress_delta = CONFIRMED_WRITE_PROGRESS_TOTAL.load(Ordering::Relaxed) - progress_before;
    assert!(
        progress_delta as usize >= payload.len(),
        "instrumentation must be live in the real gate chain: \
         confirmed-progress delta {progress_delta} < payload {}",
        payload.len()
    );

    // close_notify so the stub's drip loop sees a clean EOF.
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

/// The negative control: the SAME chain shape, the SAME drip-paced
/// stub, the SAME bounded send — but the raw gate transport boxed
/// WITHOUT the `ProgressReportingWriter`, exactly the pre-fix
/// `use_gate` construction (it calls these very `tunnel_hop`s).
/// Without the lower instrumentation nothing increments
/// `FlushProgress`, so the first congested fragment's flush must NOT
/// be renewed: the send loses the resilience the positives assert.
/// This is what proves the positive tests are not vacuous.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn uninstrumented_gate_chain_loses_slow_drain_resilience() {
    timeout(Duration::from_secs(45), async {
        let (drain, collected) = slow_drain();
        let (addr, _log, _collector) =
            spawn_draining_stub(ProxyProtocol::Https, ProxyProtocol::Http, drain).await;
        let gate = stub_config(addr, ProxyProtocol::Https, true);
        let inner = stub_config(addr, ProxyProtocol::Http, false);
        let pool = ProxyPool::new(Default::default(), Duration::from_secs(2), 4);
        let connector = stub_tls_connector();

        let mut gate_stream = pool.acquire(&gate).await.expect("gate dial");
        gate_stream.attach_permit(pool.reserve_permit(&inner).expect("inner slot"));
        // PRE-FIX construction: no ProgressReportingWriter around the
        // raw gate transport; otherwise identical to use_gate.
        let stream = tunnel_hop(
            Box::new(gate_stream),
            &gate,
            &format!("{}:{}", inner.host, inner.port),
            Some(&connector),
            HANDSHAKE,
        )
        .await
        .expect("gate hop");
        let mut upstream = AnyUpstream::Gate(
            tunnel_hop(
                stream,
                &inner,
                "example.com:443",
                Some(&connector),
                HANDSHAKE,
            )
            .await
            .expect("inner hop"),
        );

        let payload = gate_payload(CONTROL_LEN);
        let start = Instant::now();
        let outcome =
            send_possibly_fragmented(&mut upstream, &payload, &fragment_spec(), IDLE_STRICT)
                .await
                .expect("bounded send must not error");
        let elapsed = start.elapsed();

        assert_eq!(
            outcome,
            SendProgress::Stalled,
            "without the lower instrumentation a congested flush must stall, \
             got {outcome:?} after {elapsed:?}"
        );
        assert!(
            elapsed >= IDLE_STRICT && elapsed <= Duration::from_secs(15),
            "the stall must be bounded by about one idle window past congestion: {elapsed:?}"
        );

        // Whatever reached the wire is a strict PREFIX: the stalled
        // fragment's ciphertext died inside rustls' buffer and is lost
        // with the stream. (The stub keeps draining kernel-held bytes,
        // but it can never see past the lost fragment.)
        let got = collected.lock().unwrap().clone();
        assert!(
            got.len() < payload.len(),
            "an uninstrumented chain must not deliver the whole payload"
        );
        assert_eq!(
            &got[..],
            &payload[..got.len()],
            "the delivered prefix must be intact"
        );

        drop(upstream);
    })
    .await
    .expect("negative control must not hang");
}

/// Zero-progress timeout preserved on the instrumented chain: a stub
/// that completes the handshakes and then never reads congests the
/// transport with zero confirmed progress — the reporting writer has
/// nothing to report — so the send must still end as `Stalled`
/// promptly instead of riding forever.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dead_gate_transport_still_stalls_bounded() {
    timeout(Duration::from_secs(30), async {
        let (mut upstream, _collected) =
            connect_instrumented(ProxyProtocol::Https, ProxyProtocol::Http, Drain::Dead)
                .await
                .expect("instrumented gate chain");

        let payload = gate_payload(CONTROL_LEN);
        let start = Instant::now();
        let outcome =
            send_possibly_fragmented(&mut upstream, &payload, &fragment_spec(), IDLE_STRICT)
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
    })
    .await
    .expect("dead-transport control must not hang");
}
