// progress_tests: R3-H — the server-first relay inside the
// fragmentation prelude is bounded by per-write idle windows, not by
// the whole-block duration.

use super::*;
use tokio::io::duplex;

fn fragmentation() -> TlsFragmentConfig {
    TlsFragmentConfig {
        enabled: true,
        ..Default::default()
    }
}

fn idle_one_sec() -> NetworkConfig {
    NetworkConfig {
        tunnel_idle_timeout_sec: 1,
        tunnel_max_lifetime_sec: 0,
        ..Default::default()
    }
}

/// R3-H positive: a server-first block of 1024 bytes relayed to a
/// client that accepts 8 bytes per 200 ms. The transfer takes ~25.6 s —
/// 25x the 1 s idle window — yet every relay write lands well inside
/// its own window, so the tunnel must deliver every byte. Under the
/// old whole-write timeout the relay died at ~1 s with ~100 bytes on
/// the wire.
#[tokio::test(start_paused = true)]
async fn slow_client_relay_outlasts_idle_window() {
    let (mut client, client_inner) = duplex(64);
    let (mut upstream, upstream_inner) = duplex(64);
    let expected = vec![0xA5u8; 1024];
    let payload = expected.clone();
    let task = tokio::spawn(async move {
        forward_tunnel(
            client_inner,
            upstream_inner,
            Vec::new(),
            &fragmentation(),
            &idle_one_sec(),
            None,
        )
        .await
    });
    let writer = tokio::spawn(async move {
        let _ = upstream.write_all(&payload).await;
        let _ = upstream.shutdown().await;
    });

    // Drain the relayed block in 8-byte pieces, one piece per 200 ms.
    let start = tokio::time::Instant::now();
    let mut received = vec![0u8; expected.len()];
    for chunk in received.chunks_mut(8) {
        tokio::time::sleep(Duration::from_millis(200)).await;
        let n = tokio::time::timeout(Duration::from_secs(5), client.read_exact(chunk))
            .await
            .expect("the relay must keep feeding a slow but steady reader")
            .unwrap();
        assert_eq!(n, 8);
    }
    // The transfer demonstrably outlasted the idle window.
    assert!(
        start.elapsed() >= Duration::from_secs(2),
        "the relay must actually have outlasted the 1 s idle window: {:?}",
        start.elapsed()
    );
    assert_eq!(received, expected, "every relayed byte must arrive");

    drop(client);
    let _ = writer.await;
    tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .expect("the tunnel must end once both sides finish")
        .unwrap()
        .unwrap();
}

/// R3-H negative: a client that stops reading entirely stalls the
/// relay — the tunnel must close within ~one idle window and leave
/// only the already-accepted prefix on the wire. With no stall bound
/// the relay would hang forever instead.
#[tokio::test(start_paused = true)]
async fn silent_client_relay_stalls_within_one_idle_window() {
    let (mut client, client_inner) = duplex(64);
    let (mut upstream, upstream_inner) = duplex(64);
    let payload = vec![0x5Au8; 1024];
    let task = tokio::spawn(async move {
        forward_tunnel(
            client_inner,
            upstream_inner,
            Vec::new(),
            &fragmentation(),
            &idle_one_sec(),
            None,
        )
        .await
    });
    let writer = tokio::spawn(async move {
        let _ = upstream.write_all(&payload).await;
        let _ = upstream.shutdown().await;
    });

    // Accept one piece, then go silent for good.
    let mut first = [0u8; 16];
    tokio::time::timeout(Duration::from_secs(5), client.read_exact(&mut first))
        .await
        .expect("the first relayed bytes must reach the client")
        .unwrap();
    let start = tokio::time::Instant::now();
    tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .expect("a genuinely stalled relay must terminate the tunnel")
        .unwrap()
        .unwrap();
    let elapsed = start.elapsed();
    assert!(
        elapsed >= Duration::from_millis(900),
        "the stall must consume the idle window, not close early: {elapsed:?}"
    );
    assert!(
        elapsed <= Duration::from_secs(3),
        "the stall must fire within ~one idle window: {elapsed:?}"
    );

    // Only a prefix ever made it to the client.
    let mut rest = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(5), client.read_to_end(&mut rest)).await;
    let delivered = first.len() + rest.len();
    assert!(
        delivered < 1024,
        "a stalled relay must not deliver the whole block: {delivered}"
    );
    let _ = writer.await;
}
