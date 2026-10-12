use super::*;
use crate::progress::ProgressReportingWriter;

mod write_idle;

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
