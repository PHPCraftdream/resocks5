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
    data.len() >= 6 && data[0] == 0x16 && data[1] == 0x03 && data[5] == 0x01
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
pub async fn send_possibly_fragmented<W>(
    writer: &mut W,
    data: &[u8],
    cfg: &FragmentSpec,
) -> anyhow::Result<()>
where
    W: AsyncWriteExt + Unpin,
{
    if !cfg.enabled || !is_tls_client_hello(data) {
        writer.write_all(data).await?;
        return Ok(());
    }
    let chunk_size = cfg.fragment_size.max(1);
    for chunk in data.chunks(chunk_size) {
        writer.write_all(chunk).await?;
        writer.flush().await?;
        if cfg.delay_ms > 0 {
            tokio::time::sleep(Duration::from_millis(cfg.delay_ms)).await;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

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
        send_possibly_fragmented(&mut w, &hello, &cfg)
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
        send_possibly_fragmented(&mut buf, &hello, &cfg)
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
        send_possibly_fragmented(&mut buf, &data, &cfg)
            .await
            .unwrap();
        assert_eq!(buf, data);
    }
}
