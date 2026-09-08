use std::future::Future;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::config::{NetworkConfig, TlsFragmentConfig};
use resocks5_net::connect::tls_fragment::{classify_client_hello, ClientHelloMatch};
use resocks5_net::connect::tls_records::client_hello_is_complete;
use resocks5_net::connect::{send_possibly_fragmented, tunnel::tunnel_with_timeouts};

/// cancel-safe: NO — partial forwarding is terminal; both owned streams close.
pub(crate) async fn forward_tunnel<A, B>(
    mut client: A,
    mut upstream: B,
    initial: Vec<u8>,
    frag: &TlsFragmentConfig,
    network: &NetworkConfig,
) -> anyhow::Result<()>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    let idle = Duration::from_secs(network.tunnel_idle_timeout_sec);
    let lifetime = Duration::from_secs(network.tunnel_max_lifetime_sec);
    let forwarding = async {
        if !prepare_payload(&mut client, &mut upstream, initial, frag, idle).await? {
            return Ok(());
        }
        tunnel_with_timeouts(client, upstream, idle, Duration::ZERO).await?;
        Ok(())
    };
    if lifetime.is_zero() {
        forwarding.await
    } else {
        tokio::time::timeout(lifetime, forwarding)
            .await
            .unwrap_or(Ok(()))
    }
}

/// cancel-safe: NO — callers close both streams when a deadline expires.
async fn prepare_payload<A, B>(
    client: &mut A,
    upstream: &mut B,
    initial: Vec<u8>,
    frag: &TlsFragmentConfig,
    idle: Duration,
) -> anyhow::Result<bool>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    let unfinished_hello = frag.enabled
        && match classify_client_hello(&initial) {
            ClientHelloMatch::Indeterminate => true,
            // R2-17: a confirmed signature does not mean the whole
            // ClientHello has arrived — the SNI usually sits well past
            // byte 6 and may arrive in a later read or record.
            ClientHelloMatch::ClientHello => !client_hello_is_complete(&initial),
            ClientHelloMatch::Other => false,
        };
    if !initial.is_empty() && !unfinished_hello {
        return within_idle(
            idle,
            send_possibly_fragmented(upstream, &initial, &frag.to_spec()),
        )
        .await
        .map(|sent| sent.is_some());
    }
    if !frag.enabled {
        return Ok(true);
    }
    // The client prefix accumulates across multiple reads until the
    // whole ClientHello handshake message is assembled — a single TCP
    // segment often carries only part of a ClientHello (R2-06), and the
    // message itself may span several TLS records (R2-17). Deciding at
    // the 6-byte signature would send every later SNI-bearing byte
    // unfragmented.
    let mut first = initial;
    let mut len = first.len();
    first.resize(16 * 1024, 0);
    let mut reply = [0; 1024];
    loop {
        let step = async {
            tokio::select! {
                n = client.read(&mut first[len..]) => {
                    let n = n?;
                    len += n;
                    // n == 0: client EOF — nothing more will ever arrive,
                    // so decide from what we have. len == cap: the bounded
                    // accumulator cannot take more either; degrade rather
                    // than hang on a pathological oversized hello.
                    let exhausted = n == 0 || len == first.len();
                    let decided = match classify_client_hello(&first[..len]) {
                        ClientHelloMatch::Other => true,
                        // Still inside the 6-byte signature window.
                        ClientHelloMatch::Indeterminate => exhausted,
                        // Signature confirmed: hold until the whole
                        // handshake message is assembled so no later-read
                        // SNI bytes escape unfragmented.
                        ClientHelloMatch::ClientHello => {
                            exhausted || client_hello_is_complete(&first[..len])
                        }
                    };
                    if decided {
                        // Forward the whole accumulated prefix in one
                        // fragmented (or plain) write.
                        if len != 0 {
                            send_possibly_fragmented(upstream, &first[..len], &frag.to_spec())
                                .await?;
                        }
                        return Ok(true);
                    }
                    // Keep accumulating. Safe against an empty read slice:
                    // both undecided states imply len < first.len().
                    Ok(false)
                }
                n = upstream.read(&mut reply) => {
                    let n = n?;
                    if n == 0 {
                        if len != 0 {
                            send_possibly_fragmented(upstream, &first[..len], &frag.to_spec()).await?;
                        }
                        return Ok(true);
                    }
                    client.write_all(&reply[..n]).await?;
                    Ok(false)
                }
            }
        };
        match within_idle(idle, step).await? {
            Some(true) => return Ok(true),
            Some(false) => {}
            // A cancelled write may have sent a prefix; never replay it.
            None => return Ok(false),
        }
    }
}

/// cancel-safe: NO — timeout discards the I/O future; callers close its streams.
async fn within_idle<T>(
    idle: Duration,
    operation: impl Future<Output = anyhow::Result<T>>,
) -> anyhow::Result<Option<T>> {
    if idle.is_zero() {
        return operation.await.map(Some);
    }
    match tokio::time::timeout(idle, operation).await {
        Ok(result) => result.map(Some),
        Err(_) => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use tokio::io::duplex;

    fn fragmentation() -> TlsFragmentConfig {
        TlsFragmentConfig {
            enabled: true,
            ..Default::default()
        }
    }

    fn fragmentation_with_size(size: usize) -> TlsFragmentConfig {
        TlsFragmentConfig {
            enabled: true,
            fragment_size: size,
            ..Default::default()
        }
    }

    /// Records every `poll_write` chunk so a test can assert the exact
    /// fragment boundaries. Never readable: the select! in
    /// `prepare_payload` can never pick its upstream-read arm, so the
    /// client branch is deterministic.
    #[derive(Clone)]
    struct ChunkRecorder(Arc<std::sync::Mutex<Vec<usize>>>);

    #[tokio::test(start_paused = true)]
    async fn partial_prefix_survives_upstream_half_close() {
        let (mut client, client_inner) = duplex(1);
        let (mut upstream, upstream_inner) = duplex(64);
        let task = tokio::spawn(async move {
            forward_tunnel(
                client_inner,
                upstream_inner,
                Vec::new(),
                &fragmentation(),
                &NetworkConfig::default(),
            )
            .await
        });
        client.write_all(b"\x16\x03").await.unwrap();
        upstream.shutdown().await.unwrap();
        assert_eq!(client.read(&mut [0]).await.unwrap(), 0);
        client.write_all(b"payload").await.unwrap();
        client.shutdown().await.unwrap();
        let mut received = Vec::new();
        upstream.read_to_end(&mut received).await.unwrap();
        task.await.unwrap().unwrap();
        assert_eq!(received, b"\x16\x03payload");
    }

    #[tokio::test(start_paused = true)]
    async fn partial_pipelined_signature_is_accumulated() {
        let (mut client, mut reader) = duplex(256);
        let hello = client_hello_with_sni("pipelined.example");
        client.write_all(&hello[5..]).await.unwrap();
        let chunks = Arc::new(std::sync::Mutex::new(Vec::new()));
        let mut recorder = ChunkRecorder(chunks.clone());
        assert!(prepare_payload(
            &mut reader,
            &mut recorder,
            hello[..5].to_vec(),
            &fragmentation_with_size(1),
            Duration::from_secs(1),
        )
        .await
        .unwrap());
        assert_eq!(*chunks.lock().unwrap(), vec![1; hello.len()]);
    }

    #[tokio::test(start_paused = true)]
    async fn fragmentation_allows_server_to_speak_first() {
        let (mut client, client_inner) = duplex(64);
        let (mut upstream, upstream_inner) = duplex(64);
        let task = tokio::spawn(async move {
            forward_tunnel(
                client_inner,
                upstream_inner,
                Vec::new(),
                &fragmentation(),
                &NetworkConfig::default(),
            )
            .await
        });
        upstream.write_all(b"SSH-2.0-test\r\n").await.unwrap();
        let mut banner = [0; 14];
        tokio::time::timeout(Duration::from_secs(1), client.read_exact(&mut banner))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&banner, b"SSH-2.0-test\r\n");
        client.write_all(b"client").await.unwrap();
        let mut reply = [0; 6];
        upstream.read_exact(&mut reply).await.unwrap();
        assert_eq!(&reply, b"client");
        drop(client);
        drop(upstream);
        task.await.unwrap().unwrap();
    }

    impl tokio::io::AsyncWrite for ChunkRecorder {
        fn poll_write(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
            data: &[u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            self.0.lock().unwrap().push(data.len());
            std::task::Poll::Ready(Ok(data.len()))
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

    impl tokio::io::AsyncRead for ChunkRecorder {
        fn poll_read(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
            _buf: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Pending
        }
    }

    #[tokio::test(start_paused = true)]
    async fn split_client_hello_is_still_fragmented() {
        // Backpressure separates the record header from its payload.
        let (mut client, mut client_inner) = duplex(5);
        let chunks = Arc::new(std::sync::Mutex::new(Vec::new()));
        let recorded_chunks = chunks.clone();
        // Well-formed ClientHello record: 20-byte payload = 4-byte
        // handshake header (type + 16-byte declared body) + 16 body
        // bytes. The accumulator now walks the record layer, so the
        // headers must agree with the payload.
        let mut hello = vec![0x16, 0x03, 0x01, 0x00, 0x14, 0x01, 0x00, 0x00, 0x10];
        hello.extend_from_slice(&[0xAA; 16]); // total 25 bytes

        let task = tokio::spawn(async move {
            prepare_payload(
                &mut client_inner,
                &mut ChunkRecorder(chunks),
                Vec::new(),
                &fragmentation_with_size(5),
                Duration::from_secs(10),
            )
            .await
        });

        client.write_all(&hello[..5]).await.unwrap();
        client.write_all(&hello[5..]).await.unwrap();
        assert!(task.await.unwrap().unwrap());

        let recorded = recorded_chunks.lock().unwrap().clone();
        // Every fragment respects fragment_size=5 — with the old single-read
        // detection the first 5 bytes went out as ONE 5-byte chunk.
        assert!(recorded.iter().all(|&n| n <= 5), "chunks: {recorded:?}");
        assert_eq!(recorded.iter().sum::<usize>(), hello.len());
        assert_eq!(recorded, vec![5, 5, 5, 5, 5]);
    }

    #[tokio::test(start_paused = true)]
    async fn upstream_banner_interrupts_partial_prefix_accumulation() {
        let (mut client, client_inner) = duplex(1);
        let (mut upstream, upstream_inner) = duplex(64);
        let network = NetworkConfig {
            tunnel_idle_timeout_sec: 10,
            tunnel_max_lifetime_sec: 0,
            ..Default::default()
        };
        let mut hello = vec![0x16, 0x03, 0x01, 0x00, 0x14, 0x01, 0x00, 0x00, 0x10];
        hello.extend_from_slice(&[0xAA; 16]);

        let task = tokio::spawn(async move {
            forward_tunnel(
                client_inner,
                upstream_inner,
                Vec::new(),
                &fragmentation(),
                &network,
            )
            .await
        });

        // Client starts a hello; the first read is Indeterminate (5 bytes).
        client.write_all(&hello[..5]).await.unwrap();
        // The server speaks while the prefix is mid-accumulation: its
        // banner must be relayed to the client immediately.
        upstream.write_all(b"SSH-2.0-test\r\n").await.unwrap();
        let mut banner = [0; 14];
        tokio::time::timeout(Duration::from_secs(2), client.read_exact(&mut banner))
            .await
            .expect("banner relayed mid-accumulation")
            .unwrap();
        assert_eq!(&banner, b"SSH-2.0-test\r\n");
        // The remainder completes the hello; the whole accumulated prefix
        // must still reach the upstream, byte-for-byte.
        client.write_all(&hello[5..]).await.unwrap();
        let mut seen = vec![0u8; hello.len()];
        tokio::time::timeout(Duration::from_secs(2), upstream.read_exact(&mut seen))
            .await
            .expect("hello forwarded")
            .unwrap();
        // read_exact may coalesce fragments; content and order
        // are what matter here (strict chunk boundaries are TEST 1's job).
        assert_eq!(seen, hello);
        client.shutdown().await.unwrap();
        upstream.shutdown().await.unwrap();
        task.await.unwrap().unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn silent_fragmentation_preface_is_bounded() {
        let (_client, client_inner) = duplex(64);
        let (_upstream, upstream_inner) = duplex(64);
        let network = NetworkConfig {
            tunnel_idle_timeout_sec: 1,
            ..Default::default()
        };
        tokio::time::timeout(
            Duration::from_secs(2),
            forward_tunnel(
                client_inner,
                upstream_inner,
                Vec::new(),
                &fragmentation(),
                &network,
            ),
        )
        .await
        .unwrap()
        .unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn idle_timeout_closes_a_partially_written_client_hello() {
        let (mut client, client_inner) = duplex(256);
        let (mut upstream, upstream_inner) = duplex(1);
        let hello = client_hello_with_sni("blocked.example.org");
        client.write_all(&hello[6..]).await.unwrap();
        let network = NetworkConfig {
            tunnel_idle_timeout_sec: 1,
            tunnel_max_lifetime_sec: 0,
            ..Default::default()
        };
        tokio::time::timeout(
            Duration::from_secs(2),
            forward_tunnel(
                client_inner,
                upstream_inner,
                hello[..6].to_vec(),
                &fragmentation_with_size(4),
                &network,
            ),
        )
        .await
        .expect("idle timeout must close a partially written hello")
        .unwrap();
        let mut received = Vec::new();
        upstream.read_to_end(&mut received).await.unwrap();
        assert_eq!(received, hello[..1]);
    }

    #[tokio::test(start_paused = true)]
    async fn lifetime_covers_blocked_initial_payload() {
        let (_client, client_inner) = duplex(64);
        let (_upstream, upstream_inner) = duplex(1);
        let network = NetworkConfig {
            tunnel_idle_timeout_sec: 0,
            tunnel_max_lifetime_sec: 1,
            ..Default::default()
        };
        tokio::time::timeout(
            Duration::from_secs(2),
            forward_tunnel(
                client_inner,
                upstream_inner,
                b"payload".to_vec(),
                &fragmentation(),
                &network,
            ),
        )
        .await
        .unwrap()
        .unwrap();
    }

    /// A complete, well-formed single-record ClientHello carrying one
    /// SNI host_name extension (same shape as recover_host's builder).
    fn client_hello_with_sni(host: &str) -> Vec<u8> {
        let host = host.as_bytes();
        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]);
        body.extend_from_slice(&[0xAB; 32]);
        body.push(0x00); // empty session_id
        body.extend_from_slice(&0x0002u16.to_be_bytes());
        body.extend_from_slice(&[0x13, 0x01]);
        body.extend_from_slice(&[0x01, 0x00]);
        let entry_len = 1 + 2 + host.len();
        let sni_body_len = 2 + entry_len;
        let ext_len = 4 + sni_body_len;
        body.extend_from_slice(&(ext_len as u16).to_be_bytes());
        body.extend_from_slice(&0x0000u16.to_be_bytes());
        body.extend_from_slice(&(sni_body_len as u16).to_be_bytes());
        body.extend_from_slice(&(entry_len as u16).to_be_bytes());
        body.push(0x00);
        body.extend_from_slice(&(host.len() as u16).to_be_bytes());
        body.extend_from_slice(host);
        let mut rec = vec![0x16, 0x03, 0x01];
        rec.extend_from_slice(&((4 + body.len()) as u16).to_be_bytes());
        rec.push(0x01);
        rec.extend_from_slice(&[
            (body.len() >> 16) as u8,
            (body.len() >> 8) as u8,
            body.len() as u8,
        ]);
        rec.extend_from_slice(&body);
        rec
    }

    #[tokio::test(start_paused = true)]
    async fn sni_bearing_tail_of_split_hello_is_also_fragmented() {
        // R2-17: the 6-byte signature confirms on the first read, but
        // the SNI-carrying bytes arrive only in a later one. The tail
        // must go out through the fragmenting path too, not the plain
        // post-accumulation copy.
        let (mut client, mut client_inner) = duplex(6);
        let chunks = Arc::new(std::sync::Mutex::new(Vec::new()));
        let recorded_chunks = chunks.clone();
        let hello = client_hello_with_sni("tail.example.org");
        assert_eq!(
            resocks5_net::connect::parse_sni(&hello).as_deref(),
            Some("tail.example.org")
        );
        let task = tokio::spawn(async move {
            prepare_payload(
                &mut client_inner,
                &mut ChunkRecorder(chunks),
                Vec::new(),
                &fragmentation_with_size(4),
                Duration::from_secs(10),
            )
            .await
        });

        client.write_all(&hello[..6]).await.unwrap();
        client.write_all(&hello[6..]).await.unwrap();
        assert!(task.await.unwrap().unwrap());

        let recorded = recorded_chunks.lock().unwrap().clone();
        // Every byte — including the late SNI-bearing tail — was sent
        // through the fragmenting path: all chunks respect
        // fragment_size=4. The old signature-only decision sent the
        // first 6 bytes fragmented and the 71-byte tail as ONE chunk.
        assert!(recorded.iter().all(|&n| n <= 4), "chunks: {recorded:?}");
        assert_eq!(recorded.iter().sum::<usize>(), hello.len());
    }

    #[tokio::test(start_paused = true)]
    async fn oversized_hello_degrades_at_the_accumulator_cap() {
        // A hello whose handshake header declares far more than the
        // 16 KiB accumulator can never complete: the cap must forward
        // what was accumulated instead of hanging (graceful degrade).
        let (mut client, mut client_inner) = duplex(64);
        let chunks = Arc::new(std::sync::Mutex::new(Vec::new()));
        let recorded_chunks = chunks.clone();
        let mut hello = vec![0x16, 0x03, 0x01, 0xFF, 0xFF, 0x01, 0xFF, 0xFF, 0xFF];
        hello.resize(16 * 1024, 0xEE);
        let task = tokio::spawn(async move {
            prepare_payload(
                &mut client_inner,
                &mut ChunkRecorder(chunks),
                Vec::new(),
                &fragmentation(),
                Duration::from_secs(10),
            )
            .await
        });
        client.write_all(&hello).await.unwrap();
        drop(client);
        assert!(task.await.unwrap().unwrap());
        let sum: usize = recorded_chunks.lock().unwrap().iter().sum();
        assert_eq!(sum, hello.len());
    }
}
