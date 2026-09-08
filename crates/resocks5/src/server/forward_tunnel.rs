use std::future::Future;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::config::{NetworkConfig, TlsFragmentConfig};
use resocks5_net::connect::tls_fragment::{classify_client_hello, ClientHelloMatch};
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
    let partial_signature =
        frag.enabled && classify_client_hello(&initial) == ClientHelloMatch::Indeterminate;
    if !initial.is_empty() && !partial_signature {
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
    // ClientHello signature is decidable — a single TCP segment often
    // carries only part of a ClientHello, and deciding too early would
    // forward the rest unfragmented (R21).
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
                    // n == 0: client EOF — nothing more will ever arrive, so decide
                    // from what we have.
                    let decided = n == 0
                        || classify_client_hello(&first[..len]) != ClientHelloMatch::Indeterminate;
                    if decided {
                        // Forward the whole accumulated prefix in one fragmented (or
                        // plain) write. An Indeterminate tail implies len < 6, and
                        // send_possibly_fragmented forwards that as-is.
                        if len != 0 {
                            send_possibly_fragmented(upstream, &first[..len], &frag.to_spec()).await?;
                        }
                        return Ok(true);
                    }
                    // Still inside the 6-byte signature window: keep accumulating.
                    // Safe against an empty read slice: Indeterminate implies
                    // len < 6 << first.len(), so first[len..] is never empty here.
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
        let (mut client, mut reader) = duplex(64);
        client.write_all(&[0x01]).await.unwrap();
        let chunks = Arc::new(std::sync::Mutex::new(Vec::new()));
        let mut recorder = ChunkRecorder(chunks.clone());
        assert!(prepare_payload(
            &mut reader,
            &mut recorder,
            vec![0x16, 0x03, 0x01, 0, 1],
            &fragmentation_with_size(1),
            Duration::from_secs(1),
        )
        .await
        .unwrap());
        assert_eq!(*chunks.lock().unwrap(), vec![1; 6]);
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

    #[tokio::test]
    async fn split_client_hello_is_still_fragmented() {
        // No start_paused: the two writes must be separated by REAL time so
        // the tunnel's first read sees only the 5-byte record header — the
        // R21 case where the old code forwarded without fragmentation.
        let (mut client, client_inner) = duplex(64);
        let chunks = Arc::new(std::sync::Mutex::new(Vec::new()));
        let recorded_chunks = chunks.clone();
        let network = NetworkConfig {
            tunnel_idle_timeout_sec: 10,
            tunnel_max_lifetime_sec: 0,
            ..Default::default()
        };
        let mut hello = vec![0x16, 0x03, 0x01, 0x00, 0x14, 0x01]; // record hdr + ClientHello type
        hello.extend_from_slice(&[0xAA; 14]); // total 20 bytes

        let task = tokio::spawn(async move {
            forward_tunnel(
                client_inner,
                ChunkRecorder(chunks),
                Vec::new(),
                &fragmentation_with_size(4),
                &network,
            )
            .await
        });

        client.write_all(&hello[..5]).await.unwrap();
        tokio::time::sleep(Duration::from_millis(150)).await;
        client.write_all(&hello[5..]).await.unwrap();
        tokio::time::sleep(Duration::from_millis(150)).await;

        let recorded = recorded_chunks.lock().unwrap().clone();
        // Every fragment respects fragment_size=4 — with the old single-read
        // detection the first 5 bytes went out as ONE 5-byte chunk.
        assert!(recorded.iter().all(|&n| n <= 4), "chunks: {recorded:?}");
        assert_eq!(recorded.iter().sum::<usize>(), hello.len());
        assert_eq!(recorded, vec![4, 4, 4, 4, 4]);
        task.abort();
    }

    #[tokio::test]
    async fn upstream_banner_interrupts_partial_prefix_accumulation() {
        let (mut client, client_inner) = duplex(64);
        let (mut upstream, upstream_inner) = duplex(64);
        let network = NetworkConfig {
            tunnel_idle_timeout_sec: 10,
            tunnel_max_lifetime_sec: 0,
            ..Default::default()
        };
        let mut hello = vec![0x16, 0x03, 0x01, 0x00, 0x14, 0x01];
        hello.extend_from_slice(&[0xAA; 14]);

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
        tokio::time::sleep(Duration::from_millis(100)).await;
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
        task.abort();
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
}
