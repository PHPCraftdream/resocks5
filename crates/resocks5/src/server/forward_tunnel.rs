use std::future::Future;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::config::{NetworkConfig, TlsFragmentConfig};
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
    if !initial.is_empty() {
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
    let mut first = vec![0; 16 * 1024];
    let mut reply = [0; 1024];
    loop {
        let step = async {
            tokio::select! {
                n = client.read(&mut first) => {
                    let n = n?;
                    if n != 0 {
                        send_possibly_fragmented(upstream, &first[..n], &frag.to_spec()).await?;
                    }
                    Ok(true)
                }
                n = upstream.read(&mut reply) => {
                    let n = n?;
                    if n == 0 {
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
    use tokio::io::duplex;

    fn fragmentation() -> TlsFragmentConfig {
        TlsFragmentConfig {
            enabled: true,
            ..Default::default()
        }
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
