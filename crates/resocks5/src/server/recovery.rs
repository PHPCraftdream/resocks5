use std::future::Future;
use std::io;
use std::time::Duration;

use resocks5_net::connect::recover_host::{http_host_might_still_appear, sni_might_still_appear};
use resocks5_net::connect::{parse_http_host, parse_sni};
use resocks5_net::pool::AnyUpstream;
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::time::timeout;

const PEEK_MAX: usize = 16 * 1024;
const CLIENT_FIRST_GRACE: Duration = Duration::from_secs(1);

pub(crate) enum RecoveryPeek {
    Client(Vec<u8>),
    ClientClosed,
    ServerFirst(AnyUpstream, Vec<u8>),
}

/// cancel-safe: NO — consumed bytes are owned by this future; callers close on timeout.
pub(crate) async fn read_recovery_prefix<R: AsyncRead + Unpin>(
    client: &mut R,
    mut buf: Vec<u8>,
) -> io::Result<Option<Vec<u8>>> {
    let mut tmp = [0; 4096];
    loop {
        if parse_sni(&buf).is_some()
            || parse_http_host(&buf).is_some()
            || (!sni_might_still_appear(&buf) && !http_host_might_still_appear(&buf))
            || buf.len() >= PEEK_MAX
        {
            return Ok(if buf.is_empty() { None } else { Some(buf) });
        }
        let remaining = (PEEK_MAX - buf.len()).min(tmp.len());
        let n = client.read(&mut tmp[..remaining]).await?;
        if n == 0 {
            return Ok(if buf.is_empty() { None } else { Some(buf) });
        }
        buf.extend_from_slice(&tmp[..n]);
    }
}

async fn client_prefix<R: AsyncRead + Unpin>(
    client: &mut R,
    seed: &[u8],
) -> io::Result<RecoveryPeek> {
    if seed.is_empty() {
        return Ok(RecoveryPeek::ClientClosed);
    }
    read_recovery_prefix(client, seed.to_vec())
        .await
        .map(|prefix| prefix.map_or(RecoveryPeek::ClientClosed, RecoveryPeek::Client))
}

/// cancel-safe: NO — cancellation closes any owned upstream and discards the prefix.
/// The caller supplies the deadline for this entire operation.
pub(crate) async fn peek_recovery<R, F>(
    client: &mut R,
    initial: Vec<u8>,
    connect_by_ip: F,
) -> io::Result<RecoveryPeek>
where
    R: AsyncRead + Unpin,
    F: Future<Output = anyhow::Result<AnyUpstream>>,
{
    if !initial.is_empty() {
        return read_recovery_prefix(client, initial)
            .await
            .map(|prefix| prefix.map_or(RecoveryPeek::ClientClosed, RecoveryPeek::Client));
    }
    let mut tmp = [0; 4096];
    if let Ok(result) = timeout(CLIENT_FIRST_GRACE, client.read(&mut tmp)).await {
        return client_prefix(client, &tmp[..result?]).await;
    }

    let connected = tokio::select! {
        n = client.read(&mut tmp) => return client_prefix(client, &tmp[..n?]).await,
        result = connect_by_ip => result,
    };
    let mut upstream = match connected {
        Ok(stream) => stream,
        Err(_) => {
            return read_recovery_prefix(client, Vec::new())
                .await
                .map(|prefix| prefix.map_or(RecoveryPeek::ClientClosed, RecoveryPeek::Client));
        }
    };
    let mut banner = [0; 4096];
    tokio::select! {
        n = client.read(&mut tmp) => {
            drop(upstream);
            client_prefix(client, &tmp[..n?]).await
        },
        n = upstream.read(&mut banner) => match n {
            Ok(n) if n > 0 => Ok(RecoveryPeek::ServerFirst(upstream, banner[..n].to_vec())),
            _ => {
                drop(upstream);
                read_recovery_prefix(client, Vec::new()).await
                    .map(|prefix| prefix.map_or(RecoveryPeek::ClientClosed, RecoveryPeek::Client))
            },
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    };
    use tokio::io::{duplex, AsyncWriteExt};

    struct DropFlag(Arc<AtomicBool>);
    impl Drop for DropFlag {
        fn drop(&mut self) {
            self.0.store(true, Ordering::Relaxed);
        }
    }

    #[tokio::test(start_paused = true)]
    async fn late_client_payload_interrupts_a_stalled_ip_connect() {
        let (mut client, mut reader) = duplex(128);
        let (started, ready) = tokio::sync::oneshot::channel();
        let cancelled = Arc::new(AtomicBool::new(false));
        let flag = cancelled.clone();
        let mut task = tokio::spawn(async move {
            peek_recovery(&mut reader, Vec::new(), async move {
                let _guard = DropFlag(flag);
                started.send(()).unwrap();
                std::future::pending::<anyhow::Result<AnyUpstream>>().await
            })
            .await
        });
        ready.await.unwrap();
        let request = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        client.write_all(request).await.unwrap();
        let received = timeout(Duration::from_secs(1), &mut task).await;
        if received.is_err() {
            task.abort();
            let _ = task.await;
        }
        let peek = received
            .expect("IP connect blocked a complete client prefix")
            .unwrap()
            .unwrap();
        match peek {
            RecoveryPeek::Client(bytes) => assert_eq!(bytes, request),
            _ => panic!("expected the client payload"),
        }
        assert!(cancelled.load(Ordering::Relaxed));
    }
}
