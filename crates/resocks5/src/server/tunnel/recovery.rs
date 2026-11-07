use std::future::Future;
use std::io;
use std::time::Duration;

use resocks5_net::connect::recover_host::{http_host_might_still_appear, sni_might_still_appear};
use resocks5_net::connect::{parse_http_host, parse_sni};
use resocks5_net::pool::AnyUpstream;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;

const PEEK_MAX: usize = 16 * 1024;
const CLIENT_FIRST_GRACE: Duration = Duration::from_secs(1);

pub(crate) enum RecoveryPeek {
    /// A client prefix to recover the host from.
    Client(Vec<u8>),
    /// Nothing to relay: the client read failed (reset), or no
    /// upstream can be reached / produced a greeting after the
    /// propagated FIN.
    ClientClosed,
    /// The upstream greeted before (or after) the client spoke: relay
    /// the banner and tunnel by IP.
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
        let n = result?;
        if n == 0 {
            // R3-I: a clean EOF with no payload is a client
            // write-half-close, not an abort — keep the session alive
            // through the IP fallback and still relay the greeting.
            return half_closed_upstream(connect_by_ip.await).await;
        }
        return client_prefix(client, &tmp[..n]).await;
    }

    let connect_fut = connect_by_ip;
    tokio::pin!(connect_fut);
    let connected = tokio::select! {
        n = client.read(&mut tmp) => {
            let n = n?;
            if n == 0 {
                // R3-I: the write side finished while the IP dial was
                // still in flight — resume the dial and relay the
                // greeting instead of aborting the session.
                return half_closed_upstream(connect_fut.as_mut().await).await;
            }
            return client_prefix(client, &tmp[..n]).await;
        }
        result = &mut connect_fut => result,
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
            let n = n?;
            if n == 0 {
                // R3-I: the client finished its write side while the
                // already-dialed upstream has not greeted yet —
                // propagate the FIN and still wait for the greeting.
                let _ = upstream.shutdown().await;
                return banner_after_fin(upstream).await;
            }
            drop(upstream);
            client_prefix(client, &tmp[..n]).await
        }
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

/// R3-I: the client's read side returned EOF with no payload. The
/// recovery READ is over, but the session is not: finish (or take)
/// the IP fallback dial, propagate the client's FIN upstream so the
/// target sees the finished request, and relay the greeting under the
/// caller's budget. An unreachable upstream keeps the old clean-close
/// contract.
async fn half_closed_upstream(connected: anyhow::Result<AnyUpstream>) -> io::Result<RecoveryPeek> {
    let mut upstream = match connected {
        Ok(stream) => stream,
        Err(_) => return Ok(RecoveryPeek::ClientClosed),
    };
    let _ = upstream.shutdown().await;
    banner_after_fin(upstream).await
}

/// The client FIN has been propagated upstream: the target has one
/// chance to greet. A target that closes silently — or resets —
/// leaves nothing to relay: `ClientClosed`.
async fn banner_after_fin(mut upstream: AnyUpstream) -> io::Result<RecoveryPeek> {
    let mut banner = [0; 4096];
    match upstream.read(&mut banner).await {
        Ok(n) if n > 0 => Ok(RecoveryPeek::ServerFirst(upstream, banner[..n].to_vec())),
        _ => Ok(RecoveryPeek::ClientClosed),
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
    use tokio::net::{TcpListener, TcpStream};

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

    /// R3-I, grace path: a client EOF with no payload must end the
    /// READ phase but keep the session — the IP fallback is dialed,
    /// its FIN propagated, and the target's greeting comes back as
    /// ServerFirst. Mutation: empty EOF => ClientClosed again (no
    /// dial, no banner).
    #[tokio::test]
    async fn client_eof_during_grace_keeps_the_session_alive() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let target = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            // The propagated FIN is the only thing the target ever sees.
            let mut drain = Vec::new();
            sock.read_to_end(&mut drain).await.unwrap();
            assert!(
                drain.is_empty(),
                "a half-closed client sends no payload: {drain:?}"
            );
            sock.write_all(b"GREETING-10").await.unwrap();
            sock.shutdown().await.unwrap();
        });

        let (mut client, mut reader) = duplex(64);
        client.shutdown().await.unwrap();
        let peek = timeout(
            Duration::from_secs(10),
            peek_recovery(&mut reader, Vec::new(), async move {
                Ok(AnyUpstream::Direct(TcpStream::connect(addr).await.unwrap()))
            }),
        )
        .await
        .expect("the half-close fallback must not hang")
        .unwrap();
        match peek {
            RecoveryPeek::ServerFirst(upstream, banner) => {
                assert_eq!(banner, b"GREETING-10");
                drop(upstream);
            }
            _ => panic!("expected the relayed greeting"),
        }
        target.await.unwrap();
    }

    /// R3-I, post-grace path: a client that stays silent past the
    /// grace window and only then half-closes must resume the
    /// interrupted IP dial and still receive the greeting. Mutation:
    /// EOF during the select dropping the dial => ClientClosed.
    #[tokio::test]
    async fn fin_after_grace_resumes_the_interrupted_ip_dial() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let target = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut drain = Vec::new();
            sock.read_to_end(&mut drain).await.unwrap();
            sock.write_all(b"RESUMED-GREET").await.unwrap();
            sock.shutdown().await.unwrap();
        });

        let (mut client, mut reader) = duplex(64);
        let (dial_started, dial_ready) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = tokio::sync::oneshot::channel();
        let task = peek_recovery(&mut reader, Vec::new(), async move {
            dial_started.send(()).unwrap();
            release_rx.await.unwrap();
            Ok(AnyUpstream::Direct(TcpStream::connect(addr).await.unwrap()))
        });
        tokio::pin!(task);

        // The grace window elapses first (real time, ~1 s), the select
        // starts and the dial future is polled — then held.
        tokio::select! {
            _ = &mut task => panic!("the peek must wait for the held dial"),
            started = dial_ready => started.unwrap(),
        }
        // Now the client half-closes: the EOF must win the select,
        // resume the dial, propagate the FIN and bring the greeting
        // back.
        client.shutdown().await.unwrap();
        release_tx.send(()).unwrap();
        let peek = tokio::time::timeout(Duration::from_secs(10), task)
            .await
            .expect("the resumed dial must complete")
            .unwrap();
        match peek {
            RecoveryPeek::ServerFirst(upstream, banner) => {
                assert_eq!(banner, b"RESUMED-GREET");
                drop(upstream);
            }
            _ => panic!("expected the relayed greeting"),
        }
        target.await.unwrap();
    }

    /// R3-I, connected path: the client half-closes while the already
    /// dialed upstream has not greeted yet — the FIN must be
    /// propagated through the live upstream and the greeting still
    /// relayed. Mutation: dropping the upstream on EOF => ClientClosed
    /// again.
    #[tokio::test]
    async fn fin_with_live_upstream_propagates_and_relays() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let target = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            // The target waits for the client's request; the propagated
            // FIN is what unblocks it.
            let mut drain = Vec::new();
            sock.read_to_end(&mut drain).await.unwrap();
            sock.write_all(b"UNBLOCKED").await.unwrap();
            sock.shutdown().await.unwrap();
        });

        let (mut client, mut reader) = duplex(64);
        let (dialed_tx, dialed_rx) = tokio::sync::oneshot::channel();
        let task = peek_recovery(&mut reader, Vec::new(), async move {
            let upstream = AnyUpstream::Direct(TcpStream::connect(addr).await.unwrap());
            dialed_tx.send(()).unwrap();
            Ok(upstream)
        });
        tokio::pin!(task);
        // The client stays silent past the grace window (real time, ~1 s);
        // once the upstream is dialed, the client half-closes and the
        // greeting must still come back. Real sockets: no paused clock
        // (it would auto-advance while the I/O is still in flight).
        tokio::select! {
            _ = &mut task => panic!("the peek must wait for the client or the upstream"),
            dialed = dialed_rx => dialed.unwrap(),
        }
        client.shutdown().await.unwrap();
        let peek = tokio::time::timeout(Duration::from_secs(10), task)
            .await
            .expect("the greeting must still be relayed")
            .unwrap();
        match peek {
            RecoveryPeek::ServerFirst(upstream, banner) => {
                assert_eq!(banner, b"UNBLOCKED");
                drop(upstream);
            }
            _ => panic!("expected the relayed greeting"),
        }
        target.await.unwrap();
    }

    /// R3-I contract edge: an EOF with NO reachable upstream keeps the
    /// old clean-close outcome — `ClientClosed`, no greeting, no hang.
    #[tokio::test(start_paused = true)]
    async fn client_eof_without_upstream_still_ends_cleanly() {
        let (mut client, mut reader) = duplex(64);
        client.shutdown().await.unwrap();
        let unreachable: anyhow::Result<AnyUpstream> = Err(anyhow::anyhow!("upstream unreachable"));
        let peek = timeout(
            Duration::from_secs(10),
            peek_recovery(&mut reader, Vec::new(), async { unreachable }),
        )
        .await
        .expect("the unreachable-fallback path must not hang")
        .unwrap();
        assert!(matches!(peek, RecoveryPeek::ClientClosed));
    }

    /// R3-I contract edge: a genuinely failed client read (RST-shaped
    /// error) still aborts the peek with that error — it is not mapped
    /// onto the half-close path.
    #[tokio::test(start_paused = true)]
    async fn client_read_error_propagates_instead_of_half_close() {
        struct ResetReader;
        impl AsyncRead for ResetReader {
            fn poll_read(
                self: std::pin::Pin<&mut Self>,
                _cx: &mut std::task::Context<'_>,
                _buf: &mut tokio::io::ReadBuf<'_>,
            ) -> std::task::Poll<io::Result<()>> {
                std::task::Poll::Ready(Err(std::io::Error::from(
                    std::io::ErrorKind::ConnectionReset,
                )))
            }
        }
        let mut reader = ResetReader;
        let err = peek_recovery(
            &mut reader,
            Vec::new(),
            std::future::pending::<anyhow::Result<AnyUpstream>>(),
        )
        .await
        .err()
        .expect("the reset must propagate as an error");
        assert_eq!(err.kind(), std::io::ErrorKind::ConnectionReset);
    }
}
