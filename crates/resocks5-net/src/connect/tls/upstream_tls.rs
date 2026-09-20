//! HTTPS (TLS-wrapped CONNECT) upstream connector, plus a default
//! [`TlsConnector`] rooted at the Mozilla `webpki-roots` trust store.

use std::sync::Arc;
use std::time::Duration;

use anyhow::anyhow;
use tokio::time::{timeout_at, Instant};
use tokio_rustls::client::TlsStream;
use tokio_rustls::TlsConnector;

use crate::connect::connect_http_proxy::http_connect_handshake;
use crate::connect::tls_fragment::ProgressReportingWriter;
use crate::pool::proxy_pool::upstream_endpoint;
use crate::pool::{ProxyPool, UpstreamStream};
use crate::types::ProxyConfig;

/// Establish a tunnel to `target_addr` through an HTTPS proxy.
///
/// Performs the TLS handshake to the proxy itself (using `proxy.host` as the
/// server name), then runs an HTTP `CONNECT` over the encrypted stream.
/// `handshake_timeout` bounds the whole TLS + CONNECT exchange.
///
/// The acquired transport is wrapped in a [`ProgressReportingWriter`], so
/// write progress confirmed below the TLS layer is reported into any
/// enclosing confirmed-progress scope (idle-bounded sends, tunnel activity
/// tracking). The TLS and CONNECT handshakes themselves run outside any
/// such scope, where the wrapper is a pure pass-through.
pub async fn connect_https_proxy(
    target_addr: &str,
    proxy: &ProxyConfig,
    pool: &ProxyPool,
    handshake_timeout: Duration,
    tls_connector: &TlsConnector,
) -> anyhow::Result<TlsStream<ProgressReportingWriter<UpstreamStream>>> {
    let stream = pool.acquire(proxy).await?;
    let endpoint = upstream_endpoint(proxy);

    let server_name = rustls::pki_types::ServerName::try_from(proxy.host.clone())
        .map_err(|_| anyhow!("[HTTPS] invalid server name: {}", proxy.host))?;

    let deadline = Instant::now() + handshake_timeout;
    let mut tls_stream = match timeout_at(
        deadline,
        tls_connector.connect(server_name, ProgressReportingWriter::new(stream)),
    )
    .await
    {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            return Err(anyhow!("[HTTPS] TLS handshake to {}: {}", endpoint, e));
        }
        Err(_) => {
            return Err(anyhow!(
                "[HTTPS] TLS handshake timeout ({}s) to {}",
                handshake_timeout.as_secs(),
                endpoint
            ));
        }
    };

    let result = timeout_at(
        deadline,
        http_connect_handshake(&mut tls_stream, target_addr, proxy),
    )
    .await;

    match result {
        Ok(Ok(())) => Ok(tls_stream),
        Ok(Err(e)) => Err(e),
        Err(_) => Err(anyhow!(
            "[HTTPS] CONNECT handshake timeout ({}s) to {}",
            handshake_timeout.as_secs(),
            endpoint
        )),
    }
}

/// Build a [`TlsConnector`] rooted at the Mozilla `webpki-roots` trust store.
///
/// Convenience for callers without their own rustls config — both the
/// library example and the binary's HTTPS-upstream path use this.
pub fn make_tls_connector() -> TlsConnector {
    let root_store =
        rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    TlsConnector::from(Arc::new(config))
}

#[cfg(test)]
mod tests {
    //! End-to-end acceptance tests for the HTTPS upstream path: a real TLS
    //! server (tokio-rustls `TlsAcceptor`) over a real TCP loopback socket,
    //! driven through the real [`connect_proxy`] construction site, so the
    //! stream under test is a genuine
    //! `AnyUpstream::Tls(Box<TlsStream<ProgressReportingWriter<UpstreamStream>>>)`
    //! exactly as produced for a live HTTPS proxy.
    //!
    //! The loopback transport is deliberately strangled to create real
    //! backpressure: the payload (~1.5 MB in both tests, sent as 60 KB
    //! fragments on the send test) is far larger than the kernel socket
    //! pipe can absorb, and the peer drains at 8 KB / 40 ms (~200 KB/s),
    //! so the total send spans ~7.5 s — past the 5 s idle windows below
    //! — while flushes keep resolving with real bytes landing
    //! underneath. On this stack confirmed progress surfaces as
    //! drain completions (tokio-rustls writes whole records; a partially
    //! drained loopback socket stays not-writable until the outstanding
    //! ciphertext fits again), so the pacing keeps every flush well inside
    //! one idle window while the send as a whole outlasts it.
    //! (Kernel buffers are additionally shrunk best-effort — 1024 bytes
    //! on the listener, 2048 on the client's send side *through*
    //! [`AnyUpstream::as_tcp`], which also proves the reach-through digs
    //! `TlsStream` → `ProgressReportingWriter` → `UpstreamStream`.)
    //! That drip is the acceptance mechanism: with the
    //! `ProgressReportingWriter` inside `AnyUpstream::Tls`, confirmed
    //! progress renews the window; neuter the instrumentation and both
    //! tests fail (the send is killed as `Stalled`, the tunnel is torn down
    //! by the idle bound).

    use super::*;

    use base64::{engine::general_purpose, Engine as _};
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    use socket2::{Domain, Protocol, SockRef, Socket, Type};
    use std::net::SocketAddr;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use crate::connect::connect_proxy::connect_proxy;
    use crate::connect::tls_fragment::{send_possibly_fragmented, FragmentSpec, SendProgress};
    use crate::connect::tunnel::tunnel_with_timeouts;
    use crate::pool::{AnyUpstream, PoolConfig};
    use crate::types::{ProxyProtocol, IP};

    /// Throwaway test PKI (DER, EC P-256), generated for these tests and    /// Throwaway test PKI (DER, EC P-256), generated for these tests and
    /// committed as constants so they need no external files. It protects
    /// nothing and is not a secret — it exists only so the client can
    /// trust the local test server. `CA_DER_B64` is a self-signed CA
    /// (basicConstraints CA:TRUE, keyCertSign); `CERT_DER_B64` is a leaf
    /// signed by it (CA:FALSE, serverAuth, SAN IP 127.0.0.1, valid
    /// 2026-09-20 .. 2126-08-27) — rustls/webpki rejects a CA cert
    /// presented as an end-entity (`CaUsedAsEndEntity`), so the server
    /// must present the leaf, never the CA.
    const CA_DER_B64: &str = "MIIBhDCCASqgAwIBAgIUAjadSOhZ88BoryxZr19PHzoW2pAwCgYIKoZIzj0EAwIwHzEdMBsGA1UEAwwUcmVzb2NrczUtZTJlLXRlc3QtY2EwIBcNMjYwOTIwMDkxNTU2WhgPMjEyNjA4MjcwOTE1NTZaMB8xHTAbBgNVBAMMFHJlc29ja3M1LWUyZS10ZXN0LWNhMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEu8MP8l2koU6aTqsYyYZOhFqlpHdf3KWj7gRzKABaD6MgZ09s887yCClMlFNlfY8WjBdPL9S9+YmDg3/hyy1hraNCMEAwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAQYwHQYDVR0OBBYEFMjW7f3pxKR/REQSWh2SOWJ5qw6nMAoGCCqGSM49BAMCA0gAMEUCIGvkeW4xCBwhAd9ajXjRZCOkO5NSbW9cW+y4Zc1gNZY0AiEA7J3L4pKAPgzg8S5VtMLpmHj237rGUDaz4jX80ZVASu0=";

    /// Leaf certificate signed by [`CA_DER_B64`] (SAN: IP 127.0.0.1).
    const CERT_DER_B64: &str = "MIIBvzCCAWWgAwIBAgIUAw3r4+wsr/gAPVt45r5qMLXhj2EwCgYIKoZIzj0EAwIwHzEdMBsGA1UEAwwUcmVzb2NrczUtZTJlLXRlc3QtY2EwIBcNMjYwOTIwMDkxNTU2WhgPMjEyNjA4MjcwOTE1NTZaMBQxEjAQBgNVBAMMCTEyNy4wLjAuMTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABO91UpVcmOKS/Wp6EyAY4x/ehamAScKtW6Skf2KxOuG9gT629k9VGkN6SmIBo7DZYOowphF41Jmc9xnWC6nBez+jgYcwgYQwDAYDVR0TAQH/BAIwADAOBgNVHQ8BAf8EBAMCB4AwEwYDVR0lBAwwCgYIKwYBBQUHAwEwDwYDVR0RBAgwBocEfwAAATAdBgNVHQ4EFgQUCILfr8uACkvSMlrxzX3K6JZRpRMwHwYDVR0jBBgwFoAUyNbt/enEpH9ERBJaHZI5YnmrDqcwCgYIKoZIzj0EAwIDSAAwRQIhAKFgl50UiBt8OhQTobthi2lRUmcYwp0Ha12UpVPwzEHdAiBwyO+mjW/7X9iqU+3/f71fE3REVGvsvURWoNeCM+tshA==";

    /// PKCS#8 (DER) private key matching `CERT_DER_B64` — a PKCS#8
    /// `PrivateKeyInfo` (`SEQUENCE` / version 0 / `id-ecPublicKey`), the
    /// encoding rustls/ring actually parses.
    const KEY_DER_B64: &str = "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgz+ybquXKp7FsKDf8x75BqQG33PWd87U5ArAEx8RbGw6hRANCAATvdVKVXJjikv1qehMgGOMf3oWpgEnCrVukpH9isTrhvYE+tvZPVRpDekpiAaOw2WDqMKYReNSZnPcZ1gupwXs/";

    /// Loopback listener with small (1024-byte) kernel buffers — a
    /// best-effort pipe constraint; the guaranteed backpressure comes
    /// from the oversized payload vs. whatever pipe the platform keeps.
    fn small_buffer_listener() -> tokio::net::TcpListener {
        let socket = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP)).unwrap();
        socket.set_recv_buffer_size(1024).unwrap();
        socket.set_send_buffer_size(1024).unwrap();
        socket
            .bind(&socket2::SockAddr::from(
                "127.0.0.1:0".parse::<SocketAddr>().unwrap(),
            ))
            .unwrap();
        socket.listen(1).unwrap();
        let std_listener = std::net::TcpListener::from(socket);
        std_listener.set_nonblocking(true).unwrap();
        tokio::net::TcpListener::from_std(std_listener).unwrap()
    }

    /// The local HTTPS proxy: TLS-accepts one connection, reads the
    /// `CONNECT` request up to the header terminator, answers
    /// `200 Connection established`, then DRIPS — at most `drip_chunk`
    /// bytes every `drip_delay` until EOF, then sends its own TLS
    /// `close_notify` (no application-data reply). rustls treats a bare
    /// TCP close as an error (`UnexpectedEof`), not a clean end of
    /// stream, so this explicit shutdown is required even though nothing
    /// is written back. The whole body is bounded by a 30 s timeout so a
    /// regression fails fast instead of hanging the suite.
    async fn run_dripping_tls_proxy(
        listener: tokio::net::TcpListener,
        acceptor: tokio_rustls::TlsAcceptor,
        drip_chunk: usize,
        drip_delay: Duration,
    ) -> anyhow::Result<Vec<u8>> {
        tokio::time::timeout(Duration::from_secs(30), async move {
            let (accepted, _) = listener.accept().await?;
            // Accepted sockets inherit the listener's buffers on Windows;
            // shrink again for the platforms that don't inherit.
            let _ = SockRef::from(&accepted).set_recv_buffer_size(1024);
            let mut tls = acceptor.accept(accepted).await?;

            let mut request = Vec::new();
            while !request.ends_with(b"\r\n\r\n") {
                let mut byte = [0u8; 1];
                let n = tls.read(&mut byte).await?;
                anyhow::ensure!(n > 0, "proxy closed before CONNECT request completed");
                request.push(byte[0]);
            }
            tls.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                .await?;
            tls.flush().await?;

            // The deliberate slow drain: target rate is `drip_chunk` bytes
            // per `drip_delay`. The sleep is scaled to the bytes actually
            // read this call, not a flat per-call delay — the underlying
            // TCP stack is free to deliver fewer bytes per `read()` than
            // `drip_chunk` (record boundaries, segment sizes), and a flat
            // per-call sleep would then inflate the total drain time far
            // past the intended rate (observed: a real 30s test-harness
            // timeout on some platforms with a flat per-call sleep).
            let mut collected = Vec::new();
            let mut chunk = vec![0u8; drip_chunk];
            loop {
                let n = tls.read(&mut chunk).await?;
                if n == 0 {
                    break;
                }
                collected.extend_from_slice(&chunk[..n]);
                tokio::time::sleep(drip_delay.mul_f64(n as f64 / drip_chunk as f64)).await;
            }

            tls.shutdown().await?;
            Ok(collected)
        })
        .await
        .expect("dripping TLS proxy must finish well within 30s")
    }

    /// Everything both tests share: build the throwaway TLS server config
    /// and the client connector that trusts the embedded cert, start the
    /// dripping proxy, connect through the REAL production construction
    /// site (`connect_proxy` dispatching `ProxyProtocol::Https`), assert
    /// the result took the `AnyUpstream::Tls` variant, then shrink the
    /// client socket's send buffer and set NODELAY *through* the
    /// `AnyUpstream` reach-through. Returns the connected upstream plus
    /// the server task handle (its output is everything collected until
    /// EOF).
    async fn connected_tls_upstream(
        drip_chunk: usize,
        drip_delay: Duration,
    ) -> (
        AnyUpstream,
        tokio::task::JoinHandle<anyhow::Result<Vec<u8>>>,
    ) {
        let cert = CertificateDer::from(general_purpose::STANDARD.decode(CERT_DER_B64).unwrap());
        let ca_cert = CertificateDer::from(general_purpose::STANDARD.decode(CA_DER_B64).unwrap());
        let key_der = general_purpose::STANDARD.decode(KEY_DER_B64).unwrap();

        let server_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![cert.clone()],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_der)),
            )
            .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));

        let listener = small_buffer_listener();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(run_dripping_tls_proxy(
            listener, acceptor, drip_chunk, drip_delay,
        ));

        let mut roots = rustls::RootCertStore::empty();
        roots.add(ca_cert).unwrap();
        let connector = TlsConnector::from(Arc::new(
            rustls::ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth(),
        ));

        let pool = ProxyPool::new(
            PoolConfig {
                enabled: false,
                ..Default::default()
            },
            Duration::from_secs(5),
            4,
        );
        let proxy = ProxyConfig {
            protocol: ProxyProtocol::Https,
            ip: IP::V4,
            host: "127.0.0.1".into(),
            port,
            user: None,
            password: None,
            is_gate: false,
            gate: None,
        };

        let upstream = connect_proxy(
            "example.org:443",
            &proxy,
            &pool,
            Duration::from_secs(5),
            Some(&connector),
        )
        .await
        .unwrap();
        assert!(
            matches!(&upstream, AnyUpstream::Tls(_)),
            "the HTTPS path must produce AnyUpstream::Tls"
        );

        // Best-effort send-buffer shrink through the new reach-through —
        // proves as_tcp() digs through TlsStream -> ProgressReportingWriter
        // -> UpstreamStream (the guaranteed backpressure is the oversized
        // payload vs. the kernel pipe, not these buffers). Then prove the
        // set_nodelay reach-through too.
        let tcp = upstream
            .as_tcp()
            .expect("AnyUpstream::Tls exposes its innermost socket");
        SockRef::from(tcp).set_send_buffer_size(2048).unwrap();
        upstream.set_nodelay(true).unwrap();

        (upstream, server)
    }

    /// Test A: a fragmented, hello-shaped send through the real
    /// `AnyUpstream::Tls` must NOT be killed as `Stalled` while the
    /// transport drips.
    ///
    /// ~1.5 MB of ClientHello-shaped payload — far more than the kernel
    /// socket pipe can buffer — is sent in 60 KB fragments under a 5 s
    /// idle window, while the peer drains at 8 KB / 40 ms (~200 KB/s), so
    /// the whole send spans ~7.5 s — past idle in total — while every
    /// fragment's flush keeps resolving with real bytes landing. With
    /// confirmed progress reported from below the TLS layer the send must
    /// complete — not disconnect as `Stalled` — and it must genuinely
    /// have ridden the slow drain (>= 6 s), not collapsed into the kernel
    /// buffers. After the send, the client drops the stream so the
    /// server sees FIN and exits its drip loop; the server's collected
    /// bytes must equal the payload byte-for-byte (reordering or
    /// corruption cannot pass).
    /// Multi-thread runtime: same reason as the tunnel test below — the
    /// drip and the send must not share one starvable worker thread.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn fragmented_send_through_real_tls_upstream_survives_slow_drip() {
        let (mut upstream, server) =
            connected_tls_upstream(8 * 1024, Duration::from_millis(40)).await;

        let mut payload = vec![0x16, 0x03, 0x01, 0x3E, 0x80, 0x01];
        payload.extend((0..1_535_994u32).map(|i| (i & 0xFF) as u8));

        let spec = FragmentSpec {
            enabled: true,
            fragment_size: 60 * 1024,
            delay_ms: 0,
        };

        let start = tokio::time::Instant::now();
        let outcome =
            send_possibly_fragmented(&mut upstream, &payload, &spec, Duration::from_secs(5))
                .await
                .unwrap();
        let elapsed = start.elapsed();

        assert_eq!(
            outcome,
            SendProgress::Completed,
            "steady confirmed progress must renew the idle window, got {outcome:?} after {elapsed:?}"
        );
        assert!(
            elapsed >= Duration::from_secs(6),
            "the send must ride the 8KB/40ms drain, not collapse into kernel buffers: {elapsed:?}"
        );

        // close_notify so the server's drip loop sees a clean EOF (a bare
        // TCP drop surfaces in rustls as a missing-close_notify error).
        upstream.shutdown().await.unwrap();
        let collected = server.await.unwrap().unwrap();
        assert_eq!(
            collected, payload,
            "server must receive the payload byte-for-byte"
        );
    }

    /// Test B: a steady-state tunnel through the real `AnyUpstream::Tls`
    /// must survive the slow drain — confirmed write progress counts as
    /// tunnel activity.
    ///
    /// ~1.5 MB flows from a `duplex` feeder through
    /// [`tunnel_with_timeouts`] (5 s idle bound) into the TLS upstream,
    /// which can only drain at 8 KB / 40 ms (~200 KB/s). The idle bound
    /// fires many times over during the drain; it must never tear the
    /// tunnel down, because the `ProgressReportingWriter` below the TLS
    /// layer keeps confirming bytes into the tunnel's shared progress sink
    /// and `Tracked::poll_flush` records that as activity. `feeder.write_all`
    /// itself is the acceptance check: the duplex buffer is only 64 KB, so
    /// completing it requires the tunnel to keep draining client -> upstream
    /// for the whole ~7.5 s drain without being torn down; a premature
    /// idle-teardown would drop `client_half` and surface as a write error
    /// here, not a hang. The server drips until EOF and its own bare
    /// connection drop (no reply needed) then lets the tunnel's other
    /// direction finish too, so the tunnel task itself also ends cleanly.
    ///
    /// Multi-thread runtime: the dripping server task and the tunnel must
    /// progress independently of one another, so a scheduling stall of the
    /// single current-thread worker (this box runs sibling builds) cannot
    /// burn through the idle window without any task getting polled.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn steady_state_tunnel_through_real_tls_upstream_survives_slow_drip() {
        let (upstream, server) = connected_tls_upstream(8 * 1024, Duration::from_millis(40)).await;
        let data: Vec<u8> = (0..1_572_864u32).map(|i| (i * 7 % 256) as u8).collect();

        let (mut feeder, client_half) = tokio::io::duplex(64 * 1024);
        let tunnel = tokio::spawn(tunnel_with_timeouts(
            client_half,
            upstream,
            Duration::from_secs(5),
            Duration::ZERO,
        ));

        feeder.write_all(&data).await.unwrap();
        feeder.shutdown().await.unwrap();

        let collected = server.await.unwrap().unwrap();
        assert_eq!(
            collected, data,
            "server must receive the tunneled data byte-for-byte"
        );
        let result = tunnel.await.unwrap();
        assert!(result.is_ok(), "tunnel must end cleanly, got {result:?}");
    }

    /// Test C: the bounded-teardown twin. A peer that never reads jams the
    /// transport with zero confirmed progress, so the send must end as
    /// `Stalled` after roughly one idle window — promptly, and without
    /// hanging — through the same real `AnyUpstream::Tls` path. Together
    /// with the two survive tests this pins both sides of the contract:
    /// genuine stalls disconnect boundedly, slow-but-progressing drains
    /// complete.
    ///
    /// The payload is ~20 MB: `small_buffer_listener`'s tiny requested
    /// socket buffers are best-effort only (observed on macOS: the kernel
    /// does not honor them down to the requested 1-2 KB, leaving enough
    /// real buffering that a merely oversized-for-1024-bytes payload
    /// never experiences genuine backpressure and the send falsely
    /// completes). 20 MB comfortably exceeds any platform's real default
    /// or auto-tuned socket buffer capacity, so the never-reading peer
    /// guarantees a real stall regardless of what the OS actually granted.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn stalled_send_through_real_tls_upstream_is_bounded() {
        let (mut upstream, server) =
            connected_tls_upstream(4 * 1024, Duration::from_secs(3600)).await;

        let mut payload = vec![0x16, 0x03, 0x01, 0x3E, 0x80, 0x01];
        payload.extend((0..20_000_000u32).map(|i| (i & 0xFF) as u8));

        let spec = FragmentSpec {
            enabled: true,
            fragment_size: 60 * 1024,
            delay_ms: 0,
        };

        let start = tokio::time::Instant::now();
        let outcome =
            send_possibly_fragmented(&mut upstream, &payload, &spec, Duration::from_secs(5))
                .await
                .unwrap();
        let elapsed = start.elapsed();

        assert_eq!(
            outcome,
            SendProgress::Stalled,
            "a never-reading peer must stall the send, got {outcome:?} after {elapsed:?}"
        );
        assert!(
            elapsed >= Duration::from_secs(4) && elapsed <= Duration::from_secs(15),
            "the stall must be bounded by about one idle window: {elapsed:?}"
        );

        // The server task parks on its 3600 s drip sleep; drop the handle
        // (aborting it) instead of waiting the 30 s harness timeout out.
        drop(server);
        drop(upstream);
    }
}
