//! Protocol-agnostic entry point that dispatches to the per-protocol connector.

use std::time::Duration;

use tokio_rustls::TlsConnector;

use crate::connect::upstream_tls::connect_https_proxy;
use crate::connect::{connect_http_proxy, connect_socks5_proxy};
use crate::pool::{AnyUpstream, PoolConfig, ProxyPool};
use crate::types::{ProxyConfig, ProxyProtocol};

/// Connect to `target_addr` through `proxy`, dispatching on its protocol.
///
/// SOCKS5 and HTTP CONNECT return an [`AnyUpstream::Plain`]; HTTPS
/// (TLS-wrapped CONNECT) wraps the stream in TLS and returns
/// [`AnyUpstream::Tls`]. `tls_connector` is required for HTTPS upstreams and
/// ignored otherwise — pass `None` unless the pool contains HTTPS proxies. A
/// ready-made connector is available from
/// [`make_tls_connector`](crate::connect::make_tls_connector).
pub async fn connect_proxy(
    target_addr: &str,
    proxy: &ProxyConfig,
    pool: &ProxyPool,
    handshake_timeout: Duration,
    tls_connector: Option<&TlsConnector>,
) -> anyhow::Result<AnyUpstream> {
    match proxy.protocol {
        ProxyProtocol::Socks5 => {
            let s = connect_socks5_proxy(target_addr, proxy, pool, handshake_timeout).await?;
            Ok(AnyUpstream::Plain(s))
        }
        ProxyProtocol::Http => {
            let s = connect_http_proxy(target_addr, proxy, pool, handshake_timeout).await?;
            Ok(AnyUpstream::Plain(s))
        }
        ProxyProtocol::Https => {
            let connector = tls_connector
                .ok_or_else(|| anyhow::anyhow!("HTTPS upstream requires TLS connector"))?;
            let s =
                connect_https_proxy(target_addr, proxy, pool, handshake_timeout, connector).await?;
            Ok(AnyUpstream::Tls(Box::new(s)))
        }
    }
}

/// Connect to `target_addr` through a single upstream `proxy` without ever
/// constructing a [`ProxyPool`] — the one-shot counterpart of
/// [`connect_proxy`].
///
/// Prefer this over [`connect_proxy`] when calls are independent: a one-off
/// tunnel, a script dialing through exactly one upstream, or any consumer
/// with no rotation and no interest in warm-socket reuse. It delegates to
/// the same per-protocol handshakes (SOCKS5, HTTP CONNECT, HTTPS via
/// `tls_connector`), returns the same [`AnyUpstream`] variants, and fails
/// with the same errors; only the pool plumbing differs.
///
/// The cost is per call: every invocation pays a fresh TCP handshake to the
/// proxy — nothing is pre-warmed or reused across calls — and a throwaway,
/// internally constructed *disabled* [`ProxyPool`] (one that spawns no
/// background tasks and never serves a warm socket) is built and dropped
/// each time. With no shared pool there is also no shared per-upstream
/// concurrency cap; cap your own fan-out if you call this concurrently
/// against the same proxy.
///
/// `connect_timeout` bounds the TCP dial to the proxy; `handshake_timeout`
/// bounds the protocol exchange on top of it.
///
/// # Example
///
/// Dial a one-shot tunnel through a SOCKS5 upstream. `no_run` because it
/// needs a live upstream to execute:
///
/// ```no_run
/// use std::time::Duration;
///
/// use resocks5_net::connect::{connect_proxy_once, parse_proxy_str};
/// use resocks5_net::types::{IP, ProxyProtocol};
///
/// # #[tokio::main]
/// # async fn main() -> anyhow::Result<()> {
/// let proxy = parse_proxy_str("user:pass@203.0.113.7:1080", ProxyProtocol::Socks5, IP::V4)
///     .expect("valid proxy line");
/// let stream = connect_proxy_once(
///     "example.com:80",
///     &proxy,
///     Duration::from_secs(10), // TCP dial timeout
///     Duration::from_secs(10), // SOCKS5 handshake timeout
///     None,                    // TLS connector — only needed for HTTPS upstreams
/// )
/// .await?;
/// drop(stream);
/// # Ok(())
/// # }
/// ```
pub async fn connect_proxy_once(
    target_addr: &str,
    proxy: &ProxyConfig,
    connect_timeout: Duration,
    handshake_timeout: Duration,
    tls_connector: Option<&TlsConnector>,
) -> anyhow::Result<AnyUpstream> {
    // Throwaway disabled pool: `PoolConfig::default()` has `enabled =
    // false`, so no refill task is spawned and no warm socket is ever
    // served — `acquire` falls straight through to a fresh
    // `TcpStream::connect` bounded by `connect_timeout`. The pool lives
    // for this one call and one `acquire`, so its per-upstream cap can
    // never bind.
    let pool = ProxyPool::new(PoolConfig::default(), connect_timeout, 1);
    connect_proxy(target_addr, proxy, &pool, handshake_timeout, tls_connector).await
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    use super::connect_proxy_once;
    use crate::types::{ProxyConfig, ProxyProtocol, IP};

    /// Loopback listener on an ephemeral port plus a `ProxyConfig`
    /// pointing at it, so the client dials a real local socket.
    async fn loopback_proxy(protocol: ProxyProtocol) -> (TcpListener, ProxyConfig) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let config = ProxyConfig {
            protocol,
            ip: IP::V4,
            host: addr.ip().to_string(),
            port: addr.port(),
            user: None,
            password: None,
            is_gate: false,
            gate: None,
        };
        (listener, config)
    }

    #[tokio::test]
    async fn socks5_connects_end_to_end_without_a_pool() {
        let (listener, config) = loopback_proxy(ProxyProtocol::Socks5).await;
        let server = async {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut greeting = [0u8; 3];
            sock.read_exact(&mut greeting).await.unwrap();
            assert_eq!(greeting, [0x05, 0x01, 0x00]);
            sock.write_all(&[0x05, 0x00]).await.unwrap();

            let mut head = [0u8; 4];
            sock.read_exact(&mut head).await.unwrap();
            assert_eq!(head, [0x05, 0x01, 0x00, 0x01]);
            let mut rest = [0u8; 6];
            sock.read_exact(&mut rest).await.unwrap();
            assert_eq!(&rest[..4], &[1, 2, 3, 4]);
            assert_eq!(&rest[4..], &443u16.to_be_bytes());

            sock.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await
                .unwrap();
            sock.write_all(b"once-ok").await.unwrap();
            sock.shutdown().await.unwrap();
        };
        let client = async {
            // No `ProxyPool` constructed anywhere in this test: the
            // entry point must connect with the caller holding none.
            let mut stream = connect_proxy_once(
                "1.2.3.4:443",
                &config,
                Duration::from_secs(2),
                Duration::from_secs(2),
                None,
            )
            .await
            .unwrap();
            let mut payload = Vec::new();
            stream.read_to_end(&mut payload).await.unwrap();
            assert_eq!(payload, b"once-ok");
        };
        tokio::time::timeout(Duration::from_secs(5), async {
            tokio::join!(server, client);
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn http_connects_end_to_end_without_a_pool() {
        let (listener, config) = loopback_proxy(ProxyProtocol::Http).await;
        let server = async {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            while !request.ends_with(b"\r\n\r\n") {
                request.push(sock.read_u8().await.unwrap());
            }
            assert!(request.starts_with(b"CONNECT 1.2.3.4:443 HTTP/1.1\r\n"));
            sock.write_all(b"HTTP/1.1 200 OK\r\n\r\nonce-ok")
                .await
                .unwrap();
            sock.shutdown().await.unwrap();
        };
        let client = async {
            let mut stream = connect_proxy_once(
                "1.2.3.4:443",
                &config,
                Duration::from_secs(2),
                Duration::from_secs(2),
                None,
            )
            .await
            .unwrap();
            let mut payload = Vec::new();
            stream.read_to_end(&mut payload).await.unwrap();
            assert_eq!(payload, b"once-ok");
        };
        tokio::time::timeout(Duration::from_secs(5), async {
            tokio::join!(server, client);
        })
        .await
        .unwrap();
    }
}
