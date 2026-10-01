//! Protocol-agnostic entry points: the pool-free `connect_proxy_once` and,
//! with the `pool` feature, the pool-taking `connect_proxy` dispatcher.

use std::time::Duration;

#[cfg(feature = "tls")]
pub use tokio_rustls::TlsConnector;

use crate::connect::dial::{dial, DialOptions};
use crate::connect::host_port::HostPort;
#[cfg(all(feature = "pool", feature = "tls"))]
use crate::connect::upstream_tls::connect_https_proxy;
use crate::connect::AnyUpstream;
#[cfg(feature = "pool")]
use crate::connect::{connect_http_proxy, connect_socks5_proxy};
use crate::error::ConnectError;
#[cfg(feature = "pool")]
use crate::pool::ProxyPool;
use crate::types::ProxyConfig;
#[cfg(feature = "pool")]
use crate::types::ProxyProtocol;

/// Lean-build placeholder that occupies the `tls_connector` parameter slot
/// of `connect_proxy` and [`connect_proxy_once`] when resocks5-net is
/// compiled without the `tls` feature.
///
/// These entry points (`connect_proxy` needs the `pool` feature) take a
/// trailing `Option<&TlsConnector>` under *every* feature combination. Cargo unifies features across a whole dependency
/// graph, so a consumer compiled against the lean
/// (`default-features = false`) signature must keep compiling unchanged
/// when some other crate in the same final binary turns `tls` on; an
/// argument whose presence depended on the feature would change that
/// consumer's arity out from under it. This zero-sized type keeps the slot
/// occupied in lean builds.
///
/// It has no public constructor, so a lean build's slot can only ever hold
/// `None` — there is nothing to plug into it without TLS support.
#[cfg(not(feature = "tls"))]
pub struct TlsConnector {
    _private: (),
}

/// Connect to `target_addr` through `proxy`, dispatching on its protocol.
///
/// SOCKS5 and HTTP CONNECT return an [`AnyUpstream::Plain`].
#[cfg_attr(
    feature = "tls",
    doc = "HTTPS (TLS-wrapped CONNECT) wraps the stream in TLS and returns [`AnyUpstream::Tls`]."
)]
#[cfg_attr(feature = "tls", doc = "")]
#[cfg_attr(
    feature = "tls",
    doc = "`tls_connector` is required for HTTPS upstreams and ignored otherwise — pass `None` unless the pool contains HTTPS proxies. A ready-made connector is available from [`make_tls_connector`](crate::connect::make_tls_connector)."
)]
#[cfg_attr(not(feature = "tls"), doc = "")]
#[cfg_attr(
    not(feature = "tls"),
    doc = "The trailing `tls_connector` slot exists in every build — without the `tls` feature its type is the placeholder [`TlsConnector`] defined in this module — so one call site compiles identically no matter which features other crates in the same build enable. In a lean build it can only be `None`."
)]
#[cfg_attr(not(feature = "tls"), doc = "")]
#[cfg_attr(
    not(feature = "tls"),
    doc = "HTTPS (TLS-wrapped CONNECT) needs the crate's `tls` feature (on by default). Built without it, an HTTPS upstream is rejected with an error naming the missing feature — never a silent plaintext fallback."
)]
///
/// # Errors
///
/// Returns [`ConnectError`] describing the failure: pool acquisition,
/// protocol handshake, proxy rejection, cap exhaustion, or a missing
/// TLS connector / `tls` feature for HTTPS upstreams.
#[cfg(feature = "pool")]
pub async fn connect_proxy(
    target_addr: &str,
    proxy: &ProxyConfig,
    pool: &ProxyPool,
    handshake_timeout: Duration,
    tls_connector: Option<&TlsConnector>,
) -> Result<AnyUpstream, ConnectError> {
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
            #[cfg(feature = "tls")]
            {
                let connector = tls_connector.ok_or_else(|| ConnectError::Tls {
                    message: "HTTPS upstream requires TLS connector".to_string(),
                    source: None,
                })?;
                let s = connect_https_proxy(target_addr, proxy, pool, handshake_timeout, connector)
                    .await?;
                Ok(AnyUpstream::Tls(Box::new(s)))
            }
            #[cfg(not(feature = "tls"))]
            {
                // The slot exists purely for signature stability across
                // feature unification; there is nothing to plug in without
                // the `tls` feature.
                let _ = tls_connector;
                Err(ConnectError::TlsFeatureMissing {
                    host: proxy.host.clone(),
                })
            }
        }
    }
}

/// Connect to `target_addr` through a single upstream `proxy` without a
/// connection pool — the one-shot counterpart of `connect_proxy`.
///
/// Prefer this over `connect_proxy` when calls are independent: a one-off
/// tunnel, a script dialing through exactly one upstream, or any consumer
/// with no rotation and no interest in warm-socket reuse. It is a
/// string-target wrapper over [`dial`](crate::connect::dial::dial), returns
/// the same [`AnyUpstream`] variants, and fails with the same errors.
///
/// Every call pays a fresh TCP handshake to the proxy — nothing is
/// pre-warmed or reused. With no shared pool there is also no shared
/// per-upstream concurrency cap; cap your own fan-out if you call this
/// concurrently against the same proxy.
///
/// `connect_timeout` bounds the TCP dial to the proxy; `handshake_timeout`
/// bounds the protocol exchange on top of it.
///
/// # Errors
///
/// [`ConnectError::InvalidTarget`] when `target_addr` is not `host:port`;
/// otherwise the errors of [`dial`](crate::connect::dial::dial).
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
/// use resocks5_net::types::ProxyProtocol;
///
/// # #[tokio::main]
/// # async fn main() -> anyhow::Result<()> {
/// let proxy = parse_proxy_str("user:pass@203.0.113.7:1080", ProxyProtocol::Socks5)
///     .expect("valid proxy line");
/// let stream = connect_proxy_once(
///     "example.com:80",
///     &proxy,
///     Duration::from_secs(10), // TCP dial timeout
///     Duration::from_secs(10), // SOCKS5 handshake timeout
///     None,                    // TLS connector slot — always present; Some(..) only for HTTPS upstreams
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
) -> Result<AnyUpstream, ConnectError> {
    let target = HostPort::parse(target_addr)
        .ok_or_else(|| ConnectError::InvalidTarget(target_addr.to_string()))?;
    let opts = DialOptions::new()
        .with_connect_timeout(connect_timeout)
        .with_handshake_timeout(handshake_timeout);
    dial(proxy, target.host, target.port, &opts, tls_connector).await
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    use super::connect_proxy_once;
    use crate::types::{ProxyConfig, ProxyProtocol};

    /// Loopback listener on an ephemeral port plus a `ProxyConfig`
    /// pointing at it, so the client dials a real local socket.
    async fn loopback_proxy(protocol: ProxyProtocol) -> (TcpListener, ProxyConfig) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let config = ProxyConfig::new(protocol, addr.ip().to_string(), addr.port());
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
