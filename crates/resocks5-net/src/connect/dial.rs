//! Pool-free one-shot dial through a single upstream proxy.

use std::time::Duration;

use tokio::time::timeout;

use crate::connect::connect_http_proxy::http_connect_on_tcp;
use crate::connect::connect_proxy::TlsConnector;
use crate::connect::connect_socks5_proxy::socks5_auth;
use crate::connect::handshake_over_stream::socks5_handshake;
use crate::connect::host_port::HostPort;
use crate::connect::tcp_dial::tcp_dial;
use crate::connect::{AnyUpstream, UpstreamStream};
use crate::error::{ConnectError, Stage, TimeoutKind};
use crate::types::{ProxyConfig, ProxyProtocol};

/// Time budgets for [`dial`].
///
/// Defaults: 10 s TCP connect, 10 s protocol handshake, no total cap.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct DialOptions {
    /// Bound on the TCP connect to the proxy.
    pub connect_timeout: Duration,
    /// Bound on the protocol exchange (SOCKS5; HTTP CONNECT; for HTTPS the
    /// TLS handshake plus CONNECT together).
    pub handshake_timeout: Duration,
    /// Optional bound on the whole call, connect plus handshake.
    pub total_timeout: Option<Duration>,
}

impl Default for DialOptions {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(10),
            handshake_timeout: Duration::from_secs(10),
            total_timeout: None,
        }
    }
}

impl DialOptions {
    /// Same as [`DialOptions::default`].
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the TCP connect bound.
    #[must_use]
    pub fn with_connect_timeout(mut self, d: Duration) -> Self {
        self.connect_timeout = d;
        self
    }

    /// Set the protocol handshake bound.
    #[must_use]
    pub fn with_handshake_timeout(mut self, d: Duration) -> Self {
        self.handshake_timeout = d;
        self
    }

    /// Set the whole-call bound.
    #[must_use]
    pub fn with_total_timeout(mut self, d: Duration) -> Self {
        self.total_timeout = Some(d);
        self
    }
}

/// Dial `host:port` through the single upstream `proxy`, without a pool.
///
/// `host`/`port` is the TARGET to tunnel to, not the proxy. `host` may be
/// a domain, an IPv4 literal, or an IPv6 literal (with or without
/// brackets). SOCKS5 and HTTP CONNECT yield [`AnyUpstream::Plain`]; HTTPS
/// yields `AnyUpstream::Tls` (behind the `tls` feature) and needs
/// `tls_connector`.
///
/// The `tls_connector` slot exists under every feature combination, with
/// the same type as in `connect_proxy`:
/// without the `tls` feature it is a placeholder that can only be `None`.
///
/// There is no pool, so no warm sockets and no per-upstream concurrency
/// cap: permit/cap accounting is the caller's business (see
/// [`UpstreamStream::attach_permit`](crate::connect::UpstreamStream::attach_permit)).
///
/// # Errors
///
/// Returns [`ConnectError`]:
/// - `Timeout` with [`Stage::Connect`] when the TCP connect exceeds
///   `connect_timeout`; with [`Stage::Handshake`] when the protocol
///   exchange exceeds `handshake_timeout`; with [`Stage::Total`]
///   ([`TimeoutKind::Total`]) when `total_timeout` elapses first.
/// - `Io` for socket failures, `ProxyRejected`, `AuthFailed`,
///   `MethodUnsupported`, `Protocol` for proxy-side refusals and
///   violations.
/// - `TlsFeatureMissing` for an HTTPS proxy in a build without `tls`; for
///   an HTTPS proxy with `tls` but no connector, a TLS error.
///
/// # Example
///
/// ```no_run
/// use std::time::Duration;
///
/// use resocks5_net::connect::{dial, parse_proxy_str, DialOptions};
/// use resocks5_net::types::ProxyProtocol;
///
/// # #[tokio::main]
/// # async fn main() -> anyhow::Result<()> {
/// let proxy = parse_proxy_str("user:pass@203.0.113.7:1080", ProxyProtocol::Socks5)
///     .expect("valid proxy line");
/// let opts = DialOptions::new().with_total_timeout(Duration::from_secs(15));
/// let stream = dial(&proxy, "example.com", 80, &opts, None).await?;
/// drop(stream);
/// # Ok(())
/// # }
/// ```
pub async fn dial(
    proxy: &ProxyConfig,
    host: &str,
    port: u16,
    opts: &DialOptions,
    tls_connector: Option<&TlsConnector>,
) -> Result<AnyUpstream, ConnectError> {
    let run = dial_inner(proxy, host, port, opts, tls_connector);
    match opts.total_timeout {
        None => run.await,
        Some(total) => match timeout(total, run).await {
            Ok(r) => r,
            Err(_) => Err(ConnectError::Timeout {
                stage: Stage::Total,
                kind: TimeoutKind::Total,
                endpoint: format!("{}:{}", proxy.host, proxy.port),
                after: total,
            }),
        },
    }
}

async fn dial_inner(
    proxy: &ProxyConfig,
    host: &str,
    port: u16,
    opts: &DialOptions,
    tls_connector: Option<&TlsConnector>,
) -> Result<AnyUpstream, ConnectError> {
    let host = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);

    #[cfg(not(feature = "tls"))]
    let _ = tls_connector;
    #[cfg(not(feature = "tls"))]
    if proxy.protocol == ProxyProtocol::Https {
        return Err(ConnectError::TlsFeatureMissing {
            host: proxy.host.clone(),
        });
    }
    #[cfg(feature = "tls")]
    let https_connector = if proxy.protocol == ProxyProtocol::Https {
        Some(tls_connector.ok_or_else(|| ConnectError::Tls {
            message: "HTTPS upstream requires TLS connector".to_string(),
            source: None,
        })?)
    } else {
        None
    };

    let tcp = tcp_dial(proxy, opts.connect_timeout).await?;
    let mut stream = UpstreamStream::from_tcp(tcp);
    let hs = opts.handshake_timeout;
    let hs_timeout = |kind| ConnectError::Timeout {
        stage: Stage::Handshake,
        kind,
        endpoint: format!("{}:{}", proxy.host, proxy.port),
        after: hs,
    };

    match proxy.protocol {
        ProxyProtocol::Socks5 => {
            let auth = socks5_auth(proxy);
            match timeout(hs, socks5_handshake(stream, host, port, auth)).await {
                Ok(r) => Ok(AnyUpstream::Plain(r?)),
                Err(_) => Err(hs_timeout(TimeoutKind::Socks5Handshake)),
            }
        }
        ProxyProtocol::Http => {
            let target = HostPort::format(host, port);
            match timeout(hs, http_connect_on_tcp(&mut stream, &target, proxy)).await {
                Ok(r) => {
                    r?;
                    Ok(AnyUpstream::Plain(stream))
                }
                Err(_) => Err(hs_timeout(TimeoutKind::HttpHandshake)),
            }
        }
        ProxyProtocol::Https => {
            #[cfg(feature = "tls")]
            {
                let connector = https_connector.expect("checked above");
                let target = HostPort::format(host, port);
                let tls = crate::connect::upstream_tls::https_on_stream(
                    stream, &target, proxy, hs, connector,
                )
                .await?;
                Ok(AnyUpstream::Tls(Box::new(tls)))
            }
            #[cfg(not(feature = "tls"))]
            {
                Err(ConnectError::TlsFeatureMissing {
                    host: proxy.host.clone(),
                })
            }
        }
    }
}

#[cfg(test)]
#[path = "dial_tests.rs"]
mod tests;
