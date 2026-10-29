//! Pool-free multi-hop dial: follows the `ProxyConfig::gate` links.

use std::fmt;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use tokio::time::timeout;

use super::{dial_inner, DialOptions};
use crate::connect::connect_proxy::TlsConnector;
use crate::connect::connect_socks5_proxy::socks5_auth;
use crate::connect::handshake_over_stream::handshake_over_stream;
use crate::connect::host_port::HostPort;
use crate::connect::http_connect_handshake;
use crate::connect::tcp_dial::tcp_dial;
use crate::connect::{AnyUpstream, BoxedUpstream, UpstreamStream};
use crate::error::{ConnectError, Stage, TimeoutKind};
use crate::progress::ProgressReportingWriter;
use crate::types::{ProxyConfig, ProxyProtocol};

/// Which step of a [`dial_chain`] failed.
///
/// Nodes are numbered from the outermost one (the first node dialed over
/// TCP) towards the proxy passed to the call. For the classic
/// gate-plus-proxy pair: `Connect` is the gate's TCP connect, `Hop(0)` is
/// the gate tunnelling to the proxy, `Target` is the proxy reaching the
/// destination.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ChainStage {
    /// TCP connect to the outermost node failed.
    Connect,
    /// Node `n` failed to open a tunnel to node `n + 1`.
    Hop(usize),
    /// The last node failed to open a tunnel to the destination.
    Target,
}

impl ChainStage {
    fn encode(self) -> usize {
        match self {
            ChainStage::Connect => 0,
            ChainStage::Hop(n) => n + 1,
            ChainStage::Target => usize::MAX,
        }
    }

    fn decode(raw: usize) -> Self {
        match raw {
            0 => ChainStage::Connect,
            usize::MAX => ChainStage::Target,
            n => ChainStage::Hop(n - 1),
        }
    }
}

impl fmt::Display for ChainStage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ChainStage::Connect => f.write_str("chain connect"),
            ChainStage::Hop(n) => write!(f, "chain hop {n}"),
            ChainStage::Target => f.write_str("chain target"),
        }
    }
}

/// A [`dial_chain`] failure: the underlying [`ConnectError`] plus the
/// step that produced it.
#[derive(Debug)]
pub struct ChainError {
    stage: ChainStage,
    error: ConnectError,
}

impl ChainError {
    fn new(stage: ChainStage, error: ConnectError) -> Self {
        Self { stage, error }
    }

    /// The step that failed.
    #[must_use]
    pub fn stage(&self) -> ChainStage {
        self.stage
    }

    /// The underlying connect error.
    #[must_use]
    pub fn error(&self) -> &ConnectError {
        &self.error
    }

    /// Consume into the underlying connect error.
    #[must_use]
    pub fn into_error(self) -> ConnectError {
        self.error
    }
}

impl fmt::Display for ChainError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.stage, self.error)
    }
}

impl std::error::Error for ChainError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.error)
    }
}

/// Dial `host:port` through `proxy` and every node linked behind it by
/// [`ProxyConfig::gate`], without a pool.
///
/// `proxy.gate` is the outer node dialed first; its own `gate` is outer
/// still, and so on. Only the outermost node gets a TCP connection; every
/// later node is reached by a protocol tunnel (SOCKS5, HTTP CONNECT, or
/// TLS plus CONNECT) over the previous one, so each hop's protocol is
/// spoken inside the previous hop's tunnel.
///
/// Without a gate this behaves like [`dial`](super::dial) and returns the
/// same [`AnyUpstream`] variants; with one it returns
/// [`AnyUpstream::Gate`], because the stack of tunnels is type-erased.
///
/// Budgets: `connect_timeout` bounds the single TCP connect,
/// `handshake_timeout` bounds each hop separately, `total_timeout` bounds
/// the whole call. `tls_connector` is needed whenever any node is HTTPS.
///
/// # Errors
///
/// [`ChainError`] carries the failing [`ChainStage`] and the typed
/// [`ConnectError`]. Without a gate the stage is `Connect` for a failed
/// TCP connect and `Target` for anything later. A total-timeout expiry
/// reports the step that was in progress.
pub async fn dial_chain(
    proxy: &ProxyConfig,
    host: &str,
    port: u16,
    opts: &DialOptions,
    tls_connector: Option<&TlsConnector>,
) -> Result<AnyUpstream, ChainError> {
    let progress = AtomicUsize::new(ChainStage::Connect.encode());
    let run = chain_inner(proxy, host, port, opts, tls_connector, &progress);
    match opts.total_timeout {
        None => run.await,
        Some(total) => match timeout(total, run).await {
            Ok(r) => r,
            Err(_) => Err(ChainError::new(
                ChainStage::decode(progress.load(Ordering::Relaxed)),
                ConnectError::Timeout {
                    stage: Stage::Total,
                    kind: TimeoutKind::Total,
                    endpoint: format!("{}:{}", proxy.host, proxy.port),
                    after: total,
                },
            )),
        },
    }
}

async fn chain_inner(
    proxy: &ProxyConfig,
    host: &str,
    port: u16,
    opts: &DialOptions,
    tls_connector: Option<&TlsConnector>,
    progress: &AtomicUsize,
) -> Result<AnyUpstream, ChainError> {
    if proxy.gate.is_none() {
        return dial_inner(proxy, host, port, opts, tls_connector)
            .await
            .map_err(|e| {
                let stage = if matches!(
                    e,
                    ConnectError::Timeout {
                        stage: Stage::Connect,
                        ..
                    } | ConnectError::Io {
                        stage: Stage::Connect,
                        ..
                    }
                ) {
                    ChainStage::Connect
                } else {
                    ChainStage::Target
                };
                ChainError::new(stage, e)
            });
    }

    // Outermost node first, `proxy` last.
    let mut nodes = vec![proxy];
    let mut cur = proxy;
    while let Some(outer) = cur.gate.as_deref() {
        nodes.push(outer);
        cur = outer;
    }
    nodes.reverse();

    check_tls(&nodes, tls_connector).map_err(|e| ChainError::new(ChainStage::Connect, e))?;

    let host = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);

    let tcp = tcp_dial(nodes[0], opts.connect_timeout)
        .await
        .map_err(|e| ChainError::new(ChainStage::Connect, e))?;
    // The one real socket sits under every tunnel: wrapping it here (and
    // only here) lets confirmed ciphertext writes below the first TLS hop
    // count as progress while nested plaintext cannot fake it.
    let mut stream: BoxedUpstream =
        Box::new(ProgressReportingWriter::new(UpstreamStream::from_tcp(tcp)));

    for (i, node) in nodes.iter().enumerate() {
        let (target, stage) = match nodes.get(i + 1) {
            Some(next) => (HostPort::format(&next.host, next.port), ChainStage::Hop(i)),
            None => (HostPort::format(host, port), ChainStage::Target),
        };
        progress.store(stage.encode(), Ordering::Relaxed);
        stream = hop(stream, node, &target, opts.handshake_timeout, tls_connector)
            .await
            .map_err(|e| ChainError::new(stage, e))?;
    }
    Ok(AnyUpstream::Gate(stream))
}

/// Fail before any socket is opened if an HTTPS node cannot be served.
fn check_tls(
    nodes: &[&ProxyConfig],
    tls_connector: Option<&TlsConnector>,
) -> Result<(), ConnectError> {
    let https = nodes.iter().find(|n| n.protocol == ProxyProtocol::Https);
    #[cfg(not(feature = "tls"))]
    {
        let _ = tls_connector;
        if let Some(node) = https {
            return Err(ConnectError::TlsFeatureMissing {
                host: node.host.clone(),
            });
        }
    }
    #[cfg(feature = "tls")]
    if let (Some(node), None) = (https, tls_connector) {
        return Err(ConnectError::Tls {
            message: format!("HTTPS upstream {} requires TLS connector", node.host),
            source: None,
        });
    }
    Ok(())
}

/// Speak `node`'s protocol over `stream` to open a tunnel to `target`.
/// Bounded by `hs`; on error the stream is dropped.
async fn hop(
    mut stream: BoxedUpstream,
    node: &ProxyConfig,
    target: &str,
    hs: Duration,
    tls_connector: Option<&TlsConnector>,
) -> Result<BoxedUpstream, ConnectError> {
    let timed_out = |kind| ConnectError::Timeout {
        stage: Stage::Handshake,
        kind,
        endpoint: format!("{}:{}", node.host, node.port),
        after: hs,
    };
    match node.protocol {
        ProxyProtocol::Socks5 => {
            match timeout(hs, handshake_over_stream(stream, target, socks5_auth(node))).await {
                Ok(r) => r,
                Err(_) => Err(timed_out(TimeoutKind::Socks5Handshake)),
            }
        }
        ProxyProtocol::Http => {
            match timeout(hs, http_connect_handshake(&mut stream, target, node)).await {
                Ok(r) => r.map(|()| stream),
                Err(_) => Err(timed_out(TimeoutKind::HttpHandshake)),
            }
        }
        ProxyProtocol::Https => {
            #[cfg(feature = "tls")]
            {
                let connector = tls_connector.ok_or_else(|| ConnectError::Tls {
                    message: "HTTPS upstream requires TLS connector".to_string(),
                    source: None,
                })?;
                https_hop(stream, node, target, hs, connector).await
            }
            #[cfg(not(feature = "tls"))]
            {
                let _ = tls_connector;
                Err(ConnectError::TlsFeatureMissing {
                    host: node.host.clone(),
                })
            }
        }
    }
}

/// TLS to `node` over the incoming stream, then CONNECT, under one `hs`
/// budget. The TLS layer is not wrapped in a progress writer: only the
/// chain's base socket reports progress.
#[cfg(feature = "tls")]
async fn https_hop(
    stream: BoxedUpstream,
    node: &ProxyConfig,
    target: &str,
    hs: Duration,
    connector: &TlsConnector,
) -> Result<BoxedUpstream, ConnectError> {
    let endpoint = format!("{}:{}", node.host, node.port);
    let server_name = tokio_rustls::rustls::pki_types::ServerName::try_from(node.host.clone())
        .map_err(|_| ConnectError::Tls {
            message: format!("[HTTPS] invalid server name: {}", node.host),
            source: None,
        })?;

    let deadline = tokio::time::Instant::now() + hs;
    let mut tls =
        match tokio::time::timeout_at(deadline, connector.connect(server_name, stream)).await {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => {
                return Err(ConnectError::Tls {
                    message: format!("[HTTPS] TLS handshake to {}: {}", endpoint, e),
                    source: Some(e),
                });
            }
            Err(_) => {
                return Err(ConnectError::Timeout {
                    stage: Stage::Handshake,
                    kind: TimeoutKind::HttpsTlsHandshake,
                    endpoint,
                    after: hs,
                });
            }
        };

    match tokio::time::timeout_at(deadline, http_connect_handshake(&mut tls, target, node)).await {
        Ok(Ok(())) => Ok(Box::new(tls)),
        Ok(Err(e)) => Err(e),
        Err(_) => Err(ConnectError::Timeout {
            stage: Stage::Handshake,
            kind: TimeoutKind::HttpsConnectHandshake,
            endpoint,
            after: hs,
        }),
    }
}

#[cfg(test)]
#[path = "chain_tests.rs"]
mod tests;
