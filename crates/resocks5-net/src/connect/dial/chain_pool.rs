//! Pool-backed dialing through an explicit chain of proxy nodes.

use std::time::Duration;

use super::chain::{check_tls, run_chain_hops, ChainError, ChainStage};
use crate::connect::connect_proxy::{connect_proxy_on, TlsConnector};
use crate::connect::host_port::HostPort;
use crate::connect::{AnyUpstream, BoxedUpstream};
use crate::error::ConnectError;
use crate::pool::ProxyPool;
use crate::progress::ProgressReportingWriter;
use crate::types::ProxyConfig;

#[cfg(test)]
#[path = "chain_pool_tests.rs"]
mod tests;

/// Connect to `target_addr` through `chain` using the pool for every node.
///
/// Chain nodes are ordered outermost first. The pool acquires the outermost
/// node's socket, while every inner node reserves a permit before any tunnel
/// handshake begins; all permits remain attached to the base stream for the
/// lifetime of the resulting tunnel. For a single-node chain this delegates
/// to `connect_proxy_on`, preserving its protocol-specific result variants.
///
/// `handshake_timeout` bounds each protocol hop. HTTPS nodes require the
/// `tls` feature and a connector as appropriate to the build.
///
/// # Errors
///
/// Returns [`ChainError`] with `Connect` for outermost acquisition and TLS
/// preflight failures, `Hop(i - 1)` when reservation of node `i` fails (and
/// for intermediate tunnel failures), and `Target` for an invalid target or
/// final handshake failure. Invalid targets and unavailable TLS configuration
/// are rejected before opening a socket.
pub async fn connect_chain(
    chain: &ProxyConfig,
    target_addr: &str,
    pool: &ProxyPool,
    handshake_timeout: Duration,
    tls_connector: Option<&TlsConnector>,
) -> Result<AnyUpstream, ChainError> {
    let target = HostPort::parse(target_addr).ok_or_else(|| {
        ChainError::new(
            ChainStage::Target,
            ConnectError::InvalidTarget(target_addr.to_owned()),
        )
    })?;
    let nodes = chain.chain_nodes();
    check_tls(&nodes, tls_connector).map_err(|e| ChainError::new(ChainStage::Connect, e))?;

    if nodes.len() == 1 {
        let stream = pool
            .acquire(nodes[0])
            .await
            .map_err(|e| ChainError::new(ChainStage::Connect, e))?;
        return connect_proxy_on(
            stream,
            target_addr,
            nodes[0],
            handshake_timeout,
            tls_connector,
        )
        .await
        .map_err(|e| ChainError::new(ChainStage::Target, e));
    }

    let mut stream = pool
        .acquire(nodes[0])
        .await
        .map_err(|e| ChainError::new(ChainStage::Connect, e))?;
    for (i, node) in nodes.iter().enumerate().skip(1) {
        let permit = pool
            .reserve_permit(node)
            .map_err(|e| ChainError::new(ChainStage::Hop(i - 1), e))?;
        stream.attach_permit(permit);
    }
    let base: BoxedUpstream = Box::new(ProgressReportingWriter::new(stream));
    let base = run_chain_hops(
        &nodes,
        &HostPort::format(target.host, target.port),
        base,
        handshake_timeout,
        tls_connector,
        |_| {},
    )
    .await
    .map_err(|(stage, error)| ChainError::new(stage, error))?;
    Ok(AnyUpstream::Gate(base))
}
