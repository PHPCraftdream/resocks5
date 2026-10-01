//! SOCKS5 (RFC 1928) upstream connector with optional RFC 1929 auth.

use std::time::Duration;

use tokio::time::timeout;

use crate::connect::handshake_over_stream;
use crate::error::{ConnectError, Stage, TimeoutKind};
use crate::pool::proxy_pool::upstream_endpoint;
use crate::pool::{ProxyPool, UpstreamStream};
use crate::types::ProxyConfig;

/// Establishes a connection to the target through a SOCKS5 proxy.
///
/// `handshake_timeout` caps the time we wait on the SOCKS5 protocol
/// exchange itself; a proxy that accepts our TCP but never finishes
/// the handshake is treated as dead.
///
/// # Errors
///
/// Returns [`ConnectError`] when acquiring a socket or running the
/// SOCKS5 handshake fails, or when the handshake budget expires
/// (`TimeoutKind::Socks5Handshake`).
pub async fn connect_socks5_proxy(
    target_addr: &str,
    proxy: &ProxyConfig,
    pool: &ProxyPool,
    handshake_timeout: Duration,
) -> Result<UpstreamStream, ConnectError> {
    let stream = pool.acquire(proxy).await?;

    let auth = if let (Some(ref user), Some(ref password)) = (&proxy.user, &proxy.password) {
        Some((user.as_str(), password.as_str()))
    } else {
        None
    };

    match timeout(
        handshake_timeout,
        handshake_over_stream(stream, target_addr, auth),
    )
    .await
    {
        Ok(Ok(s)) => Ok(s),
        Ok(Err(e)) => Err(e),
        Err(_) => Err(ConnectError::Timeout {
            stage: Stage::Handshake,
            kind: TimeoutKind::Socks5Handshake,
            endpoint: upstream_endpoint(proxy),
            after: handshake_timeout,
        }),
    }
}
