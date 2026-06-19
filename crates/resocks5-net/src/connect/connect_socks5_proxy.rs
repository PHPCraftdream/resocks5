use std::time::Duration;

use anyhow::anyhow;
use tokio::time::timeout;

use crate::connect::handshake_over_stream;
use crate::pool::proxy_pool::upstream_endpoint;
use crate::pool::{ProxyPool, UpstreamStream};
use crate::types::ProxyConfig;

/// Establishes a connection to the target through a SOCKS5 proxy.
///
/// `handshake_timeout` caps the time we wait on the SOCKS5 protocol
/// exchange itself; a proxy that accepts our TCP but never finishes
/// the handshake is treated as dead.
pub async fn connect_socks5_proxy(
    target_addr: &str,
    proxy: &ProxyConfig,
    pool: &ProxyPool,
    handshake_timeout: Duration,
) -> anyhow::Result<UpstreamStream> {
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
        Err(_) => Err(anyhow!(
            "[SOCKS5] handshake timeout ({}s) to {}",
            handshake_timeout.as_secs(),
            upstream_endpoint(proxy)
        )),
    }
}
