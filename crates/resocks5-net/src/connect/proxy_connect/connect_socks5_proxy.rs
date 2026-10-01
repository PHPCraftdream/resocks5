//! SOCKS5 (RFC 1928) upstream connector with optional RFC 1929 auth.

#[cfg(feature = "pool")]
use std::time::Duration;

#[cfg(feature = "pool")]
use tokio::time::timeout;

#[cfg(feature = "pool")]
use crate::connect::handshake_over_stream;
#[cfg(feature = "pool")]
use crate::connect::tcp_dial::upstream_endpoint;
#[cfg(feature = "pool")]
use crate::connect::UpstreamStream;
#[cfg(feature = "pool")]
use crate::error::{ConnectError, Stage, TimeoutKind};
#[cfg(feature = "pool")]
use crate::pool::ProxyPool;
use crate::types::ProxyConfig;

/// Credentials of `proxy` for the SOCKS5 sub-negotiation, if both are set.
pub(crate) fn socks5_auth(proxy: &ProxyConfig) -> Option<(&str, &str)> {
    match (&proxy.user, &proxy.password) {
        (Some(user), Some(password)) => Some((user.as_str(), password.as_str())),
        _ => None,
    }
}

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
#[cfg(feature = "pool")]
pub async fn connect_socks5_proxy(
    target_addr: &str,
    proxy: &ProxyConfig,
    pool: &ProxyPool,
    handshake_timeout: Duration,
) -> Result<UpstreamStream, ConnectError> {
    let stream = pool.acquire(proxy).await?;

    match timeout(
        handshake_timeout,
        handshake_over_stream(stream, target_addr, socks5_auth(proxy)),
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
