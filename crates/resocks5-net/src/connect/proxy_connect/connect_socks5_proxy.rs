//! SOCKS5 (RFC 1928) upstream connector with optional RFC 1929 auth.

#[cfg(feature = "pool")]
use std::time::Duration;

#[cfg(feature = "pool")]
use crate::connect::handshake_over_stream::{deadline_after, socks5_handshake_bounded};
#[cfg(feature = "pool")]
use crate::connect::host_port::HostPort;
#[cfg(feature = "pool")]
use crate::connect::tcp_dial::upstream_endpoint;
#[cfg(feature = "pool")]
use crate::connect::UpstreamStream;
#[cfg(feature = "pool")]
use crate::error::ConnectError;
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
/// ([`TimeoutKind::Socks5Greeting`] while the upstream has not answered
/// the greeting yet — it never spoke its own protocol;
/// [`TimeoutKind::Socks5Handshake`] once the CONNECT reply may be the
/// destination's fault).
#[cfg(feature = "pool")]
pub async fn connect_socks5_proxy(
    target_addr: &str,
    proxy: &ProxyConfig,
    pool: &ProxyPool,
    handshake_timeout: Duration,
) -> Result<UpstreamStream, ConnectError> {
    let stream = pool.acquire(proxy).await?;
    socks5_on_acquired(stream, target_addr, proxy, handshake_timeout).await
}

/// The SOCKS5 half of [`connect_socks5_proxy`] on a socket already taken
/// from the pool, bounded by `handshake_timeout`. One deadline covers
/// both phases: a greeting stall reports [`TimeoutKind::Socks5Greeting`]
/// (the upstream never spoke its own protocol), a stalled CONNECT reply
/// stays [`TimeoutKind::Socks5Handshake`].
#[cfg(feature = "pool")]
pub(crate) async fn socks5_on_acquired(
    stream: UpstreamStream,
    target_addr: &str,
    proxy: &ProxyConfig,
    handshake_timeout: Duration,
) -> Result<UpstreamStream, ConnectError> {
    let parsed = HostPort::parse(target_addr)
        .ok_or_else(|| ConnectError::InvalidTarget(target_addr.to_string()))?;
    // Target checks run before any byte is written (inside the helper).
    socks5_handshake_bounded(
        stream,
        parsed.host,
        parsed.port,
        socks5_auth(proxy),
        deadline_after(handshake_timeout),
        &upstream_endpoint(proxy),
        handshake_timeout,
    )
    .await
}
