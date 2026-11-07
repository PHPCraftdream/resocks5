//! SOCKS5 (RFC 1928) upstream connector: no authentication, secure auth or GSSAPI.

#[cfg(feature = "pool")]
use std::time::Duration;

use crate::connect::handshake_over_stream::Socks5Auth;
#[cfg(feature = "pool")]
use crate::connect::handshake_over_stream::{deadline_after, socks5_handshake_bounded};
#[cfg(feature = "pool")]
use crate::connect::host_port::HostPort;
#[cfg(feature = "pool")]
use crate::connect::tcp_dial::upstream_endpoint;
#[cfg(feature = "pool")]
use crate::connect::UpstreamStream;
use crate::error::ConnectError;
#[cfg(feature = "pool")]
use crate::pool::ProxyPool;
use crate::types::ProxyConfig;

/// How the SOCKS5 greeting to `proxy` authenticates: secure auth and/or GSSAPI
/// when configured, else none. A bare user/password pair would travel in clear
/// text (RFC 1929), which this crate does not implement: such an entry is
/// refused before any byte is sent.
pub(crate) fn socks5_auth(proxy: &ProxyConfig) -> Result<Socks5Auth<'_>, ConnectError> {
    #[cfg(feature = "secure-auth")]
    {
        let secure = proxy.secure_auth.as_deref();
        #[cfg(feature = "gssapi")]
        let gssapi = proxy.gssapi.as_deref();
        #[cfg(feature = "gssapi")]
        let any = secure.is_some() || gssapi.is_some();
        #[cfg(not(feature = "gssapi"))]
        let any = secure.is_some();
        if any {
            return Ok(Socks5Auth::Strong(
                crate::connect::handshake_over_stream::Strong {
                    #[cfg(feature = "gssapi")]
                    gssapi,
                    secure,
                },
            ));
        }
    }
    proxy.refuse_cleartext()?;
    Ok(Socks5Auth::None)
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
/// ([`TimeoutKind::Socks5Greeting`](crate::error::TimeoutKind::Socks5Greeting) while the upstream has not answered
/// the greeting yet — it never spoke its own protocol;
/// [`TimeoutKind::Socks5Handshake`](crate::error::TimeoutKind::Socks5Handshake) once the CONNECT reply may be the
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
/// both phases: a greeting stall reports [`TimeoutKind::Socks5Greeting`](crate::error::TimeoutKind::Socks5Greeting)
/// (the upstream never spoke its own protocol), a stalled CONNECT reply
/// stays [`TimeoutKind::Socks5Handshake`](crate::error::TimeoutKind::Socks5Handshake).
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
        socks5_auth(proxy)?,
        deadline_after(handshake_timeout),
        &upstream_endpoint(proxy),
        handshake_timeout,
    )
    .await
}
