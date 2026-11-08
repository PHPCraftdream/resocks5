//! SOCKS5 (RFC 1928) upstream connector: the greeting offers the strongest
//! methods the entry can speak (secure auth, RFC 1929) or anonymous.

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

/// How the SOCKS5 greeting to `proxy` authenticates: the strongest methods
/// the entry can speak. A credentials entry offers secure auth (0x80) and,
/// while `allow_cleartext` is on, RFC 1929 (0x02); `secure_only` offers
/// nothing but 0x80; an entry without usable credentials offers 0x00. The
/// pre-flight policy check runs first, before any byte is sent.
///
/// An entry with secure credentials but no usable pair (the
/// `with_secure_auth` advanced API) still offers the strong 0x80 greeting;
/// RFC 1929 is only offered when a usable pair exists and clear text is
/// allowed — never a bare 0x00 when strong credentials are present.
pub(crate) fn socks5_auth(proxy: &ProxyConfig) -> Result<Socks5Auth<'_>, ConnectError> {
    proxy.preflight_auth()?;
    let pair = proxy.usable_pair();
    #[cfg(feature = "secure-auth")]
    if proxy.secure_only {
        let secure = proxy
            .secure_auth
            .as_deref()
            .expect("preflight guarantees secure credentials in secure_only mode");
        return Ok(Socks5Auth {
            secure: Some(secure),
            cleartext: None,
            secure_only: true,
        });
    }
    // Secure credentials alone (the `with_secure_auth` advanced API keeps
    // `password` unset): offer the strong method, plus RFC 1929 only while a
    // clear-text pair is usable and allowed.
    #[cfg(feature = "secure-auth")]
    if let Some(secure) = proxy.secure_auth.as_deref() {
        return Ok(Socks5Auth {
            secure: Some(secure),
            cleartext: pair.filter(|_| proxy.allow_cleartext),
            secure_only: false,
        });
    }
    match pair {
        Some((user, password)) => Ok(Socks5Auth {
            #[cfg(feature = "secure-auth")]
            secure: None,
            cleartext: Some((user, password)),
            secure_only: false,
        }),
        None => Ok(Socks5Auth::anonymous()),
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
