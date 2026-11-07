//! SOCKS5 handshake driven over an arbitrary async stream.

use std::net::{Ipv4Addr, Ipv6Addr};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};

use crate::connect::host_port::HostPort;
use crate::error::{ConnectError, ProtocolViolation, Stage, TimeoutKind};
use crate::types::ProxyProtocol;

/// Performs SOCKS5 handshake over an existing stream.
///
/// Parses `target_addr` (`host:port`, IPv6 bracketed) and runs
/// [`socks5_handshake`]; the stream contract there applies unchanged.
///
/// # Errors
///
/// Returns [`ConnectError`] for I/O failures and every SOCKS5 protocol
/// violation (method negotiation, auth, version, ATYP). An unparseable
/// `target_addr` yields [`ConnectError::InvalidTarget`] before any byte
/// is written.
pub async fn handshake_over_stream<S>(stream: S, target_addr: &str) -> Result<S, ConnectError>
where
    S: AsyncRead + AsyncWriteExt + Unpin,
{
    let parsed = super::HostPort::parse(target_addr)
        .ok_or_else(|| ConnectError::InvalidTarget(target_addr.to_string()))?;
    socks5_handshake(stream, parsed.host, parsed.port).await
}

/// SOCKS5 (RFC 1928) CONNECT handshake without authentication (method 0x00)
/// over an existing stream. `host` is unbracketed:
/// an IPv4/IPv6 literal sends ATYP 1/4, anything else a domain (ATYP 3).
///
/// Takes the stream by value or as `&mut S`; every step is flushed. There
/// is no deadline here: wrap the call in a timeout if one is needed.
///
/// On error or cancellation the stream is in an unspecified protocol
/// state and must be dropped. On success it is positioned right after the
/// CONNECT reply, ready for payload.
///
/// # Errors
///
/// Returns [`ConnectError`] for I/O failures and every SOCKS5 protocol
/// violation (method negotiation, auth, version, ATYP, domain length).
///
/// cancel-safe: NO — a cancelled handshake must close the stream.
pub async fn socks5_handshake<S>(stream: S, host: &str, port: u16) -> Result<S, ConnectError>
where
    S: AsyncRead + AsyncWriteExt + Unpin,
{
    if host.is_empty() || port == 0 {
        return Err(ConnectError::InvalidTarget(HostPort::format(host, port)));
    }
    let (stream, mut gss) = socks5_greeting(stream, Socks5Auth::None).await?;
    socks5_connect_request(stream, host, port, &mut gss).await
}

/// How a SOCKS5 greeting authenticates.
#[derive(Clone, Copy)]
pub(crate) enum Socks5Auth<'a> {
    /// Method 0x00.
    None,
    /// Strong authentication, nothing weaker: every configured method is
    /// offered, strongest first, and the server picks (see [`Strong`]).
    #[cfg(feature = "secure-auth")]
    Strong(Strong<'a>),
    /// Only to use the lifetime when `secure-auth` is off.
    #[cfg(not(feature = "secure-auth"))]
    #[allow(dead_code)]
    Unused(std::marker::PhantomData<&'a ()>),
}

/// The strong methods a client can offer, in order of preference: GSSAPI
/// (0x01) before secure auth (0x80). Neither sends a password; anonymous and
/// clear-text are never offered alongside them.
#[cfg(feature = "secure-auth")]
#[derive(Clone, Copy)]
pub(crate) struct Strong<'a> {
    #[cfg(feature = "gssapi")]
    pub(crate) gssapi: Option<&'a crate::gssapi::GssCredentials>,
    pub(crate) secure: Option<&'a crate::secure_auth::SecureCredentials>,
}

/// The GSSAPI session of a greeting, when the server chose method 0x01: the
/// CONNECT request and reply then travel as protected messages.
#[cfg(feature = "gssapi")]
pub(crate) type Gss = Option<crate::gssapi::GssSession>;
#[cfg(not(feature = "gssapi"))]
pub(crate) type Gss = ();

#[cfg(feature = "gssapi")]
fn no_gss() -> Gss {
    None
}
#[cfg(not(feature = "gssapi"))]
fn no_gss() -> Gss {}

/// Send the SOCKS5 greeting (method-selection request, RFC 1928 §3): the
/// strong methods when configured, else no authentication.
///
/// On success the stream sits right after the method-selection (or
/// auth-status) reply, ready for [`socks5_connect_request`] (with the returned
/// GSSAPI session, when one was negotiated). A stall in
/// this phase means the upstream never answered its own protocol: the
/// CONNECT request has not been sent, so the destination cannot be the
/// cause. Producers bound this phase with
/// [`TimeoutKind::Socks5Greeting`](crate::error::TimeoutKind).
pub(crate) async fn socks5_greeting<S>(
    mut stream: S,
    auth: Socks5Auth<'_>,
) -> Result<(S, Gss), ConnectError>
where
    S: AsyncRead + AsyncWriteExt + Unpin,
{
    #[cfg(feature = "secure-auth")]
    if let Socks5Auth::Strong(strong) = auth {
        // Offer every configured strong method, strongest first; the server's
        // choice decides the exchange. Nothing weaker is ever offered.
        let mut offered: Vec<u8> = Vec::new();
        #[cfg(feature = "gssapi")]
        if strong.gssapi.is_some() {
            offered.push(crate::gssapi::METHOD);
        }
        if strong.secure.is_some() {
            offered.push(crate::secure_auth::METHOD);
        }
        if offered.is_empty() {
            return Err(ConnectError::MethodUnsupported {
                got: 0xFF,
                with_auth: true,
            });
        }
        let mut greeting = vec![0x05, u8::try_from(offered.len()).unwrap_or(u8::MAX)];
        greeting.extend_from_slice(&offered);
        stream.write_all(&greeting).await?;
        stream.flush().await?;
        let mut response = [0u8; 2];
        stream.read_exact(&mut response).await?;
        if response[0] != 0x05 {
            return Err(ConnectError::Protocol(
                ProtocolViolation::Socks5BadVersion { got: response[0] },
            ));
        }
        let chosen = response[1];
        if !offered.contains(&chosen) {
            return Err(ConnectError::MethodUnsupported {
                got: chosen,
                with_auth: true,
            });
        }
        let io = |kind| ConnectError::Io {
            stage: Stage::Handshake,
            endpoint: None,
            source: std::io::Error::from(kind),
        };
        #[cfg(feature = "gssapi")]
        if chosen == crate::gssapi::METHOD {
            let credentials = strong.gssapi.expect("offered only when configured");
            let session = crate::gssapi::client_gssapi(&mut stream, credentials)
                .await
                .map_err(|error| match error {
                    crate::GssapiError::Io(kind) => io(kind),
                    other => ConnectError::Gssapi(other),
                })?;
            // Level 0: authenticated, but the request and reply are plain.
            return Ok((stream, session.is_protected().then_some(session)));
        }
        let credentials = strong.secure.expect("offered only when configured");
        crate::secure_auth::client_authenticate(&mut stream, credentials)
            .await
            .map_err(|error| match error {
                crate::SecureAuthError::Io(kind) => io(kind),
                other => ConnectError::SecureAuth(other),
            })?;
        return Ok((stream, no_gss()));
    }
    #[cfg(not(feature = "secure-auth"))]
    let _ = auth;
    // No authentication: method 0x00 only. A password is never sent in clear
    // text (RFC 1929 is not implemented).
    stream.write_all(&[0x05, 0x01, 0x00]).await?;
    stream.flush().await?;
    let mut response = [0u8; 2];
    stream.read_exact(&mut response).await?;
    if response[0] != 0x05 {
        return Err(ConnectError::Protocol(
            ProtocolViolation::Socks5BadVersion { got: response[0] },
        ));
    }
    if response[1] != 0x00 {
        return Err(ConnectError::MethodUnsupported {
            got: response[1],
            with_auth: false,
        });
    }
    Ok((stream, no_gss()))
}

/// Send the SOCKS5 CONNECT request for `host:port` (RFC 1928 §5) and read
/// the reply through the end of the bound address. With a GSSAPI session the
/// request and the reply are protected messages (RFC 1961 §5).
///
/// On success the stream sits right after the CONNECT reply, ready for
/// payload. A stall waiting for the reply may still be the destination's
/// fault — the upstream has already relayed the CONNECT — so producers
/// classify it as plain
/// [`TimeoutKind::Socks5Handshake`](crate::error::TimeoutKind).
pub(crate) async fn socks5_connect_request<S>(
    mut stream: S,
    host: &str,
    port: u16,
    gss: &mut Gss,
) -> Result<S, ConnectError>
where
    S: AsyncRead + AsyncWriteExt + Unpin,
{
    let req = connect_request_bytes(host, port)?;
    #[cfg(feature = "gssapi")]
    if let Some(session) = gss.as_mut() {
        let gss_error = |error: crate::GssapiError| match error {
            crate::GssapiError::Io(kind) => ConnectError::Io {
                stage: Stage::Handshake,
                endpoint: None,
                source: std::io::Error::from(kind),
            },
            other => ConnectError::Gssapi(other),
        };
        session
            .write_message(&mut stream, &req)
            .await
            .map_err(gss_error)?;
        let reply = session.read_message(&mut stream).await.map_err(gss_error)?;
        read_connect_reply(&mut reply.as_slice()).await?;
        return Ok(stream);
    }
    #[cfg(not(feature = "gssapi"))]
    let () = *gss;
    stream.write_all(&req).await?;
    stream.flush().await?;
    read_connect_reply(&mut stream).await?;
    Ok(stream)
}

/// The CONNECT request for `host:port`.
fn connect_request_bytes(host: &str, port: u16) -> Result<Vec<u8>, ConnectError> {
    if host.is_empty() || port == 0 {
        return Err(ConnectError::InvalidTarget(HostPort::format(host, port)));
    }
    let (atyp, addr_bytes) = if let Ok(ipv4) = host.parse::<Ipv4Addr>() {
        (0x01, ipv4.octets().to_vec())
    } else if let Ok(ipv6) = host.parse::<Ipv6Addr>() {
        (0x04, ipv6.octets().to_vec())
    } else {
        let domain = host.as_bytes();
        if domain.len() > 255 {
            return Err(ConnectError::Protocol(
                ProtocolViolation::Socks5DomainTooLong { len: domain.len() },
            ));
        }
        let mut v = vec![domain.len() as u8];
        v.extend_from_slice(domain);
        (0x03, v)
    };
    let mut req = Vec::new();
    req.extend_from_slice(&[0x05, 0x01, 0x00, atyp]);
    req.extend_from_slice(&addr_bytes);
    req.extend_from_slice(&port.to_be_bytes());
    Ok(req)
}

/// Read a CONNECT reply through the end of the bound address.
async fn read_connect_reply<R>(stream: &mut R) -> Result<(), ConnectError>
where
    R: AsyncRead + Unpin,
{
    let mut resp_header = [0u8; 4];
    stream.read_exact(&mut resp_header).await?;
    if resp_header[0] != 0x05 {
        return Err(ConnectError::Protocol(
            ProtocolViolation::Socks5BadVersion {
                got: resp_header[0],
            },
        ));
    }
    if resp_header[1] != 0x00 {
        return Err(ConnectError::ProxyRejected {
            protocol: ProxyProtocol::Socks5,
            code: Some(u16::from(resp_header[1])),
            response: String::new(),
        });
    }
    if resp_header[2] != 0x00 {
        return Err(ConnectError::Protocol(
            ProtocolViolation::Socks5BadReserved {
                got: resp_header[2],
            },
        ));
    }
    match resp_header[3] {
        0x01 => {
            stream.read_exact(&mut [0u8; 6]).await?;
        }
        0x03 => {
            let mut len_buf = [0u8; 1];
            stream.read_exact(&mut len_buf).await?;
            if len_buf[0] == 0 {
                return Err(ConnectError::Protocol(
                    ProtocolViolation::Socks5EmptyBoundDomain,
                ));
            }
            let mut skip = vec![0u8; len_buf[0] as usize + 2];
            stream.read_exact(&mut skip).await?;
        }
        0x04 => {
            stream.read_exact(&mut [0u8; 18]).await?;
        }
        _ => {
            return Err(ConnectError::Protocol(
                ProtocolViolation::Socks5UnknownAddressType {
                    got: resp_header[3],
                },
            ))
        }
    }
    Ok(())
}

/// [`socks5_handshake`] bounded by an ABSOLUTE `deadline`, with a typed
/// timeout instead of an outer `timeout_at` that loses the phase.
///
/// One deadline covers both phases and tells them apart: silence while the
/// upstream should answer the greeting (method selection, or the RFC 1929
/// sub-negotiation) is [`TimeoutKind::Socks5Greeting`] — the CONNECT request
/// was never sent, so only the upstream can be at fault
/// ([`ConnectError::is_upstream_down`] is `true`); silence after the CONNECT
/// request is [`TimeoutKind::Socks5Handshake`] — the destination may be the
/// one stalling. Both are [`ConnectError::Timeout`] with
/// [`Stage::Handshake`], `endpoint` as given (`host:port` of the upstream, for
/// the message) and `after` = the time left to the deadline at the call.
///
/// An empty `host` or port 0 is [`ConnectError::InvalidTarget`] before any
/// byte is written. The stream contract of [`socks5_handshake`] applies
/// unchanged: after an error or timeout drop the stream.
///
/// cancel-safe: NO — a cancelled handshake must close the stream.
///
/// # Errors
///
/// As [`socks5_handshake`], plus [`ConnectError::Timeout`] as above.
pub async fn socks5_handshake_until<S>(
    stream: S,
    host: &str,
    port: u16,
    deadline: tokio::time::Instant,
    endpoint: &str,
) -> Result<S, ConnectError>
where
    S: AsyncRead + AsyncWriteExt + Unpin,
{
    let after = deadline.saturating_duration_since(tokio::time::Instant::now());
    socks5_handshake_bounded(
        stream,
        host,
        port,
        Socks5Auth::None,
        deadline,
        endpoint,
        after,
    )
    .await
}

/// The deadline-bounded SOCKS5 handshake with an explicit `after` (the budget
/// the error reports); shared by the public wrapper and the dial paths, whose
/// budget is a configured duration rather than "time left".
pub(crate) async fn socks5_handshake_bounded<S>(
    stream: S,
    host: &str,
    port: u16,
    auth: Socks5Auth<'_>,
    deadline: tokio::time::Instant,
    endpoint: &str,
    after: std::time::Duration,
) -> Result<S, ConnectError>
where
    S: AsyncRead + AsyncWriteExt + Unpin,
{
    if host.is_empty() || port == 0 {
        return Err(ConnectError::InvalidTarget(HostPort::format(host, port)));
    }
    let timed_out = |kind| ConnectError::Timeout {
        stage: Stage::Handshake,
        kind,
        endpoint: endpoint.to_owned(),
        after,
    };
    let (stream, mut gss) =
        match tokio::time::timeout_at(deadline, socks5_greeting(stream, auth)).await {
            Ok(Ok(greeted)) => greeted,
            Ok(Err(error)) => return Err(error),
            Err(_) => return Err(timed_out(TimeoutKind::Socks5Greeting)),
        };
    match tokio::time::timeout_at(
        deadline,
        socks5_connect_request(stream, host, port, &mut gss),
    )
    .await
    {
        Ok(result) => result,
        Err(_) => Err(timed_out(TimeoutKind::Socks5Handshake)),
    }
}

/// `Instant::now() + budget` for a caller-supplied budget: a sum outside the
/// clock's range (e.g. `Duration::MAX`) means "no practical deadline" instead
/// of an overflow panic on the dial path.
pub(crate) fn deadline_after(budget: std::time::Duration) -> tokio::time::Instant {
    const FAR: std::time::Duration = std::time::Duration::from_secs(100 * 365 * 24 * 3600);
    let now = tokio::time::Instant::now();
    now.checked_add(budget)
        .or_else(|| now.checked_add(FAR))
        .unwrap_or(now)
}

#[cfg(test)]
mod core_tests;
#[cfg(test)]
mod deadline_tests;
#[cfg(test)]
mod tests;
