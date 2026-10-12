//! Typed errors for the public connect / pool API.
//!
//! [`ConnectError`] replaces the unstructured `anyhow::Error` that the
//! upstream connectors and `ProxyPool` used to
//! return, so callers can match on *why* a connect failed (timeout stage,
//! proxy rejection code, cap hit, ...) instead of parsing message text.
//!
//! The hand-written [`Display`](std::fmt::Display) implementation
//! reproduces the exact user-visible message text the `anyhow!` calls
//! used to produce — prefixes (`[SOCKS5] `, `[HTTP] `, `[HTTPS] `),
//! endpoints, and formatting included — so logs and message-asserting
//! tests stay unchanged. Where a legacy message embedded data the
//! canonical variant fields could not carry, the variant gained a field
//! rather than the text being lost.

use std::fmt;
use std::io;
use std::time::Duration;

#[cfg(feature = "pool")]
use crate::pool::AtCapacity;
use crate::types::ProxyProtocol;

/// Which phase of a connect attempt failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Stage {
    /// Dialing the proxy itself (TCP connect or cap reservation).
    Connect,
    /// The proxy-protocol exchange on top of the TCP connection
    /// (SOCKS5 handshake, HTTP CONNECT, TLS).
    Handshake,
    /// A total budget spanning more than one stage.
    Total,
}

/// Which specific wait timed out. Several legacy messages share a
/// [`Stage::Handshake`] but differ in text, so [`ConnectError::Timeout`]
/// carries this discriminator and `Display` picks the legacy string.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum TimeoutKind {
    /// TCP connect to the upstream timed out.
    TcpConnect,
    /// SOCKS5 handshake timeout.
    Socks5Handshake,
    /// HTTP CONNECT handshake timeout.
    HttpHandshake,
    /// HTTPS: the TLS handshake to the proxy timed out.
    HttpsTlsHandshake,
    /// HTTPS: the CONNECT exchange over the established TLS timed out.
    HttpsConnectHandshake,
    /// The whole-call budget of a one-shot dial elapsed.
    Total,
}

/// The concrete SOCKS5 / HTTP CONNECT protocol violation behind
/// [`ConnectError::Protocol`]. `Display` reproduces the exact legacy
/// message text; the offending byte / length stays reachable via the
/// variant fields.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ProtocolViolation {
    /// The first byte of a SOCKS5 reply (method selection or CONNECT)
    /// was not `0x05`.
    Socks5BadVersion {
        /// The version byte the proxy sent.
        got: u8,
    },
    /// The first byte of an RFC 1929 username/password reply was not
    /// `0x01`.
    Socks5BadAuthVersion {
        /// The sub-negotiation version byte the proxy sent.
        got: u8,
    },
    /// The ATYP byte of a SOCKS5 CONNECT reply was not 1/3/4.
    Socks5UnknownAddressType {
        /// The ATYP byte the proxy sent.
        got: u8,
    },
    /// The domain part of the target exceeded the 255-byte SOCKS5 limit.
    Socks5DomainTooLong {
        /// Domain length in bytes.
        len: usize,
    },
    /// SOCKS5 username/password credentials exceeded the 255-byte
    /// per-field RFC 1929 limit.
    Socks5CredentialsTooLong {
        /// Username length in bytes.
        username_len: usize,
        /// Password length in bytes.
        password_len: usize,
    },
    /// The HTTP CONNECT target contained control or whitespace bytes.
    HttpInvalidConnectTarget,
    /// The HTTP CONNECT response headers exceeded the 4 KiB buffer.
    HttpResponseTooLarge,
    /// The upstream closed the connection before the HTTP CONNECT
    /// response headers completed.
    HttpClosedEarly,
}

impl fmt::Display for ProtocolViolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProtocolViolation::Socks5BadVersion { .. } => {
                write!(f, "[SOCKS5] Invalid proxy response version")
            }
            ProtocolViolation::Socks5BadAuthVersion { .. } => {
                write!(f, "[SOCKS5] Invalid authentication response version")
            }
            ProtocolViolation::Socks5UnknownAddressType { .. } => {
                write!(f, "[SOCKS5] Unknown address type in response")
            }
            ProtocolViolation::Socks5DomainTooLong { .. } => {
                write!(f, "[SOCKS5] Domain name too long")
            }
            ProtocolViolation::Socks5CredentialsTooLong { .. } => {
                write!(f, "[SOCKS5] Username or password too long")
            }
            ProtocolViolation::HttpInvalidConnectTarget => {
                write!(f, "[HTTP] invalid CONNECT target")
            }
            ProtocolViolation::HttpResponseTooLarge => {
                write!(f, "[HTTP] upstream proxy response too large")
            }
            ProtocolViolation::HttpClosedEarly => {
                write!(f, "[HTTP] upstream proxy closed before completing response")
            }
        }
    }
}

/// The typed error returned by every public connect/pool entry point.
#[derive(Debug)]
#[non_exhaustive]
pub enum ConnectError {
    /// A bounded wait elapsed. `after` is the budget that expired.
    Timeout {
        /// Coarse phase, for callers that only care about connect vs
        /// handshake vs total.
        stage: Stage,
        /// Which exact wait timed out (drives the legacy message text).
        kind: TimeoutKind,
        /// `host:port` of the upstream, as it appeared in the message.
        endpoint: String,
        /// The elapsed budget.
        after: Duration,
    },
    /// An underlying socket I/O error. The `io::Error` stays reachable
    /// through [`Error::source`](std::error::Error::source).
    Io {
        /// Coarse phase.
        stage: Stage,
        /// `host:port` of the upstream when the error came from the
        /// pool's fresh-connect path (`connect to {endpoint}: ...`);
        /// `None` for bare handshake I/O, whose legacy display was the
        /// plain `io::Error` text.
        endpoint: Option<String>,
        /// The I/O error itself.
        source: io::Error,
    },
    /// The proxy answered and refused the tunnel: a non-zero SOCKS5
    /// REP or a non-2xx HTTP CONNECT status.
    ProxyRejected {
        /// Which protocol rejected.
        protocol: ProxyProtocol,
        /// The rejection code when the peer produced one (SOCKS5 REP;
        /// HTTP status digit-triple when well-formed — may be `None`
        /// for a malformed status line). `u16` because HTTP status
        /// codes (e.g. 403) exceed the `u8` of a SOCKS5 REP. For SOCKS5,
        /// `socks5_rep_description` names the code.
        code: Option<u16>,
        /// The raw status line for HTTP (`response`), empty for SOCKS5.
        response: String,
    },
    /// SOCKS5 username/password sub-negotiation failed.
    AuthFailed {
        /// The status byte the proxy returned.
        status: u8,
    },
    /// The proxy refused the requested SOCKS5 authentication method.
    MethodUnsupported {
        /// The method byte the proxy returned.
        got: u8,
        /// Whether we had asked for username/password auth (`true`) or
        /// no-auth (`false`) — the two legacy messages differ.
        with_auth: bool,
    },
    /// Protocol violation with the offending detail carried in a
    /// [`ProtocolViolation`] variant (bad version, unknown ATYP, domain
    /// too long, malformed HTTP response, ...). `Display` still prints
    /// the exact legacy message.
    Protocol(ProtocolViolation),
    /// The target address could not be parsed into a SOCKS5 request.
    InvalidTarget(String),
    /// An HTTPS upstream was requested but the crate was built without
    /// the `tls` feature.
    TlsFeatureMissing {
        /// Host of the HTTPS upstream named in the message.
        host: String,
    },
    /// TLS-specific failure (TLS handshake, invalid server name, or a
    /// missing connector). `source` keeps the underlying `io::Error`
    /// reachable where one exists.
    #[cfg(feature = "tls")]
    Tls {
        /// The full legacy message text.
        message: String,
        /// The underlying I/O error, when the failure surfaced as one.
        source: Option<io::Error>,
    },
    /// The per-upstream concurrency cap was hit — our own load, not an
    /// upstream fault.
    #[cfg(feature = "pool")]
    AtCapacity(AtCapacity),
}

impl fmt::Display for ConnectError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConnectError::Timeout {
                stage: _,
                kind,
                endpoint,
                after,
            } => match kind {
                TimeoutKind::TcpConnect => {
                    write!(f, "connect timeout ({}s) to {}", after.as_secs(), endpoint)
                }
                TimeoutKind::Socks5Handshake => {
                    write!(
                        f,
                        "[SOCKS5] handshake timeout ({}s) to {}",
                        after.as_secs(),
                        endpoint
                    )
                }
                TimeoutKind::HttpHandshake => {
                    write!(
                        f,
                        "[HTTP] handshake timeout ({}s) to {}",
                        after.as_secs(),
                        endpoint
                    )
                }
                TimeoutKind::HttpsTlsHandshake => {
                    write!(
                        f,
                        "[HTTPS] TLS handshake timeout ({}s) to {}",
                        after.as_secs(),
                        endpoint
                    )
                }
                TimeoutKind::HttpsConnectHandshake => {
                    write!(
                        f,
                        "[HTTPS] CONNECT handshake timeout ({}s) to {}",
                        after.as_secs(),
                        endpoint
                    )
                }
                TimeoutKind::Total => {
                    write!(f, "total timeout ({}s) to {}", after.as_secs(), endpoint)
                }
            },
            ConnectError::Io {
                stage: _,
                endpoint: Some(endpoint),
                source,
            } => write!(f, "connect to {}: {}", endpoint, source),
            ConnectError::Io {
                stage: _,
                endpoint: None,
                source,
            } => write!(f, "{}", source),
            ConnectError::ProxyRejected {
                protocol,
                code,
                response,
            } => match protocol {
                ProxyProtocol::Socks5 => match code {
                    Some(code) => write!(
                        f,
                        "[SOCKS5] CONNECT request error, error code: {:02x}",
                        code
                    ),
                    None => write!(f, "[SOCKS5] CONNECT request error"),
                },
                ProxyProtocol::Http | ProxyProtocol::Https => {
                    write!(f, "[HTTP] upstream proxy rejected CONNECT: {}", response)
                }
            },
            ConnectError::AuthFailed { status } => {
                write!(f, "[SOCKS5] Authentication failed (status {:02x})", status)
            }
            ConnectError::MethodUnsupported { got, with_auth } => {
                if *with_auth {
                    write!(
                        f,
                        "[SOCKS5] Proxy does not support username/password authentication (received: {:02x})",
                        got
                    )
                } else {
                    write!(
                        f,
                        "[SOCKS5] Proxy does not support no-authentication method (received: {:02x})",
                        got
                    )
                }
            }
            ConnectError::Protocol(violation) => write!(f, "{}", violation),
            ConnectError::InvalidTarget(target) => {
                write!(f, "[SOCKS5] Invalid target address format: {}", target)
            }
            ConnectError::TlsFeatureMissing { host } => write!(
                f,
                "HTTPS upstream to {} requested, but resocks5-net was built without the \
                 `tls` feature; enable it (`features = [\"tls\"]`, on by default) to dial \
                 TLS-wrapped CONNECT upstreams — refusing to fall back to plaintext",
                host
            ),
            #[cfg(feature = "tls")]
            ConnectError::Tls { message, .. } => write!(f, "{}", message),
            #[cfg(feature = "pool")]
            ConnectError::AtCapacity(cap) => write!(f, "{}", cap),
        }
    }
}

/// Human-readable meaning of a SOCKS5 reply code (`REP`, RFC 1928 §6),
/// as found in [`ConnectError::ProxyRejected`]'s `code`.
///
/// Codes outside the RFC table (and anything above `u8::MAX`) map to
/// `"unassigned"`.
pub fn socks5_rep_description(code: u16) -> &'static str {
    match code {
        0x00 => "succeeded",
        0x01 => "general SOCKS server failure",
        0x02 => "connection not allowed by ruleset",
        0x03 => "network unreachable",
        0x04 => "host unreachable",
        0x05 => "connection refused",
        0x06 => "TTL expired",
        0x07 => "command not supported",
        0x08 => "address type not supported",
        _ => "unassigned",
    }
}

impl std::error::Error for ConnectError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ConnectError::Io { source, .. } => Some(source),
            #[cfg(feature = "tls")]
            ConnectError::Tls {
                source: Some(source),
                ..
            } => Some(source),
            _ => None,
        }
    }
}

impl From<io::Error> for ConnectError {
    fn from(source: io::Error) -> Self {
        ConnectError::Io {
            stage: Stage::Handshake,
            endpoint: None,
            source,
        }
    }
}

#[cfg(test)]
mod tests;
