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
mod tests {
    //! Per-variant tests driven through the real code paths where a
    //! loopback stub can produce the error, plus Display pins on the
    //! legacy message text.

    #[cfg(feature = "pool")]
    use std::time::Duration;

    use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt};

    use super::ConnectError;
    use super::ProtocolViolation;
    #[cfg(feature = "pool")]
    use super::{Stage, TimeoutKind};
    use crate::connect::connect_http_proxy::http_connect_handshake;
    use crate::connect::handshake_over_stream::handshake_over_stream;
    #[cfg(feature = "pool")]
    use crate::pool::{PoolConfig, ProxyPool};
    use crate::types::{ProxyConfig, ProxyProtocol};

    fn http_proxy_config(host: &str, port: u16) -> ProxyConfig {
        ProxyConfig {
            protocol: ProxyProtocol::Http,
            host: host.into(),
            port,
            user: None,
            password: None,
            is_gate: false,
            gate: None,
        }
    }

    #[cfg(feature = "pool")]
    fn socks5_proxy_config(host: &str, port: u16) -> ProxyConfig {
        ProxyConfig {
            protocol: ProxyProtocol::Socks5,
            host: host.into(),
            port,
            user: None,
            password: None,
            is_gate: false,
            gate: None,
        }
    }

    #[cfg(feature = "pool")]
    /// SOCKS5 stub that swallows the greeting, replies with
    /// `method_reply` (method selection or auth status), then sends
    /// `connect_reply` (consumed as the CONNECT response). Returns the
    /// loopback `(host, port)` it listens on.
    async fn socks5_stub_replying(
        method_reply: &'static [u8],
        connect_reply: &'static [u8],
    ) -> (String, u16) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut greeting = [0u8; 3];
            let _ = sock.read_exact(&mut greeting).await;
            let _ = sock.write_all(method_reply).await;
            // Read the CONNECT request (10 bytes for the IPv4 targets
            // these tests use) before replying — a shutdown with unread
            // data would RST the socket and discard the reply.
            let mut request = [0u8; 10];
            let _ = sock.read_exact(&mut request).await;
            let _ = sock.write_all(connect_reply).await;
            let _ = sock.shutdown().await;
        });
        (addr.ip().to_string(), addr.port())
    }

    #[cfg(feature = "pool")]
    async fn handshake_error(
        target: &str,
        method_reply: &'static [u8],
        connect_reply: &'static [u8],
    ) -> ConnectError {
        let (host, port) = socks5_stub_replying(method_reply, connect_reply).await;
        let proxy = socks5_proxy_config(&host, port);
        crate::connect::connect_socks5_proxy(
            target,
            &proxy,
            &ProxyPool::new(PoolConfig::default(), Duration::from_secs(2), 1),
            Duration::from_secs(2),
        )
        .await
        .expect_err("stub reply must fail the handshake")
    }

    /// Same as [`handshake_error`] but the proxy config carries
    /// credentials, so the client asks for username/password auth.
    #[cfg(feature = "pool")]
    async fn authed_handshake_error(
        target: &str,
        method_reply: &'static [u8],
        connect_reply: &'static [u8],
    ) -> ConnectError {
        let (host, port) = socks5_stub_replying(method_reply, connect_reply).await;
        let mut proxy = socks5_proxy_config(&host, port);
        proxy.user = Some("user".into());
        proxy.password = Some("pass".into());
        crate::connect::connect_socks5_proxy(
            target,
            &proxy,
            &ProxyPool::new(PoolConfig::default(), Duration::from_secs(2), 1),
            Duration::from_secs(2),
        )
        .await
        .expect_err("stub reply must fail the handshake")
    }

    #[cfg(feature = "pool")]
    #[tokio::test]
    async fn pool_connect_timeout_yields_typed_timeout() {
        let pool = ProxyPool::new(PoolConfig::default(), Duration::from_millis(100), 1);
        let proxy = socks5_proxy_config("10.255.255.1", 6550);
        let err = pool
            .acquire(&proxy)
            .await
            .expect_err("unroutable address must time out");
        assert!(matches!(
            &err,
            ConnectError::Timeout {
                stage: Stage::Connect,
                kind: TimeoutKind::TcpConnect,
                ..
            }
        ));
        assert!(
            err.to_string()
                .starts_with("connect timeout (0s) to 10.255.255.1:6550"),
            "legacy text lost: {}",
            err
        );
    }

    #[cfg(feature = "pool")]
    #[tokio::test]
    async fn socks5_handshake_timeout_yields_typed_timeout() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        // Accept and stay silent — the handshake budget must expire.
        tokio::spawn(async move {
            // Hold the accepted socket open — dropping it would reset
            // the client's read before its handshake budget expires.
            let (sock, _) = listener.accept().await.unwrap();
            tokio::time::sleep(Duration::from_secs(5)).await;
            drop(sock);
        });
        let proxy = socks5_proxy_config(&addr.ip().to_string(), addr.port());
        let err = crate::connect::connect_socks5_proxy(
            "1.2.3.4:443",
            &proxy,
            &ProxyPool::new(PoolConfig::default(), Duration::from_secs(2), 1),
            Duration::from_millis(100),
        )
        .await
        .expect_err("silent proxy must time out");
        assert!(
            matches!(
                &err,
                ConnectError::Timeout {
                    stage: Stage::Handshake,
                    kind: TimeoutKind::Socks5Handshake,
                    ..
                }
            ),
            "got: {err:?}"
        );
        assert!(
            err.to_string()
                .starts_with("[SOCKS5] handshake timeout (0s) to "),
            "legacy text lost: {}",
            err
        );
    }

    #[cfg(feature = "pool")]
    #[tokio::test]
    async fn io_error_keeps_source_chain_and_legacy_prefix() {
        // A broadcast address fails the TCP connect() call itself,
        // immediately and without a listener to race against.
        let pool = ProxyPool::new(PoolConfig::default(), Duration::from_secs(2), 1);
        let err = pool
            .acquire(&socks5_proxy_config("255.255.255.255", 80))
            .await
            .expect_err("unusable address must fail the connect");
        assert!(
            matches!(
                &err,
                ConnectError::Io {
                    stage: Stage::Connect,
                    ..
                }
            ),
            "got: {err:?}"
        );
        let source = std::error::Error::source(&err)
            .expect("Io must expose its io::Error")
            .downcast_ref::<std::io::Error>()
            .expect("source must be the io::Error");
        assert!(
            source.kind() != std::io::ErrorKind::WouldBlock,
            "unexpected io kind: {source}"
        );
        assert!(
            err.to_string()
                .starts_with("connect to 255.255.255.255:80: "),
            "legacy text lost: {}",
            err
        );
    }

    #[cfg(feature = "pool")]
    #[tokio::test]
    async fn socks5_rejected_connect_yields_proxy_rejected() {
        let err = handshake_error(
            "1.2.3.4:443",
            &[0x05, 0x00],
            &[0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0],
        )
        .await;
        match &err {
            ConnectError::ProxyRejected {
                protocol: ProxyProtocol::Socks5,
                code: Some(code),
                ..
            } => assert_eq!(*code, 0x05),
            other => panic!("expected ProxyRejected, got: {other:?}"),
        }
        assert_eq!(
            err.to_string(),
            "[SOCKS5] CONNECT request error, error code: 05"
        );
    }

    #[tokio::test]
    async fn http_rejected_connect_yields_proxy_rejected_with_status_line() {
        let (mut client, mut upstream) = duplex(4096);
        let proxy = http_proxy_config("proxy.example", 8080);
        let (client, _upstream) = tokio::join!(
            async {
                http_connect_handshake(&mut client, "example.com:443", &proxy)
                    .await
                    .expect_err("403 must reject")
            },
            async {
                let mut request = Vec::new();
                while !request.ends_with(b"\r\n\r\n") {
                    let mut byte = [0u8; 1];
                    upstream.read_exact(&mut byte).await.unwrap();
                    request.push(byte[0]);
                }
                upstream
                    .write_all(b"HTTP/1.1 403 Forbidden\r\n\r\n")
                    .await
                    .unwrap();
            }
        );
        match &client {
            ConnectError::ProxyRejected {
                protocol: ProxyProtocol::Http,
                code: Some(code),
                response,
            } => {
                assert_eq!(*code, 403u16);
                assert_eq!(response, "HTTP/1.1 403 Forbidden");
            }
            other => panic!("expected ProxyRejected, got: {other:?}"),
        }
        assert_eq!(
            client.to_string(),
            "[HTTP] upstream proxy rejected CONNECT: HTTP/1.1 403 Forbidden"
        );
    }

    #[cfg(feature = "pool")]
    #[tokio::test]
    async fn auth_failure_yields_typed_auth_failed() {
        let err = authed_handshake_error("1.2.3.4:443", &[0x05, 0x02], &[0x01, 0x2a]).await;
        match &err {
            ConnectError::AuthFailed { status } => assert_eq!(*status, 0x2a),
            other => panic!("expected AuthFailed, got: {other:?}"),
        }
        assert_eq!(
            err.to_string(),
            "[SOCKS5] Authentication failed (status 2a)"
        );
    }

    #[cfg(feature = "pool")]
    #[tokio::test]
    async fn method_unsupported_yields_typed_variant_both_flavors() {
        // Proxy refuses username/password auth.
        let err = authed_handshake_error("1.2.3.4:443", &[0x05, 0x00], &[]).await;
        assert!(
            matches!(
                &err,
                ConnectError::MethodUnsupported {
                    got: 0x00,
                    with_auth: true
                }
            ),
            "got: {err:?}"
        );
        assert_eq!(
            err.to_string(),
            "[SOCKS5] Proxy does not support username/password authentication (received: 00)"
        );

        // Proxy refuses no-auth.
        let err = handshake_error("1.2.3.4:443", &[0x05, 0x02], &[]).await;
        assert!(
            matches!(
                &err,
                ConnectError::MethodUnsupported {
                    got: 0x02,
                    with_auth: false
                }
            ),
            "got: {err:?}"
        );
        assert_eq!(
            err.to_string(),
            "[SOCKS5] Proxy does not support no-authentication method (received: 02)"
        );
    }

    #[cfg(feature = "pool")]
    #[tokio::test]
    async fn protocol_violations_yield_typed_protocol() {
        // Bad version in the CONNECT response header.
        let err = handshake_error(
            "1.2.3.4:443",
            &[0x05, 0x00],
            &[0x04, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0],
        )
        .await;
        assert!(
            matches!(
                &err,
                ConnectError::Protocol(ProtocolViolation::Socks5BadVersion { got: 4 })
            ),
            "got: {err:?}"
        );
        assert_eq!(err.to_string(), "[SOCKS5] Invalid proxy response version");

        // Unknown ATYP in the CONNECT response.
        let err = handshake_error(
            "1.2.3.4:443",
            &[0x05, 0x00],
            &[0x05, 0x00, 0x00, 0x07, 0, 0, 0, 0, 0, 0],
        )
        .await;
        assert!(
            matches!(
                &err,
                ConnectError::Protocol(ProtocolViolation::Socks5UnknownAddressType { got: 7 })
            ),
            "got: {err:?}"
        );
        assert_eq!(err.to_string(), "[SOCKS5] Unknown address type in response");
    }

    #[cfg(feature = "pool")]
    #[tokio::test]
    async fn non_socks5_greeting_reply_is_bad_version_not_method_unsupported() {
        // No-auth greeting answered by something that is not SOCKS5.
        let err = handshake_error("1.2.3.4:443", &[0x04, 0x00], &[]).await;
        assert!(
            matches!(
                &err,
                ConnectError::Protocol(ProtocolViolation::Socks5BadVersion { got: 4 })
            ),
            "got: {err:?}"
        );

        // Same on the username/password greeting.
        let err = authed_handshake_error("1.2.3.4:443", &[0x48, 0x54], &[]).await;
        assert!(
            matches!(
                &err,
                ConnectError::Protocol(ProtocolViolation::Socks5BadVersion { got: 0x48 })
            ),
            "got: {err:?}"
        );
    }

    #[cfg(feature = "pool")]
    #[tokio::test]
    async fn bad_auth_subnegotiation_version_is_protocol_not_auth_failed() {
        let err = authed_handshake_error("1.2.3.4:443", &[0x05, 0x02], &[0x05, 0x00]).await;
        assert!(
            matches!(
                &err,
                ConnectError::Protocol(ProtocolViolation::Socks5BadAuthVersion { got: 5 })
            ),
            "got: {err:?}"
        );
        assert_eq!(
            err.to_string(),
            "[SOCKS5] Invalid authentication response version"
        );
    }

    #[test]
    fn socks5_rep_descriptions_follow_rfc_1928() {
        let expected = [
            (0, "succeeded"),
            (1, "general SOCKS server failure"),
            (2, "connection not allowed by ruleset"),
            (3, "network unreachable"),
            (4, "host unreachable"),
            (5, "connection refused"),
            (6, "TTL expired"),
            (7, "command not supported"),
            (8, "address type not supported"),
            (9, "unassigned"),
            (0xff, "unassigned"),
            (0x1ff, "unassigned"),
        ];
        for (code, text) in expected {
            assert_eq!(super::socks5_rep_description(code), text, "REP {code:#x}");
        }
    }

    #[tokio::test]
    async fn oversized_domain_yields_typed_protocol() {
        let (mut client, mut upstream) = duplex(4096);
        // Complete the greeting so the target parse (and its error) is
        // actually reached.
        let peer = tokio::spawn(async move {
            let mut greeting = [0u8; 3];
            upstream.read_exact(&mut greeting).await.unwrap();
            upstream.write_all(&[0x05, 0x00]).await.unwrap();
        });
        let domain = "a".repeat(300);
        let target = format!("{domain}:443");
        let err = handshake_over_stream(&mut client, &target, None)
            .await
            .expect_err("oversized domain must fail");
        assert!(
            matches!(
                &err,
                ConnectError::Protocol(ProtocolViolation::Socks5DomainTooLong { len: 300 })
            ),
            "got: {err:?}"
        );
        assert_eq!(err.to_string(), "[SOCKS5] Domain name too long");
        peer.await.unwrap();
    }

    #[tokio::test]
    async fn oversized_credentials_yield_typed_protocol_with_lengths() {
        let (mut client, mut upstream) = duplex(8192);
        let peer = tokio::spawn(async move {
            let mut greeting = [0u8; 3];
            upstream.read_exact(&mut greeting).await.unwrap();
            upstream.write_all(&[0x05, 0x02]).await.unwrap();
        });
        let long = "u".repeat(256);
        let err = handshake_over_stream(&mut client, "1.2.3.4:443", Some((&long, "p")))
            .await
            .expect_err("oversized credentials must fail");
        assert!(
            matches!(
                &err,
                ConnectError::Protocol(ProtocolViolation::Socks5CredentialsTooLong {
                    username_len: 256,
                    password_len: 1
                })
            ),
            "got: {err:?}"
        );
        assert_eq!(err.to_string(), "[SOCKS5] Username or password too long");
        peer.await.unwrap();
    }

    #[tokio::test]
    async fn http_invalid_connect_target_yields_typed_protocol() {
        let (mut client, mut upstream) = duplex(4096);
        let proxy = http_proxy_config("proxy.example", 8080);
        let err = http_connect_handshake(&mut client, "bad target:443", &proxy)
            .await
            .expect_err("control characters must reject");
        assert!(
            matches!(
                &err,
                ConnectError::Protocol(ProtocolViolation::HttpInvalidConnectTarget)
            ),
            "got: {err:?}"
        );
        assert_eq!(err.to_string(), "[HTTP] invalid CONNECT target");
        drop(client);
        let mut rest = Vec::new();
        upstream.read_to_end(&mut rest).await.unwrap();
        assert!(rest.is_empty());
    }

    #[tokio::test]
    async fn http_too_large_response_yields_typed_protocol() {
        let (mut client, mut upstream) = duplex(16384);
        let peer = tokio::spawn(async move {
            let mut request = Vec::new();
            while !request.ends_with(b"\r\n\r\n") {
                let mut byte = [0u8; 1];
                upstream.read_exact(&mut byte).await.unwrap();
                request.push(byte[0]);
            }
            // 4096 bytes with no header terminator must overflow the head.
            let junk = vec![b'a'; 4096];
            upstream.write_all(&junk).await.unwrap();
            upstream.write_all(&junk).await.unwrap();
        });
        let proxy = http_proxy_config("proxy.example", 8080);
        let err = http_connect_handshake(&mut client, "example.com:443", &proxy)
            .await
            .expect_err("oversized response must fail");
        assert!(
            matches!(
                &err,
                ConnectError::Protocol(ProtocolViolation::HttpResponseTooLarge)
            ),
            "got: {err:?}"
        );
        assert_eq!(err.to_string(), "[HTTP] upstream proxy response too large");
        peer.await.unwrap();
    }

    #[tokio::test]
    async fn http_closed_early_yields_typed_protocol() {
        let (mut client, mut upstream) = duplex(4096);
        let peer = tokio::spawn(async move {
            let mut request = Vec::new();
            while !request.ends_with(b"\r\n\r\n") {
                let mut byte = [0u8; 1];
                upstream.read_exact(&mut byte).await.unwrap();
                request.push(byte[0]);
            }
            upstream.write_all(b"HTTP/1.1 200 OK\r\n").await.unwrap();
            drop(upstream);
        });
        let proxy = http_proxy_config("proxy.example", 8080);
        let err = http_connect_handshake(&mut client, "example.com:443", &proxy)
            .await
            .expect_err("early close must fail");
        assert!(
            matches!(
                &err,
                ConnectError::Protocol(ProtocolViolation::HttpClosedEarly)
            ),
            "got: {err:?}"
        );
        assert_eq!(
            err.to_string(),
            "[HTTP] upstream proxy closed before completing response"
        );
        peer.await.unwrap();
    }

    #[tokio::test]
    async fn unparseable_target_yields_invalid_target() {
        let (mut client, mut upstream) = duplex(4096);
        let err = handshake_over_stream(&mut client, "no-port-target", None)
            .await
            .expect_err("invalid target must fail");
        assert!(matches!(
            &err,
            ConnectError::InvalidTarget(t) if t == "no-port-target"
        ));
        assert_eq!(
            err.to_string(),
            "[SOCKS5] Invalid target address format: no-port-target"
        );
        // Nothing reached the wire.
        drop(client);
        let mut rest = Vec::new();
        upstream.read_to_end(&mut rest).await.unwrap();
        assert!(rest.is_empty());
    }

    #[cfg(feature = "pool")]
    #[tokio::test]
    async fn pool_at_capacity_yields_typed_variant() {
        let pool = ProxyPool::new(PoolConfig::default(), Duration::from_secs(2), 1);
        let proxy = socks5_proxy_config("203.0.113.1", 1080);
        let _hold = pool.reserve_permit(&proxy).expect("first reserve");
        let err = pool.reserve_permit(&proxy).expect_err("cap is 1");
        assert!(
            matches!(&err, ConnectError::AtCapacity(cap) if cap.host == "203.0.113.1" && cap.port == 1080)
        );
        assert_eq!(err.to_string(), "upstream cap reached for 203.0.113.1:1080");
    }

    #[cfg(feature = "pool")]
    #[cfg(feature = "tls")]
    #[tokio::test]
    async fn https_without_connector_yields_tls_variant_with_legacy_text() {
        let proxy = ProxyConfig {
            protocol: ProxyProtocol::Https,
            host: "proxy.example".into(),
            port: 443,
            user: None,
            password: None,
            is_gate: false,
            gate: None,
        };
        let Err(err) = crate::connect::connect_proxy(
            "example.com:443",
            &proxy,
            &ProxyPool::new(PoolConfig::default(), Duration::from_secs(2), 1),
            Duration::from_secs(2),
            None,
        )
        .await
        else {
            panic!("missing connector must fail")
        };
        assert!(matches!(&err, ConnectError::Tls { source: None, .. }));
        assert_eq!(err.to_string(), "HTTPS upstream requires TLS connector");
    }

    #[cfg(feature = "pool")]
    #[cfg(not(feature = "tls"))]
    #[tokio::test]
    async fn https_in_lean_build_yields_tls_feature_missing() {
        let proxy = ProxyConfig {
            protocol: ProxyProtocol::Https,
            host: "proxy.example".into(),
            port: 443,
            user: None,
            password: None,
            is_gate: false,
            gate: None,
        };
        let Err(err) = crate::connect::connect_proxy(
            "example.com:443",
            &proxy,
            &ProxyPool::new(PoolConfig::default(), Duration::from_secs(2), 1),
            Duration::from_secs(2),
            None,
        )
        .await
        else {
            panic!("HTTPS without the tls feature must fail")
        };
        assert!(matches!(
            &err,
            ConnectError::TlsFeatureMissing { host } if host == "proxy.example"
        ));
        assert!(
            err.to_string().starts_with(
                "HTTPS upstream to proxy.example requested, but resocks5-net was built without the `tls` feature"
            ) && err.to_string().ends_with("refusing to fall back to plaintext"),
            "legacy text lost: {}",
            err
        );
    }
}
