//! Host-selected tunnel replies and their wire encodings for both protocols.

use super::Protocol;

const RESP_407: &[u8] = b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"resocks5\", charset=\"UTF-8\"\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";

/// Fallback for a status no caller sends today: a well-formed 500 head.
/// Callers use private fixed statuses, so this arm is unreachable now — a
/// new status must degrade to this, never panic on the network path.
const RESP_500: &[u8] =
    b"HTTP/1.1 500 Internal Server Error\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";

/// Host-selected final tunnel response; parsing itself never sends success.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Reply {
    /// Egress is ready, or the host deliberately begins early-success recovery.
    Established,
    /// Target policy rejected the request (SOCKS REP 2 / HTTP 403).
    Forbidden,
    /// Egress failed: host unreachable (SOCKS REP 4 / HTTP 502).
    UpstreamUnavailable,
    /// The target refused the connection; the host picks this when the egress
    /// dial fails with a refusal (SOCKS REP 5 / HTTP 502).
    ConnectionRefused,
    /// The target network is unreachable; the host picks this from the dial
    /// error (SOCKS REP 3 / HTTP 502).
    NetworkUnreachable,
    /// The egress attempt exceeded the host's time budget; the host picks this
    /// (SOCKS REP 6 TTL expired / HTTP 504).
    TimedOut,
    /// Egress failed without a more specific cause (SOCKS REP 1 / HTTP 502).
    GeneralFailure,
    /// Host admission cap reached (SOCKS REP 1 / HTTP 503).
    Overloaded,
}

pub(super) fn http_error(status: u16) -> &'static [u8] {
    match status {
        400 => b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",
        403 => b"HTTP/1.1 403 Forbidden\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",
        407 => RESP_407,
        431 => b"HTTP/1.1 431 Request Header Fields Too Large\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",
        501 => b"HTTP/1.1 501 Not Implemented\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",
        502 => b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",
        503 => b"HTTP/1.1 503 Service Unavailable\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",
        504 => b"HTTP/1.1 504 Gateway Timeout\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",
        505 => b"HTTP/1.1 505 HTTP Version Not Supported\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",
        _ => RESP_500,
    }
}

/// Wire bytes for one host reply on the detected protocol.
pub(super) fn reply_bytes(protocol: Protocol, reply: Reply) -> &'static [u8] {
    match (protocol, reply) {
        (Protocol::Socks5, Reply::Established) => &[5, 0, 0, 1, 0, 0, 0, 0, 0, 0],
        (Protocol::Socks5, Reply::Forbidden) => &[5, 2, 0, 1, 0, 0, 0, 0, 0, 0],
        (Protocol::Socks5, Reply::UpstreamUnavailable) => &[5, 4, 0, 1, 0, 0, 0, 0, 0, 0],
        (Protocol::Socks5, Reply::ConnectionRefused) => &[5, 5, 0, 1, 0, 0, 0, 0, 0, 0],
        (Protocol::Socks5, Reply::NetworkUnreachable) => &[5, 3, 0, 1, 0, 0, 0, 0, 0, 0],
        (Protocol::Socks5, Reply::TimedOut) => &[5, 6, 0, 1, 0, 0, 0, 0, 0, 0],
        (Protocol::Socks5, Reply::GeneralFailure) => &[5, 1, 0, 1, 0, 0, 0, 0, 0, 0],
        (Protocol::Socks5, Reply::Overloaded) => &[5, 1, 0, 1, 0, 0, 0, 0, 0, 0],
        (Protocol::Http, Reply::Established) => b"HTTP/1.1 200 Connection Established\r\n\r\n",
        (Protocol::Http, Reply::Forbidden) => http_error(403),
        (Protocol::Http, Reply::UpstreamUnavailable) => http_error(502),
        (Protocol::Http, Reply::ConnectionRefused) => http_error(502),
        (Protocol::Http, Reply::NetworkUnreachable) => http_error(502),
        (Protocol::Http, Reply::TimedOut) => http_error(504),
        (Protocol::Http, Reply::GeneralFailure) => http_error(502),
        (Protocol::Http, Reply::Overloaded) => http_error(503),
    }
}
