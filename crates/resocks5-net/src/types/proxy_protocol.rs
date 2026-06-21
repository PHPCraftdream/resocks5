//! Wire protocol spoken by an upstream proxy.

/// The protocol an upstream proxy expects on its listen socket.
#[derive(Clone, Debug, Copy, PartialEq, Eq)]
pub enum ProxyProtocol {
    /// SOCKS5 (RFC 1928), with optional RFC 1929 user/password auth.
    Socks5,
    /// Plain-text HTTP `CONNECT`.
    Http,
    /// TLS-wrapped HTTP `CONNECT` (the proxy port itself is an HTTPS server).
    Https,
}
