//! Parser for the `[*]user:pass@host:port` upstream-list line format.

use std::fmt;

use super::HostPort;
use crate::types::{ProxyConfig, ProxyProtocol, IP};

/// Why [`parse_proxy_str`] rejected a line.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ParseProxyError {
    /// The line is blank.
    Empty,
    /// The line is a `#` comment.
    Comment,
    /// Malformed `host:port` or credentials part.
    BadHostPort,
    /// Malformed gate marker: a `*` with no target, or a repeated `*`.
    BadGate,
}

impl fmt::Display for ParseProxyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Empty => "empty proxy line",
            Self::Comment => "comment line",
            Self::BadHostPort => "malformed host, port or credentials",
            Self::BadGate => "malformed gate marker",
        })
    }
}

impl std::error::Error for ParseProxyError {}

/// Parse a single proxy-list line into a [`ProxyConfig`].
///
/// Accepted forms: `host:port`, `user:pass@host:port`, and the same with a
/// leading `*` marking a gate. The host may be a bracketed IPv6 literal
/// (`[2001:db8::1]:1080`); a bare IPv6 literal followed by the port
/// (`2001:db8::1:443`) is also accepted for backward compatibility. The
/// password may contain `:` — only the first colon separates user and
/// password. Blank lines, `#` comments and anything that fails to parse
/// yield a [`ParseProxyError`]. `protocol` and `ip` are supplied by the
/// caller because the line itself carries no protocol or address-family
/// info.
pub fn parse_proxy_str(
    conn_str: &str,
    protocol: ProxyProtocol,
    ip: IP,
) -> Result<ProxyConfig, ParseProxyError> {
    if conn_str.trim().is_empty() {
        return Err(ParseProxyError::Empty);
    }
    if conn_str.starts_with('#') {
        return Err(ParseProxyError::Comment);
    }

    let (is_gate, conn_str) = if let Some(rest) = conn_str.strip_prefix('*') {
        if rest.is_empty() || rest.starts_with('*') {
            return Err(ParseProxyError::BadGate);
        }
        (true, rest)
    } else {
        (false, conn_str)
    };

    let (creds, host_port) = match conn_str.split_once('@') {
        // A second '@' cannot occur in a valid host or IPv6 literal.
        Some((creds, rest)) if !rest.contains('@') => (Some(creds), rest),
        Some(_) => return Err(ParseProxyError::BadHostPort),
        None => (None, conn_str),
    };

    // The password may contain ':'; the username may not, so split on the
    // FIRST colon.
    let (user, password) = match creds {
        Some(creds) => {
            let (user, password) = creds.split_once(':').ok_or(ParseProxyError::BadHostPort)?;
            (Some(user.to_string()), Some(password.to_string()))
        }
        None => (None, None),
    };

    let HostPort { host, port } = HostPort::parse(host_port).ok_or(ParseProxyError::BadHostPort)?;

    let mut cfg = ProxyConfig::new(protocol, host, port).with_family(ip);
    cfg.user = user;
    cfg.password = password;
    cfg.is_gate = is_gate;
    Ok(cfg)
}

#[cfg(test)]
mod tests {
    use crate::types::{ProxyProtocol, IP};

    use super::{parse_proxy_str, ParseProxyError};

    #[test]
    fn bracketed_ipv6() {
        let cfg = parse_proxy_str("[::1]:1080", ProxyProtocol::Socks5, IP::V4).unwrap();
        assert_eq!(cfg.host, "::1");
        assert_eq!(cfg.port, 1080);
        assert_eq!(cfg.user, None);
        assert_eq!(cfg.password, None);
        assert!(!cfg.is_gate);
    }

    #[test]
    fn bare_ipv6_backward_compat() {
        let cfg = parse_proxy_str("::1:1080", ProxyProtocol::Socks5, IP::V4).unwrap();
        assert_eq!(cfg.host, "::1");
        assert_eq!(cfg.port, 1080);
    }

    #[test]
    fn bare_full_ipv6() {
        let cfg = parse_proxy_str("2001:db8::1:443", ProxyProtocol::Socks5, IP::V4).unwrap();
        assert_eq!(cfg.host, "2001:db8::1");
        assert_eq!(cfg.port, 443);
    }

    #[test]
    fn ipv4_and_domain() {
        let cfg = parse_proxy_str("1.2.3.4:1080", ProxyProtocol::Socks5, IP::V4).unwrap();
        assert_eq!(cfg.host, "1.2.3.4");
        assert_eq!(cfg.port, 1080);
        let cfg = parse_proxy_str("example.com:1080", ProxyProtocol::Socks5, IP::V4).unwrap();
        assert_eq!(cfg.host, "example.com");
        assert_eq!(cfg.port, 1080);
    }

    #[test]
    fn colon_in_password() {
        let cfg = parse_proxy_str("user:pa:ss@[::1]:1080", ProxyProtocol::Socks5, IP::V4).unwrap();
        assert_eq!(cfg.user.as_deref(), Some("user"));
        assert_eq!(cfg.password.as_deref(), Some("pa:ss"));
        assert_eq!(cfg.host, "::1");
        assert_eq!(cfg.port, 1080);
    }

    #[test]
    fn credentials() {
        let cfg = parse_proxy_str(
            "alice:s3cret@198.51.100.7:1080",
            ProxyProtocol::Socks5,
            IP::V4,
        )
        .unwrap();
        assert_eq!(cfg.user.as_deref(), Some("alice"));
        assert_eq!(cfg.password.as_deref(), Some("s3cret"));
        assert_eq!(cfg.host, "198.51.100.7");
        assert_eq!(cfg.port, 1080);
        assert!(!cfg.is_gate);
    }

    #[test]
    fn gate_marker() {
        let cfg = parse_proxy_str(
            "*gateuser:gatepass@203.0.113.9:1080",
            ProxyProtocol::Socks5,
            IP::V4,
        )
        .unwrap();
        assert!(cfg.is_gate);
        assert_eq!(cfg.user.as_deref(), Some("gateuser"));
        assert_eq!(cfg.password.as_deref(), Some("gatepass"));
    }

    #[test]
    fn rejections() {
        for s in [
            "host",
            "[::1]",
            "user@host:80",
            "user:pass@host:80:extra",
            "user:pass@extra@host:80",
            "[example.com]:80",
            ":1080",
            "host:",
        ] {
            assert_eq!(
                parse_proxy_str(s, ProxyProtocol::Socks5, IP::V4).unwrap_err(),
                ParseProxyError::BadHostPort,
                "expected BadHostPort for {s:?}"
            );
        }
    }

    #[test]
    fn error_variants() {
        let parse = |s| parse_proxy_str(s, ProxyProtocol::Socks5, IP::V4).unwrap_err();
        assert_eq!(parse(""), ParseProxyError::Empty);
        assert_eq!(parse("   "), ParseProxyError::Empty);
        assert_eq!(parse("# comment"), ParseProxyError::Comment);
        assert_eq!(parse("*"), ParseProxyError::BadGate);
        assert_eq!(parse("**1.2.3.4:1"), ParseProxyError::BadGate);
        assert_eq!(parse("host"), ParseProxyError::BadHostPort);
        assert!(!ParseProxyError::BadGate.to_string().is_empty());
    }

    #[test]
    fn family_label_from_caller() {
        let cfg = parse_proxy_str("[::1]:1", ProxyProtocol::Socks5, IP::V4).unwrap();
        assert_eq!(cfg.ip, IP::V4);
        let cfg = parse_proxy_str("1.2.3.4:1", ProxyProtocol::Socks5, IP::V6).unwrap();
        assert_eq!(cfg.ip, IP::V6);
    }
}
