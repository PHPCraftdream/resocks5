//! Parser for the `[*]user:pass@host:port` upstream-list line format.

use super::HostPort;
use crate::types::{ProxyConfig, ProxyProtocol, IP};

/// Parse a single proxy-list line into a [`ProxyConfig`].
///
/// Accepted forms: `host:port`, `user:pass@host:port`, and the same with a
/// leading `*` marking a gate. The host may be a bracketed IPv6 literal
/// (`[2001:db8::1]:1080`); a bare IPv6 literal followed by the port
/// (`2001:db8::1:443`) is also accepted for backward compatibility. The
/// password may contain `:` — only the first colon separates user and
/// password. Lines beginning with `#` and anything that fails to parse
/// return `None`. `protocol` and `ip` are supplied by the caller because
/// the line itself carries no protocol or address-family info.
pub fn parse_proxy_str(conn_str: &str, protocol: ProxyProtocol, ip: IP) -> Option<ProxyConfig> {
    if conn_str.starts_with('#') {
        return None;
    }

    let (is_gate, conn_str) = if let Some(rest) = conn_str.strip_prefix('*') {
        (true, rest)
    } else {
        (false, conn_str)
    };

    let (creds, host_port) = match conn_str.split_once('@') {
        // A second '@' cannot occur in a valid host or IPv6 literal.
        Some((creds, rest)) if !rest.contains('@') => (Some(creds), rest),
        Some(_) => return None,
        None => (None, conn_str),
    };

    // The password may contain ':'; the username may not, so split on the
    // FIRST colon.
    let (user, password) = match creds {
        Some(creds) => {
            let (user, password) = creds.split_once(':')?;
            (Some(user.to_string()), Some(password.to_string()))
        }
        None => (None, None),
    };

    let HostPort { host, port } = HostPort::parse(host_port)?;

    Some(ProxyConfig {
        protocol,
        ip,
        user,
        password,
        host: host.to_string(),
        port,
        is_gate,
        gate: None,
    })
}

#[cfg(test)]
mod tests {
    use crate::types::{ProxyProtocol, IP};

    use super::parse_proxy_str;

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
            "# comment",
            "host",
            "[::1]",
            "user@host:80",
            "user:pass@host:80:extra",
            "user:pass@extra@host:80",
            "[example.com]:80",
            ":1080",
            "host:",
        ] {
            assert!(
                parse_proxy_str(s, ProxyProtocol::Socks5, IP::V4).is_none(),
                "expected None for {s:?}"
            );
        }
    }
}
