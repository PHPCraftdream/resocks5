//! Canonical parsing and formatting of `host:port` pairs whose host may be
//! an IPv4 literal, an IPv6 literal, or a domain name.
//!
//! The host is always stored WITHOUT brackets: brackets are a string-format
//! concern (RFC 3986 §3.2.2 requires them in an HTTP authority), not part
//! of the address. [`HostPort::format`] re-adds them for IPv6 hosts.

/// A parsed `host:port` pair borrowed from its input string.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HostPort<'a> {
    /// Host without brackets — an IPv4 literal, IPv6 literal, or domain name.
    pub host: &'a str,
    /// Port as parsed from the decimal text after the last `:`.
    pub port: u16,
}

impl<'a> HostPort<'a> {
    /// Parse `"host:port"`.
    ///
    /// Accepted forms:
    /// - `[ipv6]:port` — RFC 3986 authority form; the bracketed host must
    ///   parse as an IPv6 literal.
    /// - bare `ipv6:port` — inherently ambiguous (the port digits are also
    ///   valid hex), so this is only accepted when everything before the
    ///   last `:` parses as an IPv6 literal. Kept for backward compatibility
    ///   with upstream-list lines written before the bracketed form was
    ///   supported.
    /// - `ipv4:port` and `domain:port` — host is everything before the last
    ///   `:`.
    ///
    /// Anything else — no colon, empty host, non-numeric or out-of-range
    /// port, brackets around a non-IPv6 host, a host containing `:` that is
    /// not a valid IPv6 literal — returns `None`.
    pub fn parse(s: &'a str) -> Option<Self> {
        if let Some(rest) = s.strip_prefix('[') {
            let (host, after) = rest.split_once(']')?;
            if host.parse::<std::net::Ipv6Addr>().is_err() {
                return None;
            }
            let port = after.strip_prefix(':')?;
            Some(Self {
                host,
                port: port.parse().ok()?,
            })
        } else {
            let (host, port) = s.rsplit_once(':')?;
            if host.contains(':') {
                host.parse::<std::net::Ipv6Addr>().ok()?;
            } else if host.is_empty() {
                return None;
            }
            Some(Self {
                host,
                port: port.parse().ok()?,
            })
        }
    }

    /// Format `host` + `port` as an unambiguous `host:port` string:
    /// IPv6 hosts are bracketed (`[::1]:443`), IPv4 and domain hosts are
    /// not. The output round-trips through [`HostPort::parse`]. The input
    /// host must be unbracketed (as stored by [`HostPort::parse`]).
    pub fn format(host: &str, port: u16) -> String {
        if host.parse::<std::net::Ipv6Addr>().is_ok() {
            format!("[{host}]:{port}")
        } else {
            format!("{host}:{port}")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bracketed_ipv6() {
        let hp = HostPort::parse("[::1]:443").unwrap();
        assert_eq!(hp.host, "::1");
        assert_eq!(hp.port, 443);
    }

    #[test]
    fn bare_ipv6_backward_compat() {
        let hp = HostPort::parse("::1:443").unwrap();
        assert_eq!(hp.host, "::1");
        assert_eq!(hp.port, 443);
    }

    #[test]
    fn bare_full_ipv6() {
        let hp = HostPort::parse("2001:db8::1:443").unwrap();
        assert_eq!(hp.host, "2001:db8::1");
        assert_eq!(hp.port, 443);
    }

    #[test]
    fn ipv4_and_domain() {
        let hp = HostPort::parse("1.2.3.4:80").unwrap();
        assert_eq!(hp.host, "1.2.3.4");
        assert_eq!(hp.port, 80);
        let hp = HostPort::parse("example.com:8080").unwrap();
        assert_eq!(hp.host, "example.com");
        assert_eq!(hp.port, 8080);
    }

    #[test]
    fn rejections() {
        for s in [
            "host",
            "[::1]",
            "[example.com]:80",
            ":1080",
            "host:",
            "[::1]:99999",
            "fe80::1::2:80",
        ] {
            assert!(HostPort::parse(s).is_none(), "expected None for {s:?}");
        }
    }

    #[test]
    fn round_trip() {
        for s in [
            "[::1]:443",
            "::1:443",
            "1.2.3.4:80",
            "example.com:8080",
            "2001:db8::1:443",
        ] {
            let hp = HostPort::parse(s).unwrap();
            let formatted = HostPort::format(hp.host, hp.port);
            let hp2 = HostPort::parse(&formatted).unwrap();
            assert_eq!((hp.host, hp.port), (hp2.host, hp2.port), "for {s:?}");
        }
    }

    #[test]
    fn canonicalization() {
        assert_eq!(HostPort::format("::1", 443), "[::1]:443");
        let hp = HostPort::parse("::1:443").unwrap();
        assert_eq!(HostPort::format(hp.host, hp.port), "[::1]:443");
        assert_eq!(HostPort::format("1.2.3.4", 80), "1.2.3.4:80");
        assert_eq!(HostPort::format("example.com", 8080), "example.com:8080");
    }
}
