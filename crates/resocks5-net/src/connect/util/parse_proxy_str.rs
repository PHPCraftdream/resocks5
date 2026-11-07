//! Parser for upstream-list lines: `host:port`, `user:pass@host:port`, or
//! those forms with 0–255 leading `*` markers specifying gate level.

use std::borrow::Cow;
use std::fmt;

use super::HostPort;
use crate::types::{ProxyConfig, ProxyProtocol};

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
    /// Malformed gate marker: no target, or a marker count beyond 255.
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
/// leading sequence of up to 255 `*` markers specifying the gate level. The
/// host may be a bracketed IPv6 literal
/// (`[2001:db8::1]:1080`); a bare IPv6 literal followed by the port
/// (`2001:db8::1:443`) is also accepted for backward compatibility. Zero
/// markers means an ordinary proxy. Gate levels are recorded only: neither
/// `dial`/`dial_chain` nor `connect_proxy*` interpret level values. The
/// password may contain `:` — only the first colon separates user and
/// password. Blank lines, `#` comments and anything that fails to parse
/// yield a [`ParseProxyError`]. `protocol` is supplied by the caller
/// because the line itself carries no protocol info.
///
/// # Leniency
///
/// This parser is deliberately lenient: it keeps leading/trailing
/// whitespace in the host (` host:80` parses to the host `" host"`) and
/// accepts a zero port (`host:0`). [`ProxyConfig::validate`] is the
/// strict gate that rejects those forms; neither `dial`/`dial_chain` nor
/// `connect_proxy*` calls `validate`, so a lenient parse reaches the
/// dial path unchanged unless the caller validates first.
pub fn parse_proxy_str(
    conn_str: &str,
    protocol: ProxyProtocol,
) -> Result<ProxyConfig, ParseProxyError> {
    if conn_str.trim().is_empty() {
        return Err(ParseProxyError::Empty);
    }
    if conn_str.starts_with('#') {
        return Err(ParseProxyError::Comment);
    }

    let marker_count = conn_str.bytes().take_while(|byte| *byte == b'*').count();
    let gate_level = u8::try_from(marker_count).map_err(|_| ParseProxyError::BadGate)?;
    let conn_str = &conn_str[marker_count..];
    if marker_count > 0 && conn_str.is_empty() {
        return Err(ParseProxyError::BadGate);
    }
    let is_gate = gate_level > 0;

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

    let mut cfg = ProxyConfig::new(protocol, host, port);
    cfg.user = user;
    cfg.password = password;
    cfg.gate_level = gate_level;
    cfg.is_gate = is_gate;
    Ok(cfg)
}

/// Why [`parse_proxy_uri`] (and `ProxyConfig::from_uri`) rejected a URI.
///
/// The variants and their `Display` texts never contain any part of the
/// input: no host, no user name, no password — safe to log as is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ProxyUriError {
    /// The input is empty.
    Empty,
    /// Whitespace or a control character anywhere in the input.
    InvalidCharacter,
    /// No `scheme://` prefix.
    MissingScheme,
    /// A scheme other than `socks5`, `socks5h`, `http` or `https`.
    UnsupportedScheme,
    /// The authority has no host.
    MissingHost,
    /// The host is not a valid IPv4 address, bracketed IPv6 address or
    /// host name.
    InvalidHost,
    /// [`ProxyUriOptions::ip_literal_only`] is set and the host is a name.
    NotIpLiteral,
    /// The authority has no `:port`.
    MissingPort,
    /// The port is not a number in `1..=65535`.
    InvalidPort,
    /// The user-info is malformed: an empty user name.
    InvalidUserinfo,
    /// A user name without a password (`user@host`): proxy credentials are a pair.
    MissingPassword,
    /// A `%` that is not followed by two hex digits.
    InvalidPercentEncoding,
    /// The percent-decoded user name or password is not valid UTF-8.
    NotUtf8,
    /// A path after the authority (only one trailing `/` may be allowed).
    PathNotAllowed,
    /// A `?query` after the authority.
    QueryNotAllowed,
    /// A `#fragment` after the authority.
    FragmentNotAllowed,
}

impl fmt::Display for ProxyUriError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Empty => "empty proxy URI",
            Self::InvalidCharacter => "whitespace or control character in proxy URI",
            Self::MissingScheme => "proxy URI has no scheme",
            Self::UnsupportedScheme => "unsupported proxy URI scheme",
            Self::MissingHost => "proxy URI has no host",
            Self::InvalidHost => "invalid proxy URI host",
            Self::NotIpLiteral => "proxy URI host is not an IP literal",
            Self::MissingPort => "proxy URI has no port",
            Self::InvalidPort => "invalid proxy URI port",
            Self::InvalidUserinfo => "invalid proxy URI user-info",
            Self::MissingPassword => "proxy URI user-info has no password",
            Self::InvalidPercentEncoding => "invalid percent-encoding in proxy URI",
            Self::NotUtf8 => "percent-decoded proxy URI credentials are not UTF-8",
            Self::PathNotAllowed => "proxy URI has a path",
            Self::QueryNotAllowed => "proxy URI has a query",
            Self::FragmentNotAllowed => "proxy URI has a fragment",
        })
    }
}

impl std::error::Error for ProxyUriError {}

/// Strictness switches for [`parse_proxy_uri`]. The default accepts host names
/// and no trailing slash; a path, query or fragment is always rejected.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct ProxyUriOptions {
    /// Accept only an IPv4 literal or a bracketed IPv6 literal as the host.
    pub ip_literal_only: bool,
    /// Tolerate a single trailing `/` (`http://host:8080/`).
    pub allow_trailing_slash: bool,
}

impl ProxyUriOptions {
    /// The default options.
    pub fn new() -> Self {
        Self::default()
    }

    /// Require an IP literal host (no DNS names).
    #[must_use]
    pub fn ip_literal_only(mut self, on: bool) -> Self {
        self.ip_literal_only = on;
        self
    }

    /// Tolerate one trailing `/`.
    #[must_use]
    pub fn allow_trailing_slash(mut self, on: bool) -> Self {
        self.allow_trailing_slash = on;
        self
    }
}

/// Parse `scheme://[user:password@]host:port` into a [`ProxyConfig`].
///
/// Schemes (case-insensitive): `socks5` and `socks5h` → SOCKS5, `http`,
/// `https`. The user and the password are percent-decoded (`%40` → `@`,
/// `%3A` → `:`; `+` stays a plus) and must decode to UTF-8; only the first
/// `:` of the user-info separates user from password, and a user name needs a
/// password (`user:@host:1` is an empty password, `user@host:1` is an error).
/// The host is an IPv4 literal, a bracketed IPv6 literal or a host name; the
/// port is required and must be `1..=65535`. A path, a query or a fragment is
/// an error (one trailing `/` can be allowed through
/// [`ProxyUriOptions::allow_trailing_slash`]). The errors carry no input
/// text, see [`ProxyUriError`].
///
/// # Errors
///
/// A [`ProxyUriError`] naming the first problem found.
pub fn parse_proxy_uri(uri: &str, options: &ProxyUriOptions) -> Result<ProxyConfig, ProxyUriError> {
    if uri.is_empty() {
        return Err(ProxyUriError::Empty);
    }
    if uri.bytes().any(|b| b.is_ascii_control() || b == b' ') {
        return Err(ProxyUriError::InvalidCharacter);
    }
    let (scheme, rest) = uri.split_once("://").ok_or(ProxyUriError::MissingScheme)?;
    let protocol = match scheme.to_ascii_lowercase().as_str() {
        "socks5" | "socks5h" => ProxyProtocol::Socks5,
        "http" => ProxyProtocol::Http,
        "https" => ProxyProtocol::Https,
        _ => return Err(ProxyUriError::UnsupportedScheme),
    };
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let (authority, tail) = rest.split_at(end);
    match tail.as_bytes().first() {
        None => {}
        Some(b'/') if tail == "/" && options.allow_trailing_slash => {}
        Some(b'/') => return Err(ProxyUriError::PathNotAllowed),
        Some(b'?') => return Err(ProxyUriError::QueryNotAllowed),
        Some(_) => return Err(ProxyUriError::FragmentNotAllowed),
    }
    let (userinfo, hostport) = match authority.rfind('@') {
        Some(at) => (Some(&authority[..at]), &authority[at + 1..]),
        None => (None, authority),
    };
    let credentials = match userinfo {
        None => None,
        Some(info) => {
            let (user, password) = info.split_once(':').ok_or(ProxyUriError::MissingPassword)?;
            if user.is_empty() {
                return Err(ProxyUriError::InvalidUserinfo);
            }
            Some((percent_decode(user)?, percent_decode(password)?))
        }
    };
    let (host, port) = split_host_port(hostport)?;
    let is_ip =
        host.parse::<std::net::Ipv4Addr>().is_ok() || host.parse::<std::net::Ipv6Addr>().is_ok();
    if options.ip_literal_only && !is_ip {
        return Err(ProxyUriError::NotIpLiteral);
    }
    if !is_ip && !is_host_name(host) {
        return Err(ProxyUriError::InvalidHost);
    }
    let mut config = ProxyConfig::new(protocol, host, port);
    if let Some((user, password)) = credentials {
        config = config.with_auth(user.into_owned(), password.into_owned());
    }
    Ok(config)
}

/// `host`, `port` of an authority without user-info: `host:port`,
/// `[v6]:port`.
fn split_host_port(hostport: &str) -> Result<(&str, u16), ProxyUriError> {
    if hostport.is_empty() {
        return Err(ProxyUriError::MissingHost);
    }
    let (host, port) = if let Some(inner) = hostport.strip_prefix('[') {
        let (host, after) = inner.split_once(']').ok_or(ProxyUriError::InvalidHost)?;
        if host.parse::<std::net::Ipv6Addr>().is_err() {
            return Err(ProxyUriError::InvalidHost);
        }
        let port = after.strip_prefix(':').ok_or(ProxyUriError::MissingPort)?;
        (host, port)
    } else {
        let (host, port) = hostport
            .rsplit_once(':')
            .ok_or(ProxyUriError::MissingPort)?;
        if host.contains(':') {
            // A bare IPv6 literal has no unambiguous port separator.
            return Err(ProxyUriError::InvalidHost);
        }
        (host, port)
    };
    if host.is_empty() {
        return Err(ProxyUriError::MissingHost);
    }
    // Plain ASCII digits only: rules out `+80`, `0x50` and an empty port.
    if port.is_empty() || !port.bytes().all(|b| b.is_ascii_digit()) {
        return Err(ProxyUriError::InvalidPort);
    }
    let port = port
        .parse::<u16>()
        .ok()
        .filter(|port| *port != 0)
        .ok_or(ProxyUriError::InvalidPort)?;
    Ok((host, port))
}

/// A DNS-style host name: letters, digits, `-`, `_`, `.`; no empty labels.
fn is_host_name(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= 253
        && host.split('.').all(|label| {
            !label.is_empty()
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        })
}

fn percent_decode(text: &str) -> Result<Cow<'_, str>, ProxyUriError> {
    let Some(percent) = text.find('%') else {
        return Ok(Cow::Borrowed(text));
    };
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    out.extend_from_slice(&bytes[..percent]);
    let mut i = percent;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hex = bytes
                .get(i + 1..i + 3)
                .ok_or(ProxyUriError::InvalidPercentEncoding)?;
            let high = (hex[0] as char).to_digit(16);
            let low = (hex[1] as char).to_digit(16);
            match (high, low) {
                (Some(high), Some(low)) => out.push((high * 16 + low) as u8),
                _ => return Err(ProxyUriError::InvalidPercentEncoding),
            }
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out)
        .map(Cow::Owned)
        .map_err(|_| ProxyUriError::NotUtf8)
}

#[cfg(test)]
mod tests {
    use crate::types::{ProxyConfig, ProxyProtocol};

    use super::{parse_proxy_str, ParseProxyError};

    #[test]
    fn bracketed_ipv6() {
        let cfg = parse_proxy_str("[::1]:1080", ProxyProtocol::Socks5).unwrap();
        assert_eq!(cfg.host, "::1");
        assert_eq!(cfg.port, 1080);
        assert_eq!(cfg.user, None);
        assert_eq!(cfg.password, None);
        assert!(!cfg.is_gate);
    }

    #[test]
    fn bare_ipv6_backward_compat() {
        let cfg = parse_proxy_str("::1:1080", ProxyProtocol::Socks5).unwrap();
        assert_eq!(cfg.host, "::1");
        assert_eq!(cfg.port, 1080);
    }

    #[test]
    fn bare_full_ipv6() {
        let cfg = parse_proxy_str("2001:db8::1:443", ProxyProtocol::Socks5).unwrap();
        assert_eq!(cfg.host, "2001:db8::1");
        assert_eq!(cfg.port, 443);
    }

    #[test]
    fn ipv4_and_domain() {
        let cfg = parse_proxy_str("1.2.3.4:1080", ProxyProtocol::Socks5).unwrap();
        assert_eq!(cfg.host, "1.2.3.4");
        assert_eq!(cfg.port, 1080);
        let cfg = parse_proxy_str("example.com:1080", ProxyProtocol::Socks5).unwrap();
        assert_eq!(cfg.host, "example.com");
        assert_eq!(cfg.port, 1080);
    }

    #[test]
    fn colon_in_password() {
        let cfg = parse_proxy_str("user:pa:ss@[::1]:1080", ProxyProtocol::Socks5).unwrap();
        assert_eq!(cfg.user.as_deref(), Some("user"));
        assert_eq!(cfg.password.as_deref(), Some("pa:ss"));
        assert_eq!(cfg.host, "::1");
        assert_eq!(cfg.port, 1080);
    }

    #[test]
    fn credentials() {
        let cfg = parse_proxy_str("alice:s3cret@198.51.100.7:1080", ProxyProtocol::Socks5).unwrap();
        assert_eq!(cfg.user.as_deref(), Some("alice"));
        assert_eq!(cfg.password.as_deref(), Some("s3cret"));
        assert_eq!(cfg.host, "198.51.100.7");
        assert_eq!(cfg.port, 1080);
        assert!(!cfg.is_gate);
    }

    #[test]
    fn gate_marker() {
        let cfg =
            parse_proxy_str("*gateuser:gatepass@203.0.113.9:1080", ProxyProtocol::Socks5).unwrap();
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
                parse_proxy_str(s, ProxyProtocol::Socks5).unwrap_err(),
                ParseProxyError::BadHostPort,
                "expected BadHostPort for {s:?}"
            );
        }
    }

    #[test]
    fn gate_levels_count_all_markers_and_validate_bounds() {
        for (input, level, user, password, host, port) in [
            ("*a:b@h:1", 1, Some("a"), Some("b"), "h", 1),
            ("**x:1", 2, None, None, "x", 1),
            (
                "***user:pass@[::1]:1080",
                3,
                Some("user"),
                Some("pass"),
                "::1",
                1080,
            ),
            ("plain:0", 0, None, None, "plain", 0),
        ] {
            let cfg = parse_proxy_str(input, ProxyProtocol::Socks5).unwrap();
            assert_eq!(cfg.gate_level, level, "{input}");
            assert_eq!(cfg.is_gate, level > 0, "{input}");
            assert_eq!(cfg.user.as_deref(), user, "{input}");
            assert_eq!(cfg.password.as_deref(), password, "{input}");
            assert_eq!(cfg.host, host, "{input}");
            assert_eq!(cfg.port, port, "{input}");
        }
        let max = format!("{}x:1", "*".repeat(255));
        assert_eq!(
            parse_proxy_str(&max, ProxyProtocol::Socks5)
                .unwrap()
                .gate_level,
            255
        );
        let too_many = format!("{}x:1", "*".repeat(256));
        assert!(matches!(
            parse_proxy_str(&too_many, ProxyProtocol::Socks5),
            Err(ParseProxyError::BadGate)
        ));
        for stars in ["*", "**"] {
            assert!(matches!(
                parse_proxy_str(stars, ProxyProtocol::Socks5),
                Err(ParseProxyError::BadGate)
            ));
        }
    }

    #[test]
    fn error_variants() {
        let parse = |s| parse_proxy_str(s, ProxyProtocol::Socks5).unwrap_err();
        assert_eq!(parse(""), ParseProxyError::Empty);
        assert_eq!(parse("   "), ParseProxyError::Empty);
        assert_eq!(parse("# comment"), ParseProxyError::Comment);
        assert_eq!(parse("*"), ParseProxyError::BadGate);
        assert_eq!(parse("**"), ParseProxyError::BadGate);
        assert_eq!(parse("host"), ParseProxyError::BadHostPort);
        assert!(!ParseProxyError::BadGate.to_string().is_empty());
    }

    #[test]
    fn from_addr_accepts_every_host_form() {
        let cfg = ProxyConfig::from_addr(ProxyProtocol::Socks5, "example.com:1080").unwrap();
        assert_eq!(cfg.host, "example.com");
        assert_eq!(cfg.port, 1080);

        let cfg = ProxyConfig::from_addr(ProxyProtocol::Http, "192.0.2.10:8080").unwrap();
        assert_eq!(cfg.host, "192.0.2.10");
        assert_eq!(cfg.port, 8080);

        let cfg = ProxyConfig::from_addr(ProxyProtocol::Https, "[2001:db8::7]:443").unwrap();
        assert_eq!(cfg.host, "2001:db8::7");
        assert_eq!(cfg.port, 443);

        // Bare IPv6 literal stays backward-compatible.
        let cfg = ProxyConfig::from_addr(ProxyProtocol::Socks5, "2001:db8::7:1080").unwrap();
        assert_eq!(cfg.host, "2001:db8::7");
        assert_eq!(cfg.port, 1080);
    }

    #[test]
    fn from_addr_credentials_and_gate_marker() {
        // Colon in the password: only the first colon separates user/pass.
        let cfg = ProxyConfig::from_addr(ProxyProtocol::Socks5, "u:pa:ss@10.0.0.1:1080").unwrap();
        assert_eq!(cfg.user.as_deref(), Some("u"));
        assert_eq!(cfg.password.as_deref(), Some("pa:ss"));
        assert!(!cfg.is_gate);

        let cfg = ProxyConfig::from_addr(ProxyProtocol::Socks5, "*g:p@[::1]:1080").unwrap();
        assert!(cfg.is_gate);
        assert_eq!(cfg.user.as_deref(), Some("g"));
        assert_eq!(cfg.password.as_deref(), Some("p"));
        let cfg = ProxyConfig::from_addr(ProxyProtocol::Socks5, "***x:1").unwrap();
        assert_eq!(cfg.gate_level, 3);
        assert!(cfg.is_gate);
    }

    #[test]
    fn from_addr_error_variants() {
        let err = |s| ProxyConfig::from_addr(ProxyProtocol::Socks5, s).unwrap_err();
        assert_eq!(err(""), ParseProxyError::Empty);
        assert_eq!(err("# comment"), ParseProxyError::Comment);
        assert_eq!(err("*"), ParseProxyError::BadGate);
        assert_eq!(err("**"), ParseProxyError::BadGate);
        assert_eq!(err("user@host:80"), ParseProxyError::BadHostPort);
    }

    /// Pins the current parse/validate divergence (API-01): these forms
    /// parse leniently but `validate_node` rejects them. Mutations
    /// caught: rejecting them in the parser, or accepting them in
    /// `validate_node`, fails the matching assertion.
    #[test]
    fn parse_is_lenient_where_validate_is_strict() {
        for (line, host, port) in [
            (" host:80", " host", 80),
            ("host :80", "host ", 80),
            ("host:0", "host", 0),
        ] {
            let cfg = parse_proxy_str(line, ProxyProtocol::Socks5)
                .unwrap_or_else(|e| panic!("{line:?} must parse leniently: {e}"));
            assert_eq!((cfg.host.as_str(), cfg.port), (host, port), "{line:?}");
            assert!(
                cfg.validate_node().is_err(),
                "{line:?} must fail validation"
            );
        }
    }

    /// The bracketed and bare IPv6 forms both parse AND validate: the
    /// divergence is limited to whitespace-padded hosts and the zero
    /// port. Mutation caught: breaking the IPv6 handling in
    /// `HostPort::parse` (or over-tightening `validate_node`'s host rule)
    /// fails this.
    #[test]
    fn ipv6_forms_parse_and_validate_alike() {
        for (line, host, port) in [("[::1]:80", "::1", 80), ("::1:80", "::1", 80)] {
            let cfg = parse_proxy_str(line, ProxyProtocol::Socks5)
                .unwrap_or_else(|e| panic!("{line:?} must parse: {e}"));
            assert_eq!((cfg.host.as_str(), cfg.port), (host, port), "{line:?}");
            assert_eq!(cfg.validate_node(), Ok(()), "{line:?}");
        }
    }
}

#[cfg(test)]
mod uri_tests {
    use super::*;

    fn parse(uri: &str) -> Result<ProxyConfig, ProxyUriError> {
        parse_proxy_uri(uri, &ProxyUriOptions::new())
    }

    fn strict(uri: &str) -> Result<ProxyConfig, ProxyUriError> {
        parse_proxy_uri(uri, &ProxyUriOptions::new().ip_literal_only(true))
    }

    /// Accepted forms and what they decode to. Mutations: no percent decoding,
    /// splitting at the last colon, losing the scheme mapping, keeping the
    /// brackets of an IPv6 host, each fail a row.
    #[test]
    fn accepted_forms_decode_exactly() {
        type Row = (
            &'static str,
            ProxyProtocol,
            &'static str,
            u16,
            Option<(&'static str, &'static str)>,
        );
        let rows: [Row; 15] = [
            (
                "socks5://1.2.3.4:1080",
                ProxyProtocol::Socks5,
                "1.2.3.4",
                1080,
                None,
            ),
            (
                "SOCKS5://1.2.3.4:1080",
                ProxyProtocol::Socks5,
                "1.2.3.4",
                1080,
                None,
            ),
            (
                "socks5h://1.2.3.4:1080",
                ProxyProtocol::Socks5,
                "1.2.3.4",
                1080,
                None,
            ),
            (
                "http://1.2.3.4:8080",
                ProxyProtocol::Http,
                "1.2.3.4",
                8080,
                None,
            ),
            (
                "https://1.2.3.4:8443",
                ProxyProtocol::Https,
                "1.2.3.4",
                8443,
                None,
            ),
            (
                "socks5://u:p@1.2.3.4:1080",
                ProxyProtocol::Socks5,
                "1.2.3.4",
                1080,
                Some(("u", "p")),
            ),
            (
                "socks5://u:p%3Aq@1.2.3.4:1",
                ProxyProtocol::Socks5,
                "1.2.3.4",
                1,
                Some(("u", "p:q")),
            ),
            (
                "socks5://u:p:q@1.2.3.4:1",
                ProxyProtocol::Socks5,
                "1.2.3.4",
                1,
                Some(("u", "p:q")),
            ),
            (
                "socks5://us%40er:pa%40ss@1.2.3.4:1",
                ProxyProtocol::Socks5,
                "1.2.3.4",
                1,
                Some(("us@er", "pa@ss")),
            ),
            (
                "socks5://u:@1.2.3.4:1",
                ProxyProtocol::Socks5,
                "1.2.3.4",
                1,
                Some(("u", "")),
            ),
            (
                "socks5://u:a+b@1.2.3.4:1",
                ProxyProtocol::Socks5,
                "1.2.3.4",
                1,
                Some(("u", "a+b")),
            ),
            (
                "socks5://u:%D0%BF%D0%B0%D1%80@1.2.3.4:1",
                ProxyProtocol::Socks5,
                "1.2.3.4",
                1,
                Some(("u", "пар")),
            ),
            (
                "socks5://[2001:db8::1]:1080",
                ProxyProtocol::Socks5,
                "2001:db8::1",
                1080,
                None,
            ),
            (
                "socks5://u:p@[::1]:65535",
                ProxyProtocol::Socks5,
                "::1",
                65535,
                Some(("u", "p")),
            ),
            (
                "http://proxy.example.com:3128",
                ProxyProtocol::Http,
                "proxy.example.com",
                3128,
                None,
            ),
        ];
        for (uri, protocol, host, port, auth) in rows {
            let config = parse(uri).unwrap_or_else(|e| panic!("{uri}: {e}"));
            assert_eq!(config.protocol, protocol, "{uri}");
            assert_eq!(config.host, host, "{uri}");
            assert_eq!(config.port, port, "{uri}");
            assert_eq!(
                config.user.as_deref().zip(config.password.as_deref()),
                auth,
                "{uri}"
            );
        }
    }

    /// Every rejection names its own problem. Mutations: merging two checks
    /// (the wrong variant) or dropping one (an accepted URI) fails its row.
    #[test]
    fn rejections_are_typed() {
        let rows: [(&str, ProxyUriError); 26] = [
            ("", ProxyUriError::Empty),
            ("1.2.3.4:1080", ProxyUriError::MissingScheme),
            ("ftp://1.2.3.4:21", ProxyUriError::UnsupportedScheme),
            ("socks4://1.2.3.4:1080", ProxyUriError::UnsupportedScheme),
            (" socks5://1.2.3.4:1080", ProxyUriError::InvalidCharacter),
            ("socks5://1.2.3.4:1080\n", ProxyUriError::InvalidCharacter),
            ("socks5://", ProxyUriError::MissingHost),
            ("socks5://:1080", ProxyUriError::MissingHost),
            ("socks5://u:p@:1080", ProxyUriError::MissingHost),
            ("socks5://1.2.3.4", ProxyUriError::MissingPort),
            ("socks5://[::1]", ProxyUriError::MissingPort),
            ("socks5://1.2.3.4:0", ProxyUriError::InvalidPort),
            ("socks5://1.2.3.4:65536", ProxyUriError::InvalidPort),
            ("socks5://1.2.3.4:+80", ProxyUriError::InvalidPort),
            ("socks5://1.2.3.4:", ProxyUriError::InvalidPort),
            ("socks5://::1:80", ProxyUriError::InvalidHost),
            ("socks5://[1:2]:80", ProxyUriError::InvalidHost),
            ("socks5://bad_host!:80", ProxyUriError::InvalidHost),
            ("socks5://u@1.2.3.4:1", ProxyUriError::MissingPassword),
            ("socks5://:p@1.2.3.4:1", ProxyUriError::InvalidUserinfo),
            (
                "socks5://u:%zz@1.2.3.4:1",
                ProxyUriError::InvalidPercentEncoding,
            ),
            (
                "socks5://u:%4@1.2.3.4:1",
                ProxyUriError::InvalidPercentEncoding,
            ),
            ("socks5://u:%FF@1.2.3.4:1", ProxyUriError::NotUtf8),
            ("socks5://1.2.3.4:1/path", ProxyUriError::PathNotAllowed),
            ("socks5://1.2.3.4:1?x=1", ProxyUriError::QueryNotAllowed),
            ("socks5://1.2.3.4:1#frag", ProxyUriError::FragmentNotAllowed),
        ];
        for (uri, expected) in rows {
            assert_eq!(parse(uri).unwrap_err(), expected, "{uri:?}");
        }
    }

    /// The IP-literal option rejects names and keeps IP literals. Mutation:
    /// ignoring the option accepts the name row.
    #[test]
    fn ip_literal_only_rejects_names() {
        assert_eq!(
            strict("http://proxy.example.com:3128").unwrap_err(),
            ProxyUriError::NotIpLiteral
        );
        assert_eq!(
            strict("http://localhost:3128").unwrap_err(),
            ProxyUriError::NotIpLiteral
        );
        assert!(strict("http://1.2.3.4:3128").is_ok());
        assert!(strict("socks5://[::1]:1080").is_ok());
    }

    /// A lone trailing slash is accepted only on request; anything longer is a path.
    #[test]
    fn trailing_slash_only_on_request() {
        assert_eq!(
            parse("http://1.2.3.4:8080/").unwrap_err(),
            ProxyUriError::PathNotAllowed
        );
        let lenient = ProxyUriOptions::new().allow_trailing_slash(true);
        assert!(parse_proxy_uri("http://1.2.3.4:8080/", &lenient).is_ok());
        assert_eq!(
            parse_proxy_uri("http://1.2.3.4:8080//", &lenient).unwrap_err(),
            ProxyUriError::PathNotAllowed
        );
        assert_eq!(
            parse_proxy_uri("http://1.2.3.4:8080/?q", &lenient).unwrap_err(),
            ProxyUriError::PathNotAllowed
        );
    }

    /// The error texts never contain the input: no host, user or password.
    /// Mutation: formatting a value into a message fails the substring checks.
    #[test]
    fn error_texts_carry_no_input() {
        for uri in [
            "socks5://secretuser:secretpass@secret.example:99999",
            "socks5://secretuser:%zzsecretpass@secret.example:1",
            "socks5://secretuser@secret.example:1",
            "ftp://secretuser:secretpass@secret.example:1",
            "socks5://secretuser:secretpass@secret.example:1/secretpath",
        ] {
            let text = parse(uri).unwrap_err().to_string();
            for secret in ["secretuser", "secretpass", "secret.example", "secretpath"] {
                assert!(!text.contains(secret), "{text:?} leaks {secret}");
            }
        }
    }

    /// The parsed config is what the builder would produce.
    #[test]
    fn the_parsed_config_equals_the_builder() {
        let parsed = parse("socks5://u:p@[::1]:1080").unwrap();
        let built = ProxyConfig::socks5("::1", 1080).with_auth("u", "p");
        assert_eq!(parsed.host, built.host);
        assert_eq!(parsed.protocol, built.protocol);
    }

    /// `percent_decode` borrows the input when there is no `%` to decode.
    #[test]
    fn percent_decode_borrows_text_without_percent() {
        let text = "plain-user:pa:ss";
        match percent_decode(text) {
            Ok(Cow::Borrowed(decoded)) => assert!(std::ptr::eq(decoded, text)),
            other => panic!("expected a borrowed decode, got {other:?}"),
        }
        match percent_decode("") {
            Ok(Cow::Borrowed(decoded)) => assert!(std::ptr::eq(decoded, "")),
            other => panic!("expected a borrowed decode, got {other:?}"),
        }
    }

    /// Any `%` forces the owned path; the decoded forms are unchanged.
    #[test]
    fn percent_decode_owns_escaped_sequences() {
        let decoded = percent_decode("%41").unwrap();
        assert!(matches!(decoded, Cow::Owned(_)));
        assert_eq!(decoded, "A");
        let mixed = percent_decode("a%20b").unwrap();
        assert!(matches!(mixed, Cow::Owned(_)));
        assert_eq!(mixed, "a b");
    }

    /// Error variants are unchanged by the `Cow` return type.
    #[test]
    fn percent_decode_keeps_error_variants() {
        assert_eq!(
            percent_decode("trailing%").unwrap_err(),
            ProxyUriError::InvalidPercentEncoding
        );
        assert_eq!(
            percent_decode("%zz").unwrap_err(),
            ProxyUriError::InvalidPercentEncoding
        );
        assert_eq!(percent_decode("%ff").unwrap_err(), ProxyUriError::NotUtf8);
    }
}
