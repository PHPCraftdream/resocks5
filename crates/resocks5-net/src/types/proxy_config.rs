//! The full descriptor of a remote proxy: endpoint, credentials, and gate link.

use std::fmt;
use std::net::Ipv6Addr;
use std::sync::Arc;

use crate::types::{ProxyProtocol, IP};

/// Placeholder printed by [`ProxyConfig`]'s [`Debug`](std::fmt::Debug) impl in
/// place of any `user` or `password` value.
const REDACTED: &str = "<redacted>";

/// Configuration for a remote proxy with authentication.
///
/// Build one with [`ProxyConfig::new`] (or the [`socks5`](ProxyConfig::socks5),
/// [`http`](ProxyConfig::http), [`https`](ProxyConfig::https) shortcuts) plus
/// the `with_*` builders, or parse a list line with
/// [`parse_proxy_str`](crate::connect::parse_proxy_str()). The struct is
/// `#[non_exhaustive]`: struct literals are not available outside this crate.
///
/// `gate` links this entry to the outer *gate* node that is dialed first;
/// the entry itself is then reached through that gate's tunnel. It uses
/// `Arc` rather than `Box` so that constructing a gate-wrapped variant
/// (e.g. when caching a successful gate+proxy pair in
/// `ProxyRotator::link_proxy`) is a cheap refcount bump instead of a deep
/// copy of the gate's `String` fields. `connect_proxy` and
/// `connect_proxy_once` do NOT interpret `gate`; chain assembly lives in
/// the application.
///
/// The [`Debug`](std::fmt::Debug) output is redacted: `user` and `password`
/// values are replaced with a placeholder, recursively through
/// [`gate`](ProxyConfig::gate), so debug-logging a `ProxyConfig` never
/// leaks proxy credentials.
#[derive(Clone)]
#[non_exhaustive]
pub struct ProxyConfig {
    /// Wire protocol spoken to this proxy.
    pub protocol: ProxyProtocol,
    /// Address-family label of the entry (used for grouping/printing); not
    /// used when connecting.
    pub ip: IP,
    /// Proxy host (IP literal or domain), without IPv6 brackets.
    pub host: String,
    /// Proxy TCP port.
    pub port: u16,
    /// Optional username (RFC 1929 / HTTP Basic).
    pub user: Option<String>,
    /// Optional password, paired with [`user`](ProxyConfig::user).
    pub password: Option<String>,
    /// `true` when this entry is itself a gate node (a hop other proxies are
    /// reached through). Set by a leading `*` in the parsed line.
    pub is_gate: bool,
    /// The outer gate node dialed first; this entry is reached through its
    /// tunnel. `None` for a direct entry. Not interpreted by `connect_proxy`
    /// / `connect_proxy_once`.
    pub gate: Option<Arc<ProxyConfig>>,
}

impl ProxyConfig {
    /// New entry without credentials or gate. `ip` is derived from `host`:
    /// [`IP::V6`] for an IPv6 literal, otherwise [`IP::V4`]. Surrounding
    /// `[` `]` are stripped from `host`.
    pub fn new(protocol: ProxyProtocol, host: impl Into<String>, port: u16) -> Self {
        let mut host = host.into();
        if host.len() >= 2 && host.starts_with('[') && host.ends_with(']') {
            host.pop();
            host.remove(0);
        }
        let ip = if host.parse::<Ipv6Addr>().is_ok() {
            IP::V6
        } else {
            IP::V4
        };
        Self {
            protocol,
            ip,
            host,
            port,
            user: None,
            password: None,
            is_gate: false,
            gate: None,
        }
    }

    /// Shortcut for [`ProxyConfig::new`] with [`ProxyProtocol::Socks5`].
    pub fn socks5(host: impl Into<String>, port: u16) -> Self {
        Self::new(ProxyProtocol::Socks5, host, port)
    }

    /// Shortcut for [`ProxyConfig::new`] with [`ProxyProtocol::Http`].
    pub fn http(host: impl Into<String>, port: u16) -> Self {
        Self::new(ProxyProtocol::Http, host, port)
    }

    /// Shortcut for [`ProxyConfig::new`] with [`ProxyProtocol::Https`].
    pub fn https(host: impl Into<String>, port: u16) -> Self {
        Self::new(ProxyProtocol::Https, host, port)
    }

    /// Set username and password.
    pub fn with_auth(mut self, user: impl Into<String>, password: impl Into<String>) -> Self {
        self.user = Some(user.into());
        self.password = Some(password.into());
        self
    }

    /// Override the address-family label.
    pub fn with_family(mut self, ip: IP) -> Self {
        self.ip = ip;
        self
    }

    /// Link this entry to the outer `gate` node dialed first.
    pub fn with_gate(mut self, gate: ProxyConfig) -> Self {
        self.gate = Some(Arc::new(gate));
        self
    }

    /// Mark this entry as a gate node (`is_gate = true`).
    pub fn as_gate(mut self) -> Self {
        self.is_gate = true;
        self
    }
}

impl fmt::Debug for ProxyConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProxyConfig")
            .field("protocol", &self.protocol)
            .field("ip", &self.ip)
            .field("host", &self.host)
            .field("port", &self.port)
            .field("user", &self.user.as_ref().map(|_| REDACTED))
            .field("password", &self.password.as_ref().map(|_| REDACTED))
            .field("is_gate", &self.is_gate)
            .field("gate", &self.gate)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(host: &str, port: u16, user: Option<&str>, password: Option<&str>) -> ProxyConfig {
        let cfg = ProxyConfig::socks5(host, port);
        match (user, password) {
            (Some(u), Some(p)) => cfg.with_auth(u, p),
            _ => cfg,
        }
    }

    /// P2-04 release gate: `{:?}` on a gate chain must not expose
    /// credentials at ANY nesting depth, while the endpoint chain
    /// (protocol, host, port) stays visible.
    #[test]
    fn debug_redacts_credentials_through_nested_gates() {
        const USERS: [&str; 3] = ["fixture-user-0", "fixture-user-1", "fixture-user-2"];
        const SECRETS: [&str; 3] = [
            "fixture-secret-do-not-use-0",
            "fixture-secret-do-not-use-1",
            "fixture-secret-do-not-use-2",
        ];

        let inner = config("203.0.113.3", 1082, Some(USERS[2]), Some(SECRETS[2]));
        let mid = config("203.0.113.2", 1081, Some(USERS[1]), Some(SECRETS[1]))
            .as_gate()
            .with_gate(inner);
        let root = config("203.0.113.1", 1080, Some(USERS[0]), Some(SECRETS[0]))
            .as_gate()
            .with_gate(mid);

        let rendered = format!("{root:?}");

        for level in 0..3 {
            assert!(
                !rendered.contains(USERS[level]),
                "username leaked at gate depth {level}: {rendered}"
            );
            assert!(
                !rendered.contains(SECRETS[level]),
                "password leaked at gate depth {level}: {rendered}"
            );
        }
        assert!(rendered.contains("protocol: Socks5"));
        assert!(rendered.contains("host: \"203.0.113.1\""));
        assert!(rendered.contains("port: 1080"));
        assert!(rendered.contains("is_gate: true"));
        assert!(rendered.contains("gate: Some(ProxyConfig"));
        // Three chained configs, two credential fields each, all redacted.
        assert_eq!(rendered.matches(REDACTED).count(), 6);
    }

    #[test]
    fn debug_marks_credential_presence_without_values() {
        let rendered = format!("{:?}", config("203.0.113.1", 1080, None, None));
        assert!(rendered.contains("user: None"));
        assert!(rendered.contains("password: None"));

        let rendered = format!(
            "{:?}",
            config(
                "203.0.113.1",
                1080,
                Some("fixture-user"),
                Some("fixture-secret-do-not-use"),
            )
        );
        assert!(rendered.contains("user: Some(\"<redacted>\")"));
        assert!(rendered.contains("password: Some(\"<redacted>\")"));
        assert!(!rendered.contains("fixture-user"));
        assert!(!rendered.contains("fixture-secret-do-not-use"));
    }

    #[test]
    fn protocol_shortcuts() {
        let c = ProxyConfig::socks5("example.com", 1080);
        assert_eq!(c.protocol, ProxyProtocol::Socks5);
        assert_eq!(
            (c.host.as_str(), c.port, c.ip),
            ("example.com", 1080, IP::V4)
        );
        assert!(c.user.is_none() && c.password.is_none() && !c.is_gate && c.gate.is_none());
        assert_eq!(ProxyConfig::http("h", 8080).protocol, ProxyProtocol::Http);
        assert_eq!(ProxyConfig::https("h", 443).protocol, ProxyProtocol::Https);
    }

    #[test]
    fn new_derives_family_and_strips_brackets() {
        for host in ["::1", "[::1]", "2001:db8::1"] {
            let c = ProxyConfig::new(ProxyProtocol::Socks5, host, 1);
            assert_eq!(c.ip, IP::V6, "{host}");
            assert!(!c.host.contains(['[', ']']), "{host}");
        }
        assert_eq!(ProxyConfig::socks5("[::1]", 1).host, "::1");
        for host in ["1.2.3.4", "example.com"] {
            assert_eq!(ProxyConfig::socks5(host, 1).ip, IP::V4);
        }
    }

    #[test]
    fn builders() {
        let gate = ProxyConfig::socks5("gate.example", 1).as_gate();
        let c = ProxyConfig::socks5("1.2.3.4", 2)
            .with_auth("u", "p")
            .with_family(IP::V6)
            .with_gate(gate);
        assert_eq!(c.user.as_deref(), Some("u"));
        assert_eq!(c.password.as_deref(), Some("p"));
        assert_eq!(c.ip, IP::V6);
        let g = c.gate.as_ref().unwrap();
        assert_eq!(g.host, "gate.example");
        assert!(g.is_gate);
        assert!(!c.is_gate);
    }
}
