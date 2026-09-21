//! The full descriptor of a remote proxy: endpoint, credentials, and gate link.

use std::fmt;
use std::sync::Arc;

use crate::types::{ProxyProtocol, IP};

/// Placeholder printed by [`ProxyConfig`]'s [`Debug`](std::fmt::Debug) impl in
/// place of any `user` or `password` value.
const REDACTED: &str = "<redacted>";

/// Configuration for a remote proxy with authentication.
///
/// `gate` uses `Arc` rather than `Box` so that constructing a
/// gate-wrapped variant (e.g. when caching a successful gate+proxy
/// pair in `ProxyRotator::link_proxy`) is a cheap refcount bump
/// instead of a deep copy of the gate's `String` fields.
///
/// The [`Debug`](std::fmt::Debug) output is redacted: `user` and `password`
/// values are replaced with a placeholder, recursively through
/// [`gate`](ProxyConfig::gate), so debug-logging a `ProxyConfig` never
/// leaks proxy credentials.
#[derive(Clone)]
pub struct ProxyConfig {
    /// Wire protocol spoken to this proxy.
    pub protocol: ProxyProtocol,
    /// Address family of `host`.
    pub ip: IP,
    /// Proxy host (IP literal or domain).
    pub host: String,
    /// Proxy TCP port.
    pub port: u16,
    /// Optional username (RFC 1929 / HTTP Basic).
    pub user: Option<String>,
    /// Optional password, paired with [`user`](ProxyConfig::user).
    pub password: Option<String>,
    /// `true` when this entry is a gate (tunnel through it before the inner
    /// handshake). Set by a leading `*` in the parsed line.
    pub is_gate: bool,
    /// The inner proxy to reach *through* this gate. `None` for a non-gate.
    pub gate: Option<Arc<ProxyConfig>>,
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
        ProxyConfig {
            protocol: ProxyProtocol::Socks5,
            ip: IP::V4,
            host: host.to_string(),
            port,
            user: user.map(str::to_string),
            password: password.map(str::to_string),
            is_gate: false,
            gate: None,
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
        let mid = ProxyConfig {
            is_gate: true,
            gate: Some(Arc::new(inner)),
            ..config("203.0.113.2", 1081, Some(USERS[1]), Some(SECRETS[1]))
        };
        let root = ProxyConfig {
            is_gate: true,
            gate: Some(Arc::new(mid)),
            ..config("203.0.113.1", 1080, Some(USERS[0]), Some(SECRETS[0]))
        };

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
}
