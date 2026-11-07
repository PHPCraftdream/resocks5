//! The full descriptor of a remote proxy: endpoint, credentials, and gate link.

use std::fmt;
use std::sync::Arc;

use crate::connect::{
    parse_proxy_str, parse_proxy_uri, ParseProxyError, ProxyUriError, ProxyUriOptions,
};
use crate::types::ProxyProtocol;

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
/// copy of the gate's `String` fields. [`dial_chain`](crate::connect::dial_chain)
/// follows `gate` links (to any depth); `dial`, `connect_proxy` and
/// `connect_proxy_once` do NOT interpret `gate`. No `dial*` or
/// `connect_proxy*` function interprets gate levels. Use [`ProxyConfig::chain`]
/// to construct a chain from outermost node through its exit.
///
/// The [`Debug`](std::fmt::Debug) output is redacted: `user` and `password`
/// values are replaced with a placeholder at every node of the
/// [`gate`](ProxyConfig::gate) chain, so debug-logging a `ProxyConfig`
/// never leaks proxy credentials. The chain is rendered as a flat list
/// (`gate: [...]`, outermost gate first) instead of by recursion, so a
/// long chain cannot overflow the stack in `Debug`.
#[derive(Clone)]
#[non_exhaustive]
pub struct ProxyConfig {
    /// Wire protocol spoken to this proxy.
    pub protocol: ProxyProtocol,
    /// Proxy host (IP literal or domain), without IPv6 brackets.
    pub host: String,
    /// Proxy TCP port.
    pub port: u16,
    /// Optional username (RFC 1929 / HTTP Basic).
    pub user: Option<String>,
    /// Optional password, paired with [`user`](ProxyConfig::user).
    pub password: Option<String>,
    /// Secure-auth credentials (SOCKS5 method 0x80): when set, the greeting
    /// uses them instead of `user`/`password`, and the password never crosses
    /// the wire. Set with [`ProxyConfig::with_secure_auth`].
    #[cfg(feature = "secure-auth")]
    pub secure_auth: Option<Arc<crate::secure_auth::SecureCredentials>>,
    /// GSSAPI credentials (SOCKS5 method 0x01, RFC 1961). When set (alone or
    /// with `secure_auth`) the greeting offers the strong methods — GSSAPI
    /// first — and the server picks; no password crosses the wire. Set with
    /// [`ProxyConfig::with_gssapi`].
    #[cfg(feature = "gssapi")]
    pub gssapi: Option<Arc<crate::gssapi::GssCredentials>>,
    /// The number of leading `*` markers; 0 denotes an ordinary/exit proxy.
    /// `is_gate == (gate_level > 0)`.
    pub gate_level: u8,
    /// `true` exactly when `gate_level > 0`.
    pub is_gate: bool,
    /// The outer gate node dialed first; this entry is reached through its
    /// tunnel. `None` for a direct entry. Followed by
    /// [`dial_chain`](crate::connect::dial_chain); not interpreted by `dial`,
    /// `connect_proxy` or `connect_proxy_once`.
    pub gate: Option<Arc<ProxyConfig>>,
}

impl ProxyConfig {
    /// New entry without credentials or gate. Surrounding `[` `]` are
    /// stripped from `host`.
    pub fn new(protocol: ProxyProtocol, host: impl Into<String>, port: u16) -> Self {
        let mut host = host.into();
        if host.len() >= 2 && host.starts_with('[') && host.ends_with(']') {
            host.pop();
            host.remove(0);
        }
        Self {
            protocol,
            host,
            port,
            user: None,
            password: None,
            #[cfg(feature = "secure-auth")]
            secure_auth: None,
            #[cfg(feature = "gssapi")]
            gssapi: None,
            is_gate: false,
            gate_level: 0,
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

    /// Authenticate to this SOCKS5 proxy with secure auth (method 0x80): the
    /// user name is kept in `user` (the upstream's identity), the password
    /// only inside the credentials, never in `password` and never on the wire.
    #[cfg(feature = "secure-auth")]
    pub fn with_secure_auth(mut self, credentials: crate::secure_auth::SecureCredentials) -> Self {
        self.user = Some(credentials.user().to_owned());
        self.password = None;
        self.secure_auth = Some(Arc::new(credentials));
        self
    }

    /// Authenticate to this SOCKS5 proxy with GSSAPI (method 0x01, RFC 1961).
    /// Can be combined with [`ProxyConfig::with_secure_auth`]: both are offered,
    /// GSSAPI first, and the server chooses.
    #[cfg(feature = "gssapi")]
    pub fn with_gssapi(mut self, credentials: crate::gssapi::GssCredentials) -> Self {
        self.gssapi = Some(Arc::new(credentials));
        self
    }

    /// Overwrite the clear-text `user` and `password` with zeros and clear
    /// them, here and at every gate this value solely owns; drop the
    /// secure-auth credentials (their password is wiped when the last copy
    /// goes). `ProxyConfig` has no `Drop`: clones, and gates shared with other
    /// configs, keep their values. Returns `false` when a shared gate was left
    /// untouched.
    #[cfg(feature = "zeroize")]
    pub fn wipe_credentials(&mut self) -> bool {
        use zeroize::Zeroize;
        let mut node = self;
        loop {
            node.user.zeroize();
            node.password.zeroize();
            #[cfg(feature = "secure-auth")]
            {
                node.secure_auth = None;
                #[cfg(feature = "gssapi")]
                {
                    node.gssapi = None;
                }
            }
            match node.gate.as_mut() {
                None => return true,
                Some(gate) => match Arc::get_mut(gate) {
                    Some(gate) => node = gate,
                    None => return false,
                },
            }
        }
    }

    /// Set username and password.
    pub fn with_auth(mut self, user: impl Into<String>, password: impl Into<String>) -> Self {
        self.user = Some(user.into());
        self.password = Some(password.into());
        self
    }

    /// Parse a proxy address with optional credentials and leading gate markers,
    /// delegating to `parse_proxy_str` (same grammar, same
    /// [`ParseProxyError`] variants).
    ///
    /// Parse an address with 0–255 leading `*` markers (zero means an
    /// ordinary proxy); markers record gate level only. `gate` links this
    /// entry to the outer gate dialed first, and `dial_chain` follows those
    /// links. Neither `dial`/`dial_chain` nor `connect_proxy*` interprets
    /// the level value. The host may be a domain, an IPv4 literal, or an
    /// IPv6 literal (bracketed, or bare with trailing `:port` for backward
    /// compatibility).
    pub fn from_addr(protocol: ProxyProtocol, addr: &str) -> Result<Self, ParseProxyError> {
        parse_proxy_str(addr, protocol)
    }

    /// Parse `scheme://[user:password@]host:port` (schemes `socks5`, `socks5h`,
    /// `http`, `https`) with the default [`ProxyUriOptions`]: percent-decoded
    /// credentials, a required port, no path, query or fragment. Errors carry no
    /// input text. See [`parse_proxy_uri`] for the grammar.
    ///
    /// # Errors
    ///
    /// A [`ProxyUriError`] naming the first problem.
    pub fn from_uri(uri: &str) -> Result<Self, ProxyUriError> {
        parse_proxy_uri(uri, &ProxyUriOptions::new())
    }

    /// [`ProxyConfig::from_uri`] with explicit [`ProxyUriOptions`] (for example
    /// `ip_literal_only(true)` to refuse host names).
    ///
    /// # Errors
    ///
    /// A [`ProxyUriError`] naming the first problem.
    pub fn from_uri_with(uri: &str, options: &ProxyUriOptions) -> Result<Self, ProxyUriError> {
        parse_proxy_uri(uri, options)
    }

    /// Would using this entry send its credentials in clear text? SOCKS5
    /// UNAME/PASSWD would; HTTP Basic does unless the proxy is reached over
    /// TLS (`https`).
    pub(crate) fn sends_cleartext_credentials(&self) -> bool {
        self.user.is_some() && self.password.is_some() && self.protocol != ProxyProtocol::Https
    }

    /// Refuse an entry that would have to send credentials in clear text: this
    /// crate never does (no RFC 1929, no Basic over plain HTTP).
    pub(crate) fn refuse_cleartext(&self) -> Result<(), crate::ConnectError> {
        if self.sends_cleartext_credentials() {
            return Err(crate::ConnectError::CleartextCredentialsRefused);
        }
        Ok(())
    }

    /// Link this entry to the outer `gate` node dialed first.
    pub fn with_gate(mut self, gate: ProxyConfig) -> Self {
        self.gate = Some(Arc::new(gate));
        self
    }

    /// Mark this entry as a gate node, raising level to at least one.
    pub fn as_gate(mut self) -> Self {
        self.gate_level = self.gate_level.max(1);
        self.is_gate = true;
        self
    }

    /// Set gate level and synchronize [`is_gate`](ProxyConfig::is_gate).
    pub fn with_gate_level(mut self, level: u8) -> Self {
        self.gate_level = level;
        self.is_gate = level > 0;
        self
    }

    /// Borrow the chain's nodes, outermost first and exit last.
    pub fn nodes(&self) -> Vec<&ProxyConfig> {
        let mut nodes = Vec::new();
        let mut current = Some(self);
        while let Some(node) = current {
            nodes.push(node);
            current = node.gate.as_deref();
        }
        nodes.reverse();
        nodes
    }

    /// Return the outermost gate, or this entry when ungated.
    pub fn outermost(&self) -> &ProxyConfig {
        let mut current = self;
        while let Some(outer) = current.gate.as_deref() {
            current = outer;
        }
        current
    }
}

/// Prints one node's own fields without following its gate link; the
/// chain is rendered by [`GateChainDebug`] instead, so a long chain
/// cannot put one formatter frame per node on the stack.
struct NodeDebug<'a>(&'a ProxyConfig);

impl fmt::Debug for NodeDebug<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProxyConfig")
            .field("protocol", &self.0.protocol)
            .field("host", &self.0.host)
            .field("port", &self.0.port)
            .field("user", &self.0.user.as_ref().map(|_| REDACTED))
            .field("password", &self.0.password.as_ref().map(|_| REDACTED))
            .field("gate_level", &self.0.gate_level)
            .field("is_gate", &self.0.is_gate)
            .finish()
    }
}

/// Prints the gate chain as a flat list, outermost gate first, without
/// recursing through [`ProxyConfig`]'s own `Debug` impl.
struct GateChainDebug<'a>(&'a ProxyConfig);

impl fmt::Debug for GateChainDebug<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // `nodes()` is outermost-first with `self` (the exit) LAST: the
        // gates are everything before it.
        let nodes = self.0.nodes();
        let gates = &nodes[..nodes.len() - 1];
        f.debug_list()
            .entries(gates.iter().copied().map(NodeDebug))
            .finish()
    }
}

impl fmt::Debug for ProxyConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProxyConfig")
            .field("protocol", &self.protocol)
            .field("host", &self.host)
            .field("port", &self.port)
            .field("user", &self.user.as_ref().map(|_| REDACTED))
            .field("password", &self.password.as_ref().map(|_| REDACTED))
            .field("gate_level", &self.gate_level)
            .field("is_gate", &self.is_gate)
            .field("gate", &GateChainDebug(self))
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `wipe_credentials` clears every solely owned node and reports a shared
    /// gate it could not touch. Mutation: stopping at the first node leaves
    /// the gate's password.
    #[cfg(feature = "zeroize")]
    #[test]
    fn wipe_credentials_clears_owned_nodes_and_reports_shared_gates() {
        let gate = ProxyConfig::socks5("gate", 1).with_auth("gu", "gp");
        let mut owned = ProxyConfig::socks5("exit", 2)
            .with_auth("eu", "ep")
            .with_gate(gate.clone());
        assert!(owned.wipe_credentials());
        let nodes = owned.nodes();
        assert!(nodes
            .iter()
            .all(|n| n.user.is_none() && n.password.is_none()));

        let mut shared = ProxyConfig::socks5("exit", 2)
            .with_auth("eu", "ep")
            .with_gate(gate);
        let other = shared.clone();
        assert!(
            !shared.wipe_credentials(),
            "the gate is shared with `other`"
        );
        assert_eq!(shared.password, None);
        assert_eq!(other.gate.as_ref().unwrap().password.as_deref(), Some("gp"));
    }

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
        assert!(rendered.contains("gate_level: 1"));
        assert!(rendered.contains("is_gate: true"));
        assert!(rendered.contains("gate: [ProxyConfig"));
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
        assert_eq!((c.host.as_str(), c.port), ("example.com", 1080));
        assert!(
            c.user.is_none()
                && c.password.is_none()
                && !c.is_gate
                && c.gate_level == 0
                && c.gate.is_none()
        );
        assert_eq!(ProxyConfig::http("h", 8080).protocol, ProxyProtocol::Http);
        assert_eq!(ProxyConfig::https("h", 443).protocol, ProxyProtocol::Https);
    }

    #[test]
    fn new_strips_brackets() {
        let c = ProxyConfig::new(ProxyProtocol::Socks5, "[::1]", 1);
        assert!(!c.host.contains(['[', ']']));
        assert_eq!(ProxyConfig::socks5("[::1]", 1).host, "::1");
        assert_eq!(ProxyConfig::socks5("1.2.3.4", 1).host, "1.2.3.4");
    }

    #[test]
    fn from_addr_delegates_to_parse_proxy_str() {
        let c = ProxyConfig::from_addr(ProxyProtocol::Https, "*u:p@[2001:db8::1]:443").unwrap();
        assert_eq!(c.protocol, ProxyProtocol::Https);
        assert_eq!(c.gate_level, 1);
        assert!(c.is_gate);
        assert_eq!(c.user.as_deref(), Some("u"));
        assert_eq!(c.password.as_deref(), Some("p"));
        assert_eq!(c.host, "2001:db8::1");
        assert_eq!(c.port, 443);
        assert_eq!(
            ProxyConfig::from_addr(ProxyProtocol::Socks5, "no port here").unwrap_err(),
            crate::connect::ParseProxyError::BadHostPort
        );
    }

    #[test]
    fn gate_level_builders_synchronize_and_preserve_values() {
        let direct = ProxyConfig::socks5("h", 1);
        assert_eq!(direct.gate_level, 0);
        assert!(!direct.is_gate);
        let raised = direct.clone().with_gate_level(7).as_gate();
        assert_eq!(raised.gate_level, 7);
        assert!(raised.is_gate);
        let lowered = raised.with_gate_level(0);
        assert_eq!(lowered.gate_level, 0);
        assert!(!lowered.is_gate);
        assert_eq!(direct.as_gate().gate_level, 1);
    }

    #[test]
    fn builders() {
        let gate = ProxyConfig::socks5("gate.example", 1).as_gate();
        let c = ProxyConfig::socks5("1.2.3.4", 2)
            .with_auth("u", "p")
            .with_gate(gate);
        assert_eq!(c.user.as_deref(), Some("u"));
        assert_eq!(c.password.as_deref(), Some("p"));
        let g = c.gate.as_ref().unwrap();
        assert_eq!(g.host, "gate.example");
        assert_eq!(g.gate_level, 1);
        assert!(g.is_gate);
        assert_eq!(c.gate_level, 0);
        assert!(!c.is_gate);
    }

    /// Mutation caught: reverting `Debug` to the recursive
    /// `gate: Some(...)` rendering makes `, gate: ` (the field, not the
    /// `is_gate: ` of each node) appear once per nested node instead of
    /// exactly once.
    #[test]
    fn debug_renders_the_gate_chain_flat_not_nested() {
        let inner = config("203.0.113.3", 1082, None, None);
        let mid = config("203.0.113.2", 1081, None, None)
            .as_gate()
            .with_gate(inner);
        let root = config("203.0.113.1", 1080, None, None)
            .as_gate()
            .with_gate(mid);
        let rendered = format!("{root:?}");
        assert_eq!(rendered.matches(", gate: ").count(), 1, "{rendered}");
        assert!(rendered.contains("gate: [ProxyConfig"), "{rendered}");
        // Every node exactly once: the exit is the printed struct itself,
        // the list holds the gates only (outermost first).
        for host in ["203.0.113.1", "203.0.113.2", "203.0.113.3"] {
            assert_eq!(rendered.matches(host).count(), 1, "{host}: {rendered}");
        }
        assert!(
            rendered.find("203.0.113.3").unwrap() < rendered.find("203.0.113.2").unwrap(),
            "outermost gate first: {rendered}"
        );
    }

    /// 64 nodes (the [`crate::types::MAX_CHAIN_NODES`] limit), built via
    /// `with_gate`, which does not validate. Mutation caught: making
    /// `Debug` recurse over the gate chain again overflows this 256 KiB
    /// stack at 64 nodes, or at minimum breaks the flat-rendering
    /// assertion inside.
    #[test]
    fn debug_of_max_depth_chain_is_iterative_on_a_small_stack() {
        let mut cfg = ProxyConfig::socks5("chain-host", 1);
        for _ in 1..64 {
            cfg = ProxyConfig::socks5("chain-host", 1).with_gate(cfg);
        }
        let handle = std::thread::Builder::new()
            .stack_size(256 * 1024)
            .spawn(move || {
                let rendered = format!("{cfg:?}");
                assert_eq!(rendered.matches(", gate: ").count(), 1, "{rendered}");
                assert!(rendered.contains("gate: [ProxyConfig"), "{rendered}");
                assert_eq!(cfg.chain_len(), 64);
            })
            .expect("spawn 256 KiB thread");
        handle
            .join()
            .expect("Debug of a 64-node chain must not overflow");
    }
}
