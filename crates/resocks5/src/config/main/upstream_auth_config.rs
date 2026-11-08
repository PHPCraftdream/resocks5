use serde::{Deserialize, Serialize};

/// Outbound (upstream proxy) authentication policy. A SOCKS5 entry with a
/// user and password upgrades automatically: our secure method (method
/// 0x80) is offered first and clear text (0x02) after it, and the upstream
/// picks. An HTTP/HTTPS entry sends `Basic` in its first request, exactly as
/// 0.4.x did (3proxy-style upstreams answer an unauthenticated CONNECT with
/// `407` and close); only `secure_only` makes it probe and require
/// `Resocks5-Secure`. A single entry can force the secure mode with the
/// trailing option `;secure_only` in `resocks5.proxy_list.ktav`.
#[derive(Debug, Default, Serialize, Deserialize, Clone, Copy, PartialEq, Eq)]
pub struct UpstreamAuthConfig {
    /// Outbound policy switch. When `true`, EVERY upstream dial uses
    /// `ProxyConfig::secure_only()`: only our method is acceptable, so an
    /// upstream that offers nothing but clear-text credentials fails to dial
    /// before any password is sent. When `false` (default), SOCKS5 entries
    /// upgrade automatically and HTTP entries send Basic first (Basic
    /// inside HTTPS TLS is not clear text on the wire). The per-entry
    /// `;secure_only` option in `resocks5.proxy_list.ktav` forces this for a
    /// single upstream.
    #[serde(default)]
    pub secure_only: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Defaults from an (almost) empty section. Mutation: flipping the
    /// derived default (a `true` default) fails here.
    #[test]
    fn an_empty_section_takes_the_defaults() {
        let cfg: UpstreamAuthConfig = ktav::from_str("secure_only: false\n").unwrap();
        assert!(!cfg.secure_only);
        assert_eq!(cfg, UpstreamAuthConfig::default());
    }

    /// An explicit `secure_only: true` is honoured, overriding the
    /// default. Mutation: removing the `#[serde(default)]` (or
    /// hard-coding true) fails here.
    #[test]
    fn an_explicit_secure_only_true_is_honoured() {
        let cfg: UpstreamAuthConfig = ktav::from_str("secure_only: true\n").unwrap();
        assert!(cfg.secure_only);
    }
}
