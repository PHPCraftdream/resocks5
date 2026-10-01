use resocks5_net::types::ProxyConfig;

/// Formats a ProxyConfig for logging — `ip V4 - Socks5://host:port`.
///
/// The `V4`/`V6` label is derived from the host literal at print time
/// (`V6` when the host parses as an IPv6 address, `V4` otherwise) — the
/// SDK no longer carries an address-family label on `ProxyConfig`.
///
/// Upstream credentials are intentionally NOT logged: the password
/// has always been hidden, but the username half is also a credential
/// that we don't want appearing in shell scrollback, syslog, or
/// shipped log files. `host:port` is enough to identify which proxy
/// is involved — if you run multiple accounts on the same host:port
/// that's a separate concern (give them distinct endpoints).
pub fn print_cfg(cfg: &ProxyConfig) -> String {
    format!(
        "ip {} - {:?}://{}:{}",
        family_label(&cfg.host),
        cfg.protocol,
        cfg.host,
        cfg.port
    )
}

/// Address-family label for logging: `"V6"` when `host` is an IPv6
/// literal, `"V4"` otherwise (domains and IPv4 literals alike).
pub(crate) fn family_label(host: &str) -> &'static str {
    if host.parse::<std::net::Ipv6Addr>().is_ok() {
        "V6"
    } else {
        "V4"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn family_label_classifies_by_host() {
        assert_eq!(family_label("::1"), "V6");
        assert_eq!(family_label("2001:db8::1"), "V6");
        assert_eq!(family_label("10.0.0.1"), "V4");
        assert_eq!(family_label("example.com"), "V4");
        assert_eq!(family_label(""), "V4");
    }

    #[test]
    fn print_cfg_format_is_unchanged() {
        let cfg = ProxyConfig::socks5("203.0.113.7", 1080).with_auth("u", "p");
        assert_eq!(print_cfg(&cfg), "ip V4 - Socks5://203.0.113.7:1080");

        let cfg = ProxyConfig::socks5("[2001:db8::1]", 1080);
        assert_eq!(print_cfg(&cfg), "ip V6 - Socks5://2001:db8::1:1080");
    }
}
