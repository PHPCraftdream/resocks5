use std::fmt::Write as _;

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

/// Appends to a ready buffer exactly the same text as [`print_cfg`] —
/// `ip V4/V6 - DebugProtocol://host:port`, without user/password. Private
/// helper for gate_label: no intermediate String per gate.
pub(crate) fn push_cfg(out: &mut String, cfg: &ProxyConfig) {
    let _ = write!(
        out,
        "ip {} - {:?}://{}:{}",
        family_label(&cfg.host),
        cfg.protocol,
        cfg.host,
        cfg.port
    );
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

    #[test]
    fn push_cfg_matches_legacy_reference() {
        let cases = [
            ProxyConfig::socks5("203.0.113.7", 1080).with_auth("secret-user", "secret-pass"),
            ProxyConfig::socks5("[2001:db8::1]", 1080),
            ProxyConfig::http("::1", 80),
            ProxyConfig::https("example.invalid", 443),
            ProxyConfig::socks5("пример.test", 1080),
            ProxyConfig::socks5("", 1080),
            ProxyConfig::http("10.0.0.1", 1),
            ProxyConfig::https("a".repeat(300), 65535),
        ];
        for cfg in &cases {
            // The oracle is the previous formatter: the same format! verbatim.
            let expected = format!(
                "ip {} - {:?}://{}:{}",
                family_label(&cfg.host),
                cfg.protocol,
                cfg.host,
                cfg.port
            );
            let mut pushed = String::new();
            push_cfg(&mut pushed, cfg);
            assert_eq!(pushed, expected, "host={:?}", cfg.host);
            assert_eq!(print_cfg(cfg), expected);
            assert!(!expected.contains("secret-user"));
            assert!(!expected.contains("secret-pass"));
        }
    }
}

#[cfg(all(test, feature = "test-instrumentation"))]
mod perf_tests {
    use super::*;
    use crate::perf::{measure, report};

    /// The exact previous print_cfg body (before the push_cfg extraction).
    fn legacy_print_cfg(cfg: &ProxyConfig) -> String {
        format!(
            "ip {} - {:?}://{}:{}",
            family_label(&cfg.host),
            cfg.protocol,
            cfg.host,
            cfg.port
        )
    }

    /// Plain print_cfg against the previous format!: bytes and allocator.
    /// A guard against regressing direct/probe/error logs: they call the
    /// changed print_cfg and must not become costlier than the old path
    /// in alloc/alloc_zeroed/realloc or requested_bytes.
    #[test]
    fn perf208_print_cfg_matches_legacy_allocations() {
        let cases: [(&str, ProxyConfig); 8] = [
            ("socks5_ipv4", ProxyConfig::socks5("203.0.113.7", 1080)),
            ("http_ipv6", ProxyConfig::http("::1", 80)),
            ("https_domain", ProxyConfig::https("example.invalid", 443)),
            ("socks5_utf8", ProxyConfig::socks5("пример.test", 1080)),
            ("socks5_empty", ProxyConfig::socks5("", 1080)),
            (
                "socks5_long300_maxport",
                ProxyConfig::socks5("a".repeat(300), 65535),
            ),
            ("http_port1", ProxyConfig::http("10.0.0.1", 1)),
            (
                "socks5_ipv6_brackets",
                ProxyConfig::socks5("[2001:db8::1]", 1080),
            ),
        ];
        for (label, cfg) in cases {
            assert_eq!(print_cfg(&cfg), legacy_print_cfg(&cfg), "{label}");
            let (_, legacy) = measure(|| legacy_print_cfg(&cfg));
            let (_, legacy_again) = measure(|| legacy_print_cfg(&cfg));
            assert_eq!(legacy, legacy_again, "{label}");
            let (_, current) = measure(|| print_cfg(&cfg));
            let (_, current_again) = measure(|| print_cfg(&cfg));
            assert_eq!(current, current_again, "{label}");
            assert!(current.alloc <= legacy.alloc, "{label}: alloc");
            assert!(
                current.alloc_zeroed <= legacy.alloc_zeroed,
                "{label}: alloc_zeroed"
            );
            assert!(current.realloc <= legacy.realloc, "{label}: realloc");
            assert!(
                current.requested_bytes <= legacy.requested_bytes,
                "{label}: requested_bytes {} > {}",
                current.requested_bytes,
                legacy.requested_bytes
            );
            report(&format!("print_cfg/legacy/{label}"), legacy);
            report(&format!("print_cfg/current/{label}"), current);
        }
    }
}
