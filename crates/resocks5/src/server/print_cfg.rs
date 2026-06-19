use resocks5_net::types::ProxyConfig;

/// Formats a ProxyConfig for logging — `ip V4 - Socks5://host:port`.
///
/// Upstream credentials are intentionally NOT logged: the password
/// has always been hidden, but the username half is also a credential
/// that we don't want appearing in shell scrollback, syslog, or
/// shipped log files. `host:port` is enough to identify which proxy
/// is involved — if you run multiple accounts on the same host:port
/// that's a separate concern (give them distinct endpoints).
pub fn print_cfg(cfg: &ProxyConfig) -> String {
    format!(
        "ip {:?} - {:?}://{}:{}",
        cfg.ip, cfg.protocol, cfg.host, cfg.port
    )
}
