use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct ProxyListConfig {
    /// SOCKS5 over IPv4. Each entry is a `[*]user:pass@host:port` string;
    /// the `*` prefix marks a gate. See `resocks5_net::connect::parse_proxy_str`.
    #[serde(default)]
    pub socks5_v4: Vec<String>,
    /// SOCKS5 over IPv6.
    #[serde(default)]
    pub socks5_v6: Vec<String>,
    /// HTTP CONNECT proxies over IPv4.
    #[serde(default)]
    pub http_v4: Vec<String>,
    /// HTTP CONNECT proxies over IPv6.
    #[serde(default)]
    pub http_v6: Vec<String>,
    /// HTTPS (TLS-wrapped HTTP CONNECT) proxies over IPv4.
    #[serde(default)]
    pub https_v4: Vec<String>,
    /// HTTPS (TLS-wrapped HTTP CONNECT) proxies over IPv6.
    #[serde(default)]
    pub https_v6: Vec<String>,
}
