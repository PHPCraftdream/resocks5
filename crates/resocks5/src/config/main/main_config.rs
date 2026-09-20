use serde::{Deserialize, Serialize};

use crate::config::{AuthConfig, FileLogConfig, NetworkConfig, TlsFragmentConfig};
use crate::logger::LogConfig;
use resocks5_net::pool::PoolConfig;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct MainConfig {
    pub port: u16,
    /// Host (interface) the listener binds on. Defaults to `127.0.0.1`
    /// so a fresh install never accidentally exposes the proxy to the
    /// network — flip to `0.0.0.0` (LAN) or `::` (IPv6 dual-stack) only
    /// when you know the auth and banned_patterns are right for that.
    #[serde(default = "default_listen_host")]
    pub listen_host: String,
    #[serde(default)]
    pub banned_patterns: Vec<String>,
    pub auth: AuthConfig,
    /// Per-event-type log flags. Defaults via `LogConfig::default()`
    /// when the section is missing — `serde(default)` here covers the
    /// field, each flag inside has its own per-field default.
    #[serde(default)]
    pub log: LogConfig,
    /// Pre-connect TCP pool toward upstream proxies. See `pool.rs`.
    /// `enabled: false` by default, so old configs are unaffected.
    #[serde(default)]
    pub pool: PoolConfig,
    /// TLS ClientHello fragmentation for outgoing upstream connections.
    /// `enabled: false` by default, so existing configs are unaffected.
    #[serde(default)]
    pub tls_fragment: TlsFragmentConfig,
    /// Connect/handshake/tunnel timeouts and TCP keepalive — the
    /// safety net that prevents dead upstreams from leaking sockets
    /// and tasks indefinitely.
    #[serde(default)]
    pub network: NetworkConfig,
    /// Optional file destination for the log channel.
    /// `enabled: false` by default, so existing configs are unaffected.
    #[serde(default)]
    pub file_log: FileLogConfig,
}

fn default_listen_host() -> String {
    "127.0.0.1".to_string()
}
