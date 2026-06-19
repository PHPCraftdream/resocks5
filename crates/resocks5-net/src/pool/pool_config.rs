use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoolConfig {
    /// Master switch. When `false` the pool is a no-op — `checkout`
    /// always returns `None` and no background tasks run.
    #[serde(default)]
    pub enabled: bool,
    /// Target number of pre-warmed sockets per proxy `(host, port)`.
    /// Defaults to 1 — one always-fresh spare ready, the moment it's
    /// taken the refill task kicks off another connect.
    #[serde(default = "default_spare")]
    pub spare_per_proxy: usize,
    /// After this many seconds, a pre-warmed socket is discarded and
    /// reconnected. Defends against the common pattern of upstream
    /// proxies silently dropping idle TCP after 30–60 seconds.
    /// Defaults to 30.
    #[serde(default = "default_max_age")]
    pub max_session_age_sec: u64,
}

fn default_spare() -> usize {
    1
}

fn default_max_age() -> u64 {
    30
}

impl Default for PoolConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            spare_per_proxy: 1,
            max_session_age_sec: 30,
        }
    }
}
