//! Knobs for the pre-connect TCP pool ([`PoolConfig`]).

/// Serialisable configuration for [`ProxyPool`](crate::pool::ProxyPool).
///
/// The `serde` derives below exist only with the `serde` feature;
/// everything else — `Debug`, `Clone`, `Default`, the field layout — is
/// identical either way.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct PoolConfig {
    /// Master switch. When `false` the pool is a no-op — `checkout`
    /// always returns `None` and no background tasks run.
    #[cfg_attr(feature = "serde", serde(default))]
    pub enabled: bool,
    /// Target number of pre-warmed sockets per proxy `(host, port)`.
    /// Defaults to 1 — one always-fresh spare ready, the moment it's
    /// taken the refill task kicks off another connect.
    #[cfg_attr(feature = "serde", serde(default = "default_spare"))]
    pub spare_per_proxy: usize,
    /// After this many seconds, a pre-warmed socket is discarded and
    /// reconnected. Defends against the common pattern of upstream
    /// proxies silently dropping idle TCP after 30–60 seconds.
    /// Defaults to 30.
    #[cfg_attr(feature = "serde", serde(default = "default_max_age"))]
    pub max_session_age_sec: u64,
}

// Serde field-default providers, referenced only from the `serde`
// attributes above, so they exist only with the feature.
#[cfg(feature = "serde")]
fn default_spare() -> usize {
    1
}

#[cfg(feature = "serde")]
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
