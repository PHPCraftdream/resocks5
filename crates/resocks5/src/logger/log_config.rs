use serde::{Deserialize, Serialize};

/// Per-event-type flags controlling which log lines actually fire. A
/// flag set to `false` makes the corresponding `Logger::*` method a
/// no-op that doesn't even build the message string.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogConfig {
    /// Server start, bind address, "no users / N users configured".
    /// Useful, low-volume — defaults on.
    #[serde(default = "default_true")]
    pub lifecycle: bool,
    /// "Attempting to use cached proxy for X" — every cache lookup that
    /// finds an entry. Pure debug noise on a busy server. Defaults off.
    #[serde(default)]
    pub cache_attempts: bool,
    /// "Cache used for X" — every successful cache hit. Highest-volume
    /// event on a healthy server. Defaults off.
    #[serde(default)]
    pub cache_hits: bool,
    /// "Cache written for X" — fires once per first-seen target.
    /// Medium volume. Defaults off.
    #[serde(default)]
    pub cache_writes: bool,
    /// Per-attempt failures during proxy connect / handshake. Useful to
    /// see which upstream proxies are dying. Defaults on.
    #[serde(default = "default_true")]
    pub proxy_failures: bool,
    /// Connections to addresses matching `banned_patterns`. Security-
    /// relevant. Defaults on.
    #[serde(default = "default_true")]
    pub banned_targets: bool,
    /// Errors from `handle_client` — auth fails, malformed clients,
    /// half-broken handshakes. Useful for debugging. Defaults on.
    #[serde(default = "default_true")]
    pub connection_errors: bool,
    /// One line per upstream connect+handshake attempt — success or
    /// failure, with duration. High volume on a busy server; enable
    /// temporarily to diagnose which upstreams are slow/dead.
    #[serde(default)]
    pub attempts: bool,
}

fn default_true() -> bool {
    true
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            lifecycle: true,
            cache_attempts: false,
            cache_hits: false,
            cache_writes: false,
            proxy_failures: true,
            banned_targets: true,
            connection_errors: true,
            attempts: false,
        }
    }
}
