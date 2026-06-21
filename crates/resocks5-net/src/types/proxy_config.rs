//! The full descriptor of a remote proxy: endpoint, credentials, and gate link.

use std::sync::Arc;

use crate::types::{ProxyProtocol, IP};

/// Configuration for a remote proxy with authentication.
///
/// `gate` uses `Arc` rather than `Box` so that constructing a
/// gate-wrapped variant (e.g. when caching a successful gate+proxy
/// pair in `ProxyRotator::link_proxy`) is a cheap refcount bump
/// instead of a deep copy of the gate's `String` fields.
#[derive(Clone, Debug)]
pub struct ProxyConfig {
    /// Wire protocol spoken to this proxy.
    pub protocol: ProxyProtocol,
    /// Address family of `host`.
    pub ip: IP,
    /// Proxy host (IP literal or domain).
    pub host: String,
    /// Proxy TCP port.
    pub port: u16,
    /// Optional username (RFC 1929 / HTTP Basic).
    pub user: Option<String>,
    /// Optional password, paired with [`user`](ProxyConfig::user).
    pub password: Option<String>,
    /// `true` when this entry is a gate (tunnel through it before the inner
    /// handshake). Set by a leading `*` in the parsed line.
    pub is_gate: bool,
    /// The inner proxy to reach *through* this gate. `None` for a non-gate.
    pub gate: Option<Arc<ProxyConfig>>,
}
