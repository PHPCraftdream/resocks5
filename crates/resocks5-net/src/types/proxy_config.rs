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
    pub protocol: ProxyProtocol,
    pub ip: IP,
    pub host: String,
    pub port: u16,
    pub user: Option<String>,
    pub password: Option<String>,
    pub is_gate: bool,
    pub gate: Option<Arc<ProxyConfig>>,
}
