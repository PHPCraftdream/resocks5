//! Shared proxy descriptors: wire protocol ([`ProxyProtocol`]) and full
//! configuration ([`ProxyConfig`]).

pub mod proxy_config;
pub mod proxy_protocol;

pub use proxy_config::ProxyConfig;
pub use proxy_protocol::ProxyProtocol;
