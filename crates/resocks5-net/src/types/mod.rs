//! Shared proxy descriptors: address family ([`IP`]), wire protocol
//! ([`ProxyProtocol`]), and full configuration ([`ProxyConfig`]).

pub mod ip;
pub mod proxy_config;
pub mod proxy_protocol;

pub use ip::IP;
pub use proxy_config::ProxyConfig;
pub use proxy_protocol::ProxyProtocol;
