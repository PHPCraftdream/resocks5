//! Shared proxy descriptors: wire protocol ([`ProxyProtocol`]) and full
//! configuration ([`ProxyConfig`]).

mod chain;
pub mod proxy_config;
pub mod proxy_protocol;

#[cfg(test)]
mod chain_tests;

pub use chain::ChainKey;
pub use proxy_config::ProxyConfig;
pub use proxy_protocol::ProxyProtocol;
