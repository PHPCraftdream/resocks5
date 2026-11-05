//! Shared proxy descriptors: wire protocol ([`ProxyProtocol`]) and full
//! configuration ([`ProxyConfig`]).

mod chain;
pub mod proxy_config;
pub mod proxy_protocol;
mod validate;

#[cfg(test)]
mod chain_tests;
#[cfg(test)]
mod validate_tests;

pub use chain::ChainKey;
pub use proxy_config::ProxyConfig;
pub use proxy_protocol::ProxyProtocol;
pub use validate::{ChainConfigError, CredentialField, ProxyConfigError};
