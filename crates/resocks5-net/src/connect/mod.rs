//! Upstream connectors and stream plumbing.
//!
//! The top-level entry point is `connect_proxy`, which dispatches on the
//! proxy's [`ProxyProtocol`](crate::types::ProxyProtocol) to the right
//! handshake. The lower-level pieces — per-protocol handshakes, a
//! bidirectional tunneller, TCP keepalive, proxy-string parsing, a default
//! TLS connector, and ClientHello fragmentation — live in the submodules and
//! are re-exported here for direct use.

pub mod connect_http_proxy;
pub mod connect_proxy;
pub mod connect_socks5_proxy;
pub mod handshake_over_stream;
pub mod parse_proxy_str;
pub mod recover_host;
pub mod tcp_keepalive;
pub mod tls_fragment;
pub mod tunnel;
pub mod upstream_tls;

pub use connect_http_proxy::connect_http_proxy;
pub use connect_proxy::connect_proxy;
pub use connect_socks5_proxy::connect_socks5_proxy;
pub use handshake_over_stream::handshake_over_stream;
pub use parse_proxy_str::parse_proxy_str;
pub use recover_host::{parse_http_host, parse_sni};
pub use tls_fragment::{send_possibly_fragmented, FragmentSpec};
pub use upstream_tls::make_tls_connector;
