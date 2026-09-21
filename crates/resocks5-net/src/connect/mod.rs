//! Upstream connectors and stream plumbing.
//!
//! The top-level entry point is `connect_proxy`, which dispatches on the
//! proxy's [`ProxyProtocol`](crate::types::ProxyProtocol) to the right
//! handshake. The lower-level pieces — per-protocol handshakes, a
//! bidirectional tunneller, TCP keepalive, proxy-string parsing, a default
//! TLS connector, and ClientHello fragmentation — live in the submodules
//! and are re-exported here for direct use.
//!
//! Grouping: `proxy_connect` holds the per-protocol connectors and the
//! protocol dispatcher, `tls` the TLS-facing pieces (ClientHello
//! fragmentation and record-layer walking always; the default connector
//! and the HTTPS upstream behind the `tls` feature), and `util` the
//! small parsing and socket helpers. The group folders are private;
//! everything stays reachable under the flat `connect::` paths
//! re-exported below, so external callers are unaffected.

mod proxy_connect;
mod tls;
pub mod tunnel;
mod util;

pub use proxy_connect::connect_http_proxy;
pub use proxy_connect::connect_proxy;
pub use proxy_connect::connect_socks5_proxy;
pub use tls::tls_fragment;
pub use tls::tls_records;
#[cfg(feature = "tls")]
pub use tls::upstream_tls;
pub use util::handshake_over_stream;
pub use util::host_port;
pub use util::parse_proxy_str;
pub use util::recover_host;
pub use util::tcp_keepalive;

pub use connect_http_proxy::connect_http_proxy;
pub use connect_http_proxy::http_connect_handshake;
pub use connect_proxy::connect_proxy;
pub use connect_proxy::connect_proxy_once;
pub use connect_socks5_proxy::connect_socks5_proxy;
pub use handshake_over_stream::handshake_over_stream;
pub use host_port::HostPort;
pub use parse_proxy_str::parse_proxy_str;
pub use recover_host::{parse_http_host, parse_sni};
pub use tls_fragment::{send_possibly_fragmented, FragmentSpec};
#[cfg(feature = "tls")]
pub use upstream_tls::make_tls_connector;
