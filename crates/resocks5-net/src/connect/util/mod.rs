//! Small parsing and socket helpers shared by the connectors: address
//! parsing and formatting, the upstream-list line parser, hostname
//! recovery from first application bytes, the SOCKS5 handshake over an
//! arbitrary stream, and TCP keepalive.

pub mod handshake_over_stream;
pub mod host_port;
pub mod parse_proxy_str;
pub mod recover_host;
pub mod tcp_keepalive;

pub use host_port::HostPort;
