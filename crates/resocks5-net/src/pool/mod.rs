//! Pre-connect TCP pool to upstream proxies.
//!
//! For each upstream proxy, a background task maintains a small queue
//! of TCP sockets that have completed the kernel-level 3-way handshake
//! to the proxy host but **not** the SOCKS5 / HTTP-CONNECT handshake
//! on top. When a client request arrives, we pop one of these spares
//! and run the per-target handshake on it — the round-trip to set up
//! the TCP layer is already paid.
//!
//! ## Why we pre-warm TCP, not "sessions"
//!
//! SOCKS5 (RFC 1928) and HTTP-CONNECT both commit a single TCP socket
//! to one target after the protocol-level handshake. There's no way
//! to multiplex multiple targets over one socket. So "session reuse"
//! across client requests isn't possible at the proxy-protocol layer.
//! The only thing we can keep warm is the TCP layer itself — which is
//! still worth roughly one RTT (10–50 ms typical) per client request
//! to a remote proxy.

pub mod any_upstream;
pub mod pool_config;
pub mod proxy_pool;

pub use any_upstream::{AnyUpstream, BoxedUpstream};
pub use pool_config::PoolConfig;
pub use proxy_pool::{AtCapacity, ProxyPool, UpstreamStream};
