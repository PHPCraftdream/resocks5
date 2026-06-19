//! `resocks5-net` — a reusable proxy networking toolkit.
//!
//! These are the building blocks the `resocks5` proxy server is assembled
//! from, factored out so they can be used independently:
//!
//! - [`connect`] — upstream connectors for SOCKS5, HTTP CONNECT, and
//!   HTTPS (TLS-wrapped CONNECT) proxies, plus stream plumbing: bidirectional
//!   tunnelling, TCP keepalive, proxy-string parsing, and TLS ClientHello
//!   fragmentation for DPI evasion.
//! - [`pool`] — a pre-connect TCP pool that keeps warm sockets to each
//!   upstream, plus a per-upstream concurrency cap.
//! - [`rating`] — a sand-rating model: every upstream has an accumulator
//!   that grows on failures and decays over time; the rotator picks
//!   upstreams with weight inversely proportional to current sand, so
//!   bad upstreams are deprioritised without ever being fully excluded.
//! - [`rotator`] — weighted-random rotation over a set of upstreams,
//!   driven by [`rating`].
//! - [`types`] — the shared proxy descriptors ([`types::ProxyConfig`],
//!   [`types::ProxyProtocol`], [`types::IP`]).
//!
//! The crate carries no application concerns — no config-file format, no
//! logging sink, no authentication. Those live in the `resocks5` binary.

pub mod connect;
pub mod pool;
pub mod rating;
pub mod rotator;
pub mod types;
