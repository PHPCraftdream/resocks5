//! `resocks5-net` — a reusable proxy networking toolkit.
//!
//! These are the building blocks the `resocks5` proxy server is assembled
//! from, factored out so they can be used independently:
//!
//! - [`connect`] — upstream connectors for SOCKS5, HTTP CONNECT, and
//!   HTTPS (TLS-wrapped CONNECT) proxies, plus stream plumbing: bidirectional
//!   tunnelling, TCP keepalive, proxy-string parsing, and TLS ClientHello
//!   fragmentation for DPI evasion.
#![cfg_attr(
    feature = "pool",
    doc = "- [`pool`] — a pre-connect TCP pool that keeps warm sockets to each",
    doc = "  upstream, plus a per-upstream concurrency cap (the default `pool` feature)."
)]
//! - [`progress`] — confirmed-write-progress plumbing: the
//!   [`FlushProgress`](progress::FlushProgress) counter sink and the
//!   [`ProgressReportingWriter`](progress::ProgressReportingWriter)
//!   wrapper that reports accepted bytes into it. Shared by the
//!   tunnel, TLS, and pool layers; no TLS-specific logic.
#![cfg_attr(
    feature = "rating",
    doc = "- [`rating`] — a sand-rating model: every upstream has an accumulator",
    doc = "  that grows on failures and decays over time; the rotator picks",
    doc = "  upstreams with weight inversely proportional to current sand, so",
    doc = "  bad upstreams are deprioritised without ever being fully excluded."
)]
#![cfg_attr(
    feature = "rotator",
    doc = "- [`rotator`] — weighted-random rotation over a set of upstreams,",
    doc = "  driven by [`rating`]."
)]
//! - [`types`] — the shared proxy descriptors ([`types::ProxyConfig`],
//!   [`types::ProxyProtocol`]).
//! - [`error`] — the typed [`ConnectError`] returned by the public
//!   connect/pool API, with [`Stage`] and timeout-kind discriminators.
//!
//! The crate carries no application concerns — no config-file format, no
//! logging sink, no authentication. Those live in the `resocks5` binary.

// Every public item carries rustdoc. Enforced in CI by the `doc` job
// (RUSTDOCFLAGS=-D warnings). Kept at `warn` here so a local `cargo build`
// isn't noisy — only `cargo doc` surfaces it.
#![warn(missing_docs)]

pub use error::{ConnectError, Stage, TimeoutKind};

pub mod connect;
pub mod error;
#[cfg(feature = "pool")]
pub mod pool;
pub mod progress;
#[cfg(feature = "rating")]
pub mod rating;
#[cfg(feature = "rotator")]
pub mod rotator;
pub mod types;
