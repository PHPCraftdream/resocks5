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
//!   connect/pool API, with [`Stage`] and timeout-kind discriminators and
//!   the structured [`ProtocolViolation`] behind `ConnectError::Protocol`.
//!
//! - [`server`] — inbound SOCKS5/HTTP CONNECT framing with host-supplied authentication.
//!
//! The crate carries no application concerns — no config-file format, logging
//! sink, or authentication storage. Those live in the `resocks5` binary.

// Every public item carries rustdoc. Enforced in CI by the `doc` job
// (RUSTDOCFLAGS=-D warnings). Kept at `warn` here so a local `cargo build`
// isn't noisy — only `cargo doc` surfaces it.
#![warn(missing_docs)]

pub use error::{
    socks5_rep_description, ConnectError, GssapiError, ProtocolViolation, SecureAuthError, Stage,
    TimeoutKind,
};

/// May this build send credentials in clear text (feature `cleartext-client`)?
/// The crate's own unit tests always may; integration tests link the library
/// without `cfg(test)` and so exercise the default (refusing) build.
pub(crate) const CLEARTEXT_CLIENT: bool = cfg!(any(test, feature = "cleartext-client"));
/// May this build offer and accept clear-text credentials (feature
/// `cleartext-server`)? Same test rule as [`CLEARTEXT_CLIENT`].
pub(crate) const CLEARTEXT_SERVER: bool = cfg!(any(test, feature = "cleartext-server"));

#[cfg(feature = "rotator")]
#[path = "session/chain/mod.rs"]
pub mod chain;
pub mod connect;
pub mod error;
#[cfg(feature = "gssapi")]
#[path = "session/auth/gssapi/mod.rs"]
pub mod gssapi;
#[cfg(feature = "pool")]
#[path = "session/pool/mod.rs"]
pub mod pool;
#[path = "session/progress.rs"]
pub mod progress;
#[cfg(feature = "rating")]
#[path = "session/rating/mod.rs"]
pub mod rating;
#[cfg(feature = "rotator")]
#[path = "session/rotator/mod.rs"]
pub mod rotator;
#[cfg(feature = "secure-auth")]
#[path = "session/auth/secure_auth/mod.rs"]
pub mod secure_auth;
pub mod server;
#[cfg(feature = "test-instrumentation")]
#[path = "session/testing/mod.rs"]
pub mod testing;
pub mod types;

#[cfg(all(test, feature = "test-instrumentation"))]
#[path = "session/testing/perf.rs"]
mod perf;
#[cfg(all(test, feature = "test-instrumentation"))]
#[path = "session/testing/perf_cases.rs"]
mod perf_cases;
#[cfg(all(test, feature = "test-instrumentation"))]
#[path = "session/testing/perf_credentials.rs"]
mod perf_credentials;
