//! TLS-facing plumbing. ClientHello fragmentation and TLS record-layer
//! walking are pure byte-level plumbing with no TLS-stack dependency and
//! are always available; the default connector and the HTTPS
//! (TLS-wrapped CONNECT) upstream need the crate's `tls` feature.

pub mod tls_fragment;
pub mod tls_records;
#[cfg(feature = "tls")]
pub mod upstream_tls;
