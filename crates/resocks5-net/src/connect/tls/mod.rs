//! TLS-facing plumbing: the default connector, the HTTPS (TLS-wrapped
//! CONNECT) upstream, TLS record-layer walking, and ClientHello
//! fragmentation.

pub mod tls_fragment;
pub mod tls_records;
pub mod upstream_tls;
