//! IP address family of an upstream proxy's listen address.

/// The IP family an upstream proxy listens on.
///
/// Proxy lists are partitioned by family so an IPv6-only target can prefer an
/// IPv6 upstream, avoiding a broken or filtered IPv4 path.
#[derive(Clone, Debug, Copy, PartialEq, Eq)]
pub enum IP {
    /// IPv4 (`AF_INET`).
    V4,
    /// IPv6 (`AF_INET6`).
    V6,
}
