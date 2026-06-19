use resocks5_net::connect::FragmentSpec;
use serde::{Deserialize, Serialize};

/// Controls TCP fragmentation of outgoing TLS ClientHello records.
///
/// When `enabled`, resocks5 detects the TLS ClientHello in the first
/// data chunk written to the upstream tunnel and splits it into small
/// TCP segments. Stateless DPI that inspects each segment independently
/// cannot extract the SNI field from a partial record.
///
/// TCP_NODELAY is set on the upstream socket automatically when
/// `enabled` is true, so the OS does not merge fragments via Nagle's
/// algorithm.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TlsFragmentConfig {
    /// Master switch. When false all traffic is forwarded as-is.
    pub enabled: bool,
    /// Bytes per fragment. Splitting at ≤ 40 bytes typically puts the
    /// SNI field (offset ~45–80 into the record) in a later fragment,
    /// making the hostname invisible to per-segment scanners.
    pub fragment_size: usize,
    /// Milliseconds to wait between consecutive fragments. Zero (default)
    /// sends all fragments back-to-back. A non-zero value can help
    /// against stateful DPI with short reassembly windows.
    pub delay_ms: u64,
}

impl Default for TlsFragmentConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            fragment_size: 40,
            delay_ms: 0,
        }
    }
}

impl TlsFragmentConfig {
    /// Project this parsed config onto the library-level [`FragmentSpec`]
    /// consumed by `resocks5_net::connect::send_possibly_fragmented`.
    pub fn to_spec(&self) -> FragmentSpec {
        FragmentSpec {
            enabled: self.enabled,
            fragment_size: self.fragment_size,
            delay_ms: self.delay_ms,
        }
    }
}
