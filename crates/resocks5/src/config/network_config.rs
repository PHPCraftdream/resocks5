use serde::{Deserialize, Serialize};

/// Network-level timeouts and socket options.
///
/// Defaults are conservative: they prevent the catastrophic resource
/// leak from dead upstreams / half-closed tunnels without breaking
/// legitimately long-lived sessions (websockets, long-poll, SSH).
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct NetworkConfig {
    /// Maximum time to wait for a TCP `connect` to an upstream proxy.
    /// Without this cap a dead upstream blocks for the full kernel
    /// SYN timeout (~21 s on Windows, ~127 s on Linux), multiplied by
    /// the number of fallback attempts in `establish_connection`.
    #[serde(default = "default_connect_timeout")]
    pub connect_timeout_sec: u64,

    /// Maximum time for one SOCKS5 handshake exchange with an upstream
    /// (greeting + auth + CONNECT). A proxy that accepts our TCP but
    /// stalls in the middle of the protocol is treated as dead.
    #[serde(default = "default_handshake_timeout")]
    pub handshake_timeout_sec: u64,

    /// Hard cap on total lifetime of a forwarded tunnel, from the
    /// moment SOCKS5/CONNECT setup completes. Defends against tunnels
    /// that are kept alive forever by a misbehaving peer (no FIN, no
    /// RST). `0` disables the cap (not recommended).
    #[serde(default = "default_tunnel_max_lifetime")]
    pub tunnel_max_lifetime_sec: u64,

    /// TCP keepalive idle interval on every active socket
    /// (client-facing and upstream-facing). After this many seconds of
    /// silence the kernel starts probing; non-responsive peers get
    /// their socket closed without us having to detect it at the
    /// application layer. `0` disables keepalive entirely.
    #[serde(default = "default_tcp_keepalive")]
    pub tcp_keepalive_sec: u64,

    /// Time budget for the client-side protocol phase as ONE absolute
    /// deadline, anchored the moment a client connection is accepted and
    /// shared by every client-facing stage: the dispatcher's
    /// protocol-detection peek, the SOCKS5/HTTP CONNECT handshake, and the
    /// SNI/Host recovery peek. Each stage spends only the time still left
    /// on that deadline, so time consumed by an earlier phase shrinks the
    /// budget of later ones and no stage can start a fresh full-length
    /// timer; a stage entered after the deadline has passed fails
    /// immediately as a timeout. Defends against slowloris-style clients
    /// that open TCP but never finish (or never start) the handshake.
    ///
    /// Out of scope: connecting to the upstream. Each upstream attempt in
    /// `establish_connection` / `establish_direct` is bounded by
    /// `connect_timeout_sec` + `handshake_timeout_sec` independently of
    /// this setting. (The recovery peek, which races a speculative
    /// upstream dial against the client's first record, is still capped by
    /// what remains of this deadline.)
    #[serde(default = "default_client_protocol_timeout")]
    pub client_protocol_timeout_sec: u64,

    /// Maximum number of in-flight client tunnels. New connections that
    /// would exceed this are dropped immediately (no SOCKS5 reply, just
    /// TCP close). Caps the worst-case resource usage under attack or
    /// runaway load.
    #[serde(default = "default_max_concurrent_clients")]
    pub max_concurrent_clients: usize,

    /// Hard cap on upstream connect+handshake attempts per one client
    /// request. Without it, `establish_connection` can walk
    /// `gates × (v4 + v6) + v4 + v6` proxies on a bad day —
    /// `100 attempts × 10 s timeout = ~15 min` of a single client
    /// hanging in `wait`. Cap keeps the worst case bounded.
    #[serde(default = "default_max_upstream_attempts")]
    pub max_upstream_attempts: usize,

    /// Maximum simultaneous TCP connections to any single upstream
    /// proxy `(host, port)`. Respects the provider-side per-account /
    /// per-IP connection cap — without this we'd happily open 100s of
    /// sockets in parallel and saturate the upstream, after which it
    /// stops responding to our SOCKS5 greetings (the symptom: 10 s
    /// handshake timeouts on EVERY attempt).
    ///
    /// Permits are held for the lifetime of each tunnel, so an
    /// `acquire` while at capacity is a fast failure (skip this proxy,
    /// try the next), never a wait.
    #[serde(default = "default_max_per_upstream")]
    pub max_per_upstream: usize,

    /// Idle timeout on the forwarded tunnel: if no bytes flow in
    /// either direction for this many seconds, both halves get an
    /// explicit `shutdown()` (FIN) and the connection is torn down,
    /// releasing the per-upstream permit. Tighter bound than
    /// `tcp_keepalive_sec + tunnel_max_lifetime_sec` for the common
    /// case of forgotten / abandoned tunnels.
    ///
    /// `0` disables the idle check (only keepalive + lifetime apply).
    #[serde(default = "default_tunnel_idle_timeout")]
    pub tunnel_idle_timeout_sec: u64,

    /// Maximum number of simultaneous bypass (direct) tunnels across
    /// all direct-enabled users. New direct connections that would
    /// exceed this are rejected after auth (SOCKS5 general-failure /
    /// HTTP 503). Does NOT count against `max_concurrent_clients` —
    /// the client-level semaphore is acquired first.
    #[serde(default = "default_max_concurrent_direct")]
    pub max_concurrent_direct: usize,

    /// Sand model: half-life in seconds for exponential decay of
    /// accumulated failure sand.
    #[serde(default = "default_sand_half_life_sec")]
    pub sand_half_life_sec: f64,

    /// Sand model: sand added per upstream failure. Setting this to
    /// 0.0 disables the sand model entirely (pure round-robin).
    #[serde(default = "default_sand_fail_penalty")]
    pub sand_fail_penalty: f64,

    /// Sand model: hard ceiling on accumulated sand per upstream.
    #[serde(default = "default_sand_max")]
    pub sand_max: f64,

    /// Sand model: minimum weight for a fully-saturated upstream.
    #[serde(default = "default_sand_min_weight")]
    pub sand_min_weight: f64,

    /// Sand model: multiplicative factor applied to sand on success.
    #[serde(default = "default_sand_success_factor")]
    pub sand_success_factor: f64,

    /// Recover the original hostname from the client's first payload
    /// when the CONNECT target is a bare IP literal.
    ///
    /// Some SOCKS front-ends (e.g. Proxifier with local DNS) resolve
    /// the destination on the client and send an IP in the CONNECT
    /// request. Upstream proxies that refuse CONNECT to raw CDN IPs
    /// then time out every request. When this is `true` and the target
    /// is an IP, resocks5 sends the SOCKS5 success reply early, peeks
    /// the first record, and recovers the intended host from the TLS
    /// SNI (port 443) or the HTTP `Host` header (plain HTTP) — then
    /// addresses the upstream by domain. Falls back to the IP if no
    /// name can be recovered.
    ///
    /// Trade-off: enabling this means the SOCKS5 success reply is sent
    /// before the upstream connection is actually established (so a
    /// later upstream failure surfaces as a dropped tunnel rather than
    /// a SOCKS error), and the first client record is inspected. Set
    /// to `false` for strict RFC 1928 reply ordering and no payload
    /// inspection.
    #[serde(default = "default_recover_host_from_payload")]
    pub recover_host_from_payload: bool,
}

fn default_connect_timeout() -> u64 {
    10
}
fn default_handshake_timeout() -> u64 {
    10
}
fn default_tunnel_max_lifetime() -> u64 {
    1800
}
fn default_tcp_keepalive() -> u64 {
    60
}
fn default_client_protocol_timeout() -> u64 {
    30
}
fn default_max_concurrent_clients() -> usize {
    1024
}
fn default_max_upstream_attempts() -> usize {
    10
}
fn default_max_per_upstream() -> usize {
    8
}
fn default_tunnel_idle_timeout() -> u64 {
    30
}
fn default_max_concurrent_direct() -> usize {
    256
}
fn default_sand_half_life_sec() -> f64 {
    30.0
}
fn default_sand_fail_penalty() -> f64 {
    1.0
}
fn default_sand_max() -> f64 {
    8.0
}
fn default_sand_min_weight() -> f64 {
    0.05
}
fn default_sand_success_factor() -> f64 {
    0.5
}
fn default_recover_host_from_payload() -> bool {
    true
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            connect_timeout_sec: default_connect_timeout(),
            handshake_timeout_sec: default_handshake_timeout(),
            tunnel_max_lifetime_sec: default_tunnel_max_lifetime(),
            tcp_keepalive_sec: default_tcp_keepalive(),
            client_protocol_timeout_sec: default_client_protocol_timeout(),
            max_concurrent_clients: default_max_concurrent_clients(),
            max_upstream_attempts: default_max_upstream_attempts(),
            max_per_upstream: default_max_per_upstream(),
            tunnel_idle_timeout_sec: default_tunnel_idle_timeout(),
            max_concurrent_direct: default_max_concurrent_direct(),
            sand_half_life_sec: default_sand_half_life_sec(),
            sand_fail_penalty: default_sand_fail_penalty(),
            sand_max: default_sand_max(),
            sand_min_weight: default_sand_min_weight(),
            sand_success_factor: default_sand_success_factor(),
            recover_host_from_payload: default_recover_host_from_payload(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The defaults are the contract — they ship to users on a fresh
    /// install and any silent change would alter production behaviour
    /// for everyone. Pinning them in a test makes the next change
    /// require an explicit edit to this list.
    #[test]
    fn defaults_are_pinned() {
        let d = NetworkConfig::default();
        assert_eq!(d.connect_timeout_sec, 10);
        assert_eq!(d.handshake_timeout_sec, 10);
        assert_eq!(d.tunnel_max_lifetime_sec, 1800);
        assert_eq!(d.tcp_keepalive_sec, 60);
        assert_eq!(d.client_protocol_timeout_sec, 30);
        assert_eq!(d.max_concurrent_clients, 1024);
        assert_eq!(d.max_upstream_attempts, 10);
        assert_eq!(d.max_per_upstream, 8);
        assert_eq!(d.tunnel_idle_timeout_sec, 30);
        assert_eq!(d.max_concurrent_direct, 256);
        assert_eq!(d.sand_half_life_sec, 30.0);
        assert_eq!(d.sand_fail_penalty, 1.0);
        assert_eq!(d.sand_max, 8.0);
        assert_eq!(d.sand_min_weight, 0.05);
        assert_eq!(d.sand_success_factor, 0.5);
        assert!(d.recover_host_from_payload);
    }

    /// Every `#[serde(default = "...")]` attribute on a field must
    /// point at a fn whose return value equals the corresponding
    /// `Default` field. Otherwise old configs that omit the field will
    /// silently parse with a value different from a fresh-default one.
    #[test]
    fn serde_field_defaults_match_struct_default() {
        let d = NetworkConfig::default();
        assert_eq!(default_connect_timeout(), d.connect_timeout_sec);
        assert_eq!(default_handshake_timeout(), d.handshake_timeout_sec);
        assert_eq!(default_tunnel_max_lifetime(), d.tunnel_max_lifetime_sec);
        assert_eq!(default_tcp_keepalive(), d.tcp_keepalive_sec);
        assert_eq!(
            default_client_protocol_timeout(),
            d.client_protocol_timeout_sec
        );
        assert_eq!(default_max_concurrent_clients(), d.max_concurrent_clients);
        assert_eq!(default_max_upstream_attempts(), d.max_upstream_attempts);
        assert_eq!(default_max_per_upstream(), d.max_per_upstream);
        assert_eq!(default_tunnel_idle_timeout(), d.tunnel_idle_timeout_sec);
        assert_eq!(default_max_concurrent_direct(), d.max_concurrent_direct);
        assert_eq!(default_sand_half_life_sec(), d.sand_half_life_sec);
        assert_eq!(default_sand_fail_penalty(), d.sand_fail_penalty);
        assert_eq!(default_sand_max(), d.sand_max);
        assert_eq!(default_sand_min_weight(), d.sand_min_weight);
        assert_eq!(default_sand_success_factor(), d.sand_success_factor);
        assert_eq!(
            default_recover_host_from_payload(),
            d.recover_host_from_payload
        );
    }

    /// Regression: serialized default must not contain any cb_ fields
    /// (circuit breaker was removed in Phase B).
    #[test]
    fn no_cb_fields_in_serialized_default() {
        let serialized = ktav::to_string(&NetworkConfig::default())
            .expect("ktav serialization of default NetworkConfig");
        assert!(
            !serialized.contains("cb_"),
            "serialized NetworkConfig::default() still contains cb_ fields:\n{}",
            serialized
        );
    }
}
