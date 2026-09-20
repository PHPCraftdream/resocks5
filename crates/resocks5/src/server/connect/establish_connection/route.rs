use resocks5_net::rotator::ProxyRotator;
use resocks5_net::types::ProxyConfig;
use std::collections::HashSet;
use std::hash::{Hash, Hasher};
use std::sync::Arc;

/// Returns `false` for cap-hit errors (semaphore full) — those are
/// our own load, not an upstream fault, and must NOT feed the sand
/// model's failure signal.
pub(super) fn should_record_failure(err: &anyhow::Error) -> bool {
    err.downcast_ref::<resocks5_net::pool::AtCapacity>()
        .is_none()
}

/// Which stage of a gate tunnel failed. Attached to `use_gate` errors
/// as an `anyhow` context value so the caller can penalize only the
/// node actually responsible, while `AtCapacity` stays downcastable
/// through the context chain for `should_record_failure` —
/// `anyhow::Error::downcast_ref` recurses through every context layer
/// down to the concrete error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum GateStage {
    /// `pool.acquire(gate_config)` failed: the gate itself was never
    /// usable; the inner proxy was not touched.
    GateConnect,
    /// Reaching the inner proxy through the gate failed: either the
    /// gate refuses to forward or the inner proxy is down — ambiguous
    /// from here by construction.
    GateToProxy,
    /// The gate worked; the inner proxy failed to reach the target.
    ProxyToTarget,
}

impl std::fmt::Display for GateStage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GateStage::GateConnect => write!(f, "gate connect"),
            GateStage::GateToProxy => write!(f, "gate-to-proxy hop"),
            GateStage::ProxyToTarget => write!(f, "proxy-to-target hop"),
        }
    }
}

/// Extract the failing tunnel stage from a `use_gate` error. Uses the
/// anyhow-level `downcast_ref` (recurses through context layers)
/// rather than walking `chain()`: chain elements are plain `dyn Error`
/// objects that cannot see through anyhow's context wrappers.
pub(super) fn gate_stage_of(err: &anyhow::Error) -> Option<GateStage> {
    err.downcast_ref::<GateStage>().copied()
}

/// Feed one failed route attempt into this call's bookkeeping. Shared
/// by the cached-route retry path and the gates cartesian product so
/// their outcome handling cannot drift apart. Cap-hit errors are our
/// own load and feed nothing. Otherwise the failing [`GateStage`]
/// decides who pays: `GateConnect` penalizes only the gate and
/// dead-lists it, `ProxyToTarget` only the inner proxy (also
/// dead-listed), while `GateToProxy` and untagged errors stay the
/// documented ambiguous double penalty. A non-gate route
/// (`gate_config` is `None` — the error came from `connect_proxy`,
/// which never tags a stage) lands its single failure on the proxy
/// alone. Returns `true` when the attempt proved the gate itself
/// unreachable: the caller can stop pairing this gate with further
/// proxies right away, because `pool.acquire(gate)` does not involve
/// the inner proxy.
pub(super) fn apply_gate_failure(
    err: &anyhow::Error,
    proxy_rotator: &ProxyRotator,
    proxy_config: &Arc<ProxyConfig>,
    gate_config: Option<&Arc<ProxyConfig>>,
    gate_rotator: Option<&ProxyRotator>,
    dead_gates: &mut HashSet<UpstreamKey>,
    dead_proxies: &mut HashSet<UpstreamKey>,
) -> bool {
    if !should_record_failure(err) {
        return false;
    }
    let Some(gate_config) = gate_config else {
        proxy_rotator.record_failure(proxy_config);
        return false;
    };
    match gate_stage_of(err) {
        Some(GateStage::GateConnect) => {
            // Stage 1: the gate was never usable; the inner proxy was
            // not touched.
            if let Some(gate_rotator) = gate_rotator {
                gate_rotator.record_failure(gate_config);
            }
            dead_gates.insert(UpstreamKey(gate_config.clone()));
            true
        }
        Some(GateStage::GateToProxy) => {
            // Stage 2 is ambiguous by construction: gate refusal to
            // forward vs. a down inner proxy is indistinguishable
            // here, so both stay penalized. The one clear attribution
            // (inner-proxy AtCapacity) is already excluded by
            // `should_record_failure` above.
            proxy_rotator.record_failure(proxy_config);
            if let Some(gate_rotator) = gate_rotator {
                gate_rotator.record_failure(gate_config);
            }
            false
        }
        Some(GateStage::ProxyToTarget) => {
            // Stage 3: the gate worked; the inner proxy failed to
            // reach the target.
            proxy_rotator.record_failure(proxy_config);
            dead_proxies.insert(UpstreamKey(proxy_config.clone()));
            false
        }
        None => {
            // `use_gate` tags every fallible stage; keep the blanket
            // double penalty for anything untagged.
            proxy_rotator.record_failure(proxy_config);
            if let Some(gate_rotator) = gate_rotator {
                gate_rotator.record_failure(gate_config);
            }
            false
        }
    }
}

/// True when `a` and `b` are the same real upstream within this
/// call: everything that distinguishes genuinely different
/// upstreams (endpoint, protocol, account, gate flag) matches,
/// deliberately excluding `gate` — that field records only how the
/// upstream is reached on this attempt. Mirrors the rating identity
/// `ProxyRotator` uses, so a sticky-cache composite (an inner
/// config with `.gate` set) and the plain inner config from
/// `pick_order()` compare equal here. Compares borrowed fields
/// only; cheap scalars first so mismatching candidates exit early.
pub(super) fn same_upstream(a: &ProxyConfig, b: &ProxyConfig) -> bool {
    a.port == b.port
        && a.protocol == b.protocol
        && a.is_gate == b.is_gate
        && a.host == b.host
        && a.user == b.user
        && a.password == b.password
}

/// Share config storage while comparing the actual upstream identity.
pub(super) struct UpstreamKey(pub(super) Arc<ProxyConfig>);

impl PartialEq for UpstreamKey {
    fn eq(&self, other: &Self) -> bool {
        same_upstream(&self.0, &other.0)
    }
}

impl Eq for UpstreamKey {}

impl Hash for UpstreamKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        let proxy = &self.0;
        (
            proxy.host.as_str(),
            proxy.port,
            std::mem::discriminant(&proxy.protocol),
            proxy.user.as_deref(),
            proxy.password.as_deref(),
            proxy.is_gate,
        )
            .hash(state);
    }
}

pub(super) type Route = (Option<UpstreamKey>, UpstreamKey);

pub(super) fn route_key(gate: Option<&Arc<ProxyConfig>>, proxy: &Arc<ProxyConfig>) -> Route {
    (gate.cloned().map(UpstreamKey), UpstreamKey(proxy.clone()))
}
