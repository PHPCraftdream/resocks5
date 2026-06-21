//! Weighted-random upstream rotator with a per-target sticky cache.
//!
//! Wraps [`Ratings`] with a round-robin fallback
//! ([`ProxyRotator::get_next`]) and a `target → proxy` affinity cache
//! ([`ProxyRotator::link_proxy`] / [`ProxyRotator::get_linked`]).

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use dashmap::DashMap;

use crate::rating::{RatingPolicy, Ratings};
use crate::types::ProxyConfig;

/// Weighted-random rotator over a fixed set of upstream proxies, with a
/// per-target sticky cache.
///
/// Construct with [`ProxyRotator::new`] (default policy) or
/// [`ProxyRotator::with_policy`] (custom [`RatingPolicy`]).
/// [`pick_order`](ProxyRotator::pick_order) returns a weighted-random
/// permutation; [`get_next`](ProxyRotator::get_next) is plain round-robin,
/// used for the fallback and the sticky-cache-miss path.
pub struct ProxyRotator {
    /// Pre-built `Arc<ProxyConfig>` per upstream. `get_next` returns a
    /// cheap refcount clone, so no full struct copy on rotation.
    proxies: Vec<Arc<ProxyConfig>>,
    /// Round-robin counter, fetched-and-incremented atomically. Wrap
    /// at `usize::MAX` (decades away) is harmless: the `% len()` mod
    /// happens after every fetch.
    ///
    /// `Relaxed` ordering is enough — nothing else's correctness
    /// depends on the order of these increments, only on each one
    /// being atomic.
    index: AtomicUsize,
    /// Cache of `target_addr → Arc<ProxyConfig>` learned during
    /// connection attempts. `DashMap` is a sharded concurrent map —
    /// uncontended reads & writes don't serialise on one lock, so
    /// many simultaneous connections hitting different shards make
    /// progress in parallel. `RwLock<HashMap>`-style reader/writer
    /// contention is gone.
    map: DashMap<String, Arc<ProxyConfig>>,
    /// Sand-model ratings for weighted-random proxy selection.
    ratings: Ratings,
    /// Reverse lookup from `(host, port)` to index in `proxies`.
    proxy_index: DashMap<(String, u16), usize>,
}

impl ProxyRotator {
    /// Construct a rotator with the default [`RatingPolicy`].
    pub fn new(proxies: Vec<ProxyConfig>) -> Self {
        Self::with_policy(proxies, RatingPolicy::default())
    }

    /// Construct a rotator with a custom [`RatingPolicy`].
    pub fn with_policy(proxies: Vec<ProxyConfig>, policy: RatingPolicy) -> Self {
        let proxy_index = DashMap::new();
        for (i, p) in proxies.iter().enumerate() {
            proxy_index.insert((p.host.clone(), p.port), i);
        }
        let n = proxies.len();
        Self {
            proxies: proxies.into_iter().map(Arc::new).collect(),
            index: AtomicUsize::new(0),
            map: DashMap::new(),
            ratings: Ratings::new(n, policy),
            proxy_index,
        }
    }

    /// Insert (or replace) the cache entry for `addr`. Takes ownership
    /// of `Arc<ProxyConfig>` so the caller can hand off the only clone
    /// it had — refcount stays the same.
    pub fn link_proxy(&self, addr: String, proxy: Arc<ProxyConfig>) {
        self.map.insert(addr, proxy);
    }

    /// Drop the cached upstream for `addr` (e.g. after it failed).
    pub fn unlink_proxy(&self, addr: &str) {
        self.map.remove(addr);
    }

    /// Read back the cached upstream for `addr`, if any.
    pub fn get_linked(&self, addr: &str) -> Option<Arc<ProxyConfig>> {
        self.map.get(addr).map(|r| r.value().clone())
    }

    /// Round-robin next proxy (fetch-and-increment, modulo length).
    ///
    /// Returns a cheap refcount clone of the chosen [`ProxyConfig`].
    pub fn get_next(&self) -> Arc<ProxyConfig> {
        let i = self.index.fetch_add(1, Ordering::Relaxed) % self.proxies.len();
        self.proxies[i].clone()
    }

    /// Number of upstreams in the rotator.
    pub fn len(&self) -> usize {
        self.proxies.len()
    }

    /// `true` if there are no upstreams.
    pub fn is_empty(&self) -> bool {
        self.proxies.is_empty()
    }

    /// All upstream proxies in this rotator, used at startup by
    /// `ProxyPool::spawn_refill_for` to launch a per-proxy refill task.
    pub fn all_proxies(&self) -> &[Arc<ProxyConfig>] {
        &self.proxies
    }

    /// Look up the internal index for the given proxy config.
    fn index_of(&self, p: &ProxyConfig) -> Option<usize> {
        self.proxy_index.get(&(p.host.clone(), p.port)).map(|v| *v)
    }

    /// Record a failure for the given proxy in the sand model.
    pub fn record_failure(&self, proxy: &ProxyConfig) {
        if let Some(i) = self.index_of(proxy) {
            self.ratings.on_failure(i);
        }
    }

    /// Record a success for the given proxy in the sand model.
    pub fn record_success(&self, proxy: &ProxyConfig) {
        if let Some(i) = self.index_of(proxy) {
            self.ratings.on_success(i);
        }
    }

    /// Returns proxies in weighted-random order via the sand model.
    pub fn pick_order(&self) -> Vec<Arc<ProxyConfig>> {
        self.ratings
            .pick_order()
            .into_iter()
            .map(|i| self.proxies[i].clone())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{ProxyProtocol, IP as IPV};

    fn make_proxy(host: &str, port: u16) -> ProxyConfig {
        ProxyConfig {
            protocol: ProxyProtocol::Socks5,
            ip: IPV::V4,
            host: host.to_string(),
            port,
            user: None,
            password: None,
            is_gate: false,
            gate: None,
        }
    }

    #[test]
    fn record_failure_lowers_pick_probability() {
        let proxies: Vec<ProxyConfig> = (0..4).map(|i| make_proxy("host", 1000 + i)).collect();
        let policy = RatingPolicy {
            fail_penalty: 2.0,
            sand_max: 8.0,
            min_weight: 0.01,
            ..Default::default()
        };
        let r = ProxyRotator::with_policy(proxies, policy);

        // Hammer proxy 0 with failures.
        for _ in 0..10 {
            r.record_failure(&make_proxy("host", 1000));
        }

        let n = 10_000;
        let mut first_is_zero = 0u32;
        for _ in 0..n {
            let order = r.pick_order();
            if order[0].port == 1000 {
                first_is_zero += 1;
            }
        }
        let frac = first_is_zero as f64 / n as f64;
        assert!(
            frac < 0.30,
            "proxy 0 appeared first {:.1}% of the time, expected <30%",
            frac * 100.0
        );
    }

    #[test]
    fn record_success_restores_partially() {
        let proxies: Vec<ProxyConfig> = (0..4).map(|i| make_proxy("host", 1000 + i)).collect();
        let policy = RatingPolicy {
            fail_penalty: 2.0,
            sand_max: 8.0,
            min_weight: 0.01,
            ..Default::default()
        };
        let r = ProxyRotator::with_policy(proxies, policy);

        for _ in 0..10 {
            r.record_failure(&make_proxy("host", 1000));
        }
        for _ in 0..5 {
            r.record_success(&make_proxy("host", 1000));
        }

        let n = 10_000;
        let mut first_is_zero = 0u32;
        for _ in 0..n {
            let order = r.pick_order();
            if order[0].port == 1000 {
                first_is_zero += 1;
            }
        }
        let frac = first_is_zero as f64 / n as f64;
        assert!(
            frac > 0.15,
            "proxy 0 appeared first {:.1}% of the time, expected >15%",
            frac * 100.0
        );
    }

    #[test]
    fn record_unknown_proxy_is_noop() {
        let proxies: Vec<ProxyConfig> = (0..4).map(|i| make_proxy("host", 1000 + i)).collect();
        let r = ProxyRotator::with_policy(proxies, RatingPolicy::default());

        let weights_before = r.ratings.weights();
        r.record_failure(&make_proxy("unknown", 9999));
        let weights_after = r.ratings.weights();

        for (i, (a, b)) in weights_before.iter().zip(weights_after.iter()).enumerate() {
            assert!(
                (a - b).abs() < 1e-9,
                "weight[{}] changed from {} to {}",
                i,
                a,
                b
            );
        }
    }

    #[test]
    fn pick_order_returns_all_proxies() {
        let proxies: Vec<ProxyConfig> = (0..5).map(|i| make_proxy("host", 1000 + i)).collect();
        let r = ProxyRotator::with_policy(proxies, RatingPolicy::default());
        let order = r.pick_order();
        assert_eq!(order.len(), 5);

        let mut ports: Vec<u16> = order.iter().map(|p| p.port).collect();
        ports.sort();
        assert_eq!(ports, vec![1000, 1001, 1002, 1003, 1004]);
    }
}
