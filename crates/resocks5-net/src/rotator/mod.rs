//! Weighted-random upstream rotator with a per-target sticky cache.
//!
//! Wraps [`Ratings`] with a round-robin fallback
//! ([`ProxyRotator::get_next`]) and a `target → proxy` affinity cache
//! ([`ProxyRotator::link_proxy`] / [`ProxyRotator::get_linked`]).
//!
//! The sticky cache is bounded: it holds at most
//! [`DEFAULT_STICKY_CACHE_MAX_ENTRIES`] entries, each living at most
//! [`DEFAULT_STICKY_CACHE_TTL`], with LRU + TTL eviction by default.
//! Use [`ProxyRotator::with_cache_limits`] to configure both limits.

use std::collections::{hash_map::RandomState, BTreeSet, HashMap};
use std::hash::BuildHasher;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::rating::{RatingPolicy, Ratings};
use crate::types::ProxyConfig;

/// True when `a` and `b` refer to the same real-world upstream rating
/// slot: endpoint, protocol, and account all match. `gate` is
/// deliberately excluded — it records how the upstream is reached on
/// this attempt (it is set on the gate-composite configs written to
/// the sticky cache), not what the upstream is — so rating a
/// gate-composite still lands on the plain upstream's slot. Compares
/// borrowed fields only: no `host`/`user`/`password` clones on the
/// per-event `record_failure`/`record_success` path. Cheap scalars
/// are compared first so mismatching candidates exit early.
fn same_upstream(a: &ProxyConfig, b: &ProxyConfig) -> bool {
    a.port == b.port
        && a.protocol == b.protocol
        && a.is_gate == b.is_gate
        && a.host == b.host
        && a.user == b.user
        && a.password == b.password
}

fn upstream_hash(state: &RandomState, proxy: &ProxyConfig) -> u64 {
    state.hash_one((
        proxy.host.as_str(),
        proxy.port,
        std::mem::discriminant(&proxy.protocol),
        proxy.user.as_deref(),
        proxy.password.as_deref(),
        proxy.is_gate,
    ))
}

/// Default hard cap on sticky-cache entries.
pub const DEFAULT_STICKY_CACHE_MAX_ENTRIES: usize = 4096;
/// Default sticky-cache entry lifetime.
pub const DEFAULT_STICKY_CACHE_TTL: Duration = Duration::from_secs(600);

struct StickyEntry {
    proxy: Arc<ProxyConfig>,
    last_used: Instant,
    expires_at: Instant,
    generation: u64,
}

/// Each entry owns exactly one recency record and one expiry record.
struct StickyCache {
    max_entries: usize,
    ttl: Duration,
    map: HashMap<Arc<str>, StickyEntry>,
    recency: BTreeSet<(Instant, u64, Arc<str>)>,
    expiry: BTreeSet<(Instant, Arc<str>)>,
    next_generation: u64,
}

impl StickyCache {
    fn new(max_entries: usize, ttl: Duration) -> Self {
        Self {
            max_entries,
            ttl,
            map: HashMap::new(),
            recency: BTreeSet::new(),
            expiry: BTreeSet::new(),
            next_generation: 0,
        }
    }

    fn get(&mut self, addr: &str, now: Instant) -> Option<Arc<ProxyConfig>> {
        let (key, entry) = self.map.get_key_value(addr)?;
        if now >= entry.expires_at {
            self.remove(addr);
            return None;
        }
        let key = Arc::clone(key);
        let entry = self.map.get_mut(addr)?;
        self.recency
            .remove(&(entry.last_used, entry.generation, key.clone()));
        entry.last_used = now;
        entry.generation = self.next_generation;
        // Break ties between touches sharing an Instant.
        self.next_generation = self.next_generation.wrapping_add(1);
        self.recency.insert((now, entry.generation, key));
        Some(entry.proxy.clone())
    }

    fn insert(&mut self, addr: String, proxy: Arc<ProxyConfig>, now: Instant) {
        if self.max_entries == 0 {
            return;
        }
        let key = self.remove(&addr);
        if self.map.len() >= self.max_entries {
            // Reclaim one expired entry before evicting any live entry.
            let victim = self
                .expiry
                .first()
                .filter(|(deadline, _)| *deadline <= now)
                .map(|(_, key)| key)
                .or_else(|| self.recency.first().map(|(_, _, key)| key))
                .cloned();
            if let Some(victim) = victim {
                self.remove(&victim);
            }
        }
        let key = key.unwrap_or_else(|| Arc::from(addr));
        let expires_at = now.checked_add(self.ttl).unwrap_or(now);
        let generation = self.next_generation;
        self.next_generation = self.next_generation.wrapping_add(1);
        self.recency.insert((now, generation, key.clone()));
        self.expiry.insert((expires_at, key.clone()));
        self.map.insert(
            key,
            StickyEntry {
                proxy,
                last_used: now,
                expires_at,
                generation,
            },
        );
    }

    fn remove(&mut self, addr: &str) -> Option<Arc<str>> {
        let (key, entry) = self.map.remove_entry(addr)?;
        self.recency
            .remove(&(entry.last_used, entry.generation, key.clone()));
        self.expiry.remove(&(entry.expires_at, key.clone()));
        Some(key)
    }
}

/// Weighted-random rotator over a fixed set of upstream proxies, with a
/// per-target sticky cache.
///
/// The sticky cache is bounded: by default at most
/// [`DEFAULT_STICKY_CACHE_MAX_ENTRIES`] entries, each living at most
/// [`DEFAULT_STICKY_CACHE_TTL`], with LRU + TTL eviction. Use
/// [`ProxyRotator::with_cache_limits`] to configure both limits.
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
    identity_hasher: RandomState,
    /// Hash collisions are resolved by comparing the borrowed identity fields.
    by_identity: HashMap<u64, Vec<usize>>,
    /// Round-robin counter, fetched-and-incremented atomically. Wrap
    /// at `usize::MAX` (decades away) is harmless: the `% len()` mod
    /// happens after every fetch.
    ///
    /// `Relaxed` ordering is enough — nothing else's correctness
    /// depends on the order of these increments, only on each one
    /// being atomic.
    index: AtomicUsize,
    /// Bounded `target_addr → Arc<ProxyConfig>` sticky cache learned
    /// during connection attempts. Holds at most `max_entries` entries,
    /// each expiring after `ttl`; LRU eviction makes room when full.
    sticky: Mutex<StickyCache>,
    /// Sand-model ratings for weighted-random proxy selection.
    ratings: Ratings,
}

impl ProxyRotator {
    /// Construct a rotator with the default [`RatingPolicy`].
    pub fn new(proxies: Vec<ProxyConfig>) -> Self {
        Self::with_policy(proxies, RatingPolicy::default())
    }

    /// Construct a rotator with a custom [`RatingPolicy`].
    pub fn with_policy(proxies: Vec<ProxyConfig>, policy: RatingPolicy) -> Self {
        Self::with_cache_limits(
            proxies,
            policy,
            DEFAULT_STICKY_CACHE_MAX_ENTRIES,
            DEFAULT_STICKY_CACHE_TTL,
        )
    }

    /// Construct a rotator with a custom [`RatingPolicy`] and explicit
    /// sticky-cache limits.
    ///
    /// `max_entries` is the hard cap on cached target entries — `0`
    /// disables the sticky cache entirely. `ttl` is the entry lifetime —
    /// `0` expires entries immediately. A full cache reclaims an expired
    /// entry first, otherwise evicting the least-recently-used entry.
    pub fn with_cache_limits(
        proxies: Vec<ProxyConfig>,
        policy: RatingPolicy,
        max_entries: usize,
        ttl: Duration,
    ) -> Self {
        let n = proxies.len();
        let identity_hasher = RandomState::new();
        let mut by_identity = HashMap::<_, Vec<usize>>::with_capacity(n);
        for (index, proxy) in proxies.iter().enumerate() {
            let bucket = by_identity
                .entry(upstream_hash(&identity_hasher, proxy))
                .or_default();
            if let Some(slot) = bucket
                .iter_mut()
                .find(|slot| same_upstream(proxy, &proxies[**slot]))
            {
                *slot = index;
            } else {
                bucket.push(index);
            }
        }
        Self {
            proxies: proxies.into_iter().map(Arc::new).collect(),
            identity_hasher,
            by_identity,
            index: AtomicUsize::new(0),
            sticky: Mutex::new(StickyCache::new(max_entries, ttl)),
            ratings: Ratings::new(n, policy),
        }
    }

    /// Insert (or replace) the cache entry for `addr`. Takes ownership
    /// of `Arc<ProxyConfig>` so the caller can hand off the only clone
    /// it had — refcount stays the same.
    ///
    /// A full cache reclaims an expired entry first, otherwise evicting
    /// the least-recently-used entry.
    pub fn link_proxy(&self, addr: String, proxy: Arc<ProxyConfig>) {
        self.sticky
            .lock()
            .unwrap()
            .insert(addr, proxy, Instant::now());
    }

    /// Drop the cached upstream for `addr` (e.g. after it failed).
    pub fn unlink_proxy(&self, addr: &str) {
        self.sticky.lock().unwrap().remove(addr);
    }

    /// Read back the cached upstream for `addr`, if any.
    ///
    /// Expired entries are removed and reported as `None` — a normal
    /// cache miss.
    pub fn get_linked(&self, addr: &str) -> Option<Arc<ProxyConfig>> {
        self.sticky.lock().unwrap().get(addr, Instant::now())
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
    ///
    /// Expected O(1), with no lock or allocation. Duplicate identities
    /// resolve to the last configured slot.
    fn index_of(&self, p: &ProxyConfig) -> Option<usize> {
        self.by_identity
            .get(&upstream_hash(&self.identity_hasher, p))?
            .iter()
            .copied()
            .find(|index| same_upstream(p, &self.proxies[*index]))
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
    fn rating_index_checks_identity_on_hash_collision() {
        let first = make_proxy("one", 1000);
        let second = make_proxy("two", 1001);
        let mut rotator = ProxyRotator::new(vec![first.clone(), second.clone()]);
        let hash = upstream_hash(&rotator.identity_hasher, &first);
        rotator.by_identity.insert(hash, vec![1, 0]);
        assert_eq!(rotator.index_of(&first), Some(0));
        rotator.by_identity.insert(hash, vec![1]);
        assert_eq!(rotator.index_of(&first), None);
    }

    #[test]
    fn rating_index_preserves_last_duplicate_slot() {
        let proxy = make_proxy("one", 1000);
        let rotator = ProxyRotator::new(vec![proxy.clone(), proxy.clone(), proxy.clone()]);
        assert_eq!(rotator.index_of(&proxy), Some(2));
        let hash = upstream_hash(&rotator.identity_hasher, &proxy);
        assert_eq!(rotator.by_identity[&hash].len(), 1);
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

    #[test]
    fn sticky_link_get_roundtrip() {
        let proxies = vec![make_proxy("h", 1000), make_proxy("h", 1001)];
        let r = ProxyRotator::with_cache_limits(
            proxies,
            RatingPolicy::default(),
            8,
            Duration::from_secs(600),
        );
        let a = Arc::new(make_proxy("h", 1000));
        r.link_proxy("target".to_string(), a.clone());
        assert_eq!(r.get_linked("target").map(|p| p.port), Some(1000));
        assert!(Arc::ptr_eq(&r.get_linked("target").unwrap(), &a));
        r.unlink_proxy("target");
        assert!(r.get_linked("target").is_none());
    }

    #[test]
    fn sticky_relink_replaces_entry() {
        let proxies = vec![make_proxy("h", 1000), make_proxy("h", 1001)];
        let r = ProxyRotator::with_cache_limits(
            proxies,
            RatingPolicy::default(),
            8,
            Duration::from_secs(600),
        );
        r.link_proxy("target".to_string(), Arc::new(make_proxy("h", 1000)));
        r.link_proxy("target".to_string(), Arc::new(make_proxy("h", 1001)));
        assert_eq!(r.get_linked("target").map(|p| p.port), Some(1001));
    }

    #[test]
    fn bounded_sequential_unique_targets() {
        let proxies = vec![make_proxy("h", 1000), make_proxy("h", 1001)];
        let r = ProxyRotator::with_cache_limits(
            proxies,
            RatingPolicy::default(),
            8,
            Duration::from_secs(600),
        );
        let total = 2000;
        for i in 0..total {
            r.link_proxy(format!("t{i}"), Arc::new(make_proxy("h", 1000)));
            assert!(r.sticky.lock().unwrap().map.len() <= 8);
        }
        // Insertion order == recency order: the last 8 linked addresses
        // must be present, the 9th-most-recent must be gone.
        for i in (total - 8)..total {
            assert!(
                r.get_linked(&format!("t{i}")).is_some(),
                "recent target t{i} missing"
            );
        }
        assert!(r.get_linked(&format!("t{}", total - 9)).is_none());
    }

    #[test]
    fn bounded_concurrent_hammer_stays_within_cap() {
        let proxies = vec![make_proxy("h", 1000), make_proxy("h", 1001)];
        let r = Arc::new(ProxyRotator::with_cache_limits(
            proxies,
            RatingPolicy::default(),
            8,
            Duration::from_secs(6000),
        ));
        std::thread::scope(|s| {
            for t in 0..8 {
                let r = &r;
                s.spawn(move || {
                    for i in 0u32..250 {
                        let addr = format!("t{t}-{i}");
                        r.link_proxy(addr.clone(), Arc::new(make_proxy("h", 1000)));
                        assert!(r.sticky.lock().unwrap().map.len() <= 8);
                        if i % 10 == 0 {
                            let probe = format!("t{t}-{}", i / 2);
                            let _ = r.get_linked(&probe);
                            r.unlink_proxy(&format!("t{t}-{}", i.saturating_sub(1)));
                        }
                    }
                });
            }
        });
        assert!(r.sticky.lock().unwrap().map.len() <= 8);
        r.link_proxy("sentinel".to_string(), Arc::new(make_proxy("h", 1001)));
        assert_eq!(r.get_linked("sentinel").map(|p| p.port), Some(1001));
    }

    #[test]
    fn lru_touch_prevents_eviction() {
        let proxies = vec![make_proxy("h", 1000)];
        let r = ProxyRotator::with_cache_limits(
            proxies,
            RatingPolicy::default(),
            2,
            Duration::from_secs(600),
        );
        r.link_proxy("A".to_string(), Arc::new(make_proxy("h", 1000)));
        r.link_proxy("B".to_string(), Arc::new(make_proxy("h", 1001)));
        assert_eq!(r.get_linked("A").map(|p| p.port), Some(1000)); // touch
        r.link_proxy("C".to_string(), Arc::new(make_proxy("h", 1002)));
        assert!(r.get_linked("B").is_none(), "B should be LRU-evicted");
        assert!(r.get_linked("A").is_some());
        assert_eq!(r.get_linked("C").map(|p| p.port), Some(1002));
    }

    #[test]
    fn ttl_expires_entries() {
        let mut cache = StickyCache::new(8, Duration::from_secs(10));
        let t0 = Instant::now();
        cache.insert("a".to_string(), Arc::new(make_proxy("h", 1000)), t0);
        assert!(cache.get("a", t0 + Duration::from_secs(5)).is_some());
        assert!(cache.get("a", t0 + Duration::from_secs(10)).is_none());
        assert!(cache.map.is_empty());
    }

    #[test]
    fn sticky_metadata_stays_bounded_behind_a_cold_entry() {
        let mut cache = StickyCache::new(2, Duration::from_secs(60));
        let t0 = Instant::now();
        let proxy = Arc::new(make_proxy("h", 1000));
        cache.insert("cold".to_string(), proxy.clone(), t0);
        cache.insert("hot".to_string(), proxy, t0);
        for second in 1..=8 {
            assert!(cache.get("hot", t0 + Duration::from_secs(second)).is_some());
        }
        let metadata_entries = cache.recency.len() + cache.expiry.len();
        assert!(
            metadata_entries <= 2 * cache.max_entries,
            "two cached targets retained {metadata_entries} eviction records"
        );
    }

    #[test]
    fn sticky_expiry_takes_precedence_over_recency() {
        let mut cache = StickyCache::new(2, Duration::from_secs(10));
        let t0 = Instant::now();
        cache.insert("expired".to_string(), Arc::new(make_proxy("h", 1000)), t0);
        cache.insert(
            "live".to_string(),
            Arc::new(make_proxy("h", 1001)),
            t0 + Duration::from_secs(5),
        );
        assert!(cache.get("expired", t0 + Duration::from_secs(9)).is_some());
        let now = t0 + Duration::from_secs(11);
        cache.insert("new".to_string(), Arc::new(make_proxy("h", 1002)), now);
        assert_eq!(cache.get("live", now).map(|p| p.port), Some(1001));
        assert_eq!(cache.get("new", now).map(|p| p.port), Some(1002));
        assert!(cache.get("expired", now).is_none());
    }

    #[test]
    fn sticky_replacement_refreshes_expiry_and_removal_releases_metadata() {
        let mut cache = StickyCache::new(2, Duration::from_secs(10));
        let t0 = Instant::now();
        cache.insert("A".to_string(), Arc::new(make_proxy("h", 1000)), t0);
        cache.insert(
            "B".to_string(),
            Arc::new(make_proxy("h", 1001)),
            t0 + Duration::from_secs(1),
        );
        cache.insert(
            "A".to_string(),
            Arc::new(make_proxy("h", 1002)),
            t0 + Duration::from_secs(8),
        );
        assert!(cache.get("B", t0 + Duration::from_secs(9)).is_some());
        let now = t0 + Duration::from_secs(11);
        cache.insert("C".to_string(), Arc::new(make_proxy("h", 1003)), now);
        assert_eq!(cache.get("A", now).map(|p| p.port), Some(1002));
        assert!(cache.get("B", now).is_none());
        cache.remove("A");
        cache.remove("C");
        assert!(cache.map.is_empty());
        assert!(cache.recency.is_empty());
        assert!(cache.expiry.is_empty());
    }

    #[test]
    fn sticky_recency_orders_operations_with_equal_timestamps() {
        let mut cache = StickyCache::new(2, Duration::from_secs(10));
        let now = Instant::now();
        let proxy = Arc::new(make_proxy("h", 1000));
        cache.insert("A".to_string(), proxy.clone(), now);
        cache.insert("B".to_string(), proxy.clone(), now);
        assert!(cache.get("A", now).is_some());
        cache.insert("C".to_string(), proxy, now);
        assert!(cache.get("A", now).is_some());
        assert!(cache.get("C", now).is_some());
        assert!(cache.get("B", now).is_none());
    }

    #[test]
    fn ttl_purge_frees_room_without_evicting_live_entries() {
        let mut cache = StickyCache::new(2, Duration::from_secs(10));
        let t0 = Instant::now();
        cache.insert("A".to_string(), Arc::new(make_proxy("h", 1000)), t0);
        cache.insert("B".to_string(), Arc::new(make_proxy("h", 1001)), t0);
        let t1 = t0 + Duration::from_secs(11);
        cache.insert("C".to_string(), Arc::new(make_proxy("h", 1002)), t1);
        cache.insert("D".to_string(), Arc::new(make_proxy("h", 1003)), t1);
        assert_eq!(cache.get("C", t1).map(|p| p.port), Some(1002));
        assert_eq!(cache.get("D", t1).map(|p| p.port), Some(1003));
        assert_eq!(cache.map.len(), 2);
    }

    #[test]
    fn cap_zero_disables_cache() {
        let proxies = vec![make_proxy("h", 1000)];
        let r = ProxyRotator::with_cache_limits(
            proxies,
            RatingPolicy::default(),
            0,
            Duration::from_secs(600),
        );
        r.link_proxy("a".to_string(), Arc::new(make_proxy("h", 1000)));
        assert!(r.get_linked("a").is_none());
        assert_eq!(r.sticky.lock().unwrap().map.len(), 0);
    }

    #[test]
    fn same_endpoint_different_accounts_rate_independently() {
        let mut alice = make_proxy("host", 1000);
        alice.user = Some("alice".to_string());
        alice.password = Some("pw-a".to_string());
        let mut bob = make_proxy("host", 1000);
        bob.user = Some("bob".to_string());
        bob.password = Some("pw-b".to_string());
        let policy = RatingPolicy {
            fail_penalty: 2.0,
            sand_max: 8.0,
            min_weight: 0.01,
            ..Default::default()
        };
        let r = ProxyRotator::with_policy(vec![alice.clone(), bob.clone()], policy);

        for _ in 0..10 {
            r.record_failure(&alice);
        }
        let w = r.ratings.weights();
        assert!(w[0] < 1.0, "alice's slot must be penalized, got {}", w[0]);
        assert!(
            (w[1] - 1.0).abs() < 1e-9,
            "bob's slot must be untouched by alice's failures, got {}",
            w[1]
        );
    }

    #[test]
    fn same_endpoint_different_protocols_rate_independently() {
        let socks = make_proxy("host", 1000);
        let mut http = make_proxy("host", 1000);
        http.protocol = ProxyProtocol::Http;
        let policy = RatingPolicy {
            fail_penalty: 2.0,
            sand_max: 8.0,
            min_weight: 0.01,
            ..Default::default()
        };
        let r = ProxyRotator::with_policy(vec![socks.clone(), http.clone()], policy);

        for _ in 0..10 {
            r.record_failure(&http);
        }
        let w = r.ratings.weights();
        assert!(w[1] < 1.0, "http slot must be penalized, got {}", w[1]);
        assert!(
            (w[0] - 1.0).abs() < 1e-9,
            "socks slot must be untouched by http failures, got {}",
            w[0]
        );
    }

    #[test]
    fn gate_composite_maps_to_original_rating_slot() {
        let inner = make_proxy("host", 1000);
        let other = make_proxy("host", 1001);
        let mut gate = make_proxy("gatehost", 999);
        gate.is_gate = true;
        let mut composite = inner.clone();
        composite.gate = Some(Arc::new(gate));
        let policy = RatingPolicy {
            fail_penalty: 2.0,
            sand_max: 8.0,
            min_weight: 0.01,
            ..Default::default()
        };
        let r = ProxyRotator::with_policy(vec![inner.clone(), other.clone()], policy);

        // The composite is a fresh allocation with `.gate` set; rating
        // it must still land on the original inner entry's slot.
        for _ in 0..10 {
            r.record_failure(&composite);
        }
        let w = r.ratings.weights();
        assert!(
            w[0] < 1.0,
            "composite failure must penalize the original inner slot, got {}",
            w[0]
        );
        assert!(
            (w[1] - 1.0).abs() < 1e-9,
            "unrelated upstream must be untouched, got {}",
            w[1]
        );
    }
}
