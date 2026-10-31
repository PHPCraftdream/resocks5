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
#[cfg(feature = "test-instrumentation")]
use std::sync::atomic::AtomicU64;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::rating::{QuarantinePolicy, RatingError, RatingPolicy, Ratings};
use crate::types::ProxyConfig;

mod probe;
pub use probe::ProbeEvent;

/// Error returned when a [`ProxyRotator`] cannot be constructed.
#[derive(Debug, Clone, PartialEq)]
pub enum RotatorError {
    /// The upstream list was empty. [`ProxyRotator::get_next`] would
    /// divide by zero, so empty rotators are rejected at construction.
    Empty,
    /// The [`RatingPolicy`] failed validation; the string describes the
    /// offending knob. Wrapped from [`RatingError::InvalidPolicy`].
    InvalidPolicy(String),
}

impl std::fmt::Display for RotatorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RotatorError::Empty => {
                write!(f, "cannot build a ProxyRotator from an empty upstream list")
            }
            RotatorError::InvalidPolicy(msg) => f.write_str(msg),
        }
    }
}

impl std::error::Error for RotatorError {}

impl From<RatingError> for RotatorError {
    fn from(e: RatingError) -> Self {
        match e {
            RatingError::InvalidPolicy(msg) => RotatorError::InvalidPolicy(msg),
        }
    }
}

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
        && a.gate_level == b.gate_level
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
        proxy.gate_level,
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
    /// Diagnostic count of `pick_order()` invocations. Compiled only
    /// with the `test-instrumentation` feature — a bare `#[cfg(test)]`
    /// field would be invisible to tests in dependent crates, and an
    /// always-compiled field would tax every production route-order
    /// selection with an unused atomic RMW. Dependents enable the
    /// feature from their `[dev-dependencies]`. Test/diagnostic only:
    /// nothing in production reads it.
    #[cfg(feature = "test-instrumentation")]
    pick_order_calls: AtomicU64,
}

impl ProxyRotator {
    /// Construct a rotator with the default [`RatingPolicy`].
    ///
    /// # Panics
    /// Panics when `proxies` is empty ([`RotatorError::Empty`]) or the
    /// default policy is invalid — see [`ProxyRotator::try_new`] for the
    /// fallible twin.
    pub fn new(proxies: Vec<ProxyConfig>) -> Self {
        Self::try_new(proxies).expect("ProxyRotator::new: invalid arguments")
    }

    /// Fallibly construct a rotator with the default [`RatingPolicy`].
    ///
    /// # Errors
    /// Returns [`RotatorError::Empty`] when `proxies` is empty.
    pub fn try_new(proxies: Vec<ProxyConfig>) -> Result<Self, RotatorError> {
        Self::try_with_policy(proxies, RatingPolicy::default())
    }

    /// Construct a rotator with a custom [`RatingPolicy`].
    ///
    /// # Panics
    /// Panics when `proxies` is empty ([`RotatorError::Empty`]) or
    /// `policy` fails [`RatingPolicy::validate`]
    /// ([`RotatorError::InvalidPolicy`]) — see
    /// [`ProxyRotator::try_with_policy`] for the fallible twin.
    pub fn with_policy(proxies: Vec<ProxyConfig>, policy: RatingPolicy) -> Self {
        Self::try_with_policy(proxies, policy)
            .expect("ProxyRotator::with_policy: invalid arguments")
    }

    /// Fallibly construct a rotator with a custom [`RatingPolicy`].
    ///
    /// # Errors
    /// Returns [`RotatorError::Empty`] when `proxies` is empty, or
    /// [`RotatorError::InvalidPolicy`] when `policy` fails
    /// [`RatingPolicy::validate`].
    pub fn try_with_policy(
        proxies: Vec<ProxyConfig>,
        policy: RatingPolicy,
    ) -> Result<Self, RotatorError> {
        Self::try_with_cache_limits(
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
    ///
    /// # Panics
    /// Panics when `proxies` is empty ([`RotatorError::Empty`]) or
    /// `policy` fails [`RatingPolicy::validate`]
    /// ([`RotatorError::InvalidPolicy`]) — see
    /// [`ProxyRotator::try_with_cache_limits`] for the fallible twin.
    pub fn with_cache_limits(
        proxies: Vec<ProxyConfig>,
        policy: RatingPolicy,
        max_entries: usize,
        ttl: Duration,
    ) -> Self {
        Self::try_with_cache_limits(proxies, policy, max_entries, ttl)
            .expect("ProxyRotator::with_cache_limits: invalid arguments")
    }

    /// Fallibly construct a rotator with a custom [`RatingPolicy`] and
    /// explicit sticky-cache limits.
    ///
    /// `max_entries` is the hard cap on cached target entries — `0`
    /// disables the sticky cache entirely. `ttl` is the entry lifetime —
    /// `0` expires entries immediately. A full cache reclaims an expired
    /// entry first, otherwise evicting the least-recently-used entry.
    ///
    /// # Errors
    /// Returns [`RotatorError::Empty`] when `proxies` is empty, or
    /// [`RotatorError::InvalidPolicy`] when `policy` fails
    /// [`RatingPolicy::validate`].
    ///
    /// # Invariants
    /// On `Ok`, the rotator holds at least one upstream: `get_next`,
    /// `pick_order` and `Ratings::pick` are therefore infallible and
    /// never panic (modulo `Ratings::pick`'s documented empty-set
    /// panic, unreachable here).
    pub fn try_with_cache_limits(
        proxies: Vec<ProxyConfig>,
        policy: RatingPolicy,
        max_entries: usize,
        ttl: Duration,
    ) -> Result<Self, RotatorError> {
        Self::try_with_quarantine(
            proxies,
            policy,
            QuarantinePolicy::disabled(),
            max_entries,
            ttl,
        )
    }

    /// Fallibly construct a rotator with a [`RatingPolicy`], a
    /// [`QuarantinePolicy`] and explicit sticky-cache limits.
    ///
    /// With the quarantine enabled, an upstream that keeps failing hard
    /// (see [`ProxyRotator::record_hard_failure`]) leaves
    /// [`pick_order`](ProxyRotator::pick_order) and the sticky cache for a
    /// backoff period while healthy upstreams exist; then
    /// [`take_probes`](ProxyRotator::take_probes) hands it out for one
    /// out-of-band check at a time.
    ///
    /// # Errors
    /// Returns [`RotatorError::Empty`] when `proxies` is empty, or
    /// [`RotatorError::InvalidPolicy`] when `policy` or `quarantine` fails
    /// validation.
    pub fn try_with_quarantine(
        proxies: Vec<ProxyConfig>,
        policy: RatingPolicy,
        quarantine: QuarantinePolicy,
        max_entries: usize,
        ttl: Duration,
    ) -> Result<Self, RotatorError> {
        if proxies.is_empty() {
            return Err(RotatorError::Empty);
        }
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
        let ratings = Ratings::try_with_quarantine(n, policy, quarantine)?;
        Ok(Self {
            proxies: proxies.into_iter().map(Arc::new).collect(),
            identity_hasher,
            by_identity,
            index: AtomicUsize::new(0),
            sticky: Mutex::new(StickyCache::new(max_entries, ttl)),
            ratings,
            #[cfg(feature = "test-instrumentation")]
            pick_order_calls: AtomicU64::new(0),
        })
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
    ///
    /// An entry whose upstream is quarantined (or on probation) is not
    /// returned, so a sticky target does not keep walking into a dead
    /// upstream; the entry itself stays until it expires or is replaced.
    pub fn get_linked(&self, addr: &str) -> Option<Arc<ProxyConfig>> {
        let linked = self.sticky.lock().unwrap().get(addr, Instant::now())?;
        if self.is_quarantined(&linked) {
            return None;
        }
        Some(linked)
    }

    /// Round-robin next proxy (fetch-and-increment, modulo length).
    ///
    /// Returns a cheap refcount clone of the chosen [`ProxyConfig`].
    ///
    /// Infallible: construction rejects empty lists, so `len() >= 1`
    /// always holds and the modulo never divides by zero.
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

    /// Record a hard failure: the upstream itself looks down (connect
    /// refused or timed out, handshake timeout, broken proxy protocol), as
    /// opposed to a refusal of one particular target. Counts in the sand
    /// model like [`record_failure`](ProxyRotator::record_failure) and toward
    /// the quarantine.
    ///
    /// Returns how long the upstream was just quarantined for, if this
    /// failure tripped (or extended) the quarantine.
    pub fn record_hard_failure(&self, proxy: &ProxyConfig) -> Option<Duration> {
        let i = self.index_of(proxy)?;
        self.ratings.on_hard_failure(i)
    }

    /// Claim the upstreams due for a probe (quarantine over, no probe in
    /// flight). Check each one out of band and report with
    /// [`record_success`](ProxyRotator::record_success) or
    /// [`record_hard_failure`](ProxyRotator::record_hard_failure). Empty
    /// without a quarantine.
    pub fn take_probes(&self) -> Vec<Arc<ProxyConfig>> {
        self.ratings
            .take_probes()
            .into_iter()
            .map(|i| self.proxies[i].clone())
            .collect()
    }

    /// Quarantine the proxy right away, without waiting for the failure
    /// threshold — for an explicit health check that found it down (e.g.
    /// at startup). Returns the quarantine length; `None` without a
    /// quarantine or for an unknown proxy.
    pub fn quarantine_now(&self, proxy: &ProxyConfig) -> Option<Duration> {
        let i = self.index_of(proxy)?;
        self.ratings.quarantine_now(i)
    }

    /// `true` while the proxy is quarantined or on probation. Unknown
    /// proxies are never quarantined.
    pub fn is_quarantined(&self, proxy: &ProxyConfig) -> bool {
        self.index_of(proxy)
            .is_some_and(|i| self.ratings.is_quarantined(i))
    }

    /// Record a success for the given proxy in the sand model. Also lifts
    /// its quarantine.
    pub fn record_success(&self, proxy: &ProxyConfig) {
        if let Some(i) = self.index_of(proxy) {
            self.ratings.on_success(i);
        }
    }

    /// Returns proxies in weighted-random order via the sand model.
    ///
    /// Quarantined and probing upstreams are omitted while a healthy one
    /// exists, so a client request never waits on a dead upstream. See
    /// [`ProxyRotator::try_with_quarantine`] and
    /// [`ProxyRotator::take_probes`].
    pub fn pick_order(&self) -> Vec<Arc<ProxyConfig>> {
        #[cfg(feature = "test-instrumentation")]
        self.pick_order_calls.fetch_add(1, Ordering::Relaxed);
        self.ratings
            .pick_order()
            .into_iter()
            .map(|i| self.proxies[i].clone())
            .collect()
    }

    /// Diagnostic/test-only reader: how many times
    /// [`ProxyRotator::pick_order`] has been called on this rotator.
    /// Hidden from docs; nothing in production consumes it — it exists
    /// so tests in dependent crates can assert that budget
    /// exhaustion skips order building. Compiled only with the
    /// `test-instrumentation` feature.
    #[doc(hidden)]
    #[cfg(feature = "test-instrumentation")]
    pub fn pick_order_calls(&self) -> u64 {
        self.pick_order_calls.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod construction_tests;
#[cfg(test)]
mod probe_tests;
#[cfg(test)]
mod quarantine_tests;
#[cfg(test)]
mod tests;
