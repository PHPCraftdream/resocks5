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

use crate::rating::{Health, ProbeClaim, QuarantinePolicy, RatingError, RatingPolicy, Ratings};
use crate::types::ProxyConfig;

mod probe;
pub use probe::ProbeEvent;

/// A saved quarantine record of one upstream; see [`ProxyRotator::health`].
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct UpstreamHealth {
    /// The upstream the record belongs to.
    pub proxy: Arc<ProxyConfig>,
    /// Its quarantine record.
    pub health: Health,
}

impl UpstreamHealth {
    /// Pair an upstream with its record.
    #[must_use]
    pub fn new(proxy: Arc<ProxyConfig>, health: Health) -> Self {
        Self { proxy, health }
    }
}

/// A claimed due-probe: the upstream plus the ownership token its outcome
/// is bound to. [`ProxyRotator::take_probe_claims`] issues one per granted
/// probe lease; [`ProxyRotator::record_success_for`] and
/// [`ProxyRotator::record_hard_failure_for`] apply the outcome only while
/// the token still matches the slot's state generation — a reset,
/// re-trip, restore or newer lease in between makes it stale and it is
/// dropped without a rating change.
#[derive(Debug, Clone)]
pub struct UpstreamProbeClaim {
    /// The claimed upstream.
    pub proxy: Arc<ProxyConfig>,
    pub(crate) claim: ProbeClaim,
}

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
/// slot: endpoint, protocol, account and `gate_level` (the node's own rank:
/// the same endpoint at two levels is two slots) all match. The `gate`
/// LINK field is deliberately excluded — it records how the upstream is reached on
/// this attempt (it is set on the gate-composite configs written to
/// the sticky cache), not what the upstream is — so rating a
/// gate-composite still lands on the plain upstream's slot. Compares
/// borrowed fields only: no `host`/`user`/`password` clones on the
/// per-event `record_failure`/`record_success` path. Cheap scalars
/// are compared first so mismatching candidates exit early.
pub(crate) fn same_upstream(a: &ProxyConfig, b: &ProxyConfig) -> bool {
    a.port == b.port
        && a.protocol == b.protocol
        && a.gate_level == b.gate_level
        && a.host == b.host
        && a.user == b.user
        && a.password == b.password
}

pub(crate) fn upstream_hash(state: &RandomState, proxy: &ProxyConfig) -> u64 {
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

    fn insert(&mut self, addr: impl AsRef<str>, proxy: Arc<ProxyConfig>, now: Instant) {
        let addr = addr.as_ref();
        if self.max_entries == 0 {
            return;
        }
        // A replaced entry hands its key back, so only a new address
        // allocates one.
        let key = self.remove(addr);
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
///
/// Identical upstreams (same endpoint, protocol and account) are
/// deduplicated at construction, keeping the first occurrence's
/// position; the rotator then describes unique upstreams only.
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
    /// Identical upstreams (same endpoint, protocol and account) are
    /// deduplicated at construction, keeping the first occurrence's
    /// position; [`RotatorError::Empty`] still applies to an empty
    /// input list.
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
        let identity_hasher = RandomState::new();
        // One rating slot per unique identity: identical upstreams
        // collapse onto the first occurrence's position, so `len()`,
        // `all_proxies()`, the ratings and `health()` describe unique
        // upstreams only.
        let mut unique: Vec<ProxyConfig> = Vec::with_capacity(proxies.len());
        let mut by_identity = HashMap::<_, Vec<usize>>::with_capacity(proxies.len());
        for proxy in proxies {
            let bucket = by_identity
                .entry(upstream_hash(&identity_hasher, &proxy))
                .or_default();
            if bucket
                .iter()
                .any(|slot| same_upstream(&proxy, &unique[*slot]))
            {
                continue;
            }
            bucket.push(unique.len());
            unique.push(proxy);
        }
        let ratings = Ratings::try_with_quarantine(unique.len(), policy, quarantine)?;
        Ok(Self {
            proxies: unique.into_iter().map(Arc::new).collect(),
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
    /// it had — refcount stays the same. `addr` is only borrowed: pass a
    /// `&str` and nothing is allocated when the entry already exists.
    ///
    /// A full cache reclaims an expired entry first, otherwise evicting
    /// the least-recently-used entry.
    pub fn link_proxy(&self, addr: impl AsRef<str>, proxy: Arc<ProxyConfig>) {
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

    /// Number of upstreams in the rotator (duplicates collapsed at
    /// construction).
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
    /// Expected O(1), with no lock or allocation. Identities are unique
    /// in the rotator (duplicates collapsed at construction); the
    /// per-slot comparison still guards against hash collisions.
    pub(crate) fn index_of(&self, p: &ProxyConfig) -> Option<usize> {
        self.by_identity
            .get(&upstream_hash(&self.identity_hasher, p))?
            .iter()
            .copied()
            .find(|index| same_upstream(p, &self.proxies[*index]))
    }

    /// Разрешение identity узла cached-цепочки через construction-time индекс:
    /// его использует `GateLevels::resolve` вместо линейного скана
    /// `all_proxies`. Bucket хранится в порядке слотов, поэтому возвращается
    /// тот же слот, что нашёл бы линейный поиск. Совпадение hash только
    /// отбирает кандидатов — identity доказывается сравнением полей
    /// `same_upstream`, поэтому коллизии разрешаются корректно. С
    /// `test-instrumentation` каждое сравнение bucket учитывается в
    /// `resolve_comparisons` (счётчик пути resolve, не `index_of`).
    pub(crate) fn resolve_identity(&self, node: &ProxyConfig) -> Option<&Arc<ProxyConfig>> {
        let bucket = self
            .by_identity
            .get(&upstream_hash(&self.identity_hasher, node))?;
        for slot in bucket {
            #[cfg(all(test, feature = "test-instrumentation"))]
            crate::perf::operation(|c| c.resolve_comparisons += 1);
            if same_upstream(node, &self.proxies[*slot]) {
                return Some(&self.proxies[*slot]);
            }
        }
        None
    }

    /// Тестовый оракул: ожидаемое число сравнений индексного пути для
    /// `node` — позиция совпавшего слота в bucket (hit, скан до первого
    /// совпадения) или длина bucket (miss, bucket исчерпан). Корректно
    /// для произвольных коллизий, раннего совпадения и пустого bucket.
    #[cfg(all(test, feature = "test-instrumentation"))]
    pub(crate) fn identity_scan_expectation(&self, node: &ProxyConfig) -> usize {
        let Some(bucket) = self
            .by_identity
            .get(&upstream_hash(&self.identity_hasher, node))
        else {
            return 0;
        };
        bucket
            .iter()
            .position(|slot| same_upstream(node, &self.proxies[*slot]))
            .map_or(bucket.len(), |position| position + 1)
    }

    /// Снапшотный прокси по индексу ratings (только для внутренних планов;
    /// идентичность — same_upstream).
    pub(crate) fn proxy_at(&self, index: usize) -> &ProxyConfig {
        &self.proxies[index]
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

    /// [`ProxyRotator::take_probes`] with ownership: each claim pairs the
    /// upstream with the generation token its outcome must still match.
    /// Report through [`ProxyRotator::record_success_for`] /
    /// [`ProxyRotator::record_hard_failure_for`]. Empty without a
    /// quarantine.
    pub fn take_probe_claims(&self) -> Vec<UpstreamProbeClaim> {
        self.ratings
            .take_probe_claims()
            .into_iter()
            .map(|claim| {
                let proxy = self.proxies[claim.index()].clone();
                UpstreamProbeClaim { proxy, claim }
            })
            .collect()
    }

    /// Apply a claimed probe's success only while the claim still owns
    /// the upstream's probation slot; stale claims change nothing.
    /// Returns `true` when the success was applied.
    pub fn record_success_for(&self, claim: &UpstreamProbeClaim) -> bool {
        self.ratings.record_success_for(&claim.claim)
    }

    /// Apply a claimed probe's hard failure only while the claim still
    /// owns the slot; stale claims change nothing. Returns the new
    /// quarantine length when the applied failure (re-)tripped the
    /// quarantine; `None` when the claim was stale or the applied failure
    /// did not trip.
    pub fn record_hard_failure_for(&self, claim: &UpstreamProbeClaim) -> Option<Duration> {
        self.ratings.record_hard_failure_for(&claim.claim)
    }

    /// Quarantine the proxy right away, without waiting for the failure
    /// threshold — for an explicit health check that found it down (e.g.
    /// at startup). Returns the quarantine length; `None` without a
    /// quarantine or for an unknown proxy.
    pub fn quarantine_now(&self, proxy: &ProxyConfig) -> Option<Duration> {
        let i = self.index_of(proxy)?;
        self.ratings.quarantine_now(i)
    }

    /// [`ProxyRotator::quarantine_now`] unless the upstream is already
    /// tripped (quarantined or on probation): a single ratings lock
    /// acquisition, so a concurrent hard failure cannot slip between the
    /// check and the trip and double the backoff on one piece of
    /// evidence. Returns the quarantine length when THIS call did the
    /// quarantining; `None` when the upstream was already tripped or
    /// unknown.
    pub fn quarantine_now_unless_tripped(&self, proxy: &ProxyConfig) -> Option<Duration> {
        let i = self.index_of(proxy)?;
        self.ratings.quarantine_now_unless_tripped(i)
    }

    /// `true` while the proxy is quarantined or on probation. Unknown
    /// proxies are never quarantined.
    pub fn is_quarantined(&self, proxy: &ProxyConfig) -> bool {
        self.index_of(proxy)
            .is_some_and(|i| self.ratings.is_quarantined(i))
    }

    /// Quarantine records of every upstream, in configuration order — what
    /// to save so a restart can resume without relearning which ones are dead.
    pub fn health(&self) -> Vec<UpstreamHealth> {
        self.proxies
            .iter()
            .zip(self.ratings.health())
            .map(|(proxy, health)| UpstreamHealth {
                proxy: proxy.clone(),
                health,
            })
            .collect()
    }

    /// Re-create saved quarantines; meant for start-up, it overwrites the
    /// matching slots. Entries for unknown upstreams and `Alive` ones are
    /// skipped. Returns how many upstreams were put back into quarantine
    /// (always `0` without a quarantine policy).
    pub fn restore_health(&self, entries: &[UpstreamHealth]) -> usize {
        entries
            .iter()
            .filter(|entry| {
                self.index_of(&entry.proxy)
                    .is_some_and(|i| self.ratings.restore_health(i, &entry.health))
            })
            .count()
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
    /// [`ProxyRotator::pick_order`] or [`ProxyRotator::pick_iter`] has been
    /// called on this rotator.
    /// Hidden from docs; nothing in production consumes it — it exists
    /// so tests in dependent crates can assert that budget
    /// exhaustion skips order building. Compiled only with the
    /// `test-instrumentation` feature.
    #[doc(hidden)]
    #[cfg(feature = "test-instrumentation")]
    pub fn pick_order_calls(&self) -> u64 {
        self.pick_order_calls.load(Ordering::Relaxed)
    }

    /// Ленивый аналог pick_order: тот же снапшот (момент, quarantine,
    /// RNG-потребление), порядок и материализация по мере потребления.
    pub(crate) fn pick_order_lazy(self: &Arc<Self>) -> LazyCandidates {
        let (eligible, cursor) = self.ratings.pick_order_lazy().into_parts();
        LazyCandidates {
            rotator: Arc::clone(self),
            eligible,
            cursor,
        }
    }

    /// Public lazy twin of [`ProxyRotator::pick_order`]: the same snapshot
    /// (eligibility, quarantine screening and RNG consumption at call
    /// time) yielding the same order, but the weighted keys are sorted
    /// and the `Arc<ProxyConfig>` candidates materialised only as the
    /// iterator is consumed, so the cost is proportional to consumption
    /// instead of the pool size. Draining it produces exactly
    /// [`ProxyRotator::pick_order`] for the same RNG state.
    pub fn pick_iter(self: &Arc<Self>) -> PickOrder {
        #[cfg(feature = "test-instrumentation")]
        self.pick_order_calls.fetch_add(1, Ordering::Relaxed);
        PickOrder {
            inner: self.pick_order_lazy(),
        }
    }

    /// Тестовый хук: ротатор с фиксированным seed RNG рейтингов.
    #[cfg(test)]
    pub(crate) fn with_rng_seed(
        proxies: Vec<ProxyConfig>,
        policy: RatingPolicy,
        quarantine: QuarantinePolicy,
        max_entries: usize,
        ttl: Duration,
        seed: u64,
    ) -> Result<Self, RotatorError> {
        let rotator = Self::try_with_quarantine(proxies, policy, quarantine, max_entries, ttl)?;
        rotator.ratings.reseed(seed);
        Ok(rotator)
    }
}

/// Ленивая выдача pick_order: тот же снапшот рейтингов, proxies
/// материализуются Arc-клоном только по мере потребления.
pub(crate) struct LazyCandidates {
    rotator: Arc<ProxyRotator>,
    eligible: Vec<usize>,
    cursor: crate::rating::select::LazyOrder,
}

impl LazyCandidates {
    /// Индексы eligible-слотов снапшота (для точного mark_dead без ключей).
    pub(crate) fn eligible(&self) -> &[usize] {
        &self.eligible
    }

    /// Владелец снапшота (используется ленивыми слоями ChainPlan).
    pub(crate) fn rotator(&self) -> &Arc<ProxyRotator> {
        &self.rotator
    }

    /// Следующий прокси в точном порядке pick_order.
    pub(crate) fn next_proxy(&mut self) -> Option<Arc<ProxyConfig>> {
        self.cursor
            .next()
            .map(|j| self.rotator.proxies[self.eligible[j]].clone())
    }

    /// Полный дренаж; эквивалентен pick_order().
    #[cfg(test)]
    pub(crate) fn into_proxies(mut self) -> Vec<Arc<ProxyConfig>> {
        std::iter::from_fn(|| self.next_proxy()).collect()
    }
}

/// Lazy candidate iterator returned by [`ProxyRotator::pick_iter`].
/// See that method for the snapshot, ordering and cost contract: the
/// order equals [`ProxyRotator::pick_order`] for the same RNG state, and
/// sorting/materialisation happen only as items are pulled. After
/// exhaustion it keeps returning `None`.
pub struct PickOrder {
    inner: LazyCandidates,
}

impl Iterator for PickOrder {
    type Item = Arc<ProxyConfig>;

    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next_proxy()
    }
}

impl std::iter::FusedIterator for PickOrder {}

#[cfg(test)]
mod construction_tests;
#[cfg(test)]
mod probe_tests;
#[cfg(test)]
mod quarantine_tests;
mod record_error;
#[cfg(test)]
mod tests;
