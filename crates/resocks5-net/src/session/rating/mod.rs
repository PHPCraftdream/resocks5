//! Sand-rating model: exponential-decay failure accumulators driving
//! weighted-random upstream selection.
//!
//! Each upstream has a [`Sand`] cell that grows on failure and halves every
//! `half_life_sec` of silence; selection weight is `exp(-k * level)`, so bad
//! upstreams are picked less often but never zero. [`Ratings`] is the
//! thread-safe integrator over a vector of cells. See `docs/ARCHITECTURE.md`
//! for the full maths and convergence argument.
//!
//! On top of the soft weights, an optional [`QuarantinePolicy`] removes an
//! upstream from the selection order for a backoff period after repeated hard
//! failures (see [`Ratings::on_hard_failure`]), while healthy upstreams exist.

pub mod health;
pub mod policy;
pub mod quarantine;
pub mod rng;
pub mod sand;
pub mod select;

pub use health::{Health, UpstreamState};
pub use policy::{RatingError, RatingPolicy};
pub use quarantine::QuarantinePolicy;
pub use rng::SmallRng;
pub use sand::Sand;

use std::sync::Mutex;
use std::time::{Duration, Instant};

use quarantine::{Cell, State};

struct Inner {
    cells: Vec<Sand>,
    quarantine: Vec<Cell>,
    rng: SmallRng,
}

/// Thread-safe weighted-random upstream selector driven by exponential-decay
/// sand accumulators.
pub struct Ratings {
    policy: RatingPolicy,
    quarantine: QuarantinePolicy,
    inner: Mutex<Inner>,
}

/// Opaque ownership token of one probation slot: what a probe outcome is
/// bound to. [`Ratings::take_probe_claims`] issues one claim per granted
/// probe lease; every success, trip, restore and newer lease changes the
/// slot's generation, and [`Ratings::record_success_for`] /
/// [`Ratings::record_hard_failure_for`] then drop outcomes whose claim no
/// longer matches instead of rating a slot somebody else owns now.
///
/// The claim is about ownership, not about time: the lease only keeps a
/// second probe away while it runs. An outcome that arrives after its lease
/// ran out but before anybody claimed the slot again is still evidence about
/// that upstream and is applied; once a newer claim (or any reset, trip or
/// restore) exists, the old outcome is dropped. Bound a probe's own run time
/// with its connect/handshake budget, not with the lease.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProbeClaim {
    index: usize,
    token: u64,
}

impl ProbeClaim {
    /// The rated slot this claim belongs to.
    #[must_use]
    pub fn index(&self) -> usize {
        self.index
    }
}

impl Ratings {
    /// Create `n` fresh upstreams, all starting at weight 1.0.
    ///
    /// # Panics
    /// Panics when `policy` fails [`RatingPolicy::validate`] — invalid
    /// knobs would silently produce `inf`/`NaN` weights during
    /// selection. See [`Ratings::try_new`] for the fallible twin.
    pub fn new(n: usize, policy: RatingPolicy) -> Self {
        Self::try_new(n, policy).expect("Ratings::new: invalid policy")
    }

    /// Fallibly create `n` fresh upstreams, all starting at weight 1.0.
    ///
    /// # Errors
    /// Returns [`RatingError::InvalidPolicy`] when `policy` fails
    /// [`RatingPolicy::validate`].
    pub fn try_new(n: usize, policy: RatingPolicy) -> Result<Self, RatingError> {
        Self::try_with_quarantine(n, policy, QuarantinePolicy::disabled())
    }

    /// Fallibly create `n` fresh upstreams with a [`QuarantinePolicy`] on
    /// top of the sand model.
    ///
    /// # Errors
    /// Returns [`RatingError::InvalidPolicy`] when `policy` fails
    /// [`RatingPolicy::validate`] or `quarantine` fails
    /// [`QuarantinePolicy::validate`].
    pub fn try_with_quarantine(
        n: usize,
        policy: RatingPolicy,
        quarantine: QuarantinePolicy,
    ) -> Result<Self, RatingError> {
        policy.validate()?;
        quarantine.validate()?;
        let now = Instant::now();
        Ok(Self {
            policy,
            quarantine,
            inner: Mutex::new(Inner {
                cells: (0..n).map(|_| Sand::new(now)).collect(),
                quarantine: (0..n).map(|_| Cell::default()).collect(),
                rng: SmallRng::from_os(),
            }),
        })
    }

    /// The policy these ratings were constructed with.
    pub fn policy(&self) -> &RatingPolicy {
        &self.policy
    }

    /// The quarantine policy these ratings were constructed with.
    pub fn quarantine_policy(&self) -> &QuarantinePolicy {
        &self.quarantine
    }

    /// Number of upstreams in this set.
    pub fn len(&self) -> usize {
        self.inner.lock().unwrap().cells.len()
    }

    /// `true` if there are no upstreams.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Record a failure for upstream `i` in the sand model only.
    ///
    /// Use this for failures that say little about the upstream's health
    /// (e.g. it refused one particular target). For failures that mean the
    /// upstream itself is down, use [`Ratings::on_hard_failure`].
    pub fn on_failure(&self, i: usize) {
        if !self.policy.enabled() {
            return;
        }
        let mut inner = self.inner.lock().unwrap();
        if i < inner.cells.len() {
            let now = Instant::now();
            inner.cells[i].observe_failure(now, &self.policy);
        }
    }

    /// Record a hard failure for upstream `i`: the upstream itself looks
    /// down (connect refused or timed out, handshake timeout, broken proxy
    /// protocol). Counts in the sand model like [`Ratings::on_failure`] and
    /// toward the quarantine.
    ///
    /// Returns the length of the quarantine when this failure started (or
    /// extended) one, `None` otherwise.
    pub fn on_hard_failure(&self, i: usize) -> Option<Duration> {
        self.on_hard_failure_at(i, Instant::now())
    }

    fn on_hard_failure_at(&self, i: usize, now: Instant) -> Option<Duration> {
        let mut inner = self.inner.lock().unwrap();
        if i >= inner.cells.len() {
            return None;
        }
        if self.policy.enabled() {
            inner.cells[i].observe_failure(now, &self.policy);
        }
        if !self.quarantine.enabled() {
            return None;
        }
        inner.quarantine[i].hard_failure(now, &self.quarantine)
    }

    /// Apply a probe's success only while `claim` still owns the slot:
    /// under one lock acquisition the claim's generation is checked
    /// against the slot's; a reset, re-trip, restore or newer lease in
    /// between makes the outcome stale and nothing is changed. Returns
    /// `true` when the success was applied.
    pub fn record_success_for(&self, claim: &ProbeClaim) -> bool {
        let mut inner = self.inner.lock().unwrap();
        if claim.index >= inner.cells.len() {
            return false;
        }
        if inner.quarantine[claim.index].generation() != claim.token {
            return false;
        }
        let now = Instant::now();
        if self.policy.enabled() {
            inner.cells[claim.index].observe_success(now, &self.policy);
        }
        inner.quarantine[claim.index].success();
        true
    }

    /// Apply a probe's hard failure only while `claim` still owns the
    /// slot (same generation gate as [`Ratings::record_success_for`],
    /// under the same lock). Returns the new quarantine length when the
    /// applied failure (re-)tripped the quarantine; `None` when the claim
    /// was stale (nothing changed) or the applied failure did not trip.
    pub fn record_hard_failure_for(&self, claim: &ProbeClaim) -> Option<Duration> {
        self.record_hard_failure_for_at(claim, Instant::now())
    }

    fn record_hard_failure_for_at(&self, claim: &ProbeClaim, now: Instant) -> Option<Duration> {
        let mut inner = self.inner.lock().unwrap();
        if claim.index >= inner.cells.len() {
            return None;
        }
        if inner.quarantine[claim.index].generation() != claim.token {
            return None;
        }
        if self.policy.enabled() {
            inner.cells[claim.index].observe_failure(now, &self.policy);
        }
        if !self.quarantine.enabled() {
            return None;
        }
        inner.quarantine[claim.index].hard_failure(now, &self.quarantine)
    }

    /// Quarantine upstream `i` right away, without waiting for the failure
    /// threshold: for an explicit health check that found it down (e.g. at
    /// startup). Returns the quarantine length; `None` without a quarantine
    /// or for an unknown index.
    pub fn quarantine_now(&self, i: usize) -> Option<Duration> {
        if !self.quarantine.enabled() {
            return None;
        }
        let mut inner = self.inner.lock().unwrap();
        let now = Instant::now();
        let cell = inner.quarantine.get_mut(i)?;
        Some(cell.trip_now(now, &self.quarantine))
    }

    /// [`Ratings::quarantine_now`] unless the upstream is already tripped
    /// (quarantined or on probation) — one lock acquisition, so a
    /// concurrent [`Ratings::on_hard_failure`] cannot slip between the
    /// check and the trip and double the backoff on one piece of
    /// evidence. Returns the quarantine length when THIS call did the
    /// quarantining; `None` when the upstream was already tripped or the
    /// index is unknown.
    pub fn quarantine_now_unless_tripped(&self, i: usize) -> Option<Duration> {
        if !self.quarantine.enabled() {
            return None;
        }
        let mut inner = self.inner.lock().unwrap();
        let now = Instant::now();
        let cell = inner.quarantine.get_mut(i)?;
        if cell.is_tripped() {
            return None;
        }
        Some(cell.trip_now(now, &self.quarantine))
    }

    /// Record a success for upstream `i`. Also lifts any quarantine.
    pub fn on_success(&self, i: usize) {
        let mut inner = self.inner.lock().unwrap();
        if i >= inner.cells.len() {
            return;
        }
        if self.policy.enabled() {
            let now = Instant::now();
            inner.cells[i].observe_success(now, &self.policy);
        }
        inner.quarantine[i].success();
    }

    /// `true` while upstream `i` is quarantined or on probation (tripped
    /// and not yet confirmed alive by a success).
    pub fn is_quarantined(&self, i: usize) -> bool {
        self.inner
            .lock()
            .unwrap()
            .quarantine
            .get(i)
            .is_some_and(Cell::is_tripped)
    }

    /// Snapshot of current decayed weights for all upstreams.
    pub fn weights(&self) -> Vec<f64> {
        let inner = self.inner.lock().unwrap();
        let now = Instant::now();
        inner
            .cells
            .iter()
            .map(|s| s.weight(now, &self.policy))
            .collect()
    }

    /// Pick one upstream index via weighted random selection. Quarantined
    /// and probing upstreams are skipped while a healthy one exists.
    ///
    /// # Panics
    /// Panics if `len() == 0`.
    pub fn pick(&self) -> usize {
        self.pick_at(Instant::now())
    }

    fn pick_at(&self, now: Instant) -> usize {
        let mut inner = self.inner.lock().unwrap();
        let mut weights: Vec<f64> = inner
            .cells
            .iter()
            .map(|s| s.weight(now, &self.policy))
            .collect();
        assert!(!weights.is_empty(), "Ratings::pick called on empty set");
        if self.quarantine.enabled() {
            let healthy: Vec<bool> = inner
                .quarantine
                .iter()
                .map(|c| c.state(now) == State::Healthy)
                .collect();
            if healthy.iter().any(|&h| h) {
                for (w, ok) in weights.iter_mut().zip(healthy) {
                    if !ok {
                        *w = 0.0;
                    }
                }
            }
        }
        select::weighted_index(&weights, &mut inner.rng)
    }

    /// Return a weighted permutation of the selectable upstream indices.
    ///
    /// Without a quarantine this is every index. With one, quarantined and
    /// probing upstreams are left out while at least one upstream is
    /// healthy, so no client request ever waits on a dead upstream; when no
    /// upstream is healthy the quarantine is ignored and every index is
    /// returned. Upstreams whose quarantine ended are handed out by
    /// [`Ratings::take_probes`] instead, for an out-of-band check.
    pub fn pick_order(&self) -> Vec<usize> {
        self.pick_order_at(Instant::now())
    }

    fn pick_order_at(&self, now: Instant) -> Vec<usize> {
        let (eligible, keyed) = {
            let mut inner = self.inner.lock().unwrap();
            let Inner {
                cells,
                quarantine,
                rng,
            } = &mut *inner;
            let eligible: Vec<usize> = if self.quarantine.enabled()
                && quarantine.iter().any(|c| c.state(now) == State::Healthy)
            {
                (0..cells.len())
                    .filter(|&i| quarantine[i].state(now) == State::Healthy)
                    .collect()
            } else {
                (0..cells.len()).collect()
            };
            let keyed = select::weighted_keys(
                eligible.iter().map(|&i| cells[i].weight(now, &self.policy)),
                rng,
            );
            (eligible, keyed)
        };
        // The O(n log n) sort does not hold the ratings lock.
        select::order_keys(keyed)
            .into_iter()
            .map(|j| eligible[j])
            .collect()
    }

    /// Claim the upstreams that are due for a probe: their quarantine has
    /// ended and no other probe holds them (see
    /// [`QuarantinePolicy::probe_lease`]). The caller checks each one out of
    /// band (e.g. a TCP connect) and reports the outcome with
    /// [`Ratings::on_success`] (back into rotation) or
    /// [`Ratings::on_hard_failure`] (quarantined again, twice as long).
    /// Empty without a quarantine.
    pub fn take_probes(&self) -> Vec<usize> {
        self.take_probes_at(Instant::now())
    }

    /// [`Ratings::take_probes`] with ownership: each returned
    /// [`ProbeClaim`] carries the generation of the slot at lease-grant
    /// time. Report the outcome with [`Ratings::record_success_for`] /
    /// [`Ratings::record_hard_failure_for`]; outcomes whose slot changed
    /// hands meanwhile are dropped. Empty without a quarantine.
    pub fn take_probe_claims(&self) -> Vec<ProbeClaim> {
        self.take_probe_claims_at(Instant::now())
    }

    fn take_probes_at(&self, now: Instant) -> Vec<usize> {
        self.take_probe_claims_at(now)
            .into_iter()
            .map(|claim| claim.index)
            .collect()
    }

    fn take_probe_claims_at(&self, now: Instant) -> Vec<ProbeClaim> {
        if !self.quarantine.enabled() {
            return Vec::new();
        }
        let mut inner = self.inner.lock().unwrap();
        inner
            .quarantine
            .iter_mut()
            .enumerate()
            .filter_map(|(i, c)| {
                c.try_lease(now, &self.quarantine)
                    .map(|token| ProbeClaim { index: i, token })
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_with_zero_n_works() {
        let r = Ratings::new(0, RatingPolicy::default());
        assert_eq!(r.len(), 0);
        assert!(r.is_empty());
        assert!(r.pick_order().is_empty());
    }

    #[test]
    fn on_failure_increases_sand() {
        let r = Ratings::new(2, RatingPolicy::default());
        r.on_failure(0);
        let w = r.weights();
        assert!(
            w[0] < 1.0,
            "weight after failure should be < 1.0, got {}",
            w[0]
        );
    }

    #[test]
    fn on_failure_disabled_when_penalty_zero() {
        let p = RatingPolicy {
            fail_penalty: 0.0,
            ..Default::default()
        };
        let r = Ratings::new(2, p);
        r.on_failure(0);
        let w = r.weights();
        assert!(
            (w[0] - 1.0).abs() < 1e-9,
            "weight should stay 1.0 when disabled, got {}",
            w[0]
        );
    }

    #[test]
    fn pick_order_is_permutation_of_all_indices() {
        let r = Ratings::new(5, RatingPolicy::default());
        let order = r.pick_order();
        assert_eq!(order.len(), 5);
        let mut sorted = order.clone();
        sorted.sort();
        assert_eq!(sorted, vec![0, 1, 2, 3, 4]);
    }

    #[test]
    fn weights_equal_at_start() {
        let r = Ratings::new(4, RatingPolicy::default());
        let w = r.weights();
        for (i, &v) in w.iter().enumerate() {
            assert!((v - 1.0).abs() < 1e-9, "weight[{i}] = {v}, expected 1.0");
        }
    }

    #[test]
    fn bad_upstream_picked_less_but_nonzero_over_many_pulls() {
        let r = Ratings::new(4, RatingPolicy::default());
        // Saturate cell 0.
        for _ in 0..100 {
            r.on_failure(0);
        }
        let n = 10_000;
        let mut count0 = 0u32;
        for _ in 0..n {
            if r.pick() == 0 {
                count0 += 1;
            }
        }
        assert!(count0 >= 1, "index 0 should still be picked at least once");
        let frac = count0 as f64 / n as f64;
        assert!(
            frac < 0.10,
            "index 0 picked {frac}*100% of the time, expected <10%"
        );
    }

    #[test]
    fn converges_under_sustained_failure_rate() {
        let r = Ratings::new(4, RatingPolicy::default());
        // Simulate: index 0 fails roughly 50% of the time over many iterations.
        // We use a deterministic pattern: fail on even iterations.
        for i in 0..10_000 {
            if i % 2 == 0 {
                r.on_failure(0);
            } else {
                r.on_success(0);
            }
        }
        let w = r.weights();
        // With 50% failure rate the sand level stabilises around ~1.0
        // (fail adds 1.0, success halves), giving a weight strictly below 1.0
        // but well above min_weight.  This proves the model neither runs away
        // nor collapses to zero.
        assert!(
            w[0] < 1.0,
            "weight[0] should be below 1.0 under sustained failures, got {}",
            w[0]
        );
        assert!(
            w[0] > 0.05,
            "weight[0] should stay above min_weight (0.05), got {}",
            w[0]
        );
    }
}

#[cfg(test)]
mod construction_tests {
    use super::*;

    #[test]
    fn new_rejects_invalid_policy() {
        let p = RatingPolicy {
            sand_max: 0.0,
            ..Default::default()
        };
        assert!(matches!(
            Ratings::try_new(2, p),
            Err(RatingError::InvalidPolicy(msg)) if msg.contains("sand_max")
        ));
    }

    #[test]
    fn new_accepts_default_policy() {
        assert!(Ratings::try_new(3, RatingPolicy::default()).is_ok());
    }

    #[test]
    #[should_panic(expected = "Ratings::new: invalid policy")]
    fn new_panics_on_invalid_policy() {
        let p = RatingPolicy {
            sand_max: 0.0,
            ..Default::default()
        };
        let _ = Ratings::new(2, p);
    }
}

#[cfg(test)]
mod quarantine_tests {
    use super::*;

    fn ratings(n: usize) -> Ratings {
        Ratings::try_with_quarantine(
            n,
            RatingPolicy::default(),
            QuarantinePolicy::default()
                .with_threshold(3)
                .with_initial(Duration::from_secs(30))
                .with_max(Duration::from_secs(600))
                .with_probe_lease(Duration::from_secs(25)),
        )
        .unwrap()
    }

    fn trip(r: &Ratings, i: usize, now: Instant) {
        for _ in 0..3 {
            r.on_hard_failure_at(i, now);
        }
    }

    #[test]
    fn dead_upstream_leaves_the_order_while_healthy_ones_exist() {
        let r = ratings(3);
        let t0 = Instant::now();
        trip(&r, 0, t0);
        assert!(r.is_quarantined(0));
        for _ in 0..200 {
            let order = r.pick_order_at(t0);
            assert_eq!(order.len(), 2);
            assert!(!order.contains(&0), "{order:?}");
            assert_ne!(r.pick_at(t0), 0);
        }
    }

    #[test]
    fn fewer_failures_than_the_threshold_do_not_quarantine() {
        let r = ratings(3);
        let t0 = Instant::now();
        r.on_hard_failure_at(0, t0);
        r.on_hard_failure_at(0, t0);
        assert!(!r.is_quarantined(0));
        assert_eq!(r.pick_order_at(t0).len(), 3);
    }

    #[test]
    fn hard_failure_reports_the_quarantine_length_once() {
        let r = ratings(2);
        let t0 = Instant::now();
        assert_eq!(r.on_hard_failure_at(0, t0), None);
        assert_eq!(r.on_hard_failure_at(0, t0), None);
        assert_eq!(r.on_hard_failure_at(0, t0), Some(Duration::from_secs(30)));
        // A request that was in flight before the trip fails late: ignored.
        assert_eq!(r.on_hard_failure_at(0, t0 + Duration::from_secs(1)), None);
    }

    #[test]
    fn probes_are_handed_out_once_and_never_enter_the_order() {
        let r = ratings(3);
        let t0 = Instant::now();
        trip(&r, 0, t0);
        assert!(r.take_probes_at(t0).is_empty(), "still quarantined");
        let t1 = t0 + Duration::from_secs(31);
        // Client orders never carry the probing upstream.
        assert!(!r.pick_order_at(t1).contains(&0));
        assert_eq!(r.take_probes_at(t1), vec![0]);
        // The lease is held: the probe is not handed out again.
        assert!(r.take_probes_at(t1 + Duration::from_secs(1)).is_empty());
        assert!(!r.pick_order_at(t1 + Duration::from_secs(1)).contains(&0));
        // A probe that never reported back is re-issued after the lease.
        assert_eq!(r.take_probes_at(t1 + Duration::from_secs(25)), vec![0]);
    }

    #[test]
    fn simultaneous_expiries_give_independent_probes() {
        let r = ratings(4);
        let t0 = Instant::now();
        trip(&r, 0, t0);
        trip(&r, 1, t0);
        let t1 = t0 + Duration::from_secs(31);
        assert_eq!(r.take_probes_at(t1), vec![0, 1]);
        assert_eq!(r.pick_order_at(t1).len(), 2);
    }

    #[test]
    fn no_probes_without_a_quarantine() {
        let r = Ratings::new(2, RatingPolicy::default());
        assert!(r.take_probes().is_empty());
    }

    #[test]
    fn failed_probe_requarantines_for_twice_as_long() {
        let r = ratings(3);
        let t0 = Instant::now();
        trip(&r, 0, t0);
        let t1 = t0 + Duration::from_secs(31);
        assert_eq!(r.take_probes_at(t1), vec![0]);
        assert_eq!(r.on_hard_failure_at(0, t1), Some(Duration::from_secs(60)));
        assert!(!r.pick_order_at(t1 + Duration::from_secs(59)).contains(&0));
    }

    #[test]
    fn successful_probe_returns_the_upstream_to_rotation() {
        let r = ratings(3);
        let t0 = Instant::now();
        trip(&r, 0, t0);
        let t1 = t0 + Duration::from_secs(31);
        assert_eq!(r.take_probes_at(t1), vec![0]);
        r.on_success(0);
        assert!(!r.is_quarantined(0));
        assert_eq!(r.pick_order_at(t1).len(), 3);
    }

    #[test]
    fn when_nothing_is_healthy_the_quarantine_is_ignored() {
        let r = ratings(3);
        let t0 = Instant::now();
        for i in 0..3 {
            trip(&r, i, t0);
        }
        assert_eq!(r.pick_order_at(t0).len(), 3);
        let _ = r.pick_at(t0);
    }

    #[test]
    fn soft_failures_never_quarantine() {
        let r = ratings(3);
        for _ in 0..100 {
            r.on_failure(0);
        }
        assert!(!r.is_quarantined(0));
        assert_eq!(r.pick_order().len(), 3);
    }

    #[test]
    fn disabled_quarantine_never_excludes() {
        let r = Ratings::new(3, RatingPolicy::default());
        for _ in 0..100 {
            assert_eq!(r.on_hard_failure(0), None);
        }
        assert!(!r.is_quarantined(0));
        assert_eq!(r.pick_order().len(), 3);
    }

    #[test]
    fn quarantine_works_with_the_sand_model_off() {
        let r = Ratings::try_with_quarantine(
            2,
            RatingPolicy {
                fail_penalty: 0.0,
                ..Default::default()
            },
            QuarantinePolicy::default(),
        )
        .unwrap();
        let t0 = Instant::now();
        trip(&r, 1, t0);
        assert_eq!(r.pick_order_at(t0), vec![0]);
        r.on_success(1);
        assert_eq!(r.pick_order_at(t0).len(), 2);
    }

    #[test]
    fn invalid_quarantine_policy_is_rejected() {
        let bad = QuarantinePolicy::default().with_initial(Duration::ZERO);
        assert!(matches!(
            Ratings::try_with_quarantine(2, RatingPolicy::default(), bad),
            Err(RatingError::InvalidPolicy(msg)) if msg.contains("initial")
        ));
    }

    // Finding E: a claim carries the slot's generation. An ordinary
    // request success resets the slot, renewed failures re-quarantine it,
    // a fresh probe claims it — and the old probe's late outcome must
    // then change nothing, while the fresh claim still applies.
    // Mutations: drop the generation comparison (the stale calls apply:
    // P1's success clears P2's quarantine / P1's failure re-trips) or
    // skip the generation bump in success() (the old claim stays valid).
    #[test]
    fn stale_probe_claims_change_nothing_after_reset_and_retrip() {
        let r = ratings(2);
        let t0 = Instant::now();
        trip(&r, 0, t0);
        let t1 = t0 + Duration::from_secs(31);
        let old = r.take_probe_claims_at(t1).pop().unwrap();
        // A normal (fail-open) request succeeds: the slot resets ...
        r.on_success(0);
        // ... and fresh hard failures quarantine it again.
        for _ in 0..3 {
            r.on_hard_failure_at(0, t1);
        }
        assert_eq!(r.health_at(t1)[0].trips, 1);
        let t2 = t1 + Duration::from_secs(31);
        let fresh = r.take_probe_claims_at(t2).pop().unwrap();
        assert_ne!(old, fresh, "the new lease must own a new generation");
        // The slot is leased to the fresh claim only.
        assert!(r.take_probe_claims_at(t2).is_empty());

        // P1's late success: stale — dropped, the new quarantine stands.
        assert!(!r.record_success_for(&old));
        // Re-quarantined at t1 for 30 s, so at t2 the slot is on probation
        // (leased to the fresh claim) and still counts as tripped.
        assert_eq!(r.health_at(t2)[0].state, UpstreamState::Probation);
        assert_eq!(r.health_at(t2)[0].trips, 1);
        // P1's late hard failure: stale too — dropped.
        assert_eq!(r.record_hard_failure_for(&old), None);
        assert_eq!(r.health_at(t2)[0].trips, 1);
        // P2's ownership is intact: its success applies.
        assert!(r.record_success_for(&fresh));
        assert_eq!(r.health_at(t2)[0].state, UpstreamState::Alive);
        assert_eq!(r.health_at(t2)[0].trips, 0);
    }

    // Finding E, direct path: a fresh claim's hard failure still
    // requarantines (doubled length), and soft failures never invalidate
    // a claim. Mutations: gating the claim path off entirely (returns
    // None) or bumping the generation on soft failures (claim stale).
    #[test]
    fn fresh_claim_failure_requarantines_and_soft_failures_do_not_invalidate() {
        let r = ratings(2);
        let t0 = Instant::now();
        trip(&r, 0, t0);
        let t1 = t0 + Duration::from_secs(31);
        let claim = r.take_probe_claims_at(t1).pop().unwrap();
        r.on_failure(0);
        r.on_failure(0);
        // Evaluated at the probe's own instant, like the rest of this table.
        assert_eq!(
            r.record_hard_failure_for_at(&claim, t1),
            Some(Duration::from_secs(60))
        );
    }

    // Finding H3, deterministic half: quarantining an already-tripped
    // upstream must be a no-op — one piece of evidence, one trip.
    // Mutation: unconditional trip_now (check dropped): the second
    // call returns Some and trips becomes 2.
    #[test]
    fn quarantine_now_unless_tripped_is_a_noop_for_a_tripped_upstream() {
        let r = ratings(2);
        let t0 = Instant::now();
        assert_eq!(
            r.quarantine_now_unless_tripped(0),
            Some(Duration::from_secs(30))
        );
        assert_eq!(r.quarantine_now_unless_tripped(0), None);
        assert_eq!(r.quarantine_now_unless_tripped(9), None);
        assert_eq!(r.health_at(t0)[0].trips, 1);
        assert_eq!(r.health_at(t0)[1].trips, 0);
    }

    // Finding H3, race half: with the check and the trip in ONE lock
    // acquisition, exactly one of many concurrent callers quarantines
    // and trips == 1. Mutation: splitting it back into is_quarantined +
    // quarantine_now (two acquisitions) lets several callers trip under
    // contention.
    #[test]
    fn concurrent_quarantine_trips_only_once() {
        let r = std::sync::Arc::new(ratings(1));
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(8));
        let mut handles = Vec::new();
        for _ in 0..8 {
            let r = std::sync::Arc::clone(&r);
            let barrier = std::sync::Arc::clone(&barrier);
            handles.push(std::thread::spawn(move || {
                barrier.wait();
                r.quarantine_now_unless_tripped(0)
            }));
        }
        let applied = handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .filter(|result| result.is_some())
            .count();
        assert_eq!(applied, 1, "exactly one caller does the quarantining");
        assert_eq!(r.health()[0].trips, 1);
    }
}
