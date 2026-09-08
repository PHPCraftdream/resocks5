//! Sand-rating model: exponential-decay failure accumulators driving
//! weighted-random upstream selection.
//!
//! Each upstream has a [`Sand`] cell that grows on failure and halves every
//! `half_life_sec` of silence; selection weight is `exp(-k * level)`, so bad
//! upstreams are picked less often but never zero. [`Ratings`] is the
//! thread-safe integrator over a vector of cells. See `docs/ARCHITECTURE.md`
//! for the full maths and convergence argument.

pub mod policy;
pub mod rng;
pub mod sand;
pub mod select;

pub use policy::RatingPolicy;
pub use rng::SmallRng;
pub use sand::Sand;

use std::sync::Mutex;
use std::time::Instant;

struct Inner {
    cells: Vec<Sand>,
    rng: SmallRng,
}

/// Thread-safe weighted-random upstream selector driven by exponential-decay
/// sand accumulators.
pub struct Ratings {
    policy: RatingPolicy,
    inner: Mutex<Inner>,
}

impl Ratings {
    /// Create `n` fresh upstreams, all starting at weight 1.0.
    pub fn new(n: usize, policy: RatingPolicy) -> Self {
        let now = Instant::now();
        Self {
            policy,
            inner: Mutex::new(Inner {
                cells: (0..n).map(|_| Sand::new(now)).collect(),
                rng: SmallRng::from_os(),
            }),
        }
    }

    /// The policy these ratings were constructed with.
    pub fn policy(&self) -> &RatingPolicy {
        &self.policy
    }

    /// Number of upstreams in this set.
    pub fn len(&self) -> usize {
        self.inner.lock().unwrap().cells.len()
    }

    /// `true` if there are no upstreams.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Record a failure for upstream `i`.
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

    /// Record a success for upstream `i`.
    pub fn on_success(&self, i: usize) {
        if !self.policy.enabled() {
            return;
        }
        let mut inner = self.inner.lock().unwrap();
        if i < inner.cells.len() {
            let now = Instant::now();
            inner.cells[i].observe_success(now, &self.policy);
        }
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

    /// Pick one upstream index via weighted random selection.
    ///
    /// # Panics
    /// Panics if `len() == 0`.
    pub fn pick(&self) -> usize {
        let mut inner = self.inner.lock().unwrap();
        let now = Instant::now();
        let weights: Vec<f64> = inner
            .cells
            .iter()
            .map(|s| s.weight(now, &self.policy))
            .collect();
        assert!(!weights.is_empty(), "Ratings::pick called on empty set");
        select::weighted_index(&weights, &mut inner.rng)
    }

    /// Return a weighted permutation of all upstream indices.
    pub fn pick_order(&self) -> Vec<usize> {
        let keyed = {
            let mut inner = self.inner.lock().unwrap();
            let now = Instant::now();
            let Inner { cells, rng } = &mut *inner;
            select::weighted_keys(cells.iter().map(|s| s.weight(now, &self.policy)), rng)
        };
        // The O(n log n) sort does not hold the ratings lock.
        select::order_keys(keyed)
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
