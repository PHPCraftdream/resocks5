//! The per-upstream sand accumulator ([`Sand`]).

use std::time::Instant;

use crate::rating::policy::RatingPolicy;

/// Per-upstream exponential-decay "sand" accumulator.
///
/// Sand increases on failure and decays over time.  The current
/// *effective* level is computed lazily at query time so there is no
/// background timer.
#[derive(Debug)]
pub struct Sand {
    level: f64,
    last: Instant,
}

impl Sand {
    /// Create a fresh accumulator with zero sand.
    pub fn new(now: Instant) -> Self {
        Self {
            level: 0.0,
            last: now,
        }
    }

    /// Effective sand level at `now`, after exponential decay.
    pub fn level_at(&self, now: Instant, p: &RatingPolicy) -> f64 {
        let dt = now.saturating_duration_since(self.last).as_secs_f64();
        let decayed = self.level * (-dt / p.tau()).exp();
        if decayed < 1e-6 {
            0.0
        } else {
            decayed
        }
    }

    /// Record a failure: add `fail_penalty`, clamped to `sand_max`.
    pub fn observe_failure(&mut self, now: Instant, p: &RatingPolicy) {
        self.level = (self.level_at(now, p) + p.fail_penalty).min(p.sand_max);
        self.last = now;
    }

    /// Record a success: multiply current level by `success_factor`.
    pub fn observe_success(&mut self, now: Instant, p: &RatingPolicy) {
        self.level = self.level_at(now, p) * p.success_factor;
        self.last = now;
    }

    /// Weight in `[min_weight, 1.0]` derived from the current sand level.
    pub fn weight(&self, now: Instant, p: &RatingPolicy) -> f64 {
        (-p.k() * self.level_at(now, p)).exp()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn starts_at_zero_level_and_weight_one() {
        let now = Instant::now();
        let p = RatingPolicy::default();
        let s = Sand::new(now);
        assert_eq!(s.level_at(now, &p), 0.0);
        assert!((s.weight(now, &p) - 1.0).abs() < 1e-12);
    }

    #[test]
    fn decay_halves_at_half_life() {
        let t0 = Instant::now();
        let p = RatingPolicy::default();
        let mut s = Sand::new(t0);
        s.observe_failure(t0, &p);
        let peak = s.level_at(t0, &p);

        let t1 = t0 + Duration::from_secs_f64(p.half_life_sec);
        let level = s.level_at(t1, &p);
        let ratio = level / peak;
        assert!((ratio - 0.5).abs() < 0.01, "ratio = {ratio}, expected ~0.5");
    }

    #[test]
    fn decays_to_floor_zero() {
        let t0 = Instant::now();
        let p = RatingPolicy::default();
        let mut s = Sand::new(t0);
        s.observe_failure(t0, &p);

        let t1 = t0 + Duration::from_secs_f64(100.0 * p.half_life_sec);
        assert_eq!(s.level_at(t1, &p), 0.0);
    }

    #[test]
    fn clamps_at_sand_max() {
        let t0 = Instant::now();
        let p = RatingPolicy::default();
        let mut s = Sand::new(t0);
        for _ in 0..1000 {
            s.observe_failure(t0, &p);
        }
        assert_eq!(s.level_at(t0, &p), p.sand_max);
    }

    #[test]
    fn success_multiplies() {
        let t0 = Instant::now();
        let p = RatingPolicy::default();
        let mut s = Sand::new(t0);
        // Set a known level.
        s.observe_failure(t0, &p);
        s.observe_failure(t0, &p);
        let before = s.level_at(t0, &p);
        s.observe_success(t0, &p);
        let after = s.level_at(t0, &p);
        assert!(
            (after - before * p.success_factor).abs() < 1e-9,
            "after={after}, expected {}",
            before * p.success_factor
        );
    }

    #[test]
    fn weight_monotonic_in_level() {
        let t0 = Instant::now();
        let p = RatingPolicy::default();
        let mut s = Sand::new(t0);
        let w_before = s.weight(t0, &p);
        s.observe_failure(t0, &p);
        let w_after = s.weight(t0, &p);
        assert!(
            w_after < w_before,
            "w_after={w_after} >= w_before={w_before}"
        );
    }

    #[test]
    fn weight_at_sand_max_equals_min_weight() {
        let t0 = Instant::now();
        let p = RatingPolicy::default();
        let mut s = Sand::new(t0);
        for _ in 0..1000 {
            s.observe_failure(t0, &p);
        }
        let w = s.weight(t0, &p);
        assert!(
            (w - p.min_weight).abs() < 1e-9,
            "w={w}, expected {}",
            p.min_weight
        );
    }
}
