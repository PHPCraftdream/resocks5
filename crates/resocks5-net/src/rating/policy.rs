/// Tunable knobs that control the exponential-decay sand model.
#[derive(Debug, Clone, Copy)]
pub struct RatingPolicy {
    /// Time (seconds) for sand level to decay by half.
    pub half_life_sec: f64,
    /// Sand added per failure observation. 0.0 disables the model (pure round-robin).
    pub fail_penalty: f64,
    /// Hard ceiling on accumulated sand.
    pub sand_max: f64,
    /// Weight of a fully-saturated upstream (`exp(-k * sand_max)`).
    pub min_weight: f64,
    /// Multiplicative factor applied to sand on success.
    pub success_factor: f64,
}

impl Default for RatingPolicy {
    fn default() -> Self {
        Self {
            half_life_sec: 30.0,
            fail_penalty: 1.0,
            sand_max: 8.0,
            min_weight: 0.05,
            success_factor: 0.5,
        }
    }
}

impl RatingPolicy {
    /// Returns `true` when the sand model is active (fail_penalty > 0).
    pub fn enabled(&self) -> bool {
        self.fail_penalty > 0.0
    }

    /// Exponential-decay time constant: `half_life / ln(2)`.
    pub fn tau(&self) -> f64 {
        self.half_life_sec / std::f64::consts::LN_2
    }

    /// Exponential weight-mapping constant chosen so that
    /// `exp(-k * sand_max) == min_weight`.
    pub fn k(&self) -> f64 {
        (1.0 / self.min_weight).ln() / self.sand_max
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_values_match_spec() {
        let p = RatingPolicy::default();
        assert_eq!(p.half_life_sec, 30.0);
        assert_eq!(p.fail_penalty, 1.0);
        assert_eq!(p.sand_max, 8.0);
        assert_eq!(p.min_weight, 0.05);
        assert_eq!(p.success_factor, 0.5);
    }

    #[test]
    fn enabled_is_false_when_penalty_zero() {
        let p = RatingPolicy {
            fail_penalty: 0.0,
            ..Default::default()
        };
        assert!(!p.enabled());
        assert!(RatingPolicy::default().enabled());
    }

    #[test]
    fn tau_matches_half_life() {
        let p = RatingPolicy::default();
        let expected = 30.0 / std::f64::consts::LN_2;
        assert!((p.tau() - expected).abs() < 1e-12);
    }

    #[test]
    fn k_makes_min_weight_at_sand_max() {
        let p = RatingPolicy::default();
        let w = (-p.k() * p.sand_max).exp();
        assert!(
            (w - p.min_weight).abs() < 1e-9,
            "exp(-k*sand_max) = {w}, expected {}",
            p.min_weight
        );
    }
}
