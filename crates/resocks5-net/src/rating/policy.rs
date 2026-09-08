//! Tuning knobs for the sand-rating model ([`RatingPolicy`]).

use anyhow::anyhow;

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

    /// Validate the knobs are finite and inside the ranges the sand
    /// model's maths requires. Call this before building any rating
    /// consumer from config: invalid values do not fail immediately —
    /// they silently produce `inf`/`NaN` weights downstream (e.g.
    /// `sand_max = 0` makes `k()` infinite, so a fresh upstream's
    /// weight is `exp(-inf * 0)` = `NaN`). Derived quantities are checked
    /// too: `tau()`, `k()` and the boundary weights at sand level 0 (fresh) and
    /// `sand_max` (fully saturated) must all be finite — e.g. a subnormal
    /// `min_weight` passes every per-field check yet overflows
    /// `1.0 / min_weight`.
    pub fn validate(&self) -> anyhow::Result<()> {
        for (name, value) in [
            ("half_life_sec", self.half_life_sec),
            ("fail_penalty", self.fail_penalty),
            ("sand_max", self.sand_max),
            ("min_weight", self.min_weight),
            ("success_factor", self.success_factor),
        ] {
            if !value.is_finite() {
                return Err(anyhow!("rating policy: {name} must be finite, got {value}"));
            }
        }
        if self.half_life_sec <= 0.0 {
            return Err(anyhow!(
                "rating policy: half_life_sec must be > 0, got {}; it is the decay \
                 timescale (tau = half_life_sec / ln 2), and zero or negative values \
                 yield inf/NaN sand levels",
                self.half_life_sec
            ));
        }
        if !self.tau().is_finite() {
            return Err(anyhow!(
                "rating policy: half_life_sec / ln 2 must be finite"
            ));
        }
        if self.sand_max <= 0.0 {
            return Err(anyhow!(
                "rating policy: sand_max must be > 0, got {}; it is the denominator of \
                 k() = ln(1/min_weight) / sand_max, so 0 makes k() infinite and the \
                 weight of every fresh upstream undefined",
                self.sand_max
            ));
        }
        if self.min_weight <= 0.0 || self.min_weight > 1.0 {
            return Err(anyhow!(
                "rating policy: min_weight must be in (0, 1], got {}; k() takes \
                 ln(1/min_weight), so values <= 0 give NaN, and values > 1 make k() \
                 negative so a fully-saturated upstream would be boosted above weight 1",
                self.min_weight
            ));
        }
        if self.min_weight < f64::MIN_POSITIVE {
            return Err(anyhow!(
                "rating policy: min_weight must be >= f64::MIN_POSITIVE (2.225e-308, \
                 the smallest positive normal f64), got {}; smaller subnormal values can \
                 overflow 1/min_weight to infinity, which makes k() infinite and a fresh \
                 upstream's weight exp(-k * 0) undefined (NaN)",
                self.min_weight
            ));
        }
        if !(0.0..=1.0).contains(&self.success_factor) {
            return Err(anyhow!(
                "rating policy: success_factor must be in [0, 1], got {}; success \
                 multiplies the remaining sand by it, so < 0 produces negative sand and \
                 weight > 1, and > 1 makes success increase sand",
                self.success_factor
            ));
        }
        if self.fail_penalty < 0.0 {
            return Err(anyhow!(
                "rating policy: fail_penalty must be >= 0, got {}; it is the sand added \
                 per failure, and a negative value produces negative sand and weight > 1",
                self.fail_penalty
            ));
        }
        // Derived-value checks: the fields above are individually in
        // range, but the quantities the sand model computes from them
        // can still overflow. These mirror the exact expressions
        // `Sand::weight` evaluates (see sand.rs).
        let k = self.k();
        if !k.is_finite() {
            return Err(anyhow!(
                "rating policy: k() = ln(1/min_weight) / sand_max must be finite, got {}; \
                 min_weight = {} and sand_max = {} are individually in range but their \
                 combination overflows the division, and a non-finite k makes a fresh \
                 upstream's weight exp(-k * 0) undefined (NaN)",
                k,
                self.min_weight,
                self.sand_max
            ));
        }
        let fresh_weight = (-k * 0.0).exp();
        if !fresh_weight.is_finite() {
            return Err(anyhow!(
                "rating policy: a fresh upstream's weight exp(-k * 0) must be finite, \
                 got {}; k = {} is non-finite for this min_weight/sand_max combination",
                fresh_weight,
                k
            ));
        }
        let saturated_weight = (-k * self.sand_max).exp();
        if !saturated_weight.is_finite() {
            return Err(anyhow!(
                "rating policy: a fully-saturated upstream's weight exp(-k * sand_max) \
                 must be finite, got {}; k = {}, sand_max = {}",
                saturated_weight,
                k,
                self.sand_max
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_rejects_an_overflowing_decay_constant() {
        let p = RatingPolicy {
            half_life_sec: f64::MAX,
            ..Default::default()
        };
        assert!(p.validate().is_err());
    }

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

    #[test]
    fn validate_accepts_default_and_boundaries() {
        assert!(RatingPolicy::default().validate().is_ok());
        let p = RatingPolicy {
            min_weight: 1.0,
            ..Default::default()
        };
        assert!(
            p.validate().is_ok(),
            "min_weight=1 is degenerate (k=0, weight always 1) but defined"
        );
        for success_factor in [0.0, 0.5, 1.0] {
            let p = RatingPolicy {
                success_factor,
                ..Default::default()
            };
            assert!(p.validate().is_ok(), "success_factor={success_factor}");
        }
        let p = RatingPolicy {
            fail_penalty: 0.0,
            ..Default::default()
        };
        assert!(p.validate().is_ok(), "fail_penalty=0 disables the model");
    }

    #[test]
    fn validate_rejects_each_invalid_field() {
        let cases: Vec<(&str, RatingPolicy)> = vec![
            (
                "half_life_sec",
                RatingPolicy {
                    half_life_sec: 0.0,
                    ..Default::default()
                },
            ),
            (
                "half_life_sec",
                RatingPolicy {
                    half_life_sec: -1.0,
                    ..Default::default()
                },
            ),
            (
                "half_life_sec",
                RatingPolicy {
                    half_life_sec: f64::NAN,
                    ..Default::default()
                },
            ),
            (
                "half_life_sec",
                RatingPolicy {
                    half_life_sec: f64::INFINITY,
                    ..Default::default()
                },
            ),
            (
                "sand_max",
                RatingPolicy {
                    sand_max: 0.0,
                    ..Default::default()
                },
            ),
            (
                "sand_max",
                RatingPolicy {
                    sand_max: -2.0,
                    ..Default::default()
                },
            ),
            (
                "min_weight",
                RatingPolicy {
                    min_weight: 0.0,
                    ..Default::default()
                },
            ),
            (
                "min_weight",
                RatingPolicy {
                    min_weight: -0.5,
                    ..Default::default()
                },
            ),
            (
                "min_weight",
                RatingPolicy {
                    min_weight: 1.5,
                    ..Default::default()
                },
            ),
            (
                "min_weight",
                RatingPolicy {
                    min_weight: f64::NAN,
                    ..Default::default()
                },
            ),
            (
                "success_factor",
                RatingPolicy {
                    success_factor: -0.1,
                    ..Default::default()
                },
            ),
            (
                "success_factor",
                RatingPolicy {
                    success_factor: 1.5,
                    ..Default::default()
                },
            ),
            (
                "success_factor",
                RatingPolicy {
                    success_factor: f64::NAN,
                    ..Default::default()
                },
            ),
            (
                "fail_penalty",
                RatingPolicy {
                    fail_penalty: -1.0,
                    ..Default::default()
                },
            ),
        ];
        for (field, policy) in cases {
            let err = policy.validate().expect_err(field);
            assert!(
                err.to_string().contains(field),
                "error for {field} must name the field, got: {err}"
            );
        }
    }

    /// Premise for validating sand_max: with sand_max = 0 the weight
    /// mapping constant k() is not finite, so a fresh cell's weight is
    /// undefined exactly as the review describes.
    #[test]
    fn zero_sand_max_makes_k_non_finite() {
        let p = RatingPolicy {
            sand_max: 0.0,
            ..Default::default()
        };
        assert!(!p.k().is_finite());
        assert!(p.validate().is_err());
        let p = RatingPolicy {
            sand_max: 0.0,
            min_weight: 1.0,
            ..Default::default()
        };
        assert!(p.k().is_nan(), "0/0 must be NaN");
    }

    /// Premise for the derived checks: min_weight = 1e-310 passes every
    /// per-field check, but 1/min_weight overflows, so k() is infinite and
    /// a fresh cell's weight exp(-k * 0) is NaN, exactly as R2-20 describes.
    #[test]
    fn subnormal_min_weight_makes_fresh_weight_nan() {
        let p = RatingPolicy {
            min_weight: 1e-310,
            ..Default::default()
        };
        assert!(!p.k().is_finite());
        assert!(
            (-p.k() * 0.0).exp().is_nan(),
            "-inf * 0 must be NaN, so the fresh weight is undefined"
        );
    }

    #[test]
    fn validate_rejects_subnormal_min_weight() {
        for min_weight in [1e-310, f64::MIN_POSITIVE / 2.0] {
            let p = RatingPolicy {
                min_weight,
                ..Default::default()
            };
            let err = p.validate().expect_err("subnormal min_weight");
            let msg = err.to_string();
            assert!(
                msg.contains("min_weight") && msg.contains("subnormal"),
                "error must name min_weight and the overflow mechanism, got: {msg}"
            );
        }
    }

    /// Extreme-but-finite sand_max with an ordinary min_weight: every field
    /// passes its own range check, but ln(1/min_weight) / sand_max overflows.
    #[test]
    fn validate_rejects_min_sand_max_overflowing_k() {
        let p = RatingPolicy {
            sand_max: f64::from_bits(1), // smallest positive subnormal (~5e-324)
            ..Default::default()
        };
        assert!(!p.k().is_finite());
        let err = p.validate().expect_err("sand_max too small for finite k");
        let msg = err.to_string();
        assert!(
            msg.contains("sand_max") && msg.contains("k()"),
            "error must name sand_max and k(), got: {msg}"
        );
    }

    /// The named lower bound itself must validate: at min_weight =
    /// f64::MIN_POSITIVE, 1/min_weight <= 2^1022 < f64::MAX exactly, so k()
    /// and both boundary weights stay finite.
    #[test]
    fn validate_accepts_extreme_but_finite_boundary() {
        let p = RatingPolicy {
            min_weight: f64::MIN_POSITIVE,
            ..Default::default()
        };
        assert!(p.validate().is_ok());
        assert!(p.k().is_finite());
        let fresh = (-p.k() * 0.0).exp();
        assert!(fresh.is_finite(), "fresh weight must be finite");
        assert!((fresh - 1.0).abs() < 1e-12);
        let saturated = (-p.k() * p.sand_max).exp();
        assert!(
            saturated.is_finite() && saturated > 0.0,
            "saturated weight must be finite and positive, got {saturated}"
        );
    }
}
