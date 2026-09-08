//! Weighted-random selection primitives: single index + full permutation.

use crate::rating::rng::SmallRng;

/// Small epsilon to avoid division by zero in `weighted_order`.
const EPS: f64 = 1e-18;

/// Return index `i` with probability `weights[i] / sum(weights)`.
///
/// Defensive: if total weight is zero (or `weights` is empty), returns 0.
pub fn weighted_index(weights: &[f64], rng: &mut SmallRng) -> usize {
    let total: f64 = weights.iter().sum();
    if total <= 0.0 || weights.is_empty() {
        return 0;
    }
    let mut dart = rng.next_f64() * total;
    for (i, &w) in weights.iter().enumerate() {
        dart -= w;
        if dart <= 0.0 {
            return i;
        }
    }
    weights.len() - 1
}

/// Return a permutation of `0..weights.len()` where higher-weight items
/// tend to appear first (Efraimidis–Spirakis weighted reservoir sampling).
///
/// The key is the textbook `u^(1/w)` computed in log space: since
/// `u^(1/w) == exp(ln(u)/w)` and `exp` is strictly increasing, ordering by
/// `ln(u)/w` descending is the identical ranking. The direct form must not
/// be used: `u.powf(1/w)` underflows to exactly `0.0` for tiny weights
/// (`0.25^1e6 == 0.0` for every `u < 1`), collapsing all small-weight
/// entries to one key and letting the stable sort fall back to input
/// order. `ln(u)/w` stays finite and distinct for any `w > 0`; a zero
/// draw gives `-inf`, which still sorts last (a zero draw got key `0.0`
/// under the old form too).
pub fn weighted_order(weights: &[f64], rng: &mut SmallRng) -> Vec<usize> {
    let mut keyed: Vec<(usize, f64)> = weights
        .iter()
        .enumerate()
        .map(|(i, &w)| {
            let key = rng.next_f64().ln() / w.max(EPS);
            (i, key)
        })
        .collect();
    keyed.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
    keyed.into_iter().map(|(i, _)| i).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn weighted_index_uniform_when_weights_equal() {
        let mut rng = SmallRng::from_seed(42);
        let weights = [1.0, 1.0, 1.0, 1.0];
        let n = 100_000;
        let mut counts = [0u32; 4];
        for _ in 0..n {
            counts[weighted_index(&weights, &mut rng)] += 1;
        }
        for (i, &c) in counts.iter().enumerate() {
            let frac = c as f64 / n as f64;
            assert!(
                (frac - 0.25).abs() < 0.01,
                "bucket {i}: {frac}, expected ~0.25"
            );
        }
    }

    #[test]
    fn weighted_index_respects_weights() {
        let mut rng = SmallRng::from_seed(42);
        let weights = [10.0, 1.0];
        let n = 10_000;
        let mut first = 0u32;
        for _ in 0..n {
            if weighted_index(&weights, &mut rng) == 0 {
                first += 1;
            }
        }
        let frac = first as f64 / n as f64;
        assert!(
            (0.89..=0.93).contains(&frac),
            "first-index fraction = {frac}, expected 0.89..0.93"
        );
    }

    #[test]
    fn weighted_index_never_picks_zero_weight() {
        let mut rng = SmallRng::from_seed(42);
        let weights = [0.0, 1.0, 1.0];
        for _ in 0..1_000 {
            assert_ne!(
                weighted_index(&weights, &mut rng),
                0,
                "picked zero-weight index"
            );
        }
    }

    #[test]
    fn weighted_order_is_permutation() {
        let mut rng = SmallRng::from_seed(42);
        let weights = [1.0, 2.0, 3.0, 4.0, 5.0];
        for _ in 0..100 {
            let order = weighted_order(&weights, &mut rng);
            assert_eq!(order.len(), weights.len());
            let mut sorted = order.clone();
            sorted.sort();
            assert_eq!(sorted, vec![0, 1, 2, 3, 4]);
        }
    }

    #[test]
    fn weighted_order_high_weight_tends_to_front() {
        let mut rng = SmallRng::from_seed(42);
        let weights = [10.0, 1.0, 1.0, 1.0];
        let n = 10_000;
        let mut first_count = 0u32;
        for _ in 0..n {
            let order = weighted_order(&weights, &mut rng);
            if order[0] == 0 {
                first_count += 1;
            }
        }
        let frac = first_count as f64 / n as f64;
        assert!(
            frac > 0.50,
            "index 0 first only {frac}*100% of the time, expected >50%"
        );
    }

    /// The old key `u.powf(1/w)` underflows to exactly 0.0 for tiny
    /// weights (0.25^1e6 == 0.0), so every small-weight entry tied at
    /// key 0.0 and the stable sort preserved input order. Equal tiny
    /// weights must instead be uniformly shuffled.
    #[test]
    fn weighted_order_equal_tiny_weights_are_uniformly_ordered() {
        let mut rng = SmallRng::from_seed(7);
        let weights = [1e-6, 1e-6, 1e-6, 1e-6];
        let n = 20_000;
        let mut first_counts = [0u32; 4];
        for _ in 0..n {
            let order = weighted_order(&weights, &mut rng);
            first_counts[order[0]] += 1;
        }
        for (i, &c) in first_counts.iter().enumerate() {
            let frac = c as f64 / n as f64;
            assert!(
                (frac - 0.25).abs() < 0.02,
                "tiny equal weights: index {i} was first in {frac} of trials, expected ~0.25"
            );
        }
    }

    /// Two 1e-6 entries among larger weights: their RELATIVE order must
    /// still be random (old code froze it to input order via the all-zero
    /// key tie + stable sort).
    #[test]
    fn weighted_order_tiny_weights_do_not_freeze_in_input_order() {
        let mut rng = SmallRng::from_seed(11);
        let weights = [1e-6, 1e-6, 1.0, 1.0];
        let n = 20_000;
        let mut zero_before_one = 0u32;
        for _ in 0..n {
            let order = weighted_order(&weights, &mut rng);
            let p0 = order.iter().position(|&i| i == 0).unwrap();
            let p1 = order.iter().position(|&i| i == 1).unwrap();
            if p0 < p1 {
                zero_before_one += 1;
            }
        }
        let frac = zero_before_one as f64 / n as f64;
        assert!(
            (0.4..0.6).contains(&frac),
            "relative order of the two 1e-6 entries settled on {frac} (expected ~0.5)"
        );
    }

    /// The log-space key is the same ranking as the textbook form:
    /// `exp(ln(u)/w)` equals `u^(1/w)` within f64 rounding, and `exp` is
    /// strictly increasing, so both induce identical orders.
    #[test]
    fn weighted_order_log_key_matches_powf_key_ranking() {
        let us = [0.01_f64, 0.05, 0.25, 0.5, 0.75, 0.9, 0.99];
        let ws = [0.5_f64, 1.0, 2.0, 4.0, 10.0];
        for &u in &us {
            let powf_keys: Vec<f64> = ws.iter().map(|&w| u.powf(1.0 / w)).collect();
            let log_keys: Vec<f64> = ws.iter().map(|&w| u.ln() / w).collect();
            let rank = |keys: &[f64]| {
                let mut v: Vec<usize> = (0..keys.len()).collect();
                v.sort_by(|&a, &b| keys[b].partial_cmp(&keys[a]).unwrap());
                v
            };
            assert_eq!(rank(&powf_keys), rank(&log_keys), "u={u}");
            for (&w, &k) in ws.iter().zip(&log_keys) {
                let back = k.exp();
                let old = u.powf(1.0 / w);
                assert!(
                    (back - old).abs() <= 1e-9 * old,
                    "u={u} w={w}: exp(ln(u)/w)={back} != u^(1/w)={old}"
                );
            }
        }
    }

    /// Pins the degeneracy that motivates the log-space key, and the
    /// edge behavior of the replacement.
    #[test]
    fn powf_key_underflow_premise_and_log_key_edges() {
        assert_eq!(0.25_f64.powf(1e6), 0.0);
        assert_eq!(0.75_f64.powf(1e6), 0.0);
        let k1 = 0.25_f64.ln() / 1e-6;
        let k2 = 0.75_f64.ln() / 1e-6;
        assert!(k1.is_finite() && k2.is_finite() && k1 < k2);
        // next_f64 can yield exactly 0.0: ln(0) = -inf sorts last, no NaN.
        assert_eq!(0.0_f64.ln() / 1e-6, f64::NEG_INFINITY);
    }
}
