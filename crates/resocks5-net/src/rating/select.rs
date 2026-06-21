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
/// tend to appear first (Efraimidis-Spirakis reservoir sampling).
pub fn weighted_order(weights: &[f64], rng: &mut SmallRng) -> Vec<usize> {
    let mut keyed: Vec<(usize, f64)> = weights
        .iter()
        .enumerate()
        .map(|(i, &w)| {
            let key = rng.next_f64().powf(1.0 / w.max(EPS));
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
}
