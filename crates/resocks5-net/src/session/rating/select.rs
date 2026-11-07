//! Weighted-random selection primitives: single index + full permutation.

use crate::rating::rng::SmallRng;

/// Return index `i` with probability `weights[i] / sum(weights)`.
///
/// Weights are normalized by their maximum before summing: raw sums of
/// finite positive weights (e.g. `[f64::MAX, f64::MAX]`) overflow to
/// +inf, which made the old fallback deterministically return the last
/// index instead of a uniform draw.
///
/// Only finite positive weights are selectable; zero, negative, NaN and
/// infinite weights act as ineligible. Returns 0 when nothing is
/// eligible.
pub fn weighted_index(weights: &[f64], rng: &mut SmallRng) -> usize {
    let max = weights.iter().fold(0.0_f64, |m, &w| {
        if w.is_finite() && w > 0.0 {
            m.max(w)
        } else {
            m
        }
    });
    if max <= 0.0 {
        return 0;
    }
    let total: f64 = weights
        .iter()
        .filter(|&&w| w.is_finite() && w > 0.0)
        .map(|&w| w / max)
        .sum();
    let mut dart = rng.next_f64() * total;
    for (i, &w) in weights.iter().enumerate() {
        if w.is_finite() && w > 0.0 {
            dart -= w / max;
            if dart <= 0.0 {
                return i;
            }
        }
    }
    weights
        .iter()
        .rposition(|&w| w.is_finite() && w > 0.0)
        .unwrap_or(0)
}

/// Return a permutation of `0..weights.len()` where higher-weight items
/// tend to appear first (Efraimidis–Spirakis weighted reservoir sampling).
///
/// Sorting `ln(-ln(u)) - ln(w)` ascending is equivalent to sorting
/// `u^(1/w)` descending. The extra logarithm avoids underflow of the
/// power and overflow of `ln(u)/w`, without clamping tiny positive weights.
/// Zero draws and nonpositive or nonfinite weights sort last.
pub fn weighted_order(weights: &[f64], rng: &mut SmallRng) -> Vec<usize> {
    order_keys(weighted_keys(weights.iter().copied(), rng))
}

pub(super) fn weighted_keys(
    weights: impl IntoIterator<Item = f64>,
    rng: &mut SmallRng,
) -> Vec<(usize, f64)> {
    weights
        .into_iter()
        .enumerate()
        .map(|(i, w)| {
            #[cfg(all(test, feature = "test-instrumentation"))]
            crate::perf::operation(|c| c.weighted_keys += 1);
            let u = rng.next_f64();
            let key = if w > 0.0 && w.is_finite() {
                (-u.ln()).ln() - w.ln()
            } else {
                f64::INFINITY
            };
            (i, key)
        })
        .collect()
}

pub(super) fn order_keys(mut keyed: Vec<(usize, f64)>) -> Vec<usize> {
    keyed.sort_unstable_by(compare_keyed);
    keyed.into_iter().map(|(i, _)| i).collect()
}

/// Key comparator: total_cmp by key, then by index. Calls from both
/// paths (full-sort and lazy) are instrumented in `sort_comparisons`.
fn compare_keyed(a: &(usize, f64), b: &(usize, f64)) -> std::cmp::Ordering {
    #[cfg(all(test, feature = "test-instrumentation"))]
    crate::perf::operation(|c| c.sort_comparisons += 1);
    a.1.total_cmp(&b.1).then(a.0.cmp(&b.0))
}

/// Lazy cursor over the exact `order_keys` order of a ready key
/// snapshot. O(1) construction with no comparisons; each next element
/// grows the sorted prefix geometrically: select_nth_unstable_by picks
/// the next batch of ranks from the unprocessed pool, then
/// sort_unstable_by orders only that batch. When the remaining pool is
/// small relative to the step, the pool is fully sorted once — total
/// exhaustion stays O(N log N), no path is quadratic. All comparator
/// calls of both algorithms are instrumented in `sort_comparisons`, so
/// the counter reflects the new path's real comparisons, including
/// rebuilds. Available under the rotator feature (consumer:
/// rotator/chain).
#[cfg(feature = "rotator")]
pub(crate) struct LazyOrder {
    keyed: Vec<(usize, f64)>,
    sorted: usize,
    served: usize,
}

#[cfg(feature = "rotator")]
impl LazyOrder {
    /// O(1): no sorts or comparisons.
    pub(crate) fn from_keyed(keyed: Vec<(usize, f64)>) -> Self {
        Self {
            keyed,
            sorted: 0,
            served: 0,
        }
    }

    /// Next index in the exact `order_keys` order, or `None` once
    /// exhausted.
    pub(crate) fn next(&mut self) -> Option<usize> {
        if self.served == self.sorted && self.sorted < self.keyed.len() {
            self.extend();
        }
        if self.served == self.keyed.len() {
            return None;
        }
        let i = self.keyed[self.served].0;
        self.served += 1;
        Some(i)
    }

    /// Full drain (for tests/oracles).
    #[cfg(all(test, feature = "rotator"))]
    pub(crate) fn into_vec(mut self) -> Vec<usize> {
        std::iter::from_fn(|| self.next()).collect()
    }

    /// Grow the sorted prefix geometrically; invariant:
    /// `keyed[0..sorted]` is exactly the first `sorted` elements of the
    /// full order, and all of pool `keyed[sorted..]` >= the prefix.
    fn extend(&mut self) {
        let len = self.keyed.len();
        debug_assert_eq!(self.sorted, self.served);
        if self.sorted == len {
            return;
        }
        let step = self.sorted.max(1);
        if len - self.sorted <= step * 8 {
            self.keyed[self.sorted..].sort_unstable_by(compare_keyed);
            self.sorted = len;
            return;
        }
        let pool = &mut self.keyed[self.sorted..];
        pool.select_nth_unstable_by(step - 1, compare_keyed);
        pool[..step].sort_unstable_by(compare_keyed);
        self.sorted += step;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn weighted_order_is_invariant_under_a_common_weight_scale() {
        let weights = [1.0, 2.0, 3.0, 4.0];
        for seed in 0..16 {
            let expected = weighted_order(&weights, &mut SmallRng::from_seed(seed));
            for scale in [f64::MIN_POSITIVE, 1e-300, 1e-30, 1e30, 1e300] {
                let scaled = weights.map(|weight| weight * scale);
                assert_eq!(
                    weighted_order(&scaled, &mut SmallRng::from_seed(seed)),
                    expected,
                    "seed {seed}, scale {scale}"
                );
            }
        }
    }

    #[test]
    fn weighted_index_skips_zero_weight_when_the_random_draw_is_zero() {
        let seed = 0u64.wrapping_sub(0x9E3779B97F4A7C15);
        assert_eq!(SmallRng::from_seed(seed).next_f64(), 0.0);
        assert_eq!(
            weighted_index(&[0.0, 1.0], &mut SmallRng::from_seed(seed)),
            1
        );
    }

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

    #[test]
    fn weighted_order_log_key_matches_powf_key_ranking() {
        let ws = [0.5_f64, 1.0, 2.0, 4.0, 10.0];
        for seed in 0..16 {
            let mut reference_rng = SmallRng::from_seed(seed);
            let keys: Vec<_> = ws
                .iter()
                .map(|&w| reference_rng.next_f64().powf(1.0 / w))
                .collect();
            let mut expected: Vec<_> = (0..ws.len()).collect();
            expected.sort_by(|&a, &b| keys[b].total_cmp(&keys[a]));
            assert_eq!(
                weighted_order(&ws, &mut SmallRng::from_seed(seed)),
                expected,
                "seed {seed}"
            );
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

    #[test]
    fn weighted_index_uniform_between_two_max_f64_weights() {
        let mut rng = SmallRng::from_seed(42);
        let weights = [f64::MAX, f64::MAX];
        let n = 100_000;
        let mut counts = [0u32; 2];
        for _ in 0..n {
            counts[weighted_index(&weights, &mut rng)] += 1;
        }
        for (i, &c) in counts.iter().enumerate() {
            let frac = c as f64 / n as f64;
            assert!(
                (frac - 0.5).abs() < 0.01,
                "bucket {i}: {frac}, expected ~0.5"
            );
        }
    }

    #[test]
    fn weighted_index_scale_invariance_even_when_the_raw_sum_overflows() {
        let base = [1.0, 2.0, 3.0, 4.0];
        let expected = [0.1, 0.2, 0.3, 0.4];
        let n = 100_000;
        // At scale 2e307 every weight is still finite (largest 8e307 <
        // f64::MAX ≈ 1.798e308) but the RAW sum is 2e308 which overflows
        // to +inf — the pre-fix code was broken for exactly this input.
        for scale in [1.0, 1e-300, 2e307] {
            let weights = base.map(|w| w * scale);
            let mut rng = SmallRng::from_seed(42);
            let mut counts = [0u32; 4];
            for _ in 0..n {
                counts[weighted_index(&weights, &mut rng)] += 1;
            }
            for (i, (&c, &p)) in counts.iter().zip(expected.iter()).enumerate() {
                let frac = c as f64 / n as f64;
                assert!(
                    (frac - p).abs() < 0.01,
                    "scale {scale}, bucket {i}: {frac}, expected ~{p}"
                );
            }
        }
    }

    #[test]
    fn weighted_index_ignores_nonfinite_and_nonpositive_weights() {
        let mut rng = SmallRng::from_seed(42);
        let weights = [f64::NAN, -1.0, f64::INFINITY, 2.0, 0.0];
        for _ in 0..1_000 {
            assert_eq!(
                weighted_index(&weights, &mut rng),
                3,
                "picked an ineligible index"
            );
        }
        assert_eq!(weighted_index(&[f64::NAN], &mut rng), 0);
        assert_eq!(weighted_index(&[0.0, f64::NEG_INFINITY], &mut rng), 0);
        assert_eq!(weighted_index(&[], &mut rng), 0);
    }

    /// Матрица длины × паттерны весов × seed: ленивый курсор обязан
    /// выдавать побайтово тот же порядок, что full-sort `order_keys` —
    /// префиксно (1 и 3 на свежих курсорах) и при полном дренаже.
    #[cfg(all(test, feature = "rotator"))]
    #[test]
    fn lazy_order_matches_order_keys_exactly() {
        let pattern_sets: &[&[f64]] = &[
            &[1.0, 1.0, 1.0, 1.0, 1.0, 1.0],
            &[0.0, 1.0, 0.0, 1.0, 0.0, 1.0],
            &[1e-300, 1e300, f64::MAX, 1e-300, 1e300, f64::MAX],
            &[f64::NAN, -1.0, f64::INFINITY, f64::NEG_INFINITY, 1.0, 2.0],
            &[0.0, 5.0, 0.0, 5.0],
        ];
        for n in [1, 2, 7, 64, 257] {
            for pattern in pattern_sets {
                for seed in 0..16u64 {
                    let weights: Vec<f64> = (0..n).map(|i| pattern[i % pattern.len()]).collect();
                    let expected = order_keys(weighted_keys(
                        weights.iter().copied(),
                        &mut SmallRng::from_seed(seed),
                    ));
                    // Префикс 1.
                    let mut c1 = LazyOrder::from_keyed(weighted_keys(
                        weights.iter().copied(),
                        &mut SmallRng::from_seed(seed),
                    ));
                    assert_eq!(
                        c1.next().unwrap(),
                        expected[0],
                        "n {n}, seed {seed}, prefix 1"
                    );
                    // Префикс 3 на свежем курсоре.
                    let mut c3 = LazyOrder::from_keyed(weighted_keys(
                        weights.iter().copied(),
                        &mut SmallRng::from_seed(seed),
                    ));
                    let got3: Vec<usize> = (0..3).filter_map(|_| c3.next()).collect();
                    assert_eq!(
                        got3,
                        expected[..3.min(expected.len())],
                        "n {n}, seed {seed}, prefix 3"
                    );
                    // Полный дренаж на третьем свежем курсоре.
                    let full = LazyOrder::from_keyed(weighted_keys(
                        weights.iter().copied(),
                        &mut SmallRng::from_seed(seed),
                    ))
                    .into_vec();
                    assert_eq!(full, expected, "n {n}, seed {seed}, full");
                }
            }
        }
    }

    #[cfg(all(test, feature = "rotator"))]
    #[test]
    fn lazy_order_empty_is_exhausted() {
        let mut c = LazyOrder::from_keyed(vec![]);
        assert_eq!(c.next(), None);
        assert_eq!(c.next(), None);
        assert!(c.into_vec().is_empty());
    }

    /// Один курсор: частичный дренаж, затем полный — сумма префиксов
    /// равна полному порядку без повторов.
    #[cfg(all(test, feature = "rotator"))]
    #[test]
    fn lazy_order_serves_from_a_single_keyed_snapshot() {
        let weights = [1.0, 0.5, 2.0, 0.0, 1.5, 3.0, 0.25];
        for seed in 0..16u64 {
            let keyed = weighted_keys(weights, &mut SmallRng::from_seed(seed));
            let expected = order_keys(weighted_keys(weights, &mut SmallRng::from_seed(seed)));
            let mut cursor = LazyOrder::from_keyed(keyed);
            let mut got: Vec<usize> = Vec::new();
            for _ in 0..4 {
                if let Some(i) = cursor.next() {
                    got.push(i);
                }
            }
            assert_eq!(&expected[..4], &got[..], "seed {seed}, partial");
            while let Some(i) = cursor.next() {
                got.push(i);
            }
            let mut sorted = got.clone();
            sorted.sort();
            let n = weights.len();
            assert_eq!(sorted, (0..n).collect::<Vec<_>>(), "seed {seed}");
            assert_eq!(got, expected, "seed {seed}, full");
        }
    }
}
