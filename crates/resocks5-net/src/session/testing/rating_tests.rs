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

#[cfg(all(test, feature = "rotator"))]
#[cfg(all(test, feature = "rotator"))]
fn quarantined_ratings(n: usize) -> Ratings {
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

#[cfg(all(test, feature = "rotator"))]
fn trip(r: &Ratings, i: usize, now: Instant) {
    for _ in 0..3 {
        r.on_hard_failure_at(i, now);
    }
}

/// Lazy snapshot must match full pick_order: prefixes 1 and 3
/// on fresh snapshots of the same seed and full drain — for n from 1 to 257,
/// with quarantine and in fail-open mode (all in quarantine).
#[cfg(all(test, feature = "rotator"))]
#[test]
fn lazy_snapshot_matches_pick_order_prefix_and_full() {
    let seed = 208u64;
    for n in [1usize, 8, 64, 257] {
        let expected = Ratings::with_rng_seed(
            n,
            RatingPolicy::default(),
            QuarantinePolicy::disabled(),
            seed,
        )
        .pick_order();
        // Prefix 1.
        let mut s1 = Ratings::with_rng_seed(
            n,
            RatingPolicy::default(),
            QuarantinePolicy::disabled(),
            seed,
        )
        .pick_order_lazy();
        assert_eq!(
            s1.next_index(),
            expected.first().copied(),
            "n {n}, без карантина, prefix 1"
        );
        // Prefix 3 on a fresh snapshot.
        let mut s3 = Ratings::with_rng_seed(
            n,
            RatingPolicy::default(),
            QuarantinePolicy::disabled(),
            seed,
        )
        .pick_order_lazy();
        let got3: Vec<usize> = (0..3).filter_map(|_| s3.next_index()).collect();
        assert_eq!(
            got3,
            expected[..3.min(expected.len())],
            "n {n}, без карантина, prefix 3"
        );
        // Full drain on a fresh snapshot.
        let full = Ratings::with_rng_seed(
            n,
            RatingPolicy::default(),
            QuarantinePolicy::disabled(),
            seed,
        )
        .pick_order_lazy()
        .into_indices();
        assert_eq!(full, expected, "n {n}, без карантина, full");

        // Same scenario with quarantine (nothing trips — eligible = all).
        let expected = quarantined_ratings_with_seed(n).pick_order();
        let full = quarantined_ratings_with_seed(n)
            .pick_order_lazy()
            .into_indices();
        assert_eq!(full, expected, "n {n}, с карантином, full");
        let mut sq = quarantined_ratings_with_seed(n).pick_order_lazy();
        assert_eq!(
            sq.next_index(),
            expected.first().copied(),
            "n {n}, с карантином, prefix 1"
        );
        let mut sq3 = quarantined_ratings_with_seed(n).pick_order_lazy();
        let got3: Vec<usize> = (0..3).filter_map(|_| sq3.next_index()).collect();
        assert_eq!(
            got3,
            expected[..3.min(expected.len())],
            "n {n}, с карантином, prefix 3"
        );
    }
    // Fail-open: all in quarantine — eligible = all indices. Two
    // identical seed instances: expected and snapshot cannot share the RNG.
    let t0 = Instant::now();
    let trip_all = |r: &Ratings| {
        for i in 0..4 {
            trip(r, i, t0);
        }
    };
    let r1 = quarantined_ratings_with_seed(4);
    trip_all(&r1);
    let expected = r1.pick_order_at(t0);
    let r2 = quarantined_ratings_with_seed(4);
    trip_all(&r2);
    let s = r2.pick_order_lazy_at(t0);
    assert_eq!(s.eligible_len(), 4);
    assert_eq!(s.into_indices(), expected, "fail-open full");
}

/// Eligibility is frozen at snapshot time: quarantine after the snapshot
/// does not change the drain, but changes a fresh full pick_order.
#[cfg(all(test, feature = "rotator"))]
#[test]
fn lazy_snapshot_keeps_eligibility_frozen_at_snapshot() {
    let r = quarantined_ratings(4);
    let s = r.pick_order_lazy();
    r.quarantine_now(2);
    let drained = s.into_indices();
    assert!(
        drained.contains(&2),
        "снапшот должен отдать индекс 2 на его снапшот-позиции"
    );
    let fresh = r.pick_order();
    assert!(
        !fresh.contains(&2),
        "свежий порядок уже без index 2: {fresh:?}"
    );
}

/// Snapshot consumes all N RNG values under lock at creation time:
/// partial consumption of the order does not change the RNG state.
#[cfg(all(test, feature = "rotator"))]
#[test]
fn lazy_snapshot_advances_rng_identically_to_full_pick_order() {
    let seed = 42u64;
    let a = Ratings::with_rng_seed(
        8,
        RatingPolicy::default(),
        QuarantinePolicy::disabled(),
        seed,
    );
    let b = Ratings::with_rng_seed(
        8,
        RatingPolicy::default(),
        QuarantinePolicy::disabled(),
        seed,
    );
    let _ = a.pick_order();
    let mut sa = b.pick_order_lazy();
    let _ = sa.next_index();
    drop(sa);
    let pa: Vec<usize> = (0..5).map(|_| a.pick()).collect();
    let pb: Vec<usize> = (0..5).map(|_| b.pick()).collect();
    assert_eq!(pa, pb, "последовательности pick() должны совпасть");
}
