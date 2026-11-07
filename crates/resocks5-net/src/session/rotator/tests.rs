use super::*;
use crate::types::ProxyProtocol;

fn make_proxy(host: &str, port: u16) -> ProxyConfig {
    ProxyConfig::socks5(host, port)
}

#[test]
fn distinct_gate_levels_have_distinct_rating_slots() {
    let base = make_proxy("host", 1000);
    let level_one = base.clone().with_gate_level(1);
    let level_two = base.clone().with_gate_level(2);
    let policy = RatingPolicy {
        fail_penalty: 2.0,
        sand_max: 8.0,
        min_weight: 0.01,
        ..Default::default()
    };
    let rotator = ProxyRotator::with_policy(
        vec![base.clone(), level_one.clone(), level_two.clone()],
        policy,
    );
    for _ in 0..8 {
        rotator.record_failure(&level_one);
    }
    let after_level_one = rotator.ratings.weights();
    assert!(after_level_one[1] < 1.0);
    assert!((after_level_one[0] - 1.0).abs() < 1e-9);
    assert!((after_level_one[2] - 1.0).abs() < 1e-9);
    for _ in 0..8 {
        rotator.record_failure(&level_two);
    }
    let after_level_two = rotator.ratings.weights();
    assert!(after_level_two[2] < 1.0);
    // Weights recover with time, so level-two failures may only leave slot 1 equal or higher.
    assert!(after_level_two[1] >= after_level_one[1] - 1e-9);
    assert!((after_level_two[0] - 1.0).abs() < 1e-9);
}

/// The `gate` link (how the upstream is reached) is not part of the identity:
/// a gate-composite config from the sticky cache lands on the plain
/// upstream's slot. Mutation: comparing or hashing `gate` makes `index_of`
/// miss the composite and the failure rates nothing.
#[test]
fn gate_composite_lands_on_the_plain_upstream_slot() {
    let plain = make_proxy("host", 1000);
    let composite = plain.clone().with_gate(make_proxy("outer", 2000));
    let rotator = ProxyRotator::new(vec![plain.clone(), make_proxy("other", 1001)]);
    assert_eq!(rotator.index_of(&composite), Some(0));
    assert_eq!(rotator.index_of(&composite), rotator.index_of(&plain));
    for _ in 0..8 {
        rotator.record_failure(&composite);
    }
    let weights = rotator.ratings.weights();
    assert!(
        weights[0] < 1.0,
        "the composite's failure rates the plain slot"
    );
    assert!((weights[1] - 1.0).abs() < 1e-9);
}

#[test]
fn rating_index_checks_identity_on_hash_collision() {
    let first = make_proxy("one", 1000);
    let second = make_proxy("two", 1001);
    let mut rotator = ProxyRotator::new(vec![first.clone(), second.clone()]);
    let hash = upstream_hash(&rotator.identity_hasher, &first);
    rotator.by_identity.insert(hash, vec![1, 0]);
    assert_eq!(rotator.index_of(&first), Some(0));
    rotator.by_identity.insert(hash, vec![1]);
    assert_eq!(rotator.index_of(&first), None);
}

/// Forced collisions for the index resolve: a hash match does not
/// prove identity — the path scans the bucket to the first field match
/// and returns its own slot. Target positions in the bucket: start, middle,
/// end; plus a miss on a non-empty bucket. Mutation: trusting the hash — a
/// foreign slot is returned; a scan without early exit — the counter exceeds the position.
#[test]
fn perf208_resolve_identity_scans_forced_collision_bucket() {
    let target = make_proxy("target", 1000);
    let other = make_proxy("other", 1001);
    let mut rotator = ProxyRotator::new(vec![target.clone(), other.clone()]);
    let hash = upstream_hash(&rotator.identity_hasher, &target);
    rotator.by_identity.insert(hash, vec![1, 0]);
    let resolved = rotator.resolve_identity(&target).unwrap();
    assert!(Arc::ptr_eq(resolved, &rotator.proxies[0]));
    // Bucket of foreign slots: no identity comparison confirms.
    rotator.by_identity.insert(hash, vec![1]);
    assert!(rotator.resolve_identity(&target).is_none());
    #[cfg(all(test, feature = "test-instrumentation"))]
    {
        rotator.by_identity.insert(hash, vec![1, 0]);
        let (_, counts) = crate::perf::measure(|| rotator.resolve_identity(&target));
        assert_eq!(counts.resolve_comparisons, 2);
        crate::perf::report("resolve/collision/bucket=2", counts);
    }

    // Position matrix on a three-slot bucket: the result is the own slot,
    // the counter equals the match position (1/2/3) or the bucket length for a miss.
    let extra = make_proxy("extra", 1002);
    let mut rotator = ProxyRotator::new(vec![target.clone(), other.clone(), extra.clone()]);
    let hash = upstream_hash(&rotator.identity_hasher, &target);
    rotator.by_identity.insert(hash, vec![0, 1, 2]);
    assert!(Arc::ptr_eq(
        rotator.resolve_identity(&target).unwrap(),
        &rotator.proxies[0]
    ));
    rotator.by_identity.insert(hash, vec![1, 0, 2]);
    assert!(Arc::ptr_eq(
        rotator.resolve_identity(&target).unwrap(),
        &rotator.proxies[0]
    ));
    rotator.by_identity.insert(hash, vec![1, 2, 0]);
    assert!(Arc::ptr_eq(
        rotator.resolve_identity(&target).unwrap(),
        &rotator.proxies[0]
    ));
    rotator.by_identity.insert(hash, vec![1, 2]);
    assert!(rotator.resolve_identity(&target).is_none());
    #[cfg(all(test, feature = "test-instrumentation"))]
    {
        // Counter: 1 (start), 2 (middle), 3 (end), 2 (miss = bucket length [1,2]).
        for (bucket, expected) in [
            (vec![0usize, 1, 2], 1u64),
            (vec![1, 0, 2], 2),
            (vec![1, 2, 0], 3),
            (vec![1, 2], 2),
        ] {
            rotator.by_identity.insert(hash, bucket);
            let (_, counts) = crate::perf::measure(|| rotator.resolve_identity(&target));
            assert_eq!(counts.resolve_comparisons, expected);
        }
    }
}

#[test]
fn duplicate_identity_collapses_onto_the_first_slot() {
    let proxy = make_proxy("one", 1000);
    let rotator = ProxyRotator::new(vec![proxy.clone(), proxy.clone(), proxy.clone()]);
    assert_eq!(rotator.len(), 1);
    assert_eq!(rotator.index_of(&proxy), Some(0));
    let hash = upstream_hash(&rotator.identity_hasher, &proxy);
    assert_eq!(rotator.by_identity[&hash], vec![0]);
}

#[test]
fn record_failure_lowers_pick_probability() {
    let proxies: Vec<ProxyConfig> = (0..4).map(|i| make_proxy("host", 1000 + i)).collect();
    let policy = RatingPolicy {
        fail_penalty: 2.0,
        sand_max: 8.0,
        min_weight: 0.01,
        ..Default::default()
    };
    let r = ProxyRotator::with_policy(proxies, policy);

    // Hammer proxy 0 with failures.
    for _ in 0..10 {
        r.record_failure(&make_proxy("host", 1000));
    }

    let n = 10_000;
    let mut first_is_zero = 0u32;
    for _ in 0..n {
        let order = r.pick_order();
        if order[0].port == 1000 {
            first_is_zero += 1;
        }
    }
    let frac = first_is_zero as f64 / n as f64;
    assert!(
        frac < 0.30,
        "proxy 0 appeared first {:.1}% of the time, expected <30%",
        frac * 100.0
    );
}

#[test]
fn record_success_restores_partially() {
    let proxies: Vec<ProxyConfig> = (0..4).map(|i| make_proxy("host", 1000 + i)).collect();
    let policy = RatingPolicy {
        fail_penalty: 2.0,
        sand_max: 8.0,
        min_weight: 0.01,
        ..Default::default()
    };
    let r = ProxyRotator::with_policy(proxies, policy);

    for _ in 0..10 {
        r.record_failure(&make_proxy("host", 1000));
    }
    for _ in 0..5 {
        r.record_success(&make_proxy("host", 1000));
    }

    let n = 10_000;
    let mut first_is_zero = 0u32;
    for _ in 0..n {
        let order = r.pick_order();
        if order[0].port == 1000 {
            first_is_zero += 1;
        }
    }
    let frac = first_is_zero as f64 / n as f64;
    assert!(
        frac > 0.15,
        "proxy 0 appeared first {:.1}% of the time, expected >15%",
        frac * 100.0
    );
}

#[test]
fn record_unknown_proxy_is_noop() {
    let proxies: Vec<ProxyConfig> = (0..4).map(|i| make_proxy("host", 1000 + i)).collect();
    let r = ProxyRotator::with_policy(proxies, RatingPolicy::default());

    let weights_before = r.ratings.weights();
    r.record_failure(&make_proxy("unknown", 9999));
    let weights_after = r.ratings.weights();

    for (i, (a, b)) in weights_before.iter().zip(weights_after.iter()).enumerate() {
        assert!(
            (a - b).abs() < 1e-9,
            "weight[{}] changed from {} to {}",
            i,
            a,
            b
        );
    }
}

#[test]
fn pick_order_returns_all_proxies() {
    let proxies: Vec<ProxyConfig> = (0..5).map(|i| make_proxy("host", 1000 + i)).collect();
    let r = ProxyRotator::with_policy(proxies, RatingPolicy::default());
    let order = r.pick_order();
    assert_eq!(order.len(), 5);

    let mut ports: Vec<u16> = order.iter().map(|p| p.port).collect();
    ports.sort();
    assert_eq!(ports, vec![1000, 1001, 1002, 1003, 1004]);
}

#[test]
fn sticky_link_get_roundtrip() {
    let proxies = vec![make_proxy("h", 1000), make_proxy("h", 1001)];
    let r = ProxyRotator::with_cache_limits(
        proxies,
        RatingPolicy::default(),
        8,
        Duration::from_secs(600),
    );
    let a = Arc::new(make_proxy("h", 1000));
    r.link_proxy("target", a.clone());
    assert_eq!(r.get_linked("target").map(|p| p.port), Some(1000));
    assert!(Arc::ptr_eq(&r.get_linked("target").unwrap(), &a));
    r.unlink_proxy("target");
    assert!(r.get_linked("target").is_none());
}

#[test]
fn sticky_relink_replaces_entry() {
    let proxies = vec![make_proxy("h", 1000), make_proxy("h", 1001)];
    let r = ProxyRotator::with_cache_limits(
        proxies,
        RatingPolicy::default(),
        8,
        Duration::from_secs(600),
    );
    r.link_proxy("target", Arc::new(make_proxy("h", 1000)));
    r.link_proxy("target", Arc::new(make_proxy("h", 1001)));
    assert_eq!(r.get_linked("target").map(|p| p.port), Some(1001));
}

#[test]
fn bounded_sequential_unique_targets() {
    let proxies = vec![make_proxy("h", 1000), make_proxy("h", 1001)];
    let r = ProxyRotator::with_cache_limits(
        proxies,
        RatingPolicy::default(),
        8,
        Duration::from_secs(600),
    );
    let total = 2000;
    for i in 0..total {
        r.link_proxy(format!("t{i}"), Arc::new(make_proxy("h", 1000)));
        assert!(r.sticky.lock().unwrap().map.len() <= 8);
    }
    // Insertion order == recency order: the last 8 linked addresses
    // must be present, the 9th-most-recent must be gone.
    for i in (total - 8)..total {
        assert!(
            r.get_linked(&format!("t{i}")).is_some(),
            "recent target t{i} missing"
        );
    }
    assert!(r.get_linked(&format!("t{}", total - 9)).is_none());
}

#[test]
fn bounded_concurrent_hammer_stays_within_cap() {
    let proxies = vec![make_proxy("h", 1000), make_proxy("h", 1001)];
    let r = Arc::new(ProxyRotator::with_cache_limits(
        proxies,
        RatingPolicy::default(),
        8,
        Duration::from_secs(6000),
    ));
    std::thread::scope(|s| {
        for t in 0..8 {
            let r = &r;
            s.spawn(move || {
                for i in 0u32..250 {
                    let addr = format!("t{t}-{i}");
                    r.link_proxy(addr.clone(), Arc::new(make_proxy("h", 1000)));
                    assert!(r.sticky.lock().unwrap().map.len() <= 8);
                    if i % 10 == 0 {
                        let probe = format!("t{t}-{}", i / 2);
                        let _ = r.get_linked(&probe);
                        r.unlink_proxy(&format!("t{t}-{}", i.saturating_sub(1)));
                    }
                }
            });
        }
    });
    assert!(r.sticky.lock().unwrap().map.len() <= 8);
    r.link_proxy("sentinel", Arc::new(make_proxy("h", 1001)));
    assert_eq!(r.get_linked("sentinel").map(|p| p.port), Some(1001));
}

#[test]
fn lru_touch_prevents_eviction() {
    let proxies = vec![make_proxy("h", 1000)];
    let r = ProxyRotator::with_cache_limits(
        proxies,
        RatingPolicy::default(),
        2,
        Duration::from_secs(600),
    );
    r.link_proxy("A", Arc::new(make_proxy("h", 1000)));
    r.link_proxy("B", Arc::new(make_proxy("h", 1001)));
    assert_eq!(r.get_linked("A").map(|p| p.port), Some(1000)); // touch
    r.link_proxy("C", Arc::new(make_proxy("h", 1002)));
    assert!(r.get_linked("B").is_none(), "B should be LRU-evicted");
    assert!(r.get_linked("A").is_some());
    assert_eq!(r.get_linked("C").map(|p| p.port), Some(1002));
}

#[test]
fn ttl_expires_entries() {
    let mut cache = StickyCache::new(8, Duration::from_secs(10));
    let t0 = Instant::now();
    cache.insert("a", Arc::new(make_proxy("h", 1000)), t0);
    assert!(cache.get("a", t0 + Duration::from_secs(5)).is_some());
    assert!(cache.get("a", t0 + Duration::from_secs(10)).is_none());
    assert!(cache.map.is_empty());
}

#[test]
fn sticky_metadata_stays_bounded_behind_a_cold_entry() {
    let mut cache = StickyCache::new(2, Duration::from_secs(60));
    let t0 = Instant::now();
    let proxy = Arc::new(make_proxy("h", 1000));
    cache.insert("cold", proxy.clone(), t0);
    cache.insert("hot", proxy, t0);
    for second in 1..=8 {
        assert!(cache.get("hot", t0 + Duration::from_secs(second)).is_some());
    }
    let metadata_entries = cache.recency.len() + cache.expiry.len();
    assert!(
        metadata_entries <= 2 * cache.max_entries,
        "two cached targets retained {metadata_entries} eviction records"
    );
}

#[test]
fn sticky_expiry_takes_precedence_over_recency() {
    let mut cache = StickyCache::new(2, Duration::from_secs(10));
    let t0 = Instant::now();
    cache.insert("expired", Arc::new(make_proxy("h", 1000)), t0);
    cache.insert(
        "live",
        Arc::new(make_proxy("h", 1001)),
        t0 + Duration::from_secs(5),
    );
    assert!(cache.get("expired", t0 + Duration::from_secs(9)).is_some());
    let now = t0 + Duration::from_secs(11);
    cache.insert("new", Arc::new(make_proxy("h", 1002)), now);
    assert_eq!(cache.get("live", now).map(|p| p.port), Some(1001));
    assert_eq!(cache.get("new", now).map(|p| p.port), Some(1002));
    assert!(cache.get("expired", now).is_none());
}

#[test]
fn sticky_replacement_refreshes_expiry_and_removal_releases_metadata() {
    let mut cache = StickyCache::new(2, Duration::from_secs(10));
    let t0 = Instant::now();
    cache.insert("A", Arc::new(make_proxy("h", 1000)), t0);
    cache.insert(
        "B",
        Arc::new(make_proxy("h", 1001)),
        t0 + Duration::from_secs(1),
    );
    cache.insert(
        "A",
        Arc::new(make_proxy("h", 1002)),
        t0 + Duration::from_secs(8),
    );
    assert!(cache.get("B", t0 + Duration::from_secs(9)).is_some());
    let now = t0 + Duration::from_secs(11);
    cache.insert("C", Arc::new(make_proxy("h", 1003)), now);
    assert_eq!(cache.get("A", now).map(|p| p.port), Some(1002));
    assert!(cache.get("B", now).is_none());
    cache.remove("A");
    cache.remove("C");
    assert!(cache.map.is_empty());
    assert!(cache.recency.is_empty());
    assert!(cache.expiry.is_empty());
}

#[test]
fn sticky_recency_orders_operations_with_equal_timestamps() {
    let mut cache = StickyCache::new(2, Duration::from_secs(10));
    let now = Instant::now();
    let proxy = Arc::new(make_proxy("h", 1000));
    cache.insert("A", proxy.clone(), now);
    cache.insert("B", proxy.clone(), now);
    assert!(cache.get("A", now).is_some());
    cache.insert("C", proxy, now);
    assert!(cache.get("A", now).is_some());
    assert!(cache.get("C", now).is_some());
    assert!(cache.get("B", now).is_none());
}

#[test]
fn ttl_purge_frees_room_without_evicting_live_entries() {
    let mut cache = StickyCache::new(2, Duration::from_secs(10));
    let t0 = Instant::now();
    cache.insert("A", Arc::new(make_proxy("h", 1000)), t0);
    cache.insert("B", Arc::new(make_proxy("h", 1001)), t0);
    let t1 = t0 + Duration::from_secs(11);
    cache.insert("C", Arc::new(make_proxy("h", 1002)), t1);
    cache.insert("D", Arc::new(make_proxy("h", 1003)), t1);
    assert_eq!(cache.get("C", t1).map(|p| p.port), Some(1002));
    assert_eq!(cache.get("D", t1).map(|p| p.port), Some(1003));
    assert_eq!(cache.map.len(), 2);
}

#[test]
fn cap_zero_disables_cache() {
    let proxies = vec![make_proxy("h", 1000)];
    let r = ProxyRotator::with_cache_limits(
        proxies,
        RatingPolicy::default(),
        0,
        Duration::from_secs(600),
    );
    r.link_proxy("a", Arc::new(make_proxy("h", 1000)));
    assert!(r.get_linked("a").is_none());
    assert_eq!(r.sticky.lock().unwrap().map.len(), 0);
}

#[test]
fn same_endpoint_different_accounts_rate_independently() {
    let mut alice = make_proxy("host", 1000);
    alice.user = Some("alice".to_string());
    alice.password = Some("pw-a".to_string());
    let mut bob = make_proxy("host", 1000);
    bob.user = Some("bob".to_string());
    bob.password = Some("pw-b".to_string());
    let policy = RatingPolicy {
        fail_penalty: 2.0,
        sand_max: 8.0,
        min_weight: 0.01,
        ..Default::default()
    };
    let r = ProxyRotator::with_policy(vec![alice.clone(), bob.clone()], policy);

    for _ in 0..10 {
        r.record_failure(&alice);
    }
    let w = r.ratings.weights();
    assert!(w[0] < 1.0, "alice's slot must be penalized, got {}", w[0]);
    assert!(
        (w[1] - 1.0).abs() < 1e-9,
        "bob's slot must be untouched by alice's failures, got {}",
        w[1]
    );
}

#[test]
fn same_endpoint_different_protocols_rate_independently() {
    let socks = make_proxy("host", 1000);
    let mut http = make_proxy("host", 1000);
    http.protocol = ProxyProtocol::Http;
    let policy = RatingPolicy {
        fail_penalty: 2.0,
        sand_max: 8.0,
        min_weight: 0.01,
        ..Default::default()
    };
    let r = ProxyRotator::with_policy(vec![socks.clone(), http.clone()], policy);

    for _ in 0..10 {
        r.record_failure(&http);
    }
    let w = r.ratings.weights();
    assert!(w[1] < 1.0, "http slot must be penalized, got {}", w[1]);
    assert!(
        (w[0] - 1.0).abs() < 1e-9,
        "socks slot must be untouched by http failures, got {}",
        w[0]
    );
}

#[test]
fn gate_composite_maps_to_original_rating_slot() {
    let inner = make_proxy("host", 1000);
    let other = make_proxy("host", 1001);
    let gate = make_proxy("gatehost", 999).with_gate_level(1);
    let mut composite = inner.clone();
    composite.gate = Some(Arc::new(gate));
    let policy = RatingPolicy {
        fail_penalty: 2.0,
        sand_max: 8.0,
        min_weight: 0.01,
        ..Default::default()
    };
    let r = ProxyRotator::with_policy(vec![inner.clone(), other.clone()], policy);

    // The composite is a fresh allocation with `.gate` set; rating
    // it must still land on the original inner entry's slot.
    for _ in 0..10 {
        r.record_failure(&composite);
    }
    let w = r.ratings.weights();
    assert!(
        w[0] < 1.0,
        "composite failure must penalize the original inner slot, got {}",
        w[0]
    );
    assert!(
        (w[1] - 1.0).abs() < 1e-9,
        "unrelated upstream must be untouched, got {}",
        w[1]
    );
}

/// Lazy candidates must match the full pick_order: prefixes 1 and 3
/// on fresh snapshots of the same seed, and a full drain.
#[test]
fn lazy_candidates_match_pick_order_exactly() {
    fn fresh() -> std::sync::Arc<ProxyRotator> {
        std::sync::Arc::new(
            ProxyRotator::with_rng_seed(
                (0..40)
                    .map(|i| make_proxy(&format!("host{i}"), 1000 + i as u16))
                    .collect(),
                RatingPolicy::default(),
                QuarantinePolicy::disabled(),
                DEFAULT_STICKY_CACHE_MAX_ENTRIES,
                DEFAULT_STICKY_CACHE_TTL,
                208,
            )
            .expect("валидные параметры в тесте"),
        )
    }
    let addr = |p: &Arc<ProxyConfig>| (p.host.clone(), p.port);
    let expected: Vec<_> = fresh().pick_order().iter().map(&addr).collect();
    // Prefix 1.
    let mut c1 = fresh().pick_order_lazy();
    assert_eq!(c1.next_proxy().map(|p| addr(&p)).as_ref(), expected.first());
    // Prefix 3 on a fresh snapshot.
    let mut c3 = fresh().pick_order_lazy();
    let got3: Vec<_> = (0..3)
        .filter_map(|_| c3.next_proxy())
        .map(|p| addr(&p))
        .collect();
    assert_eq!(got3, expected[..3], "prefix 3");
    // Full drain on a fresh snapshot.
    let full: Vec<_> = fresh()
        .pick_order_lazy()
        .into_proxies()
        .iter()
        .map(addr)
        .collect();
    assert_eq!(full, expected, "full");
    // Eligible length = full order length.
    let c = fresh().pick_order_lazy();
    assert_eq!(c.eligible().len(), expected.len());
}

/// Replacing an entry keeps its key allocation: the map, the recency set, the
/// expiry set and this test hold the one `Arc<str>`. Mutation: building a new
/// key on every insert breaks `ptr_eq` and leaves the old key alive in the
/// sets until it is removed.
#[test]
fn sticky_replacement_reuses_the_key_allocation() {
    let mut cache = StickyCache::new(4, Duration::from_secs(10));
    let t0 = Instant::now();
    cache.insert("A", Arc::new(make_proxy("h", 1000)), t0);
    let first = Arc::clone(cache.map.get_key_value("A").unwrap().0);
    assert_eq!(Arc::strong_count(&first), 4);
    cache.insert(
        "A",
        Arc::new(make_proxy("h", 1001)),
        t0 + Duration::from_secs(1),
    );
    let second = cache.map.get_key_value("A").unwrap().0;
    assert!(Arc::ptr_eq(&first, second));
    assert_eq!(Arc::strong_count(&first), 4);
    assert_eq!(cache.map.len(), 1);
    assert_eq!(cache.recency.len(), 1);
    assert_eq!(cache.expiry.len(), 1);
    assert_eq!(
        cache.get("A", t0 + Duration::from_secs(2)).map(|p| p.port),
        Some(1001)
    );
}

/// A borrowed address is copied once, for a new entry only, and the stored key
/// reads back equal to it.
#[test]
fn sticky_insert_from_a_borrowed_address_stores_an_equal_key() {
    let mut cache = StickyCache::new(4, Duration::from_secs(10));
    let t0 = Instant::now();
    let address = String::from("example.com:443");
    cache.insert(address.as_str(), Arc::new(make_proxy("h", 1000)), t0);
    drop(address);
    let (key, _) = cache.map.get_key_value("example.com:443").unwrap();
    assert_eq!(&**key, "example.com:443");
    assert_eq!(cache.get("example.com:443", t0).map(|p| p.port), Some(1000));
}

/// Eviction still picks the least recently used entry when keys arrive as
/// borrowed addresses.
#[test]
fn sticky_borrowed_inserts_evict_the_least_recently_used_entry() {
    let mut cache = StickyCache::new(2, Duration::from_secs(60));
    let t0 = Instant::now();
    cache.insert("A", Arc::new(make_proxy("h", 1000)), t0);
    cache.insert(
        "B",
        Arc::new(make_proxy("h", 1001)),
        t0 + Duration::from_secs(1),
    );
    cache.insert(
        "C",
        Arc::new(make_proxy("h", 1002)),
        t0 + Duration::from_secs(2),
    );
    let now = t0 + Duration::from_secs(3);
    assert!(cache.get("A", now).is_none());
    assert!(cache.get("B", now).is_some());
    assert!(cache.get("C", now).is_some());
    assert_eq!(cache.recency.len(), 2);
    assert_eq!(cache.expiry.len(), 2);
}

/// `link_proxy` takes `String`, `&String` and `&str` alike and keeps one entry
/// per address.
#[test]
fn link_proxy_accepts_owned_and_borrowed_addresses() {
    let rotator = ProxyRotator::new(vec![make_proxy("h", 1000)]);
    let owned = String::from("owned.example:443");
    rotator.link_proxy(owned.clone(), Arc::new(make_proxy("h", 1001)));
    rotator.link_proxy("borrowed.example:443", Arc::new(make_proxy("h", 1002)));
    rotator.link_proxy(&owned, Arc::new(make_proxy("h", 1003)));
    assert_eq!(
        rotator.get_linked("owned.example:443").map(|p| p.port),
        Some(1003)
    );
    assert_eq!(
        rotator.get_linked("borrowed.example:443").map(|p| p.port),
        Some(1002)
    );
    assert_eq!(rotator.sticky.lock().unwrap().map.len(), 2);
}

/// `pick_iter` must equal `pick_order` element-wise (same slots, same order) for identically built,
/// identically seeded rotators: full drain (same `Arc`s), prefixes
/// `take(1)`/`take(3)`, and exhaustion keeps returning `None`. Mutation:
/// a different snapshot (eligibility, RNG, quarantine) or a different
/// key comparison breaks the element-wise equality.
#[test]
fn pick_iter_matches_pick_order_across_seeds_and_sizes() {
    fn make_rotator(n: usize, seed: u64) -> std::sync::Arc<ProxyRotator> {
        std::sync::Arc::new(
            ProxyRotator::with_rng_seed(
                (0..n)
                    .map(|i| make_proxy(&format!("host{i}"), 1000 + i as u16))
                    .collect(),
                RatingPolicy::default(),
                QuarantinePolicy::disabled(),
                DEFAULT_STICKY_CACHE_MAX_ENTRIES,
                DEFAULT_STICKY_CACHE_TTL,
                seed,
            )
            .expect("valid parameters in test"),
        )
    }
    for n in [1usize, 2, 7, 64] {
        for seed in [0u64, 1, 7, 208] {
            let expected = make_rotator(n, seed).pick_order();
            // Each rotator owns its own proxies, so identity is compared by
            // host and port (unique per slot here), not by `Arc::ptr_eq`.
            let same = |a: &ProxyConfig, b: &ProxyConfig| a.host == b.host && a.port == b.port;
            // Full drain: the same slots in the same order as pick_order.
            let drained: Vec<_> = make_rotator(n, seed).pick_iter().collect();
            assert_eq!(drained.len(), expected.len(), "n {n}, seed {seed}");
            for (got, want) in drained.iter().zip(&expected) {
                assert!(same(got, want), "n {n}, seed {seed}");
            }
            // Prefixes 1 and 3 on fresh snapshots.
            for take in [1usize, 3] {
                let prefix: Vec<_> = make_rotator(n, seed).pick_iter().take(take).collect();
                assert_eq!(prefix.len(), take.min(n), "n {n}, seed {seed}, take {take}");
                for (got, want) in prefix.iter().zip(&expected) {
                    assert!(same(got, want), "n {n}, seed {seed}, take {take}");
                }
            }
            // Exhaustion keeps returning None.
            let mut exhausted = make_rotator(n, seed).pick_iter();
            for _ in 0..n {
                assert!(exhausted.next().is_some(), "n {n}, seed {seed}");
            }
            assert!(exhausted.next().is_none(), "n {n}, seed {seed}");
            assert!(exhausted.next().is_none(), "fused after exhaustion");
        }
    }
}

/// The iterator may be moved across threads or await points by
/// consumers: pin `Send` at compile time.
#[test]
fn pick_order_is_send() {
    fn assert_send<T: Send>() {}
    assert_send::<PickOrder>();
}

/// A quarantined upstream is absent from the lazy order exactly as from
/// `pick_order`, while a healthy upstream exists.
#[test]
fn pick_iter_skips_a_quarantined_upstream_like_pick_order() {
    fn make_rotator() -> std::sync::Arc<ProxyRotator> {
        std::sync::Arc::new(
            ProxyRotator::with_rng_seed(
                vec![
                    make_proxy("a", 1080),
                    make_proxy("b", 1081),
                    make_proxy("c", 1082),
                ],
                RatingPolicy::default(),
                QuarantinePolicy::default().with_threshold(3),
                DEFAULT_STICKY_CACHE_MAX_ENTRIES,
                DEFAULT_STICKY_CACHE_TTL,
                208,
            )
            .expect("valid parameters in test"),
        )
    }
    let rotator = make_rotator();
    let dead = make_proxy("a", 1080);
    let mut tripped = None;
    for _ in 0..3 {
        tripped = rotator.record_hard_failure(&dead);
    }
    assert!(tripped.is_some(), "the quarantine must trip");
    let eager = rotator.pick_order();
    assert_eq!(eager.len(), 2);
    assert!(eager.iter().all(|p| p.host != "a"));
    let lazy: Vec<_> = rotator.pick_iter().collect();
    assert_eq!(lazy.len(), 2);
    assert!(lazy.iter().all(|p| p.host != "a"));
    // A success lifts the quarantine on both paths.
    rotator.record_success(&dead);
    assert_eq!(rotator.pick_iter().count(), 3);
}

/// Consumption-proportional work behind the public iterator: taking one
/// element of an N=256 snapshot performs strictly fewer
/// `sort_comparisons` than a full `pick_order`, while key generation
/// stays N on both paths (same snapshot). Mutation: sorting the whole
/// snapshot eagerly in `pick_iter` raises the one-element cost to the
/// full sort.
#[cfg(all(test, feature = "test-instrumentation"))]
#[test]
fn perf208_pick_iter_one_element_costs_less_than_full_pick_order() {
    fn make_rotator(seed: u64) -> std::sync::Arc<ProxyRotator> {
        std::sync::Arc::new(
            ProxyRotator::with_rng_seed(
                (0..256usize)
                    .map(|i| make_proxy(&format!("host{i}"), 1000 + i as u16))
                    .collect(),
                RatingPolicy::default(),
                QuarantinePolicy::disabled(),
                DEFAULT_STICKY_CACHE_MAX_ENTRIES,
                DEFAULT_STICKY_CACHE_TTL,
                seed,
            )
            .expect("valid parameters in test"),
        )
    }
    // Rebuilding reseeds the RNG, so identical seeds produce identical
    // keys and the counters are deterministic.
    let run_first = |seed| {
        crate::perf::measure(move || {
            let mut iter = make_rotator(seed).pick_iter();
            std::hint::black_box(iter.next());
            std::hint::black_box(&iter);
        })
    };
    let (_, lazy) = run_first(208u64);
    let (_, repeated) = run_first(208u64);
    assert_eq!(lazy, repeated, "same seed must reproduce the same counters");
    let (_, full) = crate::perf::measure(|| make_rotator(208).pick_order());
    // Same snapshot: all N weighted keys on both paths.
    assert_eq!(lazy.weighted_keys, 256);
    assert_eq!(full.weighted_keys, 256);
    // One element sorts a fraction of the snapshot, the full order all of it.
    assert!(
        lazy.sort_comparisons < full.sort_comparisons,
        "one element: {} comparisons, full pick_order: {}",
        lazy.sort_comparisons,
        full.sort_comparisons
    );
    crate::perf::report("rotator/pick_iter/n=256/consumed=1", lazy);
    crate::perf::report("rotator/pick_order/n=256/full_sort_control", full);
}

/// `pick_iter` counts as one order build, like `pick_order`: the dependent
/// crates' budget-exhaustion oracles read this counter and must keep seeing
/// the direct path. Mutation: a `pick_iter` that does not count turns those
/// "no order was built" assertions vacuous.
#[cfg(feature = "test-instrumentation")]
#[test]
fn pick_iter_and_pick_order_both_count_as_order_builds() {
    let rotator = std::sync::Arc::new(ProxyRotator::new(vec![
        make_proxy("a", 1),
        make_proxy("b", 2),
    ]));
    assert_eq!(rotator.pick_order_calls(), 0);
    let _ = rotator.pick_order();
    assert_eq!(rotator.pick_order_calls(), 1);
    let mut iter = rotator.pick_iter();
    assert_eq!(rotator.pick_order_calls(), 2, "counted when built");
    while iter.next().is_some() {}
    assert_eq!(
        rotator.pick_order_calls(),
        2,
        "consuming the iterator is not another build"
    );
}
