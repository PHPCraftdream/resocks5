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
    assert!((after_level_two[1] - after_level_one[1]).abs() < 1e-9);
    assert!((after_level_two[0] - 1.0).abs() < 1e-9);
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

#[test]
fn rating_index_preserves_last_duplicate_slot() {
    let proxy = make_proxy("one", 1000);
    let rotator = ProxyRotator::new(vec![proxy.clone(), proxy.clone(), proxy.clone()]);
    assert_eq!(rotator.index_of(&proxy), Some(2));
    let hash = upstream_hash(&rotator.identity_hasher, &proxy);
    assert_eq!(rotator.by_identity[&hash].len(), 1);
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
    r.link_proxy("target".to_string(), a.clone());
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
    r.link_proxy("target".to_string(), Arc::new(make_proxy("h", 1000)));
    r.link_proxy("target".to_string(), Arc::new(make_proxy("h", 1001)));
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
    r.link_proxy("sentinel".to_string(), Arc::new(make_proxy("h", 1001)));
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
    r.link_proxy("A".to_string(), Arc::new(make_proxy("h", 1000)));
    r.link_proxy("B".to_string(), Arc::new(make_proxy("h", 1001)));
    assert_eq!(r.get_linked("A").map(|p| p.port), Some(1000)); // touch
    r.link_proxy("C".to_string(), Arc::new(make_proxy("h", 1002)));
    assert!(r.get_linked("B").is_none(), "B should be LRU-evicted");
    assert!(r.get_linked("A").is_some());
    assert_eq!(r.get_linked("C").map(|p| p.port), Some(1002));
}

#[test]
fn ttl_expires_entries() {
    let mut cache = StickyCache::new(8, Duration::from_secs(10));
    let t0 = Instant::now();
    cache.insert("a".to_string(), Arc::new(make_proxy("h", 1000)), t0);
    assert!(cache.get("a", t0 + Duration::from_secs(5)).is_some());
    assert!(cache.get("a", t0 + Duration::from_secs(10)).is_none());
    assert!(cache.map.is_empty());
}

#[test]
fn sticky_metadata_stays_bounded_behind_a_cold_entry() {
    let mut cache = StickyCache::new(2, Duration::from_secs(60));
    let t0 = Instant::now();
    let proxy = Arc::new(make_proxy("h", 1000));
    cache.insert("cold".to_string(), proxy.clone(), t0);
    cache.insert("hot".to_string(), proxy, t0);
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
    cache.insert("expired".to_string(), Arc::new(make_proxy("h", 1000)), t0);
    cache.insert(
        "live".to_string(),
        Arc::new(make_proxy("h", 1001)),
        t0 + Duration::from_secs(5),
    );
    assert!(cache.get("expired", t0 + Duration::from_secs(9)).is_some());
    let now = t0 + Duration::from_secs(11);
    cache.insert("new".to_string(), Arc::new(make_proxy("h", 1002)), now);
    assert_eq!(cache.get("live", now).map(|p| p.port), Some(1001));
    assert_eq!(cache.get("new", now).map(|p| p.port), Some(1002));
    assert!(cache.get("expired", now).is_none());
}

#[test]
fn sticky_replacement_refreshes_expiry_and_removal_releases_metadata() {
    let mut cache = StickyCache::new(2, Duration::from_secs(10));
    let t0 = Instant::now();
    cache.insert("A".to_string(), Arc::new(make_proxy("h", 1000)), t0);
    cache.insert(
        "B".to_string(),
        Arc::new(make_proxy("h", 1001)),
        t0 + Duration::from_secs(1),
    );
    cache.insert(
        "A".to_string(),
        Arc::new(make_proxy("h", 1002)),
        t0 + Duration::from_secs(8),
    );
    assert!(cache.get("B", t0 + Duration::from_secs(9)).is_some());
    let now = t0 + Duration::from_secs(11);
    cache.insert("C".to_string(), Arc::new(make_proxy("h", 1003)), now);
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
    cache.insert("A".to_string(), proxy.clone(), now);
    cache.insert("B".to_string(), proxy.clone(), now);
    assert!(cache.get("A", now).is_some());
    cache.insert("C".to_string(), proxy, now);
    assert!(cache.get("A", now).is_some());
    assert!(cache.get("C", now).is_some());
    assert!(cache.get("B", now).is_none());
}

#[test]
fn ttl_purge_frees_room_without_evicting_live_entries() {
    let mut cache = StickyCache::new(2, Duration::from_secs(10));
    let t0 = Instant::now();
    cache.insert("A".to_string(), Arc::new(make_proxy("h", 1000)), t0);
    cache.insert("B".to_string(), Arc::new(make_proxy("h", 1001)), t0);
    let t1 = t0 + Duration::from_secs(11);
    cache.insert("C".to_string(), Arc::new(make_proxy("h", 1002)), t1);
    cache.insert("D".to_string(), Arc::new(make_proxy("h", 1003)), t1);
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
    r.link_proxy("a".to_string(), Arc::new(make_proxy("h", 1000)));
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
