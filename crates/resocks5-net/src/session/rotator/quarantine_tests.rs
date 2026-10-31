use super::*;

fn proxy(host: &str) -> ProxyConfig {
    ProxyConfig::socks5(host, 1080)
}

fn rotator(hosts: &[&str]) -> ProxyRotator {
    ProxyRotator::try_with_quarantine(
        hosts.iter().map(|h| proxy(h)).collect(),
        RatingPolicy::default(),
        QuarantinePolicy::default().with_threshold(3),
        DEFAULT_STICKY_CACHE_MAX_ENTRIES,
        DEFAULT_STICKY_CACHE_TTL,
    )
    .unwrap()
}

fn trip(r: &ProxyRotator, p: &ProxyConfig) -> Option<Duration> {
    let mut last = None;
    for _ in 0..3 {
        last = r.record_hard_failure(p);
    }
    last
}

#[test]
fn quarantined_proxy_leaves_pick_order_until_a_success() {
    let r = rotator(&["a", "b", "c"]);
    let dead = proxy("a");
    assert!(trip(&r, &dead).is_some());
    assert!(r.is_quarantined(&dead));
    for _ in 0..100 {
        let order = r.pick_order();
        assert_eq!(order.len(), 2);
        assert!(order.iter().all(|p| p.host != "a"));
    }
    r.record_success(&dead);
    assert!(!r.is_quarantined(&dead));
    assert_eq!(r.pick_order().len(), 3);
}

#[test]
fn hard_failure_is_reported_only_when_it_trips() {
    let r = rotator(&["a", "b"]);
    let p = proxy("a");
    assert_eq!(r.record_hard_failure(&p), None);
    assert_eq!(r.record_hard_failure(&p), None);
    assert_eq!(r.record_hard_failure(&p), Some(Duration::from_secs(30)));
}

#[test]
fn soft_failures_do_not_quarantine() {
    let r = rotator(&["a", "b"]);
    let p = proxy("a");
    for _ in 0..50 {
        r.record_failure(&p);
    }
    assert!(!r.is_quarantined(&p));
    assert_eq!(r.pick_order().len(), 2);
}

#[test]
fn sticky_cache_skips_a_quarantined_proxy() {
    let r = rotator(&["a", "b"]);
    let a = Arc::new(proxy("a"));
    r.link_proxy("example.com:443".to_string(), a.clone());
    assert!(r.get_linked("example.com:443").is_some());
    trip(&r, &a);
    assert!(r.get_linked("example.com:443").is_none());
    r.record_success(&a);
    assert!(r.get_linked("example.com:443").is_some());
}

#[test]
fn gate_composite_failures_land_on_the_plain_upstream() {
    let r = rotator(&["a", "b"]);
    let mut composite = proxy("a");
    composite.gate = Some(Arc::new(ProxyConfig::socks5("gate", 1)));
    assert!(trip(&r, &composite).is_some());
    assert!(r.is_quarantined(&proxy("a")));
}

#[test]
fn unknown_proxy_is_ignored() {
    let r = rotator(&["a", "b"]);
    let stranger = proxy("zzz");
    assert_eq!(r.record_hard_failure(&stranger), None);
    assert!(!r.is_quarantined(&stranger));
}

#[test]
fn invalid_quarantine_policy_is_rejected() {
    let bad = QuarantinePolicy::default().with_initial(Duration::ZERO);
    let result = ProxyRotator::try_with_quarantine(
        vec![proxy("a")],
        RatingPolicy::default(),
        bad,
        16,
        Duration::from_secs(1),
    );
    assert!(matches!(result, Err(RotatorError::InvalidPolicy(_))));
}

#[test]
fn constructors_without_quarantine_never_exclude() {
    let r = ProxyRotator::new(vec![proxy("a"), proxy("b")]);
    let p = proxy("a");
    for _ in 0..20 {
        assert_eq!(r.record_hard_failure(&p), None);
    }
    assert_eq!(r.pick_order().len(), 2);
}
