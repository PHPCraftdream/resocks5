use super::*;
use crate::rating::UpstreamState;

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

fn find(health: &[UpstreamHealth], host: &str) -> UpstreamHealth {
    health
        .iter()
        .find(|entry| entry.proxy.host == host)
        .cloned()
        .unwrap()
}

#[test]
fn health_lists_every_upstream_in_configuration_order() {
    let r = rotator(&["a", "b", "c"]);
    trip(&r, &proxy("b"));
    let health = r.health();
    let hosts: Vec<_> = health.iter().map(|e| e.proxy.host.as_str()).collect();
    assert_eq!(hosts, ["a", "b", "c"]);
    assert_eq!(health[0].health.state, UpstreamState::Alive);
    assert_eq!(health[1].health.state, UpstreamState::Quarantined);
    assert!(health[1].health.remaining > Duration::ZERO);
    assert_eq!(health[1].health.trips, 1);
    assert_eq!(health[2].health.state, UpstreamState::Alive);
}

#[test]
fn restored_quarantine_keeps_the_dead_out_of_rotation_and_probes_probation() {
    let before = rotator(&["a", "b", "c"]);
    trip(&before, &proxy("a"));
    let saved = before.health();
    let mut probation = find(&saved, "a");
    probation.proxy = Arc::new(proxy("b"));
    probation.health = Health::new(UpstreamState::Probation, Duration::ZERO, 2, 3);

    let after = rotator(&["a", "b", "c"]);
    let applied = after.restore_health(&[find(&saved, "a"), probation, find(&saved, "c")]);
    assert_eq!(applied, 2);
    assert!(after.is_quarantined(&proxy("a")));
    assert!(after.is_quarantined(&proxy("b")));
    assert!(!after.is_quarantined(&proxy("c")));
    for _ in 0..50 {
        let order = after.pick_order();
        assert_eq!(order.len(), 1);
        assert_eq!(order[0].host, "c");
    }
    let probes = after.take_probes();
    assert_eq!(probes.len(), 1);
    assert_eq!(probes[0].host, "b");
}

#[test]
fn restore_skips_unknown_upstreams_and_keeps_trips_for_the_backoff() {
    let r = rotator(&["a"]);
    let stranger = UpstreamHealth::new(
        Arc::new(proxy("zzz")),
        Health::new(UpstreamState::Quarantined, Duration::from_secs(5), 1, 3),
    );
    let known = UpstreamHealth::new(
        Arc::new(proxy("a")),
        Health::new(UpstreamState::Quarantined, Duration::from_secs(5), 3, 3),
    );
    assert_eq!(r.restore_health(&[stranger, known]), 1);
    assert_eq!(r.health()[0].health.trips, 3);
}

#[test]
fn a_success_lifts_a_restored_quarantine() {
    let r = rotator(&["a", "b"]);
    let saved = UpstreamHealth::new(
        Arc::new(proxy("a")),
        Health::new(UpstreamState::Probation, Duration::ZERO, 2, 3),
    );
    assert_eq!(r.restore_health(&[saved]), 1);
    r.record_success(&proxy("a"));
    assert!(!r.is_quarantined(&proxy("a")));
    assert_eq!(r.health()[0].health.trips, 0);
}

#[test]
fn restore_without_a_quarantine_policy_applies_nothing() {
    let r = ProxyRotator::new(vec![proxy("a")]);
    let saved = UpstreamHealth::new(
        Arc::new(proxy("a")),
        Health::new(UpstreamState::Probation, Duration::ZERO, 1, 3),
    );
    assert_eq!(r.restore_health(&[saved]), 0);
    assert!(!r.is_quarantined(&proxy("a")));
}
