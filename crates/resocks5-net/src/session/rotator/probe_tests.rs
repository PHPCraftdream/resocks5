use super::*;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::net::TcpListener;
use tokio::time::Instant;

fn proxy(host: &str, port: u16) -> ProxyConfig {
    ProxyConfig::socks5(host, port)
}

fn rotator(proxies: Vec<ProxyConfig>, threshold: u32) -> ProxyRotator {
    ProxyRotator::try_with_quarantine(
        proxies,
        RatingPolicy::default(),
        QuarantinePolicy::default()
            .with_threshold(threshold)
            .with_initial(Duration::from_millis(20))
            .with_max(Duration::from_millis(20))
            .with_probe_lease(Duration::from_millis(20)),
        DEFAULT_STICKY_CACHE_MAX_ENTRIES,
        DEFAULT_STICKY_CACHE_TTL,
    )
    .unwrap()
}

async fn listener() -> (TcpListener, SocketAddr) {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let address = listener.local_addr().unwrap();
    (listener, address)
}

#[tokio::test]
async fn probe_due_recovers_a_live_proxy() {
    let (listener, address) = listener().await;
    let proxy = proxy("127.0.0.1", address.port());
    let rotator = rotator(vec![proxy.clone()], 1);
    assert!(rotator.record_hard_failure(&proxy).is_some());
    tokio::time::sleep(Duration::from_millis(25)).await;

    let events = rotator.probe_due(Duration::from_secs(1)).await;
    assert!(
        matches!(events.as_slice(), [ProbeEvent::Recovered { proxy: p }] if p.host == proxy.host)
    );
    assert!(!rotator.is_quarantined(&proxy));
    drop(listener);
}

#[tokio::test]
async fn probe_due_reports_retrip_for_a_dead_proxy() {
    let proxy = proxy("192.0.2.1", 9);
    let rotator = rotator(vec![proxy.clone()], 1);
    assert!(rotator.record_hard_failure(&proxy).is_some());
    tokio::time::sleep(Duration::from_millis(25)).await;

    let events = rotator.probe_due(Duration::from_millis(50)).await;
    assert!(
        matches!(events.as_slice(), [ProbeEvent::StillDown { proxy: p, quarantined_for, reason }] if p.host == proxy.host && *quarantined_for == Duration::from_millis(20) && !reason.is_empty())
    );
}

#[tokio::test]
async fn probe_all_quarantines_dead_and_leaves_prequarantined_live_proxy_untouched() {
    let (listener, address) = listener().await;
    let live = proxy("127.0.0.1", address.port());
    let dead = proxy("192.0.2.1", 9);
    let rotator = rotator(vec![live.clone(), dead.clone()], 3);
    assert!(rotator.quarantine_now(&live).is_some());

    let events = rotator.probe_all(Duration::from_millis(50)).await;
    assert!(
        matches!(events.as_slice(), [ProbeEvent::QuarantinedAtStart { proxy: p, quarantined_for, reason }] if p.host == dead.host && *quarantined_for == Duration::from_millis(20) && reason.contains("no answer"))
    );
    assert!(
        rotator.is_quarantined(&live),
        "reachable proxies are not recovered by probe_all"
    );
    assert!(rotator.is_quarantined(&dead));
    drop(listener);
}

#[tokio::test]
async fn probe_all_skips_an_already_quarantined_proxy_without_extending_backoff() {
    let dead = proxy("192.0.2.1", 9);
    let quarantine = QuarantinePolicy::default()
        .with_initial(Duration::from_millis(20))
        .with_max(Duration::from_millis(80))
        .with_probe_lease(Duration::from_millis(20));
    let rotator = ProxyRotator::try_with_quarantine(
        vec![dead.clone()],
        RatingPolicy::default(),
        quarantine,
        DEFAULT_STICKY_CACHE_MAX_ENTRIES,
        DEFAULT_STICKY_CACHE_TTL,
    )
    .unwrap();
    assert_eq!(
        rotator.quarantine_now(&dead),
        Some(Duration::from_millis(20))
    );

    let events = rotator.probe_all(Duration::from_millis(50)).await;
    assert!(events.is_empty());
    assert!(rotator.is_quarantined(&dead));

    tokio::time::sleep(Duration::from_millis(25)).await;
    assert_eq!(
        rotator.take_probes().len(),
        1,
        "backoff was not extended by probe_all"
    );
}

#[tokio::test]
async fn probe_due_skips_a_proxy_with_an_active_probe_lease() {
    let proxy = proxy("192.0.2.1", 9);
    let rotator = rotator(vec![proxy.clone()], 1);
    assert!(rotator.record_hard_failure(&proxy).is_some());
    tokio::time::sleep(Duration::from_millis(25)).await;
    assert_eq!(rotator.take_probes().len(), 1);
    assert!(rotator
        .probe_due(Duration::from_millis(10))
        .await
        .is_empty());
}

#[tokio::test]
async fn probe_all_and_probe_due_emit_no_events_when_quarantine_is_disabled() {
    let (listener, address) = listener().await;
    let live = proxy("127.0.0.1", address.port());
    let dead = proxy("192.0.2.1", 9);
    let rotator = ProxyRotator::new(vec![live, dead.clone()]);

    assert!(rotator
        .probe_all(Duration::from_millis(50))
        .await
        .is_empty());
    assert!(rotator
        .probe_due(Duration::from_millis(50))
        .await
        .is_empty());
    assert!(!rotator.is_quarantined(&dead));
    drop(listener);
}

#[tokio::test]
async fn probe_all_reports_many_dead_upstreams() {
    let proxies = (1..=24)
        .map(|port| proxy("192.0.2.1", 30_000 + port))
        .collect();
    let rotator = rotator(proxies, 3);
    let start = Instant::now();
    let events = rotator.probe_all(Duration::from_millis(150)).await;
    assert_eq!(events.len(), 24);
    assert!(events
        .iter()
        .all(|event| matches!(event, ProbeEvent::QuarantinedAtStart { .. })));
    assert!(start.elapsed() < Duration::from_secs(2));
}

#[tokio::test]
async fn a_refused_connect_reports_the_io_error_not_a_timeout() {
    // A port nobody listens on: bind, learn the port, drop the listener.
    let (listener, address) = listener().await;
    drop(listener);
    let proxy = proxy("127.0.0.1", address.port());
    let rotator = rotator(vec![proxy.clone()], 3);
    // Windows refuses a loopback connect only after ~2 s; the timeout must
    // outlast that or the probe reports "no answer" instead of the refusal.
    let events = rotator.probe_all(Duration::from_secs(10)).await;
    match events.as_slice() {
        [ProbeEvent::QuarantinedAtStart { reason, .. }] => {
            assert!(!reason.contains("no answer"), "{reason}");
            assert!(!reason.is_empty());
        }
        other => panic!("unexpected events: {other:?}"),
    }
}

fn rotator_with_margins(proxies: Vec<ProxyConfig>) -> ProxyRotator {
    ProxyRotator::try_with_quarantine(
        proxies,
        RatingPolicy::default(),
        QuarantinePolicy::default()
            .with_threshold(1)
            .with_initial(Duration::from_millis(300))
            .with_max(Duration::from_millis(300))
            .with_probe_lease(Duration::from_millis(300)),
        DEFAULT_STICKY_CACHE_MAX_ENTRIES,
        DEFAULT_STICKY_CACHE_TTL,
    )
    .unwrap()
}

/// Guard stand-in whose Drop counts: the probe must drop it exactly once,
/// after the attempt settles.
struct DropCounter(Arc<AtomicUsize>);

impl Drop for DropCounter {
    fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

// P2 №5 (a): at capacity the due probe is deferred — no connection, no
// health change — and the lease expires so take_probes hands the
// upstream out again.
#[tokio::test]
async fn probe_due_with_at_capacity_defers_without_connecting_or_rating() {
    let (listener, address) = listener().await;
    let proxy = proxy("127.0.0.1", address.port());
    let rotator = rotator_with_margins(vec![proxy.clone()]);
    assert!(rotator.record_hard_failure(&proxy).is_some());
    tokio::time::sleep(Duration::from_millis(400)).await;

    let before = rotator.health();
    let events = rotator
        .probe_due_with(Duration::from_secs(1), |_| None::<()>)
        .await;
    assert!(events.is_empty(), "a deferred probe reports nothing");
    assert!(
        tokio::time::timeout(Duration::from_millis(200), listener.accept())
            .await
            .is_err(),
        "a deferred probe must not connect"
    );
    let after = rotator.health();
    assert_eq!(after[0].health.state, before[0].health.state);
    assert_eq!(after[0].health.trips, before[0].health.trips);
    assert_eq!(after[0].health.consecutive, before[0].health.consecutive);
    assert!(rotator.is_quarantined(&proxy));

    tokio::time::sleep(Duration::from_millis(350)).await;
    assert_eq!(rotator.take_probes().len(), 1);
    drop(listener);
}

// P2 №5 (b): with a reservation the probe connects, recovers the
// upstream and drops the guard when the attempt settles.
#[tokio::test]
async fn probe_due_with_holds_the_guard_for_the_probe_and_recovers() {
    let (listener, address) = listener().await;
    let proxy = proxy("127.0.0.1", address.port());
    let rotator = rotator_with_margins(vec![proxy.clone()]);
    assert!(rotator.record_hard_failure(&proxy).is_some());
    tokio::time::sleep(Duration::from_millis(400)).await;

    let drops = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&drops);
    let events = rotator
        .probe_due_with(Duration::from_secs(1), move |_| {
            Some(DropCounter(Arc::clone(&counter)))
        })
        .await;
    assert!(
        matches!(events.as_slice(), [ProbeEvent::Recovered { proxy: p }] if p.host == proxy.host)
    );
    assert!(!rotator.is_quarantined(&proxy));
    assert_eq!(
        drops.load(Ordering::SeqCst),
        1,
        "the guard drops once, after the probe settles"
    );
    drop(listener);
}

// P2 №5, start-up half: an at-capacity upstream is neither probed nor
// quarantined at start-up.
#[tokio::test]
async fn probe_all_with_at_capacity_neither_probes_nor_quarantines() {
    let proxy = proxy("192.0.2.1", 9);
    let rotator = rotator_with_margins(vec![proxy.clone()]);
    let events = rotator
        .probe_all_with(Duration::from_millis(200), |_| None::<()>)
        .await;
    assert!(events.is_empty());
    assert!(!rotator.is_quarantined(&proxy));
    let health = rotator.health();
    assert_eq!(health[0].health.trips, 0);
    assert_eq!(health[0].health.consecutive, 0);
}
