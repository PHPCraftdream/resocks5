use super::dial::*;
use super::route::*;
use super::tests_unit::{socks5_config, spawn_socks5_stub, test_logger};
use crate::config::NetworkConfig;
use regex::RegexSet;
use resocks5_net::pool::ProxyPool;
use resocks5_net::rating::QuarantinePolicy;
use resocks5_net::rotator::ProxyRotator;
use resocks5_net::types::ProxyProtocol;
use resocks5_net::{ConnectError, ProtocolViolation, Stage, TimeoutKind};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn timeout(stage: Stage, kind: TimeoutKind) -> ConnectError {
    ConnectError::Timeout {
        stage,
        kind,
        endpoint: "203.0.113.1:1080".to_string(),
        after: Duration::from_secs(10),
    }
}

fn io(stage: Stage) -> ConnectError {
    ConnectError::Io {
        stage,
        endpoint: None,
        source: std::io::Error::from(std::io::ErrorKind::ConnectionRefused),
    }
}

fn hard(err: ConnectError) -> bool {
    is_hard_failure(&anyhow::Error::new(err))
}

#[test]
fn upstream_down_signals_are_hard_failures() {
    assert!(hard(timeout(Stage::Connect, TimeoutKind::TcpConnect)));
    assert!(hard(timeout(
        Stage::Handshake,
        TimeoutKind::HttpsTlsHandshake
    )));
    assert!(hard(io(Stage::Connect)));
    assert!(hard(ConnectError::AuthFailed { status: 1 }));
    assert!(hard(ConnectError::MethodUnsupported {
        got: 0xff,
        with_auth: false
    }));
    assert!(hard(ConnectError::Protocol(
        ProtocolViolation::Socks5BadVersion { got: 4 }
    )));
    assert!(hard(ConnectError::Tls {
        message: "tls".to_string(),
        source: None
    }));
}

#[test]
fn target_side_or_ambiguous_failures_are_not_hard() {
    // A stalled or refused CONNECT looks the same for a dead destination.
    assert!(!hard(timeout(
        Stage::Handshake,
        TimeoutKind::Socks5Handshake
    )));
    assert!(!hard(timeout(Stage::Handshake, TimeoutKind::HttpHandshake)));
    assert!(!hard(timeout(
        Stage::Handshake,
        TimeoutKind::HttpsConnectHandshake
    )));
    assert!(!hard(io(Stage::Handshake)));
    assert!(!hard(ConnectError::ProxyRejected {
        protocol: ProxyProtocol::Socks5,
        code: Some(5),
        response: String::new()
    }));
    assert!(!hard(ConnectError::Protocol(
        ProtocolViolation::HttpClosedEarly
    )));
    assert!(!hard(ConnectError::InvalidTarget("x".to_string())));
    assert!(!is_hard_failure(&anyhow::anyhow!("something else")));
}

#[test]
fn classification_sees_through_gate_stage_context() {
    let err = anyhow::Error::new(io(Stage::Connect)).context(GateStage::GateConnect);
    assert!(is_hard_failure(&err));
}

#[tokio::test]
async fn dead_upstream_is_quarantined_and_requests_keep_succeeding() {
    let logger = test_logger();
    let banned = Arc::new(RegexSet::empty());
    let pool = Arc::new(ProxyPool::new(
        Default::default(),
        Duration::from_secs(2),
        4,
    ));
    let network = Arc::new(NetworkConfig {
        handshake_timeout_sec: 2,
        ..Default::default()
    });
    // Port 0 is refused immediately everywhere.
    let dead = socks5_config(SocketAddr::from(([127, 0, 0, 1], 0)), false);
    let live = socks5_config(spawn_socks5_stub().await, false);
    let v4 = Arc::new(
        ProxyRotator::try_with_quarantine(
            vec![dead.clone(), live.clone()],
            Default::default(),
            QuarantinePolicy::default().with_threshold(2),
            16,
            Duration::from_secs(60),
        )
        .unwrap(),
    );

    // A distinct target per request: a success links the target to its
    // upstream in the sticky cache and the next call would skip the walk.
    let mut quarantined = false;
    for i in 0..80 {
        let target = format!("t{i}.example.com:443");
        let stream = establish_connection(
            &target,
            &None,
            &None,
            &Some(v4.clone()),
            &logger,
            &banned,
            &pool,
            &network,
            None,
            None,
        )
        .await
        .expect("a live upstream exists, so the request must succeed");
        drop(stream);
        if v4.is_quarantined(&dead) {
            quarantined = true;
            break;
        }
    }
    assert!(quarantined, "dead upstream was never quarantined");
    assert!(!v4.is_quarantined(&live));

    // From now on the dead upstream is not even in the order.
    for _ in 0..50 {
        let order = v4.pick_order();
        assert_eq!(order.len(), 1);
        assert_eq!(order[0].port, live.port);
    }
    for i in 0..10 {
        let target = format!("after{i}.example.com:443");
        drop(
            establish_connection(
                &target,
                &None,
                &None,
                &Some(v4.clone()),
                &logger,
                &banned,
                &pool,
                &network,
                None,
                None,
            )
            .await
            .expect("still served by the live upstream"),
        );
    }
}

async fn request(v4: &Arc<ProxyRotator>, target: &str) -> std::time::Duration {
    let logger = test_logger();
    let banned = Arc::new(RegexSet::empty());
    let pool = Arc::new(ProxyPool::new(
        Default::default(),
        Duration::from_secs(2),
        8,
    ));
    let network = Arc::new(NetworkConfig {
        connect_timeout_sec: 2,
        handshake_timeout_sec: 2,
        ..Default::default()
    });
    let t0 = std::time::Instant::now();
    drop(
        establish_connection(
            target,
            &None,
            &None,
            &Some(v4.clone()),
            &logger,
            &banned,
            &pool,
            &network,
            None,
            None,
        )
        .await
        .expect("a live upstream exists"),
    );
    t0.elapsed()
}

fn short_quarantine(proxies: Vec<resocks5_net::types::ProxyConfig>) -> Arc<ProxyRotator> {
    Arc::new(
        ProxyRotator::try_with_quarantine(
            proxies,
            Default::default(),
            QuarantinePolicy::default()
                .with_threshold(1)
                .with_initial(Duration::from_millis(200))
                .with_max(Duration::from_secs(5))
                .with_probe_lease(Duration::from_secs(5)),
            16,
            Duration::from_secs(60),
        )
        .unwrap(),
    )
}

#[tokio::test]
async fn background_probe_returns_a_recovered_upstream_to_rotation() {
    let a = socks5_config(spawn_socks5_stub().await, false);
    let b = socks5_config(spawn_socks5_stub().await, false);
    let v4 = short_quarantine(vec![a.clone(), b.clone()]);
    // Pretend `a` failed: it is quarantined although it is reachable.
    assert!(v4.record_hard_failure(&a).is_some());
    tokio::time::sleep(Duration::from_millis(300)).await;
    // The request is served by `b`; the probe of `a` runs beside it.
    request(&v4, "p1.example.com:443").await;
    for _ in 0..50 {
        if !v4.is_quarantined(&a) {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("the background probe never returned the reachable upstream");
}

#[tokio::test]
async fn requests_never_wait_on_a_dead_upstream_under_probation() {
    let dead = socks5_config(SocketAddr::from(([192, 0, 2, 1], 9)), false);
    let live = socks5_config(spawn_socks5_stub().await, false);
    let v4 = short_quarantine(vec![dead.clone(), live]);
    assert!(v4.record_hard_failure(&dead).is_some());
    tokio::time::sleep(Duration::from_millis(300)).await;
    // `dead` (TEST-NET-1, never answers) is due for a probe now: the probe
    // takes the full connect timeout, the request must not.
    for i in 0..5 {
        let took = request(&v4, &format!("q{i}.example.com:443")).await;
        assert!(took < Duration::from_secs(1), "request waited {took:?}");
    }
    assert!(v4.is_quarantined(&dead));
}

#[tokio::test]
async fn an_unknown_dead_upstream_costs_only_the_hedge_delay() {
    // No quarantine: the dead upstream (TEST-NET-1, never answers) keeps its
    // full weight and leads about half of the orders. Each request must
    // still finish in about the hedge delay, not the connect timeout.
    let dead = socks5_config(SocketAddr::from(([192, 0, 2, 1], 9)), false);
    let live = socks5_config(spawn_socks5_stub().await, false);
    let v4 = Arc::new(ProxyRotator::new(vec![dead, live]));
    let logger = test_logger();
    let banned = Arc::new(RegexSet::empty());
    let pool = Arc::new(ProxyPool::new(
        Default::default(),
        Duration::from_secs(5),
        16,
    ));
    let network = Arc::new(NetworkConfig {
        connect_timeout_sec: 5,
        handshake_timeout_sec: 5,
        hedge_delay_ms: 200,
        ..Default::default()
    });
    for i in 0..12 {
        let t0 = std::time::Instant::now();
        drop(
            establish_connection(
                &format!("h{i}.example.com:443"),
                &None,
                &None,
                &Some(v4.clone()),
                &logger,
                &banned,
                &pool,
                &network,
                None,
                None,
            )
            .await
            .expect("the live upstream must win"),
        );
        let took = t0.elapsed();
        assert!(took < Duration::from_secs(2), "request {i} waited {took:?}");
    }
}

async fn hedged_request(
    v4: &Arc<ProxyRotator>,
    target: &str,
    hedge_ms: u64,
) -> std::time::Duration {
    let logger = test_logger();
    let banned = Arc::new(RegexSet::empty());
    let pool = Arc::new(ProxyPool::new(
        Default::default(),
        Duration::from_secs(1),
        16,
    ));
    let network = Arc::new(NetworkConfig {
        connect_timeout_sec: 1,
        handshake_timeout_sec: 1,
        hedge_delay_ms: hedge_ms,
        ..Default::default()
    });
    let t0 = std::time::Instant::now();
    drop(
        establish_connection(
            target,
            &None,
            &None,
            &Some(v4.clone()),
            &logger,
            &banned,
            &pool,
            &network,
            None,
            None,
        )
        .await
        .expect("a live upstream exists"),
    );
    t0.elapsed()
}

#[tokio::test]
async fn attempts_that_lose_the_race_still_feed_the_quarantine() {
    let dead = socks5_config(SocketAddr::from(([192, 0, 2, 1], 9)), false);
    let live = socks5_config(spawn_socks5_stub().await, false);
    let v4 = Arc::new(
        ProxyRotator::try_with_quarantine(
            vec![dead.clone(), live],
            Default::default(),
            QuarantinePolicy::default().with_threshold(1),
            16,
            Duration::from_secs(60),
        )
        .unwrap(),
    );
    // About half of these start on `dead`, get hedged and win via `live`;
    // the abandoned `dead` attempt times out (1 s) in the background.
    for i in 0..20 {
        hedged_request(&v4, &format!("l{i}.example.com:443"), 100).await;
    }
    for _ in 0..40 {
        if v4.is_quarantined(&dead) {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("a hedged-away dead upstream was never quarantined");
}

#[tokio::test]
async fn a_dead_cached_upstream_is_raced_not_waited_for() {
    let dead = socks5_config(SocketAddr::from(([192, 0, 2, 1], 9)), false);
    let live = socks5_config(spawn_socks5_stub().await, false);
    let v4 = Arc::new(ProxyRotator::new(vec![dead.clone(), live]));
    let target = "sticky.example.com:443";
    v4.link_proxy(target.to_string(), Arc::new(dead));
    let took = hedged_request(&v4, target, 100).await;
    assert!(took < Duration::from_millis(900), "request waited {took:?}");
}

/// SOCKS5 stub that answers CONNECT after `reply_delay` and counts what it
/// sees: accepted sockets and greetings.
async fn spawn_observed_stub(
    reply_delay: Duration,
) -> (SocketAddr, Arc<AtomicUsize>, Arc<AtomicUsize>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let accepts = Arc::new(AtomicUsize::new(0));
    let greetings = Arc::new(AtomicUsize::new(0));
    let (a, g) = (accepts.clone(), greetings.clone());
    tokio::spawn(async move {
        while let Ok((mut sock, _)) = listener.accept().await {
            a.fetch_add(1, Ordering::SeqCst);
            let g = g.clone();
            tokio::spawn(async move {
                let mut greet = [0u8; 3];
                if sock.read_exact(&mut greet).await.is_err() {
                    return;
                }
                g.fetch_add(1, Ordering::SeqCst);
                if sock.write_all(&[0x05, 0x00]).await.is_err() {
                    return;
                }
                let mut head = [0u8; 5];
                if sock.read_exact(&mut head).await.is_err() {
                    return;
                }
                let mut rest = vec![0u8; head[4] as usize + 2];
                if sock.read_exact(&mut rest).await.is_err() {
                    return;
                }
                tokio::time::sleep(reply_delay).await;
                let _ = sock
                    .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                    .await;
                let mut rest = Vec::new();
                let _ = sock.read_to_end(&mut rest).await;
            });
        }
    });
    (addr, accepts, greetings)
}

#[tokio::test]
async fn a_slow_target_answer_is_not_hedged() {
    // The hedge delay must exceed a loopback TCP connect even under a loaded
    // parallel test run, or the second attempt starts legitimately.
    let (slow_addr, _, _) = spawn_observed_stub(Duration::from_millis(1500)).await;
    let (other_addr, other_accepts, _) = spawn_observed_stub(Duration::ZERO).await;
    let slow = socks5_config(slow_addr, false);
    let v4 = Arc::new(ProxyRotator::new(vec![
        slow.clone(),
        socks5_config(other_addr, false),
    ]));
    let target = "slow.example.com:443";
    // The sticky upstream leads the race.
    v4.link_proxy(target.to_string(), Arc::new(slow));
    let pool = Arc::new(ProxyPool::new(
        Default::default(),
        Duration::from_secs(5),
        16,
    ));
    let network = Arc::new(NetworkConfig {
        connect_timeout_sec: 5,
        handshake_timeout_sec: 5,
        hedge_delay_ms: 400,
        ..Default::default()
    });
    let t0 = std::time::Instant::now();
    drop(
        establish_connection(
            target,
            &None,
            &None,
            &Some(v4.clone()),
            &test_logger(),
            &Arc::new(RegexSet::empty()),
            &pool,
            &network,
            None,
            None,
        )
        .await
        .expect("the slow upstream answers"),
    );
    let took = t0.elapsed();
    assert!(
        took >= Duration::from_millis(1400),
        "served too early: {took:?}"
    );
    assert_eq!(
        other_accepts.load(Ordering::SeqCst),
        0,
        "a second CONNECT started while the first one talked to the target"
    );
}

#[tokio::test]
async fn a_late_loser_leaves_the_winners_sticky_link() {
    let dead = socks5_config(SocketAddr::from(([192, 0, 2, 1], 9)), false);
    let live = socks5_config(spawn_socks5_stub().await, false);
    let v4 = Arc::new(ProxyRotator::new(vec![dead.clone(), live.clone()]));
    let target = "relink.example.com:443";
    v4.link_proxy(target.to_string(), Arc::new(dead));
    hedged_request(&v4, target, 100).await;
    // Let the abandoned `dead` attempt time out (1 s) in the background.
    tokio::time::sleep(Duration::from_millis(1500)).await;
    let linked = v4.get_linked(target).expect("the winner stays linked");
    assert_eq!(
        (linked.host.as_str(), linked.port),
        (live.host.as_str(), live.port)
    );
}

#[tokio::test]
async fn an_attempt_reaching_its_upstream_after_the_win_stops_there() {
    let (addr, accepts, greetings) = spawn_observed_stub(Duration::ZERO).await;
    let proxy = socks5_config(addr, false);
    let pool = ProxyPool::new(Default::default(), Duration::from_secs(1), 4);
    let race = RaceState::default();
    race.won.store(true, Ordering::SeqCst);
    let err = race_attempt(
        &race,
        "x.example.com:443",
        &proxy,
        &pool,
        Duration::from_secs(1),
        None,
    )
    .await
    .err()
    .expect("a lost race yields no stream");
    assert!(err.is::<RaceLost>(), "unexpected error: {err}");
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(accepts.load(Ordering::SeqCst), 1);
    assert_eq!(
        greetings.load(Ordering::SeqCst),
        0,
        "spoke to the upstream after the win"
    );
}
