//! Probe-level tests for the chain probes: verdict classification
//! (finding D), ownership generation (finding E), checked claim
//! arithmetic (finding F-APP) and capacity accounting (review P2 №5).

use super::probes::{
    claim_instant_plus, classify_probe_error, healthy_prefix, probe_chain, ProbeAttempt,
    ProbeVerdict,
};
use super::tests_chains::config;
use crate::logger::{LogConfig, Logger};
use resocks5_net::chain::GateLevels;
use resocks5_net::connect::ChainStage;
use resocks5_net::error::{ConnectError, Stage, TimeoutKind};
use resocks5_net::pool::{AtCapacity, ProxyPool};
use resocks5_net::rating::QuarantinePolicy;
use resocks5_net::rotator::ProxyRotator;
use resocks5_net::types::{ProxyConfig, ProxyProtocol};
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

fn http_config(addr: std::net::SocketAddr, rank: u8) -> ProxyConfig {
    ProxyConfig::http(addr.ip().to_string(), addr.port()).with_gate_level(rank)
}

fn rotator(proxy: ProxyConfig) -> Arc<ProxyRotator> {
    rotator_with_policy(
        proxy,
        QuarantinePolicy::default()
            .with_threshold(1)
            .with_initial(Duration::from_secs(30))
            .with_max(Duration::from_secs(30)),
    )
}

fn rotator_with_policy(proxy: ProxyConfig, policy: QuarantinePolicy) -> Arc<ProxyRotator> {
    Arc::new(
        ProxyRotator::try_with_quarantine(
            vec![proxy],
            Default::default(),
            policy,
            16,
            Duration::from_secs(60),
        )
        .unwrap(),
    )
}

fn logger() -> Logger {
    let (tx, _) = tokio::sync::mpsc::channel(1);
    Logger::new(tx, LogConfig::default())
}

/// How a success stub holds its method-selection reply back.
pub(super) enum Hold {
    /// Reply after a fixed delay.
    Delay(Duration),
    /// Tell `reached` that the greeting arrived, then reply only once
    /// `release` is notified: the test controls the order of events.
    Barrier {
        reached: tokio::sync::mpsc::Sender<()>,
        release: Arc<tokio::sync::Notify>,
    },
}

/// SOCKS5 stub that completes its handshake only after `hold` and
/// then reports CONNECT success WITHOUT dialing the requested
/// destination. `accepts` counts accepted TCP connections; `done`
/// fires after the success reply is written.
pub(super) async fn spawn_success_stub(
    hold: Hold,
    accepts: Arc<AtomicUsize>,
    done: tokio::sync::mpsc::Sender<()>,
) -> SocketAddr {
    let hold = Arc::new(hold);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                break;
            };
            accepts.fetch_add(1, Ordering::Relaxed);
            let done = done.clone();
            let hold = Arc::clone(&hold);
            tokio::spawn(async move {
                let mut greeting = [0u8; 3];
                if socket.read_exact(&mut greeting).await.is_err() {
                    return;
                }
                match &*hold {
                    Hold::Delay(delay) => tokio::time::sleep(*delay).await,
                    Hold::Barrier { reached, release } => {
                        let _ = reached.send(()).await;
                        release.notified().await;
                    }
                }
                if socket.write_all(&[5, 0]).await.is_err() {
                    return;
                }
                let mut head = [0u8; 4];
                if socket.read_exact(&mut head).await.is_err() || head[3] != 1 {
                    return;
                }
                let mut bound = [0u8; 6];
                if socket.read_exact(&mut bound).await.is_err() {
                    return;
                }
                let _ = socket.write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 0]).await;
                let _ = done.send(()).await;
            });
        }
    });
    addr
}

/// [`spawn_success_stub`] with a fixed delay.
pub(super) async fn spawn_slow_success_stub(
    delay: Duration,
    accepts: Arc<AtomicUsize>,
    done: tokio::sync::mpsc::Sender<()>,
) -> SocketAddr {
    spawn_success_stub(Hold::Delay(delay), accepts, done).await
}

/// SOCKS5 stub that completes the greeting and answers the CONNECT
/// request with `rep` — it never dials the requested destination.
async fn spawn_socks_rep_stub(rep: u8) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let mut greeting = [0u8; 3];
                if socket.read_exact(&mut greeting).await.is_err() {
                    return;
                }
                if socket.write_all(&[5, 0]).await.is_err() {
                    return;
                }
                let mut head = [0u8; 4];
                if socket.read_exact(&mut head).await.is_err() || head[3] != 1 {
                    return;
                }
                let mut bound = [0u8; 6];
                if socket.read_exact(&mut bound).await.is_err() {
                    return;
                }
                let _ = socket.write_all(&[5, rep, 0, 1, 0, 0, 0, 0, 0, 0]).await;
            });
        }
    });
    addr
}

/// HTTP CONNECT stub that answers every request with `status_line`
/// (which must NOT include the final blank line; it is added here).
async fn spawn_http_status_stub(status_line: &str) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let reply = format!("{status_line}\r\n\r\n");
    tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                break;
            };
            let reply = reply.clone();
            tokio::spawn(async move {
                let mut buf = Vec::new();
                let mut chunk = [0u8; 512];
                loop {
                    match socket.read(&mut chunk).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => {
                            buf.extend_from_slice(&chunk[..n]);
                            if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                                break;
                            }
                        }
                    }
                }
                let _ = socket.write_all(reply.as_bytes()).await;
            });
        }
    });
    addr
}

// Finding D classification table: at the target stage ONLY a
// destination-unreachable refusal is a hard failure — SOCKS5 REP 3-6 and
// HTTP 502/503/504. Prefix-proxy policy/auth refusals (REP 2, HTTP 407 /
// 403, malformed status lines, other codes) say nothing about the tested
// node. Mutations: (a) classify every counting target-stage
// ProxyRejected as HardFailure (the pre-fix behaviour — the REP 2 / 407 /
// malformed rows fail), (b) classify nothing as HardFailure (the REP 4/5
// and 502/504 rows fail), (c) widen the SOCKS range (REP 2 row fails).
#[test]
fn classification_only_destination_unreachable_is_a_hard_failure() {
    let rejected = |protocol, code| ConnectError::ProxyRejected {
        protocol,
        code,
        response: String::new(),
    };
    let cap = || {
        ConnectError::AtCapacity(AtCapacity {
            host: "prefix".to_owned(),
            port: 1080,
        })
    };
    for rep in [3u16, 4, 5, 6] {
        assert_eq!(
            classify_probe_error(
                ChainStage::Target,
                &rejected(ProxyProtocol::Socks5, Some(rep))
            ),
            ProbeVerdict::HardFailure,
            "REP {rep} must be a hard failure"
        );
    }
    for rep in [1u16, 2, 7, 8, 256] {
        assert_eq!(
            classify_probe_error(
                ChainStage::Target,
                &rejected(ProxyProtocol::Socks5, Some(rep))
            ),
            ProbeVerdict::Inconclusive,
            "REP {rep} must be inconclusive"
        );
    }
    assert_eq!(
        classify_probe_error(ChainStage::Target, &rejected(ProxyProtocol::Socks5, None)),
        ProbeVerdict::Inconclusive
    );
    for status in [502u16, 503, 504] {
        assert_eq!(
            classify_probe_error(
                ChainStage::Target,
                &rejected(ProxyProtocol::Http, Some(status))
            ),
            ProbeVerdict::HardFailure,
            "HTTP {status} must be a hard failure"
        );
    }
    for status in [403u16, 407, 500, 501, 505] {
        assert_eq!(
            classify_probe_error(
                ChainStage::Target,
                &rejected(ProxyProtocol::Http, Some(status))
            ),
            ProbeVerdict::Inconclusive,
            "HTTP {status} must be inconclusive"
        );
    }
    assert_eq!(
        classify_probe_error(ChainStage::Target, &rejected(ProxyProtocol::Http, None)),
        ProbeVerdict::Inconclusive
    );
    // Non-refusal target-stage errors name the prefix's own handshake.
    let auth = || ConnectError::SecureAuth(resocks5_net::SecureAuthError::Denied);
    let method = || ConnectError::MethodUnsupported {
        got: 0xff,
        with_auth: false,
    };
    let handshake_timeout = || ConnectError::Timeout {
        stage: Stage::Handshake,
        kind: TimeoutKind::Socks5Handshake,
        endpoint: "prefix:1080".to_owned(),
        after: Duration::from_secs(1),
    };
    let io_err = || ConnectError::Io {
        stage: Stage::Connect,
        endpoint: None,
        source: io::Error::from(io::ErrorKind::ConnectionRefused),
    };
    for error in [auth(), method(), handshake_timeout(), io_err()] {
        assert_eq!(
            classify_probe_error(ChainStage::Target, &error),
            ProbeVerdict::Inconclusive,
            "{error:?}"
        );
    }
    // Prefix stages say nothing about the tested node, refusals included.
    for stage in [ChainStage::Connect, ChainStage::Hop(0)] {
        assert_eq!(
            classify_probe_error(stage, &rejected(ProxyProtocol::Socks5, Some(5))),
            ProbeVerdict::Inconclusive
        );
    }
    // Local capacity is never the tested node's fault.
    for stage in [ChainStage::Connect, ChainStage::Hop(0), ChainStage::Target] {
        assert_eq!(
            classify_probe_error(stage, &cap()),
            ProbeVerdict::Inconclusive
        );
    }
}

// Finding D, wire half: a PREFIX proxy's policy/auth refusal (HTTP 407 /
// 403, malformed status line, SOCKS REP 2) must not touch the tested
// node — no connect reaches it and its health record is unchanged.
// Mutation: the pre-fix behaviour (every target-stage ProxyRejected is
// hard): the node re-trips and the trips/consecutive assertions fail.
#[tokio::test]
async fn prefix_policy_refusals_are_inconclusive_for_the_tested_node() {
    for (prefix_addr, http) in [
        (
            spawn_http_status_stub("HTTP/1.1 407 Proxy Authentication Required").await,
            true,
        ),
        (spawn_http_status_stub("HTTP/1.1 403 Forbidden").await, true),
        (
            spawn_http_status_stub("NOSUCH-STATUS-LINE-HERE").await,
            true,
        ),
        (spawn_socks_rep_stub(2).await, false),
    ] {
        let middle_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let middle_addr = middle_listener.local_addr().unwrap();
        let middle = config(middle_addr, 2);
        let middle_rotator = rotator_with_policy(
            middle.clone(),
            QuarantinePolicy::default()
                .with_threshold(1)
                .with_initial(Duration::from_millis(50))
                .with_max(Duration::from_millis(200))
                .with_probe_lease(Duration::from_millis(100)),
        );
        assert_eq!(
            middle_rotator.quarantine_now(&middle),
            Some(Duration::from_millis(50))
        );
        tokio::time::sleep(Duration::from_millis(60)).await;
        let claims = middle_rotator.take_probe_claims();
        assert_eq!(claims.len(), 1);
        let before = middle_rotator.health();

        let prefix_rotator = if http {
            rotator(http_config(prefix_addr, 3))
        } else {
            rotator(config(prefix_addr, 3))
        };
        let gates = GateLevels::new(vec![(3, prefix_rotator), (2, middle_rotator.clone())]);
        let prefix = healthy_prefix(&gates, 2).unwrap();
        let pool = ProxyPool::new(Default::default(), Duration::from_secs(2), 4);
        let claimed = tokio::time::Instant::now();
        probe_chain(ProbeAttempt {
            prefix: &prefix,
            claim: &claims[0],
            rotator: &middle_rotator,
            pool: &pool,
            logger: &logger(),
            handshake_timeout: Duration::from_secs(2),
            tls: None,
            deadline: claimed + Duration::from_secs(5),
        })
        .await;

        // The tested node was never dialed: the listener stays silent.
        assert!(
            tokio::time::timeout(Duration::from_millis(300), middle_listener.accept())
                .await
                .is_err(),
            "an inconclusive probe must not connect to the tested node"
        );
        let after = middle_rotator.health();
        assert_eq!(after[0].health.state, before[0].health.state);
        assert_eq!(after[0].health.trips, before[0].health.trips);
        assert_eq!(after[0].health.consecutive, before[0].health.consecutive);
        assert!(middle_rotator.is_quarantined(&middle));
    }
}

// Finding D, wire half, positive controls: destination-unreachable
// replies (SOCKS REP 4/5, HTTP 502/504) ARE hard failures — the node
// re-trips (trips == 2, next quarantine doubled to 200 ms).
// Mutation: everything inconclusive: trips stays 1.
#[tokio::test]
async fn destination_unreachable_replies_retrip_the_tested_node() {
    for (prefix_addr, http) in [
        (spawn_socks_rep_stub(4).await, false),
        (spawn_socks_rep_stub(5).await, false),
        (
            spawn_http_status_stub("HTTP/1.1 502 Bad Gateway").await,
            true,
        ),
        (
            spawn_http_status_stub("HTTP/1.1 504 Gateway Timeout").await,
            true,
        ),
    ] {
        let unavailable = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dead_addr = unavailable.local_addr().unwrap();
        drop(unavailable);
        let middle = config(dead_addr, 2);
        let middle_rotator = rotator_with_policy(
            middle.clone(),
            QuarantinePolicy::default()
                .with_threshold(1)
                .with_initial(Duration::from_millis(50))
                .with_max(Duration::from_millis(800)),
        );
        assert_eq!(
            middle_rotator.quarantine_now(&middle),
            Some(Duration::from_millis(50))
        );
        tokio::time::sleep(Duration::from_millis(60)).await;
        let claims = middle_rotator.take_probe_claims();
        assert_eq!(claims.len(), 1);

        let prefix_rotator = if http {
            rotator(http_config(prefix_addr, 3))
        } else {
            rotator(config(prefix_addr, 3))
        };
        let gates = GateLevels::new(vec![(3, prefix_rotator), (2, middle_rotator.clone())]);
        let prefix = healthy_prefix(&gates, 2).unwrap();
        let pool = ProxyPool::new(Default::default(), Duration::from_secs(2), 4);
        let claimed = tokio::time::Instant::now();
        probe_chain(ProbeAttempt {
            prefix: &prefix,
            claim: &claims[0],
            rotator: &middle_rotator,
            pool: &pool,
            logger: &logger(),
            handshake_timeout: Duration::from_secs(2),
            tls: None,
            deadline: claimed + Duration::from_secs(5),
        })
        .await;
        assert!(middle_rotator.is_quarantined(&middle));
        assert_eq!(middle_rotator.health()[0].health.trips, 2);
        assert_eq!(
            middle_rotator.quarantine_now(&middle),
            Some(Duration::from_millis(200))
        );
    }
}

// Finding E, wire half: a probe that settles after its slot changed
// hands must be discarded — the reset, the re-trip and the newer probe's
// claim all bump the generation, so P1's late success changes nothing
// and P2's ownership is intact. Mutation: the old time fence removed
// without a generation check (or no fence at all): P1's success clears
// the fresh quarantine (state/trips assertions fail).
#[tokio::test]
async fn stale_settlement_after_a_newer_claim_is_discarded() {
    let accepts = Arc::new(AtomicUsize::new(0));
    let (done_tx, mut done_rx) = tokio::sync::mpsc::channel(1);
    let (reached_tx, mut reached_rx) = tokio::sync::mpsc::channel(1);
    let release = Arc::new(tokio::sync::Notify::new());
    let prefix_addr = spawn_success_stub(
        Hold::Barrier {
            reached: reached_tx,
            release: Arc::clone(&release),
        },
        accepts.clone(),
        done_tx,
    )
    .await;
    let unavailable = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let dead_addr = unavailable.local_addr().unwrap();
    drop(unavailable);
    let middle = config(dead_addr, 2);
    let middle_rotator = rotator_with_policy(
        middle.clone(),
        QuarantinePolicy::default()
            .with_threshold(1)
            .with_initial(Duration::from_millis(50))
            .with_max(Duration::from_millis(200)),
    );
    assert_eq!(
        middle_rotator.quarantine_now(&middle),
        Some(Duration::from_millis(50))
    );
    tokio::time::sleep(Duration::from_millis(60)).await;
    let claims = middle_rotator.take_probe_claims();
    assert_eq!(claims.len(), 1);
    let before = middle_rotator.health();

    let prefix_rotator = rotator(config(prefix_addr, 3));
    let gates = GateLevels::new(vec![(3, prefix_rotator), (2, middle_rotator.clone())]);
    let prefix = healthy_prefix(&gates, 2).unwrap();
    let pool = ProxyPool::new(Default::default(), Duration::from_secs(2), 4);
    let claimed = tokio::time::Instant::now();
    let bump = async {
        // Ordering by events, not by delays: P1 has reached the prefix's
        // CONNECT, THEN the slot changes hands, THEN P2 holds the fresh
        // claim, and only then is P1's reply released.
        reached_rx.recv().await.unwrap();
        middle_rotator.record_success(&middle);
        assert!(middle_rotator.record_hard_failure(&middle).is_some());
        // The re-trip's backoff (50 ms) must run out before P2 can claim.
        let fresh = loop {
            let claims = middle_rotator.take_probe_claims();
            if !claims.is_empty() {
                break claims;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        };
        release.notify_one();
        fresh
    };
    let log = logger();
    let ((), fresh_claims) = tokio::join!(
        probe_chain(ProbeAttempt {
            prefix: &prefix,
            claim: &claims[0],
            rotator: &middle_rotator,
            pool: &pool,
            logger: &log,
            handshake_timeout: Duration::from_secs(2),
            tls: None,
            deadline: claimed + Duration::from_secs(5),
        }),
        bump,
    );
    assert_eq!(fresh_claims.len(), 1, "P2 must claim the re-tripped slot");
    let fresh = &fresh_claims[0];

    // P1's attempt genuinely succeeded (the stub wrote its reply) ...
    tokio::time::timeout(Duration::from_secs(5), done_rx.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(accepts.load(Ordering::Relaxed), 1);
    // ... but its outcome is stale: the fresh quarantine stands.
    let after = middle_rotator.health();
    assert_eq!(after[0].health.state, before[0].health.state);
    assert_eq!(after[0].health.trips, before[0].health.trips);
    assert_eq!(after[0].health.consecutive, before[0].health.consecutive);
    assert!(middle_rotator.is_quarantined(&middle));
    // P2 still owns the slot: its success applies.
    assert!(middle_rotator.record_success_for(fresh));
    assert!(!middle_rotator.is_quarantined(&middle));
}

// Review P2 №5, hold half: the tested node's pool permit is held for the
// whole pending connect — at cap 1 a second reserve fails while the
// probe hangs — and released once the attempt is cancelled by its
// deadline. Mutation: dropping the reserve_permit call (the mid-flight
// reserve then succeeds).
#[tokio::test]
async fn probe_holds_the_pool_permit_while_connecting_and_releases_on_cancel() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let silent_addr = listener.local_addr().unwrap();
    // Accept and hold: the prefix handshake never completes, so the
    // attempt hangs until its deadline cancels it.
    let _held = tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((socket, _)) = listener.accept().await {
            held.push(socket);
        }
    });
    let unavailable = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let dead_addr = unavailable.local_addr().unwrap();
    drop(unavailable);
    let middle = config(dead_addr, 2);
    let middle_rotator = rotator_with_policy(
        middle.clone(),
        QuarantinePolicy::default()
            .with_threshold(1)
            .with_initial(Duration::from_millis(50))
            .with_max(Duration::from_millis(200)),
    );
    assert_eq!(
        middle_rotator.quarantine_now(&middle),
        Some(Duration::from_millis(50))
    );
    tokio::time::sleep(Duration::from_millis(60)).await;
    let claims = middle_rotator.take_probe_claims();
    assert_eq!(claims.len(), 1);
    let before = middle_rotator.health();

    let prefix_rotator = rotator(config(silent_addr, 3));
    let gates = GateLevels::new(vec![(3, prefix_rotator), (2, middle_rotator.clone())]);
    let prefix = healthy_prefix(&gates, 2).unwrap();
    let pool = Arc::new(ProxyPool::new(
        Default::default(),
        Duration::from_secs(2),
        1,
    ));
    let claimed = tokio::time::Instant::now();
    let bump = async {
        // Mid-flight: the probe holds the tested node's only permit.
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(
            pool.reserve_permit(&middle).is_err(),
            "the pending probe must hold the tested node's permit"
        );
    };
    let log = logger();
    let ((), ()) = tokio::join!(
        probe_chain(ProbeAttempt {
            prefix: &prefix,
            claim: &claims[0],
            rotator: &middle_rotator,
            pool: &pool,
            logger: &log,
            handshake_timeout: Duration::from_secs(5),
            tls: None,
            // Cancels the hung attempt ~300 ms in.
            deadline: claimed + Duration::from_millis(300),
        }),
        bump,
    );
    // The cancelled attempt changed nothing ...
    let after = middle_rotator.health();
    assert_eq!(after[0].health.state, before[0].health.state);
    assert_eq!(after[0].health.trips, before[0].health.trips);
    assert_eq!(after[0].health.consecutive, before[0].health.consecutive);
    // ... and released the permit.
    assert!(
        pool.reserve_permit(&middle).is_ok(),
        "the cancelled probe must release the permit"
    );
}

// Finding F-APP: claim arithmetic must never panic on huge config
// timeouts (u64 seconds) — the sum falls back to a far-future instant.
// Mutation: back to `claimed + budget` (panics on overflow).
#[tokio::test]
async fn claim_instant_plus_survives_unrepresentable_sums() {
    let now = tokio::time::Instant::now();
    assert_eq!(claim_instant_plus(now, Duration::ZERO), now);
    let far = claim_instant_plus(now, Duration::MAX);
    assert!(far > now, "a huge budget must still land in the future");
}
