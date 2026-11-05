use std::sync::Arc;
use std::time::Duration;

use tokio_rustls::TlsConnector;

use crate::logger::Logger;
use crate::server::print_cfg;
use resocks5_net::chain::GateLevels;
use resocks5_net::connect::{connect_chain, ChainStage, HostPort};
use resocks5_net::error::ConnectError;
use resocks5_net::pool::ProxyPool;
use resocks5_net::rotator::ProxyRotator;
use resocks5_net::types::ProxyConfig;

pub(super) fn healthy_prefix(gates: &GateLevels, rank: u8) -> Option<ProxyConfig> {
    let mut nodes = Vec::new();
    for (level_rank, rotator) in gates.iter() {
        if level_rank == rank {
            break;
        }
        if level_rank > rank {
            nodes.push(
                rotator
                    .pick_order()
                    .into_iter()
                    .find(|proxy| !rotator.is_quarantined(proxy))?,
            );
        }
    }
    ProxyConfig::chain(nodes)
}

/// What one chain-probe attempt says about the tested node. Success is
/// detected before classification — this enum only grades failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProbeVerdict {
    /// The tested node itself failed: quarantine it again.
    HardFailure,
    /// Prefix failure, local capacity or the probe deadline: no rating
    /// change, the lease expires and the probe is retried later.
    Inconclusive,
}

/// Pure classification of one chain-probe failure (audit V07): only a
/// failure AT the tested node — target stage, error counting against an
/// upstream — is a hard failure. Prefix stages (`Connect`, `Hop`) and
/// local-capacity errors say nothing about the tested node and must not
/// quarantine it.
///
/// Takes the decomposed error because `ChainError` has no constructor
/// outside `resocks5-net`.
fn classify_probe_error(stage: ChainStage, error: &ConnectError) -> ProbeVerdict {
    match stage {
        ChainStage::Target if error.counts_against_upstream() => ProbeVerdict::HardFailure,
        _ => ProbeVerdict::Inconclusive,
    }
}

/// Wall-clock budget of one whole chain probe over `depth` prefix nodes:
/// the single TCP connect plus one handshake per prefix node and the
/// final handshake to the tested node, each handshake bounded by
/// `handshake_timeout`. Startup's probe lease is this value with the
/// worst-case depth plus a 5 s margin; the probe itself runs under this
/// value minus 1 s — one helper so the two budgets cannot diverge
/// (audit V08).
pub(crate) fn probe_deadline(
    connect_timeout: Duration,
    handshake_timeout: Duration,
    depth: usize,
) -> Duration {
    let handshakes = u32::try_from(depth.saturating_add(1)).unwrap_or(u32::MAX);
    connect_timeout.saturating_add(handshake_timeout.saturating_mul(handshakes))
}

#[allow(clippy::too_many_arguments)]
pub(super) fn spawn_chain_probes(
    gates: Arc<GateLevels>,
    exits: Vec<Arc<ProxyRotator>>,
    pool: Arc<ProxyPool>,
    logger: Arc<Logger>,
    connect_timeout: Duration,
    handshake_timeout: Duration,
    tls: Option<TlsConnector>,
) {
    if let Some((_, outermost)) = gates.iter().next() {
        super::route::spawn_due_probes(outermost, &logger, connect_timeout);
    }
    for rotator in &exits {
        super::route::spawn_due_probes(rotator, &logger, connect_timeout);
    }
    for (rank, rotator) in gates.iter().skip(1) {
        for proxy in rotator.take_probes() {
            let (gates, pool, logger, rotator, tls) = (
                gates.clone(),
                pool.clone(),
                logger.clone(),
                rotator.clone(),
                tls.clone(),
            );
            tokio::spawn(async move {
                let Some(prefix) = healthy_prefix(&gates, rank) else {
                    return;
                };
                let deadline =
                    probe_deadline(connect_timeout, handshake_timeout, prefix.nodes().len())
                        .saturating_sub(Duration::from_secs(1));
                probe_chain(
                    &prefix,
                    &proxy,
                    &rotator,
                    &pool,
                    &logger,
                    handshake_timeout,
                    tls.as_ref(),
                    deadline,
                )
                .await;
            });
        }
    }
}

fn outcome(rotator: &ProxyRotator, proxy: &ProxyConfig, success: bool, logger: &Logger) {
    if success {
        rotator.record_success(proxy);
        logger.proxy_failure(|| {
            format!(
                "Upstream {} is reachable again - back in rotation",
                print_cfg(proxy)
            )
        });
    } else if let Some(duration) = rotator.record_hard_failure(proxy) {
        logger.proxy_failure(|| {
            format!(
                "Upstream {} is still unreachable - quarantined for {}s",
                print_cfg(proxy),
                duration.as_secs()
            )
        });
    }
}

#[allow(clippy::too_many_arguments)]
async fn probe_chain(
    cfg: &ProxyConfig,
    proxy: &ProxyConfig,
    rotator: &ProxyRotator,
    pool: &ProxyPool,
    logger: &Logger,
    handshake_timeout: Duration,
    tls: Option<&TlsConnector>,
    deadline: Duration,
) {
    let target = HostPort::format(&proxy.host, proxy.port);
    match tokio::time::timeout(
        deadline,
        connect_chain(cfg, &target, pool, handshake_timeout, tls),
    )
    .await
    {
        // Reachable through the healthy prefix: back in rotation.
        Ok(Ok(_)) => outcome(rotator, proxy, true, logger),
        // The tested node itself failed at the target stage.
        Ok(Err(error))
            if classify_probe_error(error.stage(), error.error()) == ProbeVerdict::HardFailure =>
        {
            outcome(rotator, proxy, false, logger)
        }
        // The whole attempt ran past its deadline: inconclusive, like
        // every other failure that says nothing about the tested node.
        Err(_) => logger.attempt(|| {
            format!(
                "Chain probe of {} inconclusive (probe deadline elapsed); \
                 health unchanged, probe retried later",
                print_cfg(proxy)
            )
        }),
        // Prefix failure or local capacity: blame nobody, let the lease
        // expire and retry later.
        Ok(Err(error)) => logger.attempt(|| {
            format!(
                "Chain probe of {} inconclusive ({error}); \
                 health unchanged, probe retried later",
                print_cfg(proxy)
            )
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::logger::LogConfig;
    use resocks5_net::rating::QuarantinePolicy;
    use tokio::net::TcpListener;

    fn proxy(host: &str, rank: u8) -> ProxyConfig {
        ProxyConfig::socks5(host, 1080).with_gate_level(rank)
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

    #[test]
    fn healthy_prefix_uses_higher_ranks_and_allows_gaps() {
        let outer = proxy("a", 9);
        let middle = proxy("b", 3);
        let gates = GateLevels::new(vec![(9, rotator(outer)), (3, rotator(middle))]);
        let prefix = healthy_prefix(&gates, 3).unwrap();
        let hosts: Vec<_> = prefix
            .chain_nodes()
            .iter()
            .map(|node| node.host.as_str())
            .collect();
        assert_eq!(hosts, ["a"]);
    }

    #[test]
    fn missing_healthy_prefix_skips_probe() {
        let outer = proxy("a", 9);
        let rotator = rotator(outer.clone());
        rotator.quarantine_now(&outer);
        let gates = GateLevels::new(vec![(9, rotator)]);
        assert!(healthy_prefix(&gates, 3).is_none());
    }

    // V07 success path: reachable through the prefix lifts the quarantine.
    #[tokio::test]
    async fn due_chain_probe_forwards_through_healthy_prefix_and_recovers_middle() {
        let (tx, mut requests) = tokio::sync::mpsc::channel(4);
        let outer = super::super::tests_chains::spawn_stub(tx).await;
        let middle_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let middle_addr = middle_listener.local_addr().unwrap();
        let outer_proxy = super::super::tests_chains::config(outer.addr, 3);
        let middle = super::super::tests_chains::config(middle_addr, 2);
        let outer_rotator = rotator(outer_proxy);
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
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(middle_rotator.take_probes().len(), 1);
        let gates = GateLevels::new(vec![(3, outer_rotator), (2, middle_rotator.clone())]);
        let prefix = healthy_prefix(&gates, 2).unwrap();
        let pool = ProxyPool::new(Default::default(), Duration::from_secs(2), 4);
        probe_chain(
            &prefix,
            &middle,
            &middle_rotator,
            &pool,
            &logger(),
            Duration::from_secs(2),
            None,
            Duration::from_secs(5),
        )
        .await;
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(5), requests.recv())
                .await
                .unwrap()
                .unwrap(),
            middle_addr.to_string()
        );
        tokio::time::timeout(Duration::from_secs(5), middle_listener.accept())
            .await
            .unwrap()
            .unwrap();
        assert!(!middle_rotator.is_quarantined(&middle));
    }

    // V07 hard-failure path: the prefix works, the tested node refuses —
    // still quarantines harder.
    #[tokio::test]
    async fn failed_due_probe_keeps_quarantine_and_doubles_duration() {
        let unavailable = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = unavailable.local_addr().unwrap();
        drop(unavailable);
        let (tx, _requests) = tokio::sync::mpsc::channel(4);
        let outer = super::super::tests_chains::spawn_stub(tx).await;
        let outer_proxy = super::super::tests_chains::config(outer.addr, 3);
        let middle = super::super::tests_chains::config(addr, 2);
        let outer_rotator = rotator(outer_proxy);
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
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(middle_rotator.take_probes().len(), 1);
        let gates = GateLevels::new(vec![(3, outer_rotator), (2, middle_rotator.clone())]);
        let prefix = healthy_prefix(&gates, 2).unwrap();
        let pool = ProxyPool::new(Default::default(), Duration::from_secs(2), 4);
        probe_chain(
            &prefix,
            &middle,
            &middle_rotator,
            &pool,
            &logger(),
            Duration::from_secs(2),
            None,
            Duration::from_secs(5),
        )
        .await;
        assert!(middle_rotator.is_quarantined(&middle));
        assert!(middle_rotator.take_probes().is_empty());
        assert_eq!(
            middle_rotator.quarantine_now(&middle),
            Some(Duration::from_millis(200))
        );
    }

    #[test]
    fn outcome_success_clears_quarantine_and_failure_requarantines() {
        let proxy = proxy("a", 9);
        let rotator = rotator(proxy.clone());
        let logger = logger();
        rotator.quarantine_now(&proxy);
        outcome(&rotator, &proxy, true, &logger);
        assert!(!rotator.is_quarantined(&proxy));
        outcome(&rotator, &proxy, false, &logger);
        assert!(rotator.is_quarantined(&proxy));
    }

    // V07 classification table: only a target-stage error that counts
    // against an upstream blames the tested node. Mutation: classify
    // every stage as HardFailure (the old `.is_ok()` behaviour).
    #[test]
    fn classification_only_target_stage_counting_errors_are_hard_failures() {
        use resocks5_net::error::Stage;
        use resocks5_net::pool::AtCapacity;
        use std::io;

        let refused = || ConnectError::Io {
            stage: Stage::Connect,
            endpoint: None,
            source: io::Error::from(io::ErrorKind::ConnectionRefused),
        };
        let cap = || {
            ConnectError::AtCapacity(AtCapacity {
                host: "prefix".to_owned(),
                port: 1080,
            })
        };
        // Target-stage upstream-down error: the tested node failed.
        assert_eq!(
            classify_probe_error(ChainStage::Target, &refused()),
            ProbeVerdict::HardFailure
        );
        // Local capacity is never the tested node's fault.
        for stage in [ChainStage::Connect, ChainStage::Hop(0), ChainStage::Target] {
            assert_eq!(
                classify_probe_error(stage, &cap()),
                ProbeVerdict::Inconclusive
            );
        }
        // Prefix stages say nothing about the tested node.
        for stage in [ChainStage::Connect, ChainStage::Hop(0)] {
            assert_eq!(
                classify_probe_error(stage, &refused()),
                ProbeVerdict::Inconclusive
            );
        }
    }

    // V07 integration: a failing prefix must leave the tested node on
    // probation untouched. Mutation: restore `.is_ok()` — the
    // Connect-stage refusal would become a hard failure and change the
    // snapshot.
    #[tokio::test]
    async fn inconclusive_prefix_failure_leaves_tested_node_health_unchanged() {
        let unreachable = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dead_addr = unreachable.local_addr().unwrap();
        drop(unreachable);
        let middle = super::super::tests_chains::config(dead_addr, 2);
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
        assert_eq!(middle_rotator.take_probes().len(), 1);
        let before = middle_rotator.health();

        let outer_rotator = rotator(super::super::tests_chains::config(dead_addr, 3));
        let gates = GateLevels::new(vec![(3, outer_rotator), (2, middle_rotator.clone())]);
        let prefix = healthy_prefix(&gates, 2).unwrap();
        let pool = ProxyPool::new(Default::default(), Duration::from_secs(2), 4);
        probe_chain(
            &prefix,
            &middle,
            &middle_rotator,
            &pool,
            &logger(),
            Duration::from_secs(2),
            None,
            Duration::from_millis(500),
        )
        .await;

        let after = middle_rotator.health();
        assert_eq!(after[0].health.state, before[0].health.state);
        assert_eq!(after[0].health.trips, before[0].health.trips);
        assert_eq!(after[0].health.consecutive, before[0].health.consecutive);
        assert!(middle_rotator.is_quarantined(&middle));
        // The lease simply expires and the probe is handed out again.
        tokio::time::sleep(Duration::from_millis(150)).await;
        assert_eq!(middle_rotator.take_probes().len(), 1);
    }

    // V08: the lease covers the worst-case depth plus a margin, the probe
    // deadline the actual depth minus a margin. Mutations: drop a term
    // from the formula, or one of the 5 s / 1 s margins.
    #[test]
    fn probe_deadline_stays_below_lease_for_several_depths() {
        let connect = Duration::from_secs(10);
        let handshake = Duration::from_secs(9);
        assert_eq!(
            probe_deadline(connect, handshake, 0),
            Duration::from_secs(19)
        );
        assert_eq!(
            probe_deadline(connect, handshake, 1),
            Duration::from_secs(28)
        );
        assert_eq!(
            probe_deadline(connect, handshake, 5),
            Duration::from_secs(64)
        );
        let lease = probe_deadline(connect, handshake, 6).saturating_add(Duration::from_secs(5));
        for depth in 0..=6 {
            let deadline =
                probe_deadline(connect, handshake, depth).saturating_sub(Duration::from_secs(1));
            assert!(
                deadline < lease,
                "depth {depth}: deadline {deadline:?} must be below lease {lease:?}"
            );
        }
    }

    // V08: saturating arithmetic instead of panics on extreme inputs.
    #[test]
    fn probe_deadline_saturates_on_huge_and_zero_inputs() {
        let deadline = probe_deadline(Duration::MAX, Duration::MAX, usize::MAX);
        assert_eq!(deadline, Duration::MAX);
        let lease = deadline.saturating_add(Duration::from_secs(5));
        assert!(deadline.saturating_sub(Duration::from_secs(1)) < lease);
        assert_eq!(
            probe_deadline(Duration::ZERO, Duration::ZERO, 3),
            Duration::ZERO
        );
        // The caller-side 1 s margin saturates instead of underflowing.
        assert_eq!(
            probe_deadline(Duration::ZERO, Duration::ZERO, 3)
                .saturating_sub(Duration::from_secs(1)),
            Duration::ZERO
        );
    }

    // V08 integration: the whole-attempt deadline cancels a silent prefix
    // and leaves the tested node untouched. Mutation: drop the timeout —
    // the probe then hits the 5 s handshake timeout, whose target-stage
    // error counts as a hard failure.
    #[tokio::test]
    async fn probe_deadline_cancels_silent_prefix_and_keeps_health_unchanged() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let silent_addr = listener.local_addr().unwrap();
        // Hold accepted sockets open so the handshake hangs until the
        // deadline cancels the whole attempt.
        let _held = tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((socket, _)) = listener.accept().await {
                held.push(socket);
            }
        });
        let unavailable = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dead_addr = unavailable.local_addr().unwrap();
        drop(unavailable);
        let middle = super::super::tests_chains::config(dead_addr, 2);
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
        assert_eq!(middle_rotator.take_probes().len(), 1);
        let before = middle_rotator.health();

        let outer_rotator = rotator(super::super::tests_chains::config(silent_addr, 3));
        let gates = GateLevels::new(vec![(3, outer_rotator), (2, middle_rotator.clone())]);
        let prefix = healthy_prefix(&gates, 2).unwrap();
        let pool = ProxyPool::new(Default::default(), Duration::from_secs(2), 4);
        let start = std::time::Instant::now();
        probe_chain(
            &prefix,
            &middle,
            &middle_rotator,
            &pool,
            &logger(),
            Duration::from_secs(5),
            None,
            Duration::from_millis(200),
        )
        .await;
        assert!(start.elapsed() < Duration::from_secs(3));
        let after = middle_rotator.health();
        assert_eq!(after[0].health.state, before[0].health.state);
        assert_eq!(after[0].health.trips, before[0].health.trips);
        assert_eq!(after[0].health.consecutive, before[0].health.consecutive);
    }
}
