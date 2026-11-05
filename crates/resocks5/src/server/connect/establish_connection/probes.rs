use std::sync::Arc;
use std::time::Duration;

use tokio_rustls::TlsConnector;

use crate::logger::Logger;
use crate::server::print_cfg;
use resocks5_net::chain::GateLevels;
use resocks5_net::connect::{connect_chain, ChainStage, HostPort};
use resocks5_net::error::ConnectError;
use resocks5_net::pool::ProxyPool;
use resocks5_net::rotator::{ProxyRotator, UpstreamProbeClaim};
use resocks5_net::types::{ProxyConfig, ProxyProtocol};

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
pub(super) enum ProbeVerdict {
    /// The tested node itself failed: quarantine it again.
    HardFailure,
    /// Prefix failure, local capacity or the probe deadline: no rating
    /// change, the lease expires and the probe is retried later.
    Inconclusive,
}

/// Pure classification of one chain-probe failure (audit V07, review P2
/// №3, finding D): the target stage covers the WHOLE handshake of the
/// last prefix node — its greeting, auth, TLS and its CONNECT to the
/// tested node — so a refusal there can name the prefix's own policy
/// instead of the tested node. Only destination-unreachable replies are
/// evidence about the tested node itself: SOCKS5 REP 3-6 (network/host
/// unreachable, refused, TTL expired) and HTTP 502/503/504. Everything
/// else — 407/403 auth or policy refusals, malformed status lines
/// (`code: None`), SOCKS REP 2 (ruleset), any other code — is the prefix
/// proxy's business: inconclusive.
///
/// Takes the decomposed error because `ChainError` has no constructor
/// outside `resocks5-net`.
pub(super) fn classify_probe_error(stage: ChainStage, error: &ConnectError) -> ProbeVerdict {
    let ConnectError::ProxyRejected { protocol, code, .. } = error else {
        return ProbeVerdict::Inconclusive;
    };
    match stage {
        ChainStage::Target => match protocol {
            ProxyProtocol::Socks5 => {
                if matches!(code, Some(3..=6)) {
                    ProbeVerdict::HardFailure
                } else {
                    ProbeVerdict::Inconclusive
                }
            }
            ProxyProtocol::Http | ProxyProtocol::Https => {
                if matches!(code, Some(502..=504)) {
                    ProbeVerdict::HardFailure
                } else {
                    ProbeVerdict::Inconclusive
                }
            }
        },
        _ => ProbeVerdict::Inconclusive,
    }
}

/// Wall-clock budget of one whole chain probe over `depth` prefix nodes:
/// the single TCP connect plus one handshake per prefix node and the
/// final handshake to the tested node, each handshake bounded by
/// `handshake_timeout`. The probe itself runs under this value minus 1 s
/// from its claim instant; the lease is this value plus
/// [`PROBE_LEASE_MARGIN`] — one helper pair so the two budgets cannot
/// diverge (audit V08).
pub(crate) fn probe_deadline(
    connect_timeout: Duration,
    handshake_timeout: Duration,
    depth: usize,
) -> Duration {
    let handshakes = u32::try_from(depth.saturating_add(1)).unwrap_or(u32::MAX);
    connect_timeout.saturating_add(handshake_timeout.saturating_mul(handshakes))
}

/// `instant + duration` with a far-future stand-in when the sum leaves
/// the `Instant` range (finding F-APP): config timeouts are u64 seconds,
/// and a huge `handshake_timeout`/`connect_timeout` must not panic the
/// probe scheduler.
pub(super) fn claim_instant_plus(
    instant: tokio::time::Instant,
    duration: Duration,
) -> tokio::time::Instant {
    const FAR: Duration = Duration::from_secs(100 * 365 * 24 * 3600);
    instant
        .checked_add(duration)
        .or_else(|| instant.checked_add(FAR))
        .unwrap_or(instant)
}

/// Margin between a probe's own budget and its lease (review P2 №4): an
/// attempt must finish this long before its lease expires, so one
/// attempt can never outlive the lease it claims. Shared with startup,
/// which derives the quarantine policy's lease from the same helper; the margin keeps one attempt from outliving its lease.
pub(crate) const PROBE_LEASE_MARGIN: Duration = Duration::from_secs(5);

/// Lease one claimed probe owns: the worst-case budget over `depth`
/// prefix nodes plus [`PROBE_LEASE_MARGIN`]. Startup derives the
/// quarantine policy's lease from the gate-level count with this
/// helper; the probe budget stays below it by construction, so a
/// settled attempt can never have outrun its lease (review P2 №4).
pub(crate) fn probe_lease(
    connect_timeout: Duration,
    handshake_timeout: Duration,
    depth: usize,
) -> Duration {
    probe_deadline(connect_timeout, handshake_timeout, depth).saturating_add(PROBE_LEASE_MARGIN)
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
        super::route::spawn_due_probes(outermost, &pool, &logger, connect_timeout);
    }
    for rotator in &exits {
        super::route::spawn_due_probes(rotator, &pool, &logger, connect_timeout);
    }
    for (rank, rotator) in gates.iter().skip(1) {
        // The attempt budget runs from the claim: read the clock BEFORE
        // take_probe_claims so a delayed task start cannot stretch the
        // attempt (review P2 №4).
        let claimed = tokio::time::Instant::now();
        for claim in rotator.take_probe_claims() {
            let (gates, pool, logger, rotator, tls) = (
                gates.clone(),
                pool.clone(),
                logger.clone(),
                rotator.clone(),
                tls.clone(),
            );
            // Detached by design: the probe outlives this spawner and
            // reports only through the rotator's generation-checked
            // claims (finding E), so no handle is kept.
            tokio::spawn(async move {
                let Some(prefix) = healthy_prefix(&gates, rank) else {
                    return;
                };
                let budget =
                    probe_deadline(connect_timeout, handshake_timeout, prefix.nodes().len())
                        .saturating_sub(Duration::from_secs(1));
                let deadline = claim_instant_plus(claimed, budget);
                probe_chain(ProbeAttempt {
                    prefix: &prefix,
                    claim: &claim,
                    rotator: &rotator,
                    pool: &pool,
                    logger: &logger,
                    handshake_timeout,
                    tls: tls.as_ref(),
                    deadline,
                })
                .await;
            });
        }
    }
}

/// Apply a settled probe outcome through its claim: the outcome counts
/// only while the claim still owns the slot (finding E). Returns `true`
/// when it was applied. A recovery is a lifecycle event, not a failure
/// (CC-10/GA-05) — only the re-quarantine goes to the failure channel.
fn outcome(
    rotator: &ProxyRotator,
    claim: &UpstreamProbeClaim,
    success: bool,
    logger: &Logger,
) -> bool {
    let proxy = &claim.proxy;
    if success {
        if !rotator.record_success_for(claim) {
            return false;
        }
        logger.lifecycle(|| {
            format!(
                "Upstream {} is reachable again - back in rotation",
                print_cfg(proxy)
            )
        });
        true
    } else if let Some(duration) = rotator.record_hard_failure_for(claim) {
        logger.proxy_failure(|| {
            format!(
                "Upstream {} is still unreachable - quarantined for {}s",
                print_cfg(proxy),
                duration.as_secs()
            )
        });
        true
    } else {
        false
    }
}

/// One chain-probe attempt with its budget (review P2 №4 + finding E):
/// `deadline` is an absolute instant derived from the claim, bounding the
/// work; the outcome is applied through `claim`, whose generation check
/// replaces the old time fence — a slot that changed hands while the
/// attempt ran discards the result instead of rating it.
pub(super) struct ProbeAttempt<'a> {
    pub(super) prefix: &'a ProxyConfig,
    pub(super) claim: &'a UpstreamProbeClaim,
    pub(super) rotator: &'a ProxyRotator,
    pub(super) pool: &'a ProxyPool,
    pub(super) logger: &'a Logger,
    pub(super) handshake_timeout: Duration,
    pub(super) tls: Option<&'a TlsConnector>,
    pub(super) deadline: tokio::time::Instant,
}

pub(super) async fn probe_chain(params: ProbeAttempt<'_>) {
    let ProbeAttempt {
        prefix,
        claim,
        rotator,
        pool,
        logger,
        handshake_timeout,
        tls,
        deadline,
    } = params;
    let proxy = &claim.proxy;
    // The tested node is this probe's CONNECT target: hold one cap
    // permit for it, like a real connection, until the probe settles
    // (review P2 №5). At capacity is our own load, not the node's
    // fault: defer without a rating change.
    let _permit = match pool.reserve_permit(proxy) {
        Ok(permit) => permit,
        Err(error) => {
            logger.attempt(|| {
                format!(
                    "Chain probe of {} inconclusive ({error}); \
                     health unchanged, probe retried later",
                    print_cfg(proxy)
                )
            });
            return;
        }
    };
    let target = HostPort::format(&proxy.host, proxy.port);
    let attempt = tokio::time::timeout_at(
        deadline,
        connect_chain(prefix, &target, pool, handshake_timeout, tls),
    )
    .await;
    match attempt {
        // Reachable through the healthy prefix: back in rotation.
        Ok(Ok(_)) => {
            if !outcome(rotator, claim, true, logger) {
                stale_result_discarded(logger, proxy);
            }
        }
        // The tested node could not reach its destination: quarantine it
        // again.
        Ok(Err(error))
            if classify_probe_error(error.stage(), error.error()) == ProbeVerdict::HardFailure =>
        {
            if !outcome(rotator, claim, false, logger) {
                stale_result_discarded(logger, proxy);
            }
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
        // Prefix failure (its own handshake included) or local capacity:
        // blame nobody, let the lease expire and retry later.
        Ok(Err(error)) => logger.attempt(|| {
            format!(
                "Chain probe of {} inconclusive ({error}); \
                 health unchanged, probe retried later",
                print_cfg(proxy)
            )
        }),
    }
}

/// A settled result whose slot changed hands meanwhile: dropped.
fn stale_result_discarded(logger: &Logger, proxy: &ProxyConfig) {
    logger.attempt(|| {
        format!(
            "Chain probe of {} settled stale - result discarded, \
             health unchanged",
            print_cfg(proxy)
        )
    });
}

#[cfg(test)]
mod tests {
    use super::super::probes_tests::spawn_slow_success_stub;
    use super::*;
    use crate::logger::LogConfig;
    use resocks5_net::rating::QuarantinePolicy;
    use std::sync::atomic::{AtomicUsize, Ordering};
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

    // V07 success path, review P2 №4: settled well inside the lease —
    // reachable through the prefix lifts the quarantine.
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
        let claims = middle_rotator.take_probe_claims();
        assert_eq!(claims.len(), 1);
        let gates = GateLevels::new(vec![(3, outer_rotator), (2, middle_rotator.clone())]);
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

    // V07 hard-failure path: the prefix works, the tested node answers
    // the prefix's CONNECT with a SOCKS5 refusal (REP 5) — still
    // quarantines harder.
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
        let claims = middle_rotator.take_probe_claims();
        assert_eq!(claims.len(), 1);
        let gates = GateLevels::new(vec![(3, outer_rotator), (2, middle_rotator.clone())]);
        let prefix = healthy_prefix(&gates, 2).unwrap();
        let pool = ProxyPool::new(Default::default(), Duration::from_secs(2), 4);
        let claimed = tokio::time::Instant::now();
        probe_chain(ProbeAttempt {
            prefix: &prefix,
            claim: &claims[0],
            rotator: &middle_rotator,
            pool: &pool,
            logger: &logger(),
            // Windows answers a refused loopback connect only after ~2 s: the
            // handshake budget must outlast it, or the refusal reaches the
            // probe as a timeout (inconclusive) instead of a REP 5.
            handshake_timeout: Duration::from_secs(10),
            tls: None,
            deadline: claimed + Duration::from_secs(20),
        })
        .await;
        assert!(middle_rotator.is_quarantined(&middle));
        assert!(middle_rotator.take_probes().is_empty());
        assert_eq!(
            middle_rotator.quarantine_now(&middle),
            Some(Duration::from_millis(200))
        );
    }

    // Finding E: outcomes apply only through the live claim; a consumed
    // claim is stale and must change nothing the second time. Mutation:
    // remove the generation check (the second outcome call would
    // re-quarantine and the assertion on is_quarantined fails).
    #[test]
    fn outcome_applies_only_through_the_live_claim() {
        let proxy = proxy("a", 9);
        let rotator = rotator(proxy.clone());
        let logger = logger();
        rotator.quarantine_now(&proxy);
        let claims = rotator.take_probe_claims();
        assert_eq!(claims.len(), 1);
        assert!(outcome(&rotator, &claims[0], true, &logger));
        assert!(!rotator.is_quarantined(&proxy));
        assert!(!outcome(&rotator, &claims[0], false, &logger));
        assert!(!rotator.is_quarantined(&proxy));
        // A fresh claim after a re-trip applies again.
        rotator.quarantine_now(&proxy);
        let claims = rotator.take_probe_claims();
        assert_eq!(claims.len(), 1);
        assert!(outcome(&rotator, &claims[0], false, &logger));
        assert!(rotator.is_quarantined(&proxy));
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
        let claims = middle_rotator.take_probe_claims();
        assert_eq!(claims.len(), 1);
        let before = middle_rotator.health();

        let outer_rotator = rotator(super::super::tests_chains::config(dead_addr, 3));
        let gates = GateLevels::new(vec![(3, outer_rotator), (2, middle_rotator.clone())]);
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
            deadline: claimed + Duration::from_millis(500),
        })
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

    // V08 + review P2 №4: the lease covers the worst-case depth plus the
    // shared margin, the probe deadline the actual depth minus 1 s — one
    // helper pair so startup's lease and the settlement fence cannot
    // diverge. Mutations: drop a term from the formula, or one of the
    // margins.
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
        assert_eq!(probe_lease(connect, handshake, 0), Duration::from_secs(24));
        assert_eq!(probe_lease(connect, handshake, 6), Duration::from_secs(78));
        let lease = probe_lease(connect, handshake, 6);
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
        assert_eq!(
            probe_lease(Duration::MAX, Duration::MAX, usize::MAX),
            Duration::MAX
        );
        assert!(deadline.saturating_sub(Duration::from_secs(1)) < Duration::MAX);
        assert_eq!(
            probe_deadline(Duration::ZERO, Duration::ZERO, 3),
            Duration::ZERO
        );
        assert_eq!(
            probe_lease(Duration::ZERO, Duration::ZERO, 3),
            Duration::from_secs(5)
        );
        // The caller-side 1 s margin saturates instead of underflowing.
        assert_eq!(
            probe_deadline(Duration::ZERO, Duration::ZERO, 3)
                .saturating_sub(Duration::from_secs(1)),
            Duration::ZERO
        );
    }

    // V08 integration: the whole-attempt deadline cancels a silent
    // prefix and leaves the tested node untouched (review P2 №3: the
    // handshake timeout lands at the target stage but classifies
    // inconclusive anyway). Mutation: drop the timeout — the probe then
    // hangs out the 5 s handshake timeout, caught by the elapsed bound.
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
        let claims = middle_rotator.take_probe_claims();
        assert_eq!(claims.len(), 1);
        let before = middle_rotator.health();

        let outer_rotator = rotator(super::super::tests_chains::config(silent_addr, 3));
        let gates = GateLevels::new(vec![(3, outer_rotator), (2, middle_rotator.clone())]);
        let prefix = healthy_prefix(&gates, 2).unwrap();
        let pool = ProxyPool::new(Default::default(), Duration::from_secs(2), 4);
        let start = std::time::Instant::now();
        let claimed = tokio::time::Instant::now();
        probe_chain(ProbeAttempt {
            prefix: &prefix,
            claim: &claims[0],
            rotator: &middle_rotator,
            pool: &pool,
            logger: &logger(),
            handshake_timeout: Duration::from_secs(5),
            tls: None,
            deadline: claimed + Duration::from_millis(200),
        })
        .await;
        assert!(start.elapsed() < Duration::from_secs(3));
        let after = middle_rotator.health();
        assert_eq!(after[0].health.state, before[0].health.state);
        assert_eq!(after[0].health.trips, before[0].health.trips);
        assert_eq!(after[0].health.consecutive, before[0].health.consecutive);
    }

    // Review P2 №5: the tested node is the probe's CONNECT target — its
    // pool permit must be reserved like a real connection's and held
    // until the probe settles. With the cap filled the probe makes NO
    // connection (defer: no rating change, lease expires, retried
    // later); after release it runs and the success lifts the
    // quarantine. Mutation: drop the reserve_permit call (the probe
    // then bypasses the endpoint cap and connects while it is full).
    #[tokio::test]
    async fn capacity_of_tested_node_defers_the_probe() {
        let accepts = Arc::new(AtomicUsize::new(0));
        let (done_tx, mut done_rx) = tokio::sync::mpsc::channel(1);
        let prefix_addr = spawn_slow_success_stub(Duration::ZERO, accepts.clone(), done_tx).await;
        let unavailable = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dead_addr = unavailable.local_addr().unwrap();
        drop(unavailable);
        let middle = super::super::tests_chains::config(dead_addr, 2);
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
        // Per-upstream cap 1, filled by a held permit for the tested
        // node — no connection involved.
        let pool = Arc::new(ProxyPool::new(
            Default::default(),
            Duration::from_secs(2),
            1,
        ));
        let held = pool.reserve_permit(&middle).unwrap();
        let outer_rotator = rotator(super::super::tests_chains::config(prefix_addr, 3));
        let gates = GateLevels::new(vec![(3, outer_rotator), (2, middle_rotator.clone())]);
        let prefix = healthy_prefix(&gates, 2).unwrap();
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
        // At capacity: nothing connected and health is untouched.
        assert_eq!(accepts.load(Ordering::Relaxed), 0);
        let after = middle_rotator.health();
        assert_eq!(after[0].health.state, before[0].health.state);
        assert_eq!(after[0].health.trips, before[0].health.trips);
        assert_eq!(after[0].health.consecutive, before[0].health.consecutive);
        assert!(middle_rotator.is_quarantined(&middle));
        assert!(
            tokio::time::timeout(Duration::from_millis(200), done_rx.recv())
                .await
                .is_err()
        );
        // Release the cap: the probe runs and recovers the node.
        drop(held);
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
        tokio::time::timeout(Duration::from_secs(5), done_rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(accepts.load(Ordering::Relaxed), 1);
        assert!(!middle_rotator.is_quarantined(&middle));
    }

    // Review P2 №4 absolute deadline: the attempt budget runs from the
    // CLAIM, so a stale claim only gets the remainder. The prefix here
    // is silent (accepts, never answers); the claim below is 1 s in the
    // past with a 300 ms budget, i.e. the deadline expired ~700 ms
    // before the call — the attempt must be cancelled almost at once
    // and leave health unchanged. Mutations: measure the deadline from
    // call start (a relative timeout — the attempt then runs ~300 ms)
    // or drop the deadline entirely (the 5 s handshake timeout bites).
    #[tokio::test]
    async fn deadline_is_measured_from_the_claim() {
        let unavailable = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dead_addr = unavailable.local_addr().unwrap();
        drop(unavailable);
        let middle = super::super::tests_chains::config(dead_addr, 2);
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
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let silent_addr = listener.local_addr().unwrap();
        // Hold accepted sockets open so the handshake hangs until the
        // (already past) deadline cancels the whole attempt.
        let _held = tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((socket, _)) = listener.accept().await {
                held.push(socket);
            }
        });
        let outer_rotator = rotator(super::super::tests_chains::config(silent_addr, 3));
        let gates = GateLevels::new(vec![(3, outer_rotator), (2, middle_rotator.clone())]);
        let prefix = healthy_prefix(&gates, 2).unwrap();
        let pool = ProxyPool::new(Default::default(), Duration::from_secs(2), 4);
        let claimed =
            tokio::time::Instant::from_std(std::time::Instant::now() - Duration::from_secs(1));
        let start = tokio::time::Instant::now();
        probe_chain(ProbeAttempt {
            prefix: &prefix,
            claim: &claims[0],
            rotator: &middle_rotator,
            pool: &pool,
            logger: &logger(),
            handshake_timeout: Duration::from_secs(5),
            tls: None,
            deadline: claimed + Duration::from_millis(300),
        })
        .await;
        assert!(start.elapsed() < Duration::from_millis(150));
        let after = middle_rotator.health();
        assert_eq!(after[0].health.state, before[0].health.state);
        assert_eq!(after[0].health.trips, before[0].health.trips);
        assert_eq!(after[0].health.consecutive, before[0].health.consecutive);
        assert!(middle_rotator.is_quarantined(&middle));
    }
}
