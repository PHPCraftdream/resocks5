use std::sync::Arc;
use std::time::Duration;

use tokio_rustls::TlsConnector;

use crate::logger::Logger;
use crate::server::print_cfg;
use resocks5_net::chain::GateLevels;
use resocks5_net::connect::{connect_chain, HostPort};
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
                probe_chain(
                    &prefix,
                    &proxy,
                    &rotator,
                    &pool,
                    &logger,
                    handshake_timeout,
                    tls.as_ref(),
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

async fn probe_chain(
    cfg: &ProxyConfig,
    proxy: &ProxyConfig,
    rotator: &ProxyRotator,
    pool: &ProxyPool,
    logger: &Logger,
    handshake_timeout: Duration,
    tls: Option<&TlsConnector>,
) {
    let target = HostPort::format(&proxy.host, proxy.port);
    let success = connect_chain(cfg, &target, pool, handshake_timeout, tls)
        .await
        .is_ok();
    outcome(rotator, proxy, success, logger);
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
}
