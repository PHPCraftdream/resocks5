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
            // pick_order ignores a quarantine when nothing is healthy; a probe
            // must not travel through a node known to be down.
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

    fn proxy(host: &str, rank: u8) -> ProxyConfig {
        ProxyConfig::socks5(host, 1080).with_gate_level(rank)
    }

    fn rotator(proxy: ProxyConfig) -> Arc<ProxyRotator> {
        Arc::new(
            ProxyRotator::try_with_quarantine(
                vec![proxy],
                Default::default(),
                QuarantinePolicy::default()
                    .with_threshold(1)
                    .with_initial(Duration::from_secs(30))
                    .with_max(Duration::from_secs(30)),
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
