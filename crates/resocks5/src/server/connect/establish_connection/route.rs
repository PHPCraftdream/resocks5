use crate::logger::Logger;
use crate::server::print_cfg;
use resocks5_net::pool::ProxyPool;
use resocks5_net::rotator::ProxyRotator;
use resocks5_net::types::ProxyConfig;
use resocks5_net::ConnectError;
use std::sync::Arc;

#[cfg(test)]
pub(super) fn should_record_failure(err: &anyhow::Error) -> bool {
    if err
        .downcast_ref::<resocks5_net::pool::AtCapacity>()
        .is_some()
    {
        return false;
    }
    err.downcast_ref::<ConnectError>()
        .is_none_or(ConnectError::counts_against_upstream)
}

pub(super) fn should_record_connect_failure(err: &ConnectError) -> bool {
    err.counts_against_upstream()
}
#[cfg(test)]
pub(super) fn is_hard_failure(err: &anyhow::Error) -> bool {
    err.downcast_ref::<ConnectError>()
        .is_some_and(ConnectError::is_upstream_down)
}
pub(super) fn record_proxy_failure(
    rotator: &ProxyRotator,
    proxy: &Arc<ProxyConfig>,
    error: &ConnectError,
    logger: &Logger,
    ctag: &str,
) {
    if !should_record_connect_failure(error) {
        return;
    }
    if let Some(length) = rotator.record_error(proxy, error) {
        logger.proxy_failure(|| {
            format!(
                "Upstream {} is unreachable - quarantined for {}s{}",
                print_cfg(proxy),
                length.as_secs(),
                ctag
            )
        });
    }
}
pub(crate) fn spawn_due_probes(
    rotator: &Arc<ProxyRotator>,
    pool: &Arc<ProxyPool>,
    logger: &Arc<Logger>,
    connect_timeout: std::time::Duration,
) {
    let rotator = rotator.clone();
    let pool = pool.clone();
    let logger = logger.clone();
    tokio::spawn(async move {
        // At capacity the probe is deferred (review P2 №5): the endpoint
        // is saturated by real traffic, so connecting anyway would distort
        // the cap and a failure there would blame the upstream for our own
        // load.
        let reserve = move |proxy: &ProxyConfig| pool.reserve_permit(proxy).ok();
        for event in rotator.probe_due_with(connect_timeout, reserve).await {
            match event {
                resocks5_net::rotator::ProbeEvent::Recovered { proxy } => {
                    logger.proxy_failure(|| {
                        format!(
                            "Upstream {} is reachable again - back in rotation",
                            print_cfg(&proxy)
                        )
                    })
                }
                resocks5_net::rotator::ProbeEvent::StillDown {
                    proxy,
                    quarantined_for,
                    reason,
                } => logger.proxy_failure(|| {
                    format!(
                        "Upstream {} is still unreachable ({}) - quarantined for {}s",
                        print_cfg(&proxy),
                        reason,
                        quarantined_for.as_secs()
                    )
                }),
                _ => {}
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::spawn_due_probes;
    use crate::logger::{LogConfig, Logger};
    use resocks5_net::pool::ProxyPool;
    use resocks5_net::rating::QuarantinePolicy;
    use resocks5_net::rotator::ProxyRotator;
    use resocks5_net::types::ProxyConfig;
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::net::TcpListener;

    fn logger() -> Arc<Logger> {
        let (tx, _) = tokio::sync::mpsc::channel(1);
        Arc::new(Logger::new(tx, LogConfig::default()))
    }

    /// Review P2 №5, direct half: at capacity the due probe is deferred —
    /// no connection reaches the endpoint, nothing is rated — and once the
    /// permit is gone (and the probe lease expired) the next due probe
    /// connects and recovers the upstream. Mutation caught: probing
    /// without the pool cap would connect while the cap is consumed.
    #[tokio::test]
    async fn spawn_due_probes_defers_at_capacity_and_recovers_once_free() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let address = listener.local_addr().unwrap();
        let proxy = ProxyConfig::socks5("127.0.0.1", address.port());
        let rotator = Arc::new(
            ProxyRotator::try_with_quarantine(
                vec![proxy.clone()],
                Default::default(),
                QuarantinePolicy::default()
                    .with_threshold(1)
                    .with_initial(Duration::from_millis(300))
                    .with_max(Duration::from_millis(300))
                    .with_probe_lease(Duration::from_millis(300)),
                16,
                Duration::from_secs(60),
            )
            .unwrap(),
        );
        assert_eq!(
            rotator.quarantine_now(&proxy),
            Some(Duration::from_millis(300))
        );
        tokio::time::sleep(Duration::from_millis(400)).await;

        let pool = Arc::new(ProxyPool::new(
            Default::default(),
            Duration::from_secs(2),
            1,
        ));
        let permit = pool.reserve_permit(&proxy).unwrap();

        spawn_due_probes(&rotator, &pool, &logger(), Duration::from_secs(1));
        assert!(
            tokio::time::timeout(Duration::from_millis(200), listener.accept())
                .await
                .is_err(),
            "a capacity-deferred probe must not connect"
        );
        assert!(rotator.is_quarantined(&proxy));
        assert_eq!(rotator.health()[0].health.trips, 1);

        // Lease expired and cap freed: the next due probe connects.
        tokio::time::sleep(Duration::from_millis(250)).await;
        drop(permit);
        spawn_due_probes(&rotator, &pool, &logger(), Duration::from_secs(1));
        let (socket, _) = tokio::time::timeout(Duration::from_secs(5), listener.accept())
            .await
            .expect("the due probe must connect once capacity frees up")
            .unwrap();
        drop(socket);
        tokio::time::timeout(Duration::from_secs(2), async {
            while rotator.is_quarantined(&proxy) {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("the successful probe must clear the quarantine");
    }
}
