use crate::logger::Logger;
use crate::server::print_cfg;
use resocks5_net::rotator::ProxyRotator;
use resocks5_net::types::ProxyConfig;
use resocks5_net::ConnectError;
use std::sync::Arc;

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
#[cfg(test)]
pub(super) fn is_hard_failure(err: &anyhow::Error) -> bool {
    err.downcast_ref::<ConnectError>()
        .is_some_and(ConnectError::is_upstream_down)
}
pub(super) fn record_proxy_failure(
    rotator: &ProxyRotator,
    proxy: &Arc<ProxyConfig>,
    err: &anyhow::Error,
    logger: &Logger,
    ctag: &str,
) {
    if !should_record_failure(err) {
        return;
    }
    if let Some(error) = err.downcast_ref::<ConnectError>() {
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
    } else {
        rotator.record_failure(proxy);
    }
}
pub(super) fn spawn_due_probes(
    rotator: &Arc<ProxyRotator>,
    logger: &Arc<Logger>,
    connect_timeout: std::time::Duration,
) {
    let rotator = rotator.clone();
    let logger = logger.clone();
    tokio::spawn(async move {
        for event in rotator.probe_due(connect_timeout).await {
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
                } => logger.proxy_failure(|| {
                    format!(
                        "Upstream {} is still unreachable - quarantined for {}s",
                        print_cfg(&proxy),
                        quarantined_for.as_secs()
                    )
                }),
                _ => {}
            }
        }
    });
}
