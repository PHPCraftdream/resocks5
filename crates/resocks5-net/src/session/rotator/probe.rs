use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::TcpStream;
use tokio::task::JoinSet;
use tokio::time::timeout;

use crate::types::ProxyConfig;

use super::ProxyRotator;

/// Result of a TCP reachability probe for an upstream proxy.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum ProbeEvent {
    /// The upstream accepted a TCP connection.
    Recovered {
        /// The upstream that recovered.
        proxy: Arc<ProxyConfig>,
    },
    /// The upstream remains unavailable.
    StillDown {
        /// The unavailable upstream.
        proxy: Arc<ProxyConfig>,
        /// New quarantine duration, when this failure tripped quarantine.
        quarantined_for: Duration,
        /// Why the connect failed: the I/O error or the timeout.
        reason: String,
    },
    /// A startup check found an unavailable upstream and quarantined it.
    QuarantinedAtStart {
        /// The unavailable upstream.
        proxy: Arc<ProxyConfig>,
        /// New quarantine duration.
        quarantined_for: Duration,
        /// Why the connect failed: the I/O error or the timeout.
        reason: String,
    },
}

async fn reachable(proxy: &ProxyConfig, connect_timeout: Duration) -> Result<(), String> {
    let address = (proxy.host.as_str(), proxy.port);
    match timeout(connect_timeout, TcpStream::connect(address)).await {
        Ok(Ok(_)) => Ok(()),
        Ok(Err(error)) => Err(error.to_string()),
        Err(_) => Err(format!("no answer within {connect_timeout:?}")),
    }
}

type CheckResult = Result<(), String>;

fn spawn_checks<F, Fut>(
    proxies: Vec<Arc<ProxyConfig>>,
    check: F,
) -> JoinSet<(Arc<ProxyConfig>, CheckResult)>
where
    F: Fn(Arc<ProxyConfig>) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = CheckResult> + Send + 'static,
{
    let check = Arc::new(check);
    let mut tasks = JoinSet::new();
    for proxy in proxies {
        let check = Arc::clone(&check);
        tasks.spawn(async move {
            let result = check(Arc::clone(&proxy)).await;
            (proxy, result)
        });
    }
    tasks
}

async fn drain_checks<F>(mut tasks: JoinSet<(Arc<ProxyConfig>, CheckResult)>, mut report: F)
where
    F: FnMut(Arc<ProxyConfig>, CheckResult),
{
    while let Some(result) = tasks.join_next().await {
        if let Ok((proxy, ok)) = result {
            report(proxy, ok);
        }
    }
}

impl ProxyRotator {
    /// Probe expired quarantine leases and report outcomes.
    pub async fn probe_due(&self, connect_timeout: Duration) -> Vec<ProbeEvent> {
        let tasks = spawn_checks(self.take_probes(), move |proxy| async move {
            reachable(&proxy, connect_timeout).await
        });

        let mut events = Vec::new();
        drain_checks(tasks, |proxy, result| match result {
            Ok(()) => {
                self.record_success(&proxy);
                events.push(ProbeEvent::Recovered { proxy });
            }
            Err(reason) => {
                if let Some(quarantined_for) = self.record_hard_failure(&proxy) {
                    events.push(ProbeEvent::StillDown {
                        proxy,
                        quarantined_for,
                        reason,
                    });
                }
            }
        })
        .await;
        events
    }

    /// Check every configured upstream, quarantining unavailable ones when enabled.
    pub async fn probe_all(&self, connect_timeout: Duration) -> Vec<ProbeEvent> {
        let tasks = spawn_checks(self.proxies.clone(), move |proxy| async move {
            reachable(&proxy, connect_timeout).await
        });

        let mut events = Vec::new();
        drain_checks(tasks, |proxy, result| {
            if let Err(reason) = result {
                if !self.is_quarantined(&proxy) {
                    if let Some(quarantined_for) = self.quarantine_now(&proxy) {
                        events.push(ProbeEvent::QuarantinedAtStart {
                            proxy,
                            quarantined_for,
                            reason,
                        });
                    }
                }
            }
        })
        .await;
        events
    }
}

#[cfg(test)]
mod tests {
    use super::{drain_checks, spawn_checks};
    use crate::types::ProxyConfig;
    use std::sync::Arc;
    use tokio::sync::Barrier;
    use tokio::time::{timeout, Duration};

    #[tokio::test]
    async fn drain_checks_ignores_panicked_task_and_reports_other_results() {
        let proxies = vec![
            Arc::new(ProxyConfig::socks5("192.0.2.1", 30_001)),
            Arc::new(ProxyConfig::socks5("192.0.2.1", 30_002)),
            Arc::new(ProxyConfig::socks5("192.0.2.1", 30_003)),
        ];
        let tasks = spawn_checks(proxies, |proxy| async move {
            if proxy.port == 30_001 {
                panic!("synthetic task failure");
            }
            Err("down".to_owned())
        });
        let mut completed = 0;
        drain_checks(tasks, |_, result| {
            assert_eq!(result, Err("down".to_owned()));
            completed += 1;
        })
        .await;
        assert_eq!(completed, 2);
    }

    #[tokio::test]
    async fn run_checks_starts_every_check_before_waiting_for_completion() {
        const COUNT: usize = 16;
        let barrier = Arc::new(Barrier::new(COUNT));
        let proxies = (0..COUNT)
            .map(|port| Arc::new(ProxyConfig::socks5("192.0.2.1", 30_000 + port as u16)))
            .collect();
        let barrier_for_check = Arc::clone(&barrier);

        let tasks = spawn_checks(proxies, move |_| {
            let barrier = Arc::clone(&barrier_for_check);
            async move {
                barrier.wait().await;
                Err("down".to_owned())
            }
        });
        let mut completed = 0;
        timeout(
            Duration::from_secs(2),
            drain_checks(tasks, |_, result| {
                assert!(result.is_err());
                completed += 1;
            }),
        )
        .await
        .expect("checks must be polled concurrently");
        assert_eq!(completed, COUNT);
    }
}
