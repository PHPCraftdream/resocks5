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

/// Spawn one reachability check per probe. The check decides per probe
/// whether the attempt may start: `None` (at capacity) starts nothing —
/// no task, no connection, nothing to report — while `Some(future)` runs
/// as its own task; every task is started before the first one is
/// awaited.
fn spawn_checks<P, F, Fut>(payloads: Vec<P>, check: F) -> JoinSet<(P, CheckResult)>
where
    P: Clone + Send + 'static,
    F: Fn(P) -> Option<Fut> + Send + Sync + 'static,
    Fut: Future<Output = CheckResult> + Send + 'static,
{
    let check = Arc::new(check);
    let mut tasks = JoinSet::new();
    for payload in payloads {
        let check = Arc::clone(&check);
        let Some(future) = check(payload.clone()) else {
            continue;
        };
        tasks.spawn(async move {
            let result = future.await;
            (payload, result)
        });
    }
    tasks
}

async fn drain_checks<P, F>(mut tasks: JoinSet<(P, CheckResult)>, mut report: F)
where
    P: 'static,
    F: FnMut(P, CheckResult),
{
    while let Some(result) = tasks.join_next().await {
        if let Ok((payload, ok)) = result {
            report(payload, ok);
        }
    }
}

impl ProxyRotator {
    /// Probe expired quarantine leases and report outcomes.
    pub async fn probe_due(&self, connect_timeout: Duration) -> Vec<ProbeEvent> {
        self.probe_due_with(connect_timeout, |_| Some(())).await
    }

    /// [`ProxyRotator::probe_due`] with a per-probe capacity reservation.
    ///
    /// `reserve` runs once per due upstream, before any connection is
    /// made. Returning `None` defers the probe: no connection, no health
    /// change, no [`ProbeEvent`] — capacity is this process's own load,
    /// not the upstream's fault — and the probe lease simply expires, so
    /// [`ProxyRotator::take_probes`] hands the upstream out again later.
    /// Returning `Some(guard)` pins `guard` (e.g. a pool permit) for the
    /// probe's whole duration; it drops once the connect attempt
    /// settles.
    ///
    /// The outcome applies only through the claim taken at the start; a
    /// stale outcome — the slot changed hands while the probe ran — is
    /// dropped silently.
    pub async fn probe_due_with<G, R>(
        &self,
        connect_timeout: Duration,
        reserve: R,
    ) -> Vec<ProbeEvent>
    where
        G: Send + 'static,
        R: Fn(&ProxyConfig) -> Option<G> + Send + Sync + 'static,
    {
        // Claims are taken before any reserve or spawn (finding E): the
        // outcome is bound to the slot's generation at claim time, so a
        // health change that happens while the probe runs cannot be
        // overwritten by a stale result.
        let tasks = spawn_checks(self.take_probe_claims(), move |claim| {
            let guard = reserve(&claim.proxy)?;
            Some(async move {
                let result = reachable(&claim.proxy, connect_timeout).await;
                // `_guard` holds the cap slot until the attempt settles.
                let _guard = guard;
                result
            })
        });

        let mut events = Vec::new();
        drain_checks(tasks, |claim, result| match result {
            Ok(()) => {
                if self.record_success_for(&claim) {
                    events.push(ProbeEvent::Recovered { proxy: claim.proxy });
                }
                // A stale success changes nothing and reports nothing.
            }
            Err(reason) => {
                if let Some(quarantined_for) = self.record_hard_failure_for(&claim) {
                    events.push(ProbeEvent::StillDown {
                        proxy: claim.proxy,
                        quarantined_for,
                        reason,
                    });
                }
                // A stale failure changes nothing and reports nothing.
            }
        })
        .await;
        events
    }

    /// Check every configured upstream, quarantining unavailable ones when enabled.
    pub async fn probe_all(&self, connect_timeout: Duration) -> Vec<ProbeEvent> {
        self.probe_all_with(connect_timeout, |_| Some(())).await
    }

    /// [`ProxyRotator::probe_all`] with the same per-probe reservation as
    /// [`ProxyRotator::probe_due_with`]: an at-capacity upstream is not
    /// probed and not quarantined at start-up.
    pub async fn probe_all_with<G, R>(
        &self,
        connect_timeout: Duration,
        reserve: R,
    ) -> Vec<ProbeEvent>
    where
        G: Send + 'static,
        R: Fn(&ProxyConfig) -> Option<G> + Send + Sync + 'static,
    {
        let tasks = spawn_checks(self.proxies.clone(), move |proxy| {
            let guard = reserve(&proxy)?;
            Some(async move {
                let result = reachable(&proxy, connect_timeout).await;
                let _guard = guard;
                result
            })
        });

        let mut events = Vec::new();
        drain_checks(tasks, |proxy, result| {
            if let Err(reason) = result {
                // One atomic check-and-trip (finding H3): a concurrent
                // hard failure can no longer double the backoff.
                if let Some(quarantined_for) = self.quarantine_now_unless_tripped(&proxy) {
                    events.push(ProbeEvent::QuarantinedAtStart {
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
        let tasks = spawn_checks(proxies, |proxy| {
            Some(async move {
                if proxy.port == 30_001 {
                    panic!("synthetic task failure");
                }
                Err("down".to_owned())
            })
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
            Some(async move {
                barrier.wait().await;
                Err("down".to_owned())
            })
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
