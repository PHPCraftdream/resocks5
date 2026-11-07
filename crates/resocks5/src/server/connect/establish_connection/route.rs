use crate::logger::Logger;
use crate::server::connect::print_cfg::push_cfg;
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

pub(super) fn log_chain_attempt(
    logger: &Logger,
    pick: &resocks5_net::chain::ChainPick,
    message: impl FnOnce(String) -> String,
) {
    logger.attempt(|| message(gate_label(pick)));
}

/// Верхняя граница на один gate без host: `ip V6 - Socks5://` + `:` +
/// порт до 5 цифр = 23 байта (самый длинный Debug протокола — `Socks5`).
/// Более длинный вариант протокола даст realloc — это поймает assertion
/// в perf208_gate_label_component.
const GATE_OVERHEAD: usize = "ip V6 - Socks5://:65535".len();
const HOP_SEPARATOR: &str = " -> ";

fn gate_label(pick: &resocks5_net::chain::ChainPick) -> String {
    #[cfg(all(test, feature = "test-instrumentation"))]
    crate::perf::operation(|c| c.gate_formats += 1);
    let hops = pick.hops();
    let gates = hops.len().saturating_sub(1);
    // Единый буфер по верхней границе: без String/Vec на каждый gate.
    let capacity = hops[..gates]
        .iter()
        .map(|hop| hop.proxy.host.len())
        .fold(0usize, usize::saturating_add)
        .saturating_add(gates.saturating_mul(GATE_OVERHEAD))
        .saturating_add(gates.saturating_sub(1).saturating_mul(HOP_SEPARATOR.len()));
    let mut label = String::with_capacity(capacity);
    for hop in &hops[..gates] {
        if !label.is_empty() {
            label.push_str(HOP_SEPARATOR);
        }
        push_cfg(&mut label, &hop.proxy);
    }
    label
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
    // Detached by design: the probe loop outlives this spawner and
    // reports only through the rotator and the logger, so no handle is
    // kept.
    tokio::spawn(async move {
        // At capacity the probe is deferred (review P2 №5): the endpoint
        // is saturated by real traffic, so connecting anyway would distort
        // the cap and a failure there would blame the upstream for our own
        // load.
        let reserve = move |proxy: &ProxyConfig| pool.reserve_permit(proxy).ok();
        for event in rotator.probe_due_with(connect_timeout, reserve).await {
            match event {
                resocks5_net::rotator::ProbeEvent::Recovered { proxy } => {
                    // A recovery is a lifecycle event, not a failure
                    // (CC-10/GA-05).
                    logger.lifecycle(|| {
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

#[cfg(all(test, feature = "test-instrumentation"))]
mod perf_tests {
    use super::*;
    use resocks5_net::chain::{ChainPlan, GateLevels};

    #[test]
    fn perf208_gate_label_component() {
        for depth in [0u8, 1, 4, 16] {
            let gates = GateLevels::new(
                (1..=depth)
                    .map(|rank| {
                        let mut node = ProxyConfig::socks5(format!("gate-{rank}.invalid"), 1080);
                        node.gate_level = rank;
                        node.is_gate = true;
                        (rank, Arc::new(ProxyRotator::new(vec![node])))
                    })
                    .collect(),
            );
            let exits = [Arc::new(ProxyRotator::new(vec![ProxyConfig::socks5(
                "exit.invalid",
                1080,
            )]))];
            let pick = ChainPlan::new(&gates, &exits).next().unwrap();
            let (label, first) = crate::perf::measure(|| gate_label(&pick));
            let (again, second) = crate::perf::measure(|| gate_label(&pick));
            assert_eq!(label, again);
            assert_eq!(first, second);
            assert_eq!(first.gate_formats, 1);
            // Новый formatter строит одну строку: единственная аллокация — итоговый
            // буфер (depth=0 — ни одной), дорастаний нет: ёмкость по верхней границе.
            assert_eq!(first.alloc + first.alloc_zeroed, u64::from(depth > 0));
            assert_eq!(first.realloc, 0);
            assert_eq!(label.is_empty(), depth == 0);
            crate::perf::report(&format!("gate_label/depth={depth}"), first);

            let (tx, mut rx) = tokio::sync::mpsc::channel(1);
            let disabled = Logger::new(
                tx.clone(),
                crate::logger::LogConfig {
                    attempts: false,
                    ..crate::logger::LogConfig::default()
                },
            );
            let (_, skipped) = crate::perf::measure(|| {
                log_chain_attempt(&disabled, &pick, |_| panic!("disabled formatter"));
            });
            assert_eq!(skipped, crate::perf::Counts::default());
            let enabled = Logger::new(
                tx,
                crate::logger::LogConfig {
                    attempts: true,
                    ..crate::logger::LogConfig::default()
                },
            );
            let (_, emitted) = crate::perf::measure(|| {
                log_chain_attempt(&enabled, &pick, |gate| gate);
            });
            assert_eq!(emitted.gate_formats, 1);
            let crate::logger::ELog::Log(actual) = rx.try_recv().unwrap() else {
                panic!("expected attempt log");
            };
            assert_eq!(actual, label);
            enabled.attempt(|| "occupied".to_owned());
            let (_, full) = crate::perf::measure(|| {
                log_chain_attempt(&enabled, &pick, |_| panic!("full queue formatter"));
            });
            assert_eq!(full, crate::perf::Counts::default());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::gate_label;
    use super::spawn_due_probes;
    use crate::logger::{LogConfig, Logger};
    use crate::server::connect::print_cfg::family_label;
    use resocks5_net::chain::{ChainPick, ChainPlan, GateLevels};
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

    /// Оракул — прежний formatter: `format!` из старого print_cfg на каждый
    /// gate, collect в Vec, `join(" -> ")`. Побайтовое сравнение с ним
    /// доказывает эквивалентность нового single-buffer пути старому тексту.
    fn reference_gate_label(pick: &ChainPick) -> String {
        pick.hops()
            .iter()
            .take(pick.hops().len().saturating_sub(1))
            .map(|hop| {
                format!(
                    "ip {} - {:?}://{}:{}",
                    family_label(&hop.proxy.host),
                    hop.proxy.protocol,
                    hop.proxy.host,
                    hop.proxy.port
                )
            })
            .collect::<Vec<_>>()
            .join(" -> ")
    }

    fn gate_pick(gates: Vec<ProxyConfig>) -> ChainPick {
        let total = gates.len();
        let levels = GateLevels::new(
            gates
                .into_iter()
                .enumerate()
                .map(|(index, mut node)| {
                    // GateLevels::iter отдаёт уровни по убыванию ранга: первый hop —
                    // максимальный ранг, поэтому первый элемент fixture — внешний gate.
                    let rank = (total - index) as u8;
                    node.gate_level = rank;
                    node.is_gate = true;
                    (rank, Arc::new(ProxyRotator::new(vec![node])))
                })
                .collect(),
        );
        let exits = [Arc::new(ProxyRotator::new(vec![ProxyConfig::socks5(
            "exit.invalid",
            1080,
        )]))];
        ChainPlan::new(&levels, &exits).next().unwrap()
    }

    #[test]
    fn gate_label_matches_legacy_formatter() {
        let cases: Vec<Vec<ProxyConfig>> = vec![
            Vec::new(),
            vec![ProxyConfig::socks5("203.0.113.7", 1080)],
            vec![ProxyConfig::http("[2001:db8::1]", 8128)],
            vec![ProxyConfig::https("example.invalid", 443)],
            vec![ProxyConfig::socks5("пример.test", 1080)],
            vec![ProxyConfig::socks5("", 1080)],
            vec![
                ProxyConfig::socks5("203.0.113.7", 1080),
                ProxyConfig::http("2001:db8::1", 8128),
                ProxyConfig::https("example.invalid", 443),
            ],
            (0..16)
                .map(|i| ProxyConfig::socks5(format!("g{i}.invalid"), 1080))
                .collect(),
        ];
        for gates in cases {
            let pick = gate_pick(gates);
            let label = gate_label(&pick);
            assert_eq!(label, reference_gate_label(&pick));
            // Повторный вызов с тем же входом даёт тот же текст.
            assert_eq!(gate_label(&pick), label);
            // Exit-узел (последний hop) в label не входит.
            assert!(!label.contains("exit.invalid"));
        }

        // Redaction: credentials gate-узлов не попадают в лог.
        let pick = gate_pick(vec![
            ProxyConfig::socks5("secret.invalid", 1080).with_auth("secret-user", "secret-pass")
        ]);
        let label = gate_label(&pick);
        assert_eq!(label, reference_gate_label(&pick));
        assert_eq!(label, "ip V4 - Socks5://secret.invalid:1080");
        assert!(!label.contains("secret-user"));
        assert!(!label.contains("secret-pass"));

        // Порядок hops и разделитель ровно " -> " между gates.
        let pick = gate_pick(vec![
            ProxyConfig::socks5("a.invalid", 1),
            ProxyConfig::socks5("b.invalid", 2),
        ]);
        assert_eq!(
            gate_label(&pick),
            "ip V4 - Socks5://a.invalid:1 -> ip V4 - Socks5://b.invalid:2"
        );
        let pick = gate_pick(
            (0..16)
                .map(|i| ProxyConfig::socks5(format!("g{i}.invalid"), 1080))
                .collect(),
        );
        assert_eq!(gate_label(&pick).matches(" -> ").count(), 15);
    }
}
