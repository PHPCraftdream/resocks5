use std::collections::HashSet;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::anyhow;
use regex::RegexSet;
use tokio_rustls::TlsConnector;

use super::route::*;
use crate::config::NetworkConfig;
use crate::logger::Logger;
use crate::server::print_cfg;
use resocks5_net::chain::{ChainPlan, GateLevels};
use resocks5_net::connect::{connect_hedged, AttemptOutcome, AttemptReport, HedgeOptions};
use resocks5_net::pool::{AnyUpstream, ProxyPool};
use resocks5_net::rotator::ProxyRotator;
use resocks5_net::types::{ChainKey, ProxyConfig};

/// Наблюдатель построений gate-плана для dial-маршрута.
/// Production использует `NoopPlanBuildRecorder` (ZST без состояния):
/// пустое тело `record` не может аллоцировать — отсутствие стоимости
/// гарантировано конструкцией, а не оптимизатором.
pub(super) trait PlanBuildRecorder {
    /// Зафиксировать построение плана: (число gate-уровней, число exit-ротаторов); пустой план — (0, 0).
    fn record(&mut self, gate_levels: usize, exit_rotators: usize);
}

/// Production-наблюдатель: zero-sized type без состояния и аллокаций.
pub(super) struct NoopPlanBuildRecorder;

impl PlanBuildRecorder for NoopPlanBuildRecorder {
    fn record(&mut self, _gate_levels: usize, _exit_rotators: usize) {}
}

/// Тестовый наблюдатель: журнал `(gate_levels, exit_rotators)` каждого построения плана; пустой план — `(0, 0)`.
pub(super) type PlanBuildTrace = Vec<(usize, usize)>;

impl PlanBuildRecorder for PlanBuildTrace {
    fn record(&mut self, gate_levels: usize, exit_rotators: usize) {
        self.push((gate_levels, exit_rotators));
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn establish_connection(
    target_addr: &str,
    gates: &Arc<GateLevels>,
    v6_rotator: &Option<Arc<ProxyRotator>>,
    v4_rotator: &Option<Arc<ProxyRotator>>,
    logger: &Arc<Logger>,
    banned: &Arc<RegexSet>,
    pool: &Arc<ProxyPool>,
    network: &Arc<NetworkConfig>,
    client_user: Option<&str>,
    tls_connector: Option<&TlsConnector>,
) -> anyhow::Result<AnyUpstream> {
    let mut recorder = NoopPlanBuildRecorder;
    establish_connection_traced(
        target_addr,
        gates,
        v6_rotator,
        v4_rotator,
        logger,
        banned,
        pool,
        network,
        client_user,
        tls_connector,
        &mut recorder,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn establish_connection_traced<R: PlanBuildRecorder>(
    target_addr: &str,
    gates: &Arc<GateLevels>,
    v6_rotator: &Option<Arc<ProxyRotator>>,
    v4_rotator: &Option<Arc<ProxyRotator>>,
    logger: &Arc<Logger>,
    banned: &Arc<RegexSet>,
    pool: &Arc<ProxyPool>,
    network: &Arc<NetworkConfig>,
    client_user: Option<&str>,
    tls_connector: Option<&TlsConnector>,
    recorder: &mut R,
) -> anyhow::Result<AnyUpstream> {
    let handshake_timeout = Duration::from_secs(network.handshake_timeout_sec);
    let max_attempts = network.max_upstream_attempts;
    let mut attempts: usize = 0;
    // Complete-chain route keys keep sticky and lazy picks within one budget.
    let mut tried_routes = HashSet::<ChainKey>::new();
    let exits: Vec<_> = [v6_rotator, v4_rotator]
        .iter()
        .filter_map(|r| r.as_ref().cloned())
        .collect();
    let mut plan: Option<ChainPlan> = None;
    // The gates cartesian product must not consume the whole budget
    // before the direct fallback is tried: reserve it one attempt when
    // any direct candidate exists, plus one per queued sticky candidate.
    let mut direct_reserve = usize::from(
        [v6_rotator, v4_rotator]
            .iter()
            .filter_map(|r| r.as_ref())
            .any(|r| !r.is_empty()),
    );

    let ctag: String = match client_user {
        Some(u) => format!(" [client={}]", u),
        None => " [client=anon]".to_string(),
    };

    if banned.is_match(target_addr) {
        logger.banned_target(|| format!("Target address {} is banned{}", target_addr, ctag));
        return Err(anyhow!("Banned target address"));
    }

    // Quarantined upstreams that are due are checked in the background;
    // this request only ever sees the healthy ones.
    let connect_timeout = Duration::from_secs(network.connect_timeout_sec);
    super::probes::spawn_chain_probes(
        gates.clone(),
        exits.clone(),
        pool.clone(),
        logger.clone(),
        connect_timeout,
        handshake_timeout,
        tls_connector.cloned(),
    );

    let mut candidates: Vec<Candidate> = Vec::new();
    for rotator in [v6_rotator, v4_rotator].iter().filter_map(|&r| r.as_ref()) {
        if let Some(cached_proxy) = rotator.get_linked(target_addr) {
            if cached_proxy.gate.is_none() {
                let route = ChainKey::singleton(&cached_proxy);
                if tried_routes.insert(route) {
                    candidates.push(Candidate {
                        rotator: rotator.clone(),
                        proxy: cached_proxy,
                        cached: true,
                    });
                    // One launch budget: a queued sticky candidate owns a
                    // hedged slot of its own.
                    direct_reserve = direct_reserve.max(candidates.len());
                }
                continue;
            }
            // Resolve through the owning rotator only: the same exit
            // endpoint may be configured in several groups, and matching it
            // against all of them would borrow the quarantine and the
            // success bookkeeping of a foreign rotator's copy of the exit.
            let Some(pick) = gates.resolve(std::slice::from_ref(rotator), &cached_proxy) else {
                rotator.unlink_proxy(target_addr);
                continue;
            };
            // resolve matches nodes by identity only: a chain whose gate is
            // quarantined must not be dialed while the plan offers healthy
            // alternatives. The exit hop is not re-checked: get_linked
            // already hid a quarantined exit of this rotator. Drop the
            // stale chain and fall through to the normal plan without
            // spending an attempt.
            if pick
                .hops()
                .iter()
                .take(pick.hops().len().saturating_sub(1))
                .any(|hop| hop.rotator.is_quarantined(&hop.proxy))
            {
                rotator.unlink_proxy(target_addr);
                continue;
            }
            let route = pick.key();
            if tried_routes.contains(&route) {
                continue;
            }
            // A cached chain honours the same direct fallback reserve as
            // the fresh plan, so several sticky chains cannot spend the
            // reserved attempt; a budget of 1 stays cache-first.
            let cache_budget_free =
                attempts + direct_reserve < max_attempts || (max_attempts == 1 && attempts == 0);
            if !cache_budget_free {
                continue;
            }
            tried_routes.insert(route.clone());
            attempts += 1;
            logger.cache_attempt(|| {
                format!("Attempting to use cached proxy for {}{}", target_addr, ctag)
            });
            let config = pick.config_arc();
            let t0 = Instant::now();
            match resocks5_net::connect::connect_chain(
                &config,
                target_addr,
                pool,
                handshake_timeout,
                tls_connector,
            )
            .await
            {
                Ok(stream) => {
                    pick.record_success();
                    log_chain_attempt(logger, &pick, |gate| {
                        format!(
                            "attempt target={} via={} gate={} path=cache outcome=ok dur={}ms{}",
                            target_addr,
                            print_cfg(pick.exit().proxy.as_ref()),
                            gate,
                            t0.elapsed().as_millis(),
                            ctag
                        )
                    });
                    logger.cache_hit(|| format!("Cache used for {}{}", target_addr, ctag));
                    return Ok(stream);
                }
                Err(error) => {
                    log_chain_attempt(logger, &pick, |gate| {
                        format!("attempt target={} via={} gate={} path=cache outcome=fail dur={}ms err={}{}", target_addr, print_cfg(pick.exit().proxy.as_ref()), gate, t0.elapsed().as_millis(), error, ctag)
                    });
                    logger.proxy_failure(|| {
                        format!(
                            "Cached proxy failed: {} - {}{}",
                            error,
                            print_cfg(&config),
                            ctag
                        )
                    });
                    // The plan is only built once a cached chain has failed, so a
                    // cache hit costs no node selection; with the budget spent it
                    // stays empty (R5-09: no gate order is built for nothing).
                    for q in plan
                        .get_or_insert_with(|| {
                            if attempts + direct_reserve < max_attempts {
                                recorder.record(gates.len(), exits.len());
                                ChainPlan::new(gates, &exits)
                            } else {
                                recorder.record(0, 0);
                                ChainPlan::new(&GateLevels::default(), &[])
                            }
                        })
                        .record_failure(&pick, &error)
                    {
                        logger.proxy_failure(|| {
                            format!(
                                "Upstream {} is unreachable - quarantined for {}s{}",
                                print_cfg(&q.proxy),
                                q.length.as_secs(),
                                ctag
                            )
                        });
                    }
                    rotator.unlink_proxy(target_addr);
                }
            }
        }
    }

    if !gates.is_empty() && attempts + direct_reserve < max_attempts && plan.is_none() {
        recorder.record(gates.len(), exits.len());
        plan = Some(ChainPlan::new(gates, &exits));
    }
    while !gates.is_empty() && attempts + direct_reserve < max_attempts {
        let Some(pick) = plan.as_mut().expect("initialized chain plan").next() else {
            break;
        };
        let key = pick.key();
        if !tried_routes.insert(key) {
            continue;
        }
        attempts += 1;
        let config = pick.config_arc();
        let t0 = Instant::now();
        match resocks5_net::connect::connect_chain(
            &config,
            target_addr,
            pool,
            handshake_timeout,
            tls_connector,
        )
        .await
        {
            Ok(stream) => {
                pick.record_success();
                log_chain_attempt(logger, &pick, |gate| {
                    format!(
                        "attempt target={} via={} gate={} path=gate outcome=ok dur={}ms{}",
                        target_addr,
                        print_cfg(pick.exit().proxy.as_ref()),
                        gate,
                        t0.elapsed().as_millis(),
                        ctag
                    )
                });
                pick.exit().rotator.link_proxy(target_addr, config);
                logger
                    .cache_write(|| format!("Cache written for {} with gate{}", target_addr, ctag));
                return Ok(stream);
            }
            Err(error) => {
                log_chain_attempt(logger, &pick, |gate| {
                    format!(
                        "attempt target={} via={} gate={} path=gate outcome=fail dur={}ms err={}{}",
                        target_addr,
                        print_cfg(pick.exit().proxy.as_ref()),
                        gate,
                        t0.elapsed().as_millis(),
                        error,
                        ctag
                    )
                });
                logger.proxy_failure(|| format!("Failed: {} - {}{}", target_addr, error, ctag));
                for q in plan
                    .as_mut()
                    .expect("initialized chain plan")
                    .record_failure(&pick, &error)
                {
                    logger.proxy_failure(|| {
                        format!(
                            "Upstream {} is unreachable - quarantined for {}s{}",
                            print_cfg(&q.proxy),
                            q.length.as_secs(),
                            ctag
                        )
                    });
                }
            }
        }
    }

    // Check direct connections. An attempt whose TCP connect is still
    // pending after `hedge_delay_ms` does not hold the request: the next
    // candidate starts beside it and the first success wins. A dead upstream
    // that no rating knows about yet (e.g. right after start) then costs the
    // hedge delay instead of the full connect timeout. Once an attempt has
    // reached its upstream, no new one starts while it talks to the target,
    // so the target does not see duplicate CONNECTs. Attempts still running
    // when one wins finish in the background, so their outcome still feeds
    // the ratings and the quarantine; those that reach their upstream only
    // after the win stop there.
    for rotator in [v6_rotator, v4_rotator].iter().filter_map(|&r| r.as_ref()) {
        if attempts + candidates.len() >= max_attempts {
            break;
        }
        for proxy_config in rotator.pick_iter() {
            let route = ChainKey::singleton(&proxy_config);
            if tried_routes.contains(&route) {
                continue;
            }
            if attempts + candidates.len() >= max_attempts {
                break;
            }
            tried_routes.insert(route);
            candidates.push(Candidate {
                rotator: rotator.clone(),
                proxy: proxy_config,
                cached: false,
            });
        }
    }

    // The hedged slice may never exceed the remaining budget; queued
    // sticky candidates lead it, so truncation keeps the cache first.
    candidates.truncate(max_attempts.saturating_sub(attempts));
    let hedge_delay = Duration::from_millis(network.hedge_delay_ms);
    let proxies: Vec<_> = candidates
        .iter()
        .map(|candidate| candidate.proxy.clone())
        .collect();
    let candidates = Arc::new(candidates);
    let logger = logger.clone();
    let target = target_addr.to_owned();
    let ctag = ctag.clone();
    match connect_hedged(
        &proxies,
        target_addr,
        pool,
        tls_connector,
        &HedgeOptions::default()
            .with_hedge_delay(hedge_delay)
            .with_handshake_timeout(handshake_timeout),
        move |report: &AttemptReport| {
            report_attempt(&candidates[report.index], report, &target, &logger, &ctag);
        },
    )
    .await
    {
        Ok(hedged) => Ok(hedged.stream),
        Err(error) => Err(anyhow!(
            "All {} upstream attempts to {} failed",
            attempts + error.attempts,
            target_addr
        )),
    }
}

/// One upstream a request may race through.
struct Candidate {
    rotator: Arc<ProxyRotator>,
    proxy: Arc<ProxyConfig>,
    /// Came from the target's sticky-cache entry.
    cached: bool,
}

fn report_attempt(
    candidate: &Candidate,
    report: &AttemptReport,
    target_addr: &str,
    logger: &Arc<Logger>,
    ctag: &str,
) {
    let Candidate {
        rotator,
        proxy,
        cached,
    } = candidate;
    let path = if *cached { "cache" } else { "direct" };
    let ms = report.elapsed.as_millis();
    match &report.outcome {
        AttemptOutcome::Won => {
            logger.attempt(|| {
                format!(
                    "attempt target={} via={} path={} outcome=ok dur={}ms{}",
                    target_addr,
                    print_cfg(proxy),
                    path,
                    ms,
                    ctag
                )
            });
            rotator.record_success(proxy);
            if !report.after_win && *cached {
                logger.cache_hit(|| format!("Cache used for {}{}", target_addr, ctag));
            } else if !report.after_win {
                rotator.link_proxy(target_addr, proxy.clone());
                logger
                    .cache_write(|| format!("Cache written for {} directly{}", target_addr, ctag));
            }
        }
        AttemptOutcome::LateSuccess => {
            logger.attempt(|| {
                format!(
                    "attempt target={} via={} path={} outcome=ok-late dur={}ms{}",
                    target_addr,
                    print_cfg(proxy),
                    path,
                    ms,
                    ctag
                )
            });
            rotator.record_success(proxy);
        }
        AttemptOutcome::Lost => {
            logger.attempt(|| {
                format!(
                    "attempt target={} via={} path={} outcome=lost dur={}ms{}",
                    target_addr,
                    print_cfg(proxy),
                    path,
                    ms,
                    ctag
                )
            });
        }
        AttemptOutcome::Failed(error) => {
            logger.attempt(|| {
                format!(
                    "attempt target={} via={} path={} outcome=fail dur={}ms err={}{}",
                    target_addr,
                    print_cfg(proxy),
                    path,
                    ms,
                    error,
                    ctag
                )
            });
            if *cached {
                logger.proxy_failure(|| {
                    format!(
                        "Cached proxy failed: {} - {}{}",
                        error,
                        print_cfg(proxy),
                        ctag
                    )
                });
                if !report.after_win {
                    rotator.unlink_proxy(target_addr);
                }
            } else {
                logger.proxy_failure(|| {
                    format!(
                        "Failed direct: {} - {} - {}{}",
                        target_addr,
                        error,
                        print_cfg(proxy),
                        ctag,
                    )
                });
            }
            if should_record_connect_failure(error) {
                record_proxy_failure(rotator, proxy, error, logger, ctag);
            }
        }
        _ => logger.attempt(|| {
            format!(
                "attempt target={} via={} path={} outcome=unknown dur={}ms{}",
                target_addr,
                print_cfg(proxy),
                path,
                ms,
                ctag
            )
        }),
    }
}
