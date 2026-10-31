use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
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
use resocks5_net::connect::connect_proxy_on;
use resocks5_net::pool::{AnyUpstream, ProxyPool};
use resocks5_net::rotator::ProxyRotator;
use resocks5_net::types::{ChainKey, ProxyConfig};
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
    // any direct candidate exists.
    let direct_reserve = usize::from(
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
                let route = ChainKey::new(Arc::new(
                    ProxyConfig::chain([cached_proxy.clone()]).expect("singleton chain"),
                ));
                if tried_routes.insert(route) {
                    candidates.push(Candidate {
                        rotator: rotator.clone(),
                        proxy: cached_proxy,
                        cached: true,
                    });
                }
                continue;
            }
            let Some(pick) = gates.resolve(&exits, &cached_proxy) else {
                rotator.unlink_proxy(target_addr);
                continue;
            };
            let route = pick.key();
            if tried_routes.contains(&route) {
                continue;
            }
            if attempts >= max_attempts {
                return Err(anyhow!(
                    "max upstream attempts ({}) reached for {}",
                    max_attempts,
                    target_addr
                ));
            }
            tried_routes.insert(route.clone());
            if plan.is_none() {
                plan = Some(if attempts + 1 + direct_reserve < max_attempts {
                    ChainPlan::new(gates, &exits)
                } else {
                    ChainPlan::new(&GateLevels::default(), &[])
                });
            }
            plan.as_mut()
                .expect("initialized chain plan")
                .exclude(&route);
            attempts += 1;
            logger.cache_attempt(|| {
                format!("Attempting to use cached proxy for {}{}", target_addr, ctag)
            });
            let config = pick.config();
            let gate = pick
                .hops()
                .iter()
                .take(pick.hops().len().saturating_sub(1))
                .map(|hop| print_cfg(&hop.proxy))
                .collect::<Vec<_>>()
                .join(" -> ");
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
                    plan.as_ref()
                        .expect("initialized chain plan")
                        .record_success(&pick);
                    logger.attempt(|| {
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
                    let gate = pick
                        .hops()
                        .iter()
                        .take(pick.hops().len().saturating_sub(1))
                        .map(|hop| print_cfg(&hop.proxy))
                        .collect::<Vec<_>>()
                        .join(" -> ");
                    logger.attempt(|| format!("attempt target={} via={} gate={} path=cache outcome=fail dur={}ms err={}{}", target_addr, print_cfg(pick.exit().proxy.as_ref()), gate, t0.elapsed().as_millis(), error, ctag));
                    logger.proxy_failure(|| {
                        format!(
                            "Cached proxy failed: {} - {}{}",
                            error,
                            print_cfg(&config),
                            ctag
                        )
                    });
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
                    rotator.unlink_proxy(target_addr);
                }
            }
        }
    }

    if !gates.is_empty() && attempts + direct_reserve < max_attempts && plan.is_none() {
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
        let config = pick.config();
        let gate = pick
            .hops()
            .iter()
            .take(pick.hops().len().saturating_sub(1))
            .map(|hop| print_cfg(&hop.proxy))
            .collect::<Vec<_>>()
            .join(" -> ");
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
                plan.as_ref()
                    .expect("initialized chain plan")
                    .record_success(&pick);
                logger.attempt(|| {
                    format!(
                        "attempt target={} via={} gate={} path=gate outcome=ok dur={}ms{}",
                        target_addr,
                        print_cfg(pick.exit().proxy.as_ref()),
                        gate,
                        t0.elapsed().as_millis(),
                        ctag
                    )
                });
                pick.exit()
                    .rotator
                    .link_proxy(target_addr.to_string(), Arc::new(config));
                logger
                    .cache_write(|| format!("Cache written for {} with gate{}", target_addr, ctag));
                return Ok(stream);
            }
            Err(error) => {
                logger.attempt(|| {
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
        for proxy_config in rotator.pick_order() {
            let route = ChainKey::new(Arc::new(
                ProxyConfig::chain([proxy_config.clone()]).expect("singleton chain"),
            ));
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

    let hedge_delay = Duration::from_millis(network.hedge_delay_ms);
    let mut pending = candidates.into_iter();
    let mut launched: Vec<Candidate> = Vec::new();
    let mut running: Attempts = tokio::task::JoinSet::new();
    let race = Arc::new(RaceState::default());
    let mut hedge_at = tokio::time::Instant::now();
    let launch = |running: &mut Attempts, launched: &mut Vec<Candidate>, candidate: Candidate| {
        let id = launched.len();
        let target = target_addr.to_string();
        let pool = pool.clone();
        let tls = tls_connector.cloned();
        let proxy = candidate.proxy.clone();
        let race = race.clone();
        running.spawn(async move {
            let t0 = Instant::now();
            let result = race_attempt(
                &race,
                &target,
                &proxy,
                &pool,
                handshake_timeout,
                tls.as_ref(),
            )
            .await;
            (id, result, t0.elapsed())
        });
        launched.push(candidate);
    };
    loop {
        if running.is_empty() {
            match pending.next() {
                Some(candidate) => {
                    attempts += 1;
                    launch(&mut running, &mut launched, candidate);
                    hedge_at = tokio::time::Instant::now() + hedge_delay;
                }
                None => break,
            }
        }
        let can_hedge = !hedge_delay.is_zero() && pending.len() > 0;
        tokio::select! {
            joined = running.join_next() => {
                let Some(Ok((id, result, elapsed))) = joined else {
                    continue;
                };
                let outcome = settle_attempt(&launched[id], result, elapsed, true, target_addr, logger, &ctag);
                if let Some(stream) = outcome {
                    race.won.store(true, Ordering::Release);
                    let launched = Arc::new(launched);
                    let logger = logger.clone();
                    let target = target_addr.to_string();
                    let ctag = ctag.clone();
                    tokio::spawn(async move {
                        while let Some(joined) = running.join_next().await {
                            if let Ok((id, result, elapsed)) = joined {
                                drop(settle_attempt(&launched[id], result, elapsed, false, &target, &logger, &ctag));
                            }
                        }
                    });
                    return Ok(stream);
                }
            }
            _ = tokio::time::sleep_until(hedge_at), if can_hedge => {
                hedge_at = tokio::time::Instant::now() + hedge_delay;
                // An attempt talking to the target holds the race.
                if race.handshaking.load(Ordering::Acquire) == 0 {
                    if let Some(candidate) = pending.next() {
                        attempts += 1;
                        launch(&mut running, &mut launched, candidate);
                    }
                }
            }
        }
    }

    Err(anyhow!(
        "All {} upstream attempts to {} failed",
        attempts,
        target_addr
    ))
}

/// One upstream a request may race through.
struct Candidate {
    rotator: Arc<ProxyRotator>,
    proxy: Arc<ProxyConfig>,
    /// Came from the target's sticky-cache entry.
    cached: bool,
}

type Attempts = tokio::task::JoinSet<(usize, anyhow::Result<AnyUpstream>, std::time::Duration)>;

/// Shared by the attempts of one race.
#[derive(Default)]
pub(super) struct RaceState {
    /// Set once an attempt won.
    pub(super) won: AtomicBool,
    /// Attempts past their TCP connect, talking to the target.
    pub(super) handshaking: AtomicUsize,
}

/// An attempt that reached its upstream after the race was already won;
/// it stops before asking the upstream for the target.
#[derive(Debug)]
pub(super) struct RaceLost;

impl std::fmt::Display for RaceLost {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("race already won by another upstream")
    }
}

impl std::error::Error for RaceLost {}

/// One direct attempt: TCP connect to the upstream, then — unless the race
/// is already won — the protocol handshake to the target.
pub(super) async fn race_attempt(
    race: &RaceState,
    target_addr: &str,
    proxy: &ProxyConfig,
    pool: &ProxyPool,
    handshake_timeout: Duration,
    tls_connector: Option<&TlsConnector>,
) -> anyhow::Result<AnyUpstream> {
    let stream = pool.acquire(proxy).await.map_err(anyhow::Error::new)?;
    if race.won.load(Ordering::Acquire) {
        return Err(RaceLost.into());
    }
    race.handshaking.fetch_add(1, Ordering::AcqRel);
    let result = connect_proxy_on(stream, target_addr, proxy, handshake_timeout, tls_connector)
        .await
        .map_err(anyhow::Error::new);
    race.handshaking.fetch_sub(1, Ordering::AcqRel);
    result
}

/// Log a finished race attempt and feed it into the ratings. Returns the
/// stream on success (the caller either uses it or drops it).
///
/// `in_race` is false for attempts that finish after another one won: they
/// still feed the ratings but leave the target's sticky link alone.
fn settle_attempt(
    candidate: &Candidate,
    result: anyhow::Result<AnyUpstream>,
    elapsed: std::time::Duration,
    in_race: bool,
    target_addr: &str,
    logger: &Arc<Logger>,
    ctag: &str,
) -> Option<AnyUpstream> {
    let Candidate {
        rotator,
        proxy,
        cached,
    } = candidate;
    let path = if *cached { "cache" } else { "direct" };
    let ms = elapsed.as_millis();
    match result {
        Ok(stream) => {
            logger.attempt(|| {
                format!(
                    "attempt target={} via={} path={} outcome={} dur={}ms{}",
                    target_addr,
                    print_cfg(proxy),
                    path,
                    if in_race { "ok" } else { "ok-late" },
                    ms,
                    ctag
                )
            });
            rotator.record_success(proxy);
            if !in_race {
                return None;
            }
            if *cached {
                logger.cache_hit(|| format!("Cache used for {}{}", target_addr, ctag));
            } else {
                rotator.link_proxy(target_addr.to_string(), proxy.clone());
                logger
                    .cache_write(|| format!("Cache written for {} directly{}", target_addr, ctag));
            }
            Some(stream)
        }
        Err(e) if e.is::<RaceLost>() => {
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
            None
        }
        Err(e) => {
            logger.attempt(|| {
                format!(
                    "attempt target={} via={} path={} outcome=fail dur={}ms err={}{}",
                    target_addr,
                    print_cfg(proxy),
                    path,
                    ms,
                    e,
                    ctag
                )
            });
            if *cached {
                logger.proxy_failure(|| {
                    format!("Cached proxy failed: {} - {}{}", e, print_cfg(proxy), ctag)
                });
                // After the win the link already names the winner.
                if in_race {
                    rotator.unlink_proxy(target_addr);
                }
            } else {
                logger.proxy_failure(|| {
                    format!(
                        "Failed direct: {} - {} - {}{}",
                        target_addr,
                        e,
                        print_cfg(proxy),
                        ctag,
                    )
                });
            }
            if should_record_failure(&e) {
                record_proxy_failure(rotator, proxy, &e, logger, ctag);
            }
            None
        }
    }
}
