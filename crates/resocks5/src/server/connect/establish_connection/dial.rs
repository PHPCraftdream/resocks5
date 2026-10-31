use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Context};
use regex::RegexSet;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;

use crate::config::NetworkConfig;
use crate::logger::Logger;
use crate::server::{get_auth, print_cfg};
use resocks5_net::connect::{
    connect_proxy, connect_proxy_on, handshake_over_stream, http_connect_handshake, HostPort,
};
use resocks5_net::pool::{AnyUpstream, BoxedUpstream, ProxyPool};
use resocks5_net::progress::ProgressReportingWriter;
use resocks5_net::rotator::ProxyRotator;
use resocks5_net::types::{ProxyConfig, ProxyProtocol};

use super::route::*;
/// One hop of a gate tunnel: speak `hop`'s protocol over the incoming
/// erased stream to reach `target_addr`, returning the stream for the
/// next hop (or for tunnelling).
///
/// An HTTPS hop TLS-wraps whatever came in — including a previous TLS
/// layer, when both the gate and the inner proxy are HTTPS — so the
/// concrete type of the result depends on both hops' protocols. The
/// gate path therefore erases its streams into [`BoxedUpstream`]
/// instead of enumerating that matrix as distinct Rust types. Each hop
/// is bounded by `handshake_timeout` (TLS + CONNECT count as one hop),
/// mirroring the per-hop timeouts of the direct path.
pub(super) async fn tunnel_hop(
    stream: BoxedUpstream,
    hop: &ProxyConfig,
    target_addr: &str,
    tls_connector: Option<&TlsConnector>,
    handshake_timeout: Duration,
) -> anyhow::Result<BoxedUpstream> {
    let auth = get_auth(hop);
    match hop.protocol {
        ProxyProtocol::Socks5 => {
            match timeout(
                handshake_timeout,
                handshake_over_stream(stream, target_addr, auth),
            )
            .await
            {
                Ok(Ok(s)) => Ok(s),
                Ok(Err(e)) => Err(e.into()),
                Err(_) => Err(anyhow!(
                    "[SOCKS5] handshake timeout ({}s) for target {}",
                    handshake_timeout.as_secs(),
                    target_addr
                )),
            }
        }
        ProxyProtocol::Http => {
            let mut stream = stream;
            match timeout(
                handshake_timeout,
                http_connect_handshake(&mut stream, target_addr, hop),
            )
            .await
            {
                Ok(Ok(())) => Ok(stream),
                Ok(Err(e)) => Err(e.into()),
                Err(_) => Err(anyhow!(
                    "[HTTP] handshake timeout ({}s) to target {}",
                    handshake_timeout.as_secs(),
                    target_addr
                )),
            }
        }
        ProxyProtocol::Https => {
            let connector =
                tls_connector.ok_or_else(|| anyhow!("HTTPS upstream requires TLS connector"))?;
            let server_name =
                tokio_rustls::rustls::pki_types::ServerName::try_from(hop.host.clone())
                    .map_err(|_| anyhow!("[HTTPS] invalid server name: {}", hop.host))?;
            match timeout(handshake_timeout, async {
                let mut tls = connector
                    .connect(server_name, stream)
                    .await
                    .map_err(|e| anyhow!("[HTTPS] TLS handshake to {}: {}", hop.host, e))?;
                http_connect_handshake(&mut tls, target_addr, hop).await?;
                Ok::<BoxedUpstream, anyhow::Error>(Box::new(tls))
            })
            .await
            {
                Ok(Ok(s)) => Ok(s),
                Ok(Err(e)) => Err(e),
                Err(_) => Err(anyhow!(
                    "[HTTPS] handshake timeout ({}s) to {}",
                    handshake_timeout.as_secs(),
                    hop.host
                )),
            }
        }
    }
}

pub(super) async fn use_gate(
    target_addr: &str,
    gate_config: &ProxyConfig,
    proxy_config: &ProxyConfig,
    pool: &ProxyPool,
    handshake_timeout: Duration,
    tls_connector: Option<&TlsConnector>,
) -> anyhow::Result<AnyUpstream> {
    let proxy_addr = HostPort::format(&proxy_config.host, proxy_config.port);

    let mut gate_stream = pool
        .acquire(gate_config)
        .await
        .map_err(|e| anyhow::Error::new(e).context(GateStage::GateConnect))
        .with_context(|| format!("Failed to connect to gate {}", print_cfg(gate_config)))?;
    // The tunnel holds a live connection to `proxy_config` THROUGH the
    // gate, so it must consume `max_per_upstream` exactly like a
    // direct connection — without this reservation gate-routed traffic
    // is invisible to the cap shared with `connect_proxy`. No second
    // socket is opened; the permit is pure accounting, held inside the
    // tunnel and released with it (a chain is always exactly gate +
    // inner proxy: the parser never nests `gate` deeper). On failure
    // here the `?` drops `gate_stream`, releasing the gate's permit.
    gate_stream.attach_permit(
        pool.reserve_permit(proxy_config)
            .map_err(|e| anyhow::Error::new(e).context(GateStage::GateToProxy))
            .with_context(|| format!("Failed to reserve permit for {}", print_cfg(proxy_config)))?,
    );
    let stream = tunnel_hop(
        // The base of the whole gate chain: every hop multiplexes over
        // this ONE TCP connection (the gate socket), so wrapping it
        // here sits below the FIRST TLS hop whatever the hop protocols
        // are. Ciphertext the outermost TLS layer manages to push to
        // the wire counts as confirmed progress; plaintext buffered by
        // a nested TLS layer never passes this wrapper and cannot fake
        // progress. Without the wrapping writer a gate chain is
        // invisible to FlushProgress and the false-idle protection
        // never engages (review P2-02).
        Box::new(ProgressReportingWriter::new(gate_stream)),
        gate_config,
        &proxy_addr,
        tls_connector,
        handshake_timeout,
    )
    .await
    .map_err(|e| e.context(GateStage::GateToProxy))
    .with_context(|| {
        format!(
            "Failed to connect to proxy {} through gate {}",
            print_cfg(proxy_config),
            print_cfg(gate_config),
        )
    })?;
    let stream = tunnel_hop(
        stream,
        proxy_config,
        target_addr,
        tls_connector,
        handshake_timeout,
    )
    .await
    .map_err(|e| e.context(GateStage::ProxyToTarget))
    .with_context(|| {
        format!(
            "Failed to connect to target {} by proxy {} with gate {}",
            target_addr,
            print_cfg(proxy_config),
            print_cfg(gate_config),
        )
    })?;
    Ok(AnyUpstream::Gate(stream))
}

async fn try_proxy(
    target_addr: &str,
    proxy_config: &Arc<ProxyConfig>,
    pool: &ProxyPool,
    handshake_timeout: Duration,
    tls_connector: Option<&TlsConnector>,
) -> anyhow::Result<AnyUpstream> {
    if let Some(gate) = &proxy_config.gate {
        use_gate(
            target_addr,
            gate,
            proxy_config,
            pool,
            handshake_timeout,
            tls_connector,
        )
        .await
    } else {
        connect_proxy(
            target_addr,
            proxy_config,
            pool,
            handshake_timeout,
            tls_connector,
        )
        .await
        .map_err(anyhow::Error::new)
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn establish_connection(
    target_addr: &str,
    gate_rotator: &Option<Arc<ProxyRotator>>,
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
    // Routes already attempted within THIS call: a repeat of an
    // already-tried route must not consume another budget slot — the
    // cache composite and the gates phase can independently select the
    // same underlying route once the cache entry fails and is unlinked.
    let mut tried_routes = HashSet::new();
    // Nodes proven unusable THIS call by a classified single-node
    // fault; excluded from later combinations within the same call.
    // Shared `Arc`s compared by value — no per-event String clones.
    let mut dead_gates = HashSet::new();
    let mut dead_proxies = HashSet::new();
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
    for rotator in [gate_rotator, v6_rotator, v4_rotator].into_iter().flatten() {
        spawn_due_probes(rotator, logger, connect_timeout);
    }

    // Check cached proxies. A plain (gate-less) cached upstream is not
    // tried alone: it leads the direct race below, so a cached upstream
    // that died since costs the hedge delay, not the connect timeout.
    let mut candidates: Vec<Candidate> = Vec::new();
    for rotator in [v6_rotator, v4_rotator].iter().filter_map(|&r| r.as_ref()) {
        if let Some(cached_proxy) = rotator.get_linked(target_addr) {
            if cached_proxy.gate.is_none() {
                let route = route_key(None, &cached_proxy);
                if !tried_routes.contains(&route) {
                    tried_routes.insert(route);
                    candidates.push(Candidate {
                        rotator: rotator.clone(),
                        proxy: cached_proxy,
                        cached: true,
                    });
                }
                continue;
            }
            let route = route_key(cached_proxy.gate.as_ref(), &cached_proxy);
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
            tried_routes.insert(route);
            attempts += 1;
            logger.cache_attempt(|| {
                format!("Attempting to use cached proxy for {}{}", target_addr, ctag)
            });
            let t0 = Instant::now();
            match try_proxy(
                target_addr,
                &cached_proxy,
                pool,
                handshake_timeout,
                tls_connector,
            )
            .await
            {
                Ok(stream) => {
                    let ms = t0.elapsed().as_millis();
                    logger.attempt(|| {
                        format!(
                            "attempt target={} via={} path=cache outcome=ok dur={}ms{}",
                            target_addr,
                            print_cfg(&cached_proxy),
                            ms,
                            ctag
                        )
                    });
                    logger.cache_hit(|| format!("Cache used for {}{}", target_addr, ctag));
                    rotator.record_success(&cached_proxy);
                    return Ok(stream);
                }
                Err(e) => {
                    let ms = t0.elapsed().as_millis();
                    logger.attempt(|| {
                        format!(
                            "attempt target={} via={} path=cache outcome=fail dur={}ms err={}{}",
                            target_addr,
                            print_cfg(&cached_proxy),
                            ms,
                            e,
                            ctag
                        )
                    });
                    logger.proxy_failure(|| {
                        format!(
                            "Cached proxy failed: {} - {}{}",
                            e,
                            print_cfg(&cached_proxy),
                            ctag
                        )
                    });
                    apply_gate_failure(
                        &e,
                        rotator,
                        &cached_proxy,
                        cached_proxy.gate.as_ref(),
                        gate_rotator.as_deref(),
                        &mut dead_gates,
                        &mut dead_proxies,
                        logger,
                        &ctag,
                    );
                    rotator.unlink_proxy(target_addr);
                }
            }
        }
    }

    // Check new connections through gates
    if let Some(gate_rotator) = gate_rotator {
        // R5-09: a gated attempt needs headroom for the direct reserve,
        // so once `attempts + direct_reserve` reaches the cap the
        // per-proxy check below breaks out of the gates loop at its
        // first eligible route — don't build the full gate order at all.
        let gate_order = if attempts + direct_reserve < max_attempts {
            gate_rotator.pick_order()
        } else {
            Vec::new()
        };
        'gates: for gate_config in &gate_order {
            if dead_gates.contains(&UpstreamKey(gate_config.clone())) {
                continue;
            }
            for rotator in [v6_rotator, v4_rotator].iter().filter_map(|&r| r.as_ref()) {
                // R5-09: same budget condition as the per-proxy check
                // below, hoisted above the build — a budget exhausted by
                // earlier gates must not trigger another full build+sort
                // for this gate.
                if attempts + direct_reserve >= max_attempts {
                    break 'gates;
                }
                let order = rotator.pick_order();
                for proxy_config in &order {
                    let route = route_key(Some(gate_config), proxy_config);
                    if dead_proxies.contains(&UpstreamKey(proxy_config.clone()))
                        || tried_routes.contains(&route)
                    {
                        continue;
                    }
                    if attempts + direct_reserve >= max_attempts {
                        break 'gates;
                    }
                    tried_routes.insert(route);
                    attempts += 1;
                    let t0 = Instant::now();
                    match use_gate(
                        target_addr,
                        gate_config,
                        proxy_config,
                        pool,
                        handshake_timeout,
                        tls_connector,
                    )
                    .await
                    {
                        Ok(stream) => {
                            let ms = t0.elapsed().as_millis();
                            logger.attempt(|| {
                                format!(
                                    "attempt target={} via={} gate={} path=gate outcome=ok dur={}ms{}",
                                    target_addr, print_cfg(proxy_config), print_cfg(gate_config), ms, ctag
                                )
                            });
                            rotator.record_success(proxy_config);
                            gate_rotator.record_success(gate_config);
                            let mut new_cfg = (**proxy_config).clone();
                            new_cfg.gate = Some(gate_config.clone());
                            rotator.link_proxy(target_addr.to_string(), Arc::new(new_cfg));
                            logger.cache_write(|| {
                                format!("Cache written for {} with gate{}", target_addr, ctag)
                            });
                            return Ok(stream);
                        }
                        Err(e) => {
                            let ms = t0.elapsed().as_millis();
                            logger.attempt(|| {
                                format!(
                                    "attempt target={} via={} gate={} path=gate outcome=fail dur={}ms err={}{}",
                                    target_addr, print_cfg(proxy_config), print_cfg(gate_config), ms, e, ctag
                                )
                            });
                            logger.proxy_failure(|| {
                                format!("Failed: {} - {}{}", target_addr, e, ctag)
                            });
                            if apply_gate_failure(
                                &e,
                                rotator,
                                proxy_config,
                                Some(gate_config),
                                Some(gate_rotator.as_ref()),
                                &mut dead_gates,
                                &mut dead_proxies,
                                logger,
                                &ctag,
                            ) {
                                // The gate itself is proven dead for the
                                // rest of this call — no proxy pairing
                                // can succeed against it — so stop
                                // burning attempt budget on this gate
                                // now instead of at the next
                                // outer-loop entry (R2-19).
                                continue 'gates;
                            }
                        }
                    }
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
    'direct: for rotator in [v6_rotator, v4_rotator].iter().filter_map(|&r| r.as_ref()) {
        // R5-09: an exhausted budget must not build another full order.
        if attempts + candidates.len() >= max_attempts {
            break 'direct;
        }
        for proxy_config in rotator.pick_order() {
            let route = route_key(None, &proxy_config);
            if dead_proxies.contains(&UpstreamKey(proxy_config.clone()))
                || tried_routes.contains(&route)
            {
                continue;
            }
            if attempts + candidates.len() >= max_attempts {
                break 'direct;
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
                    ctag,
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
