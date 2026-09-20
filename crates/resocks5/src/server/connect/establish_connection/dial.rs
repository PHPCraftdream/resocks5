use std::collections::HashSet;
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
    connect_proxy, handshake_over_stream, http_connect_handshake, HostPort,
};
use resocks5_net::pool::{AnyUpstream, BoxedUpstream, ProxyPool};
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
async fn tunnel_hop(
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
                Ok(Err(e)) => Err(e),
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
                Ok(Err(e)) => Err(e),
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
        .map_err(|e| e.context(GateStage::GateConnect))
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
            .map_err(|e| e.context(GateStage::GateToProxy))
            .with_context(|| format!("Failed to reserve permit for {}", print_cfg(proxy_config)))?,
    );
    let stream = tunnel_hop(
        Box::new(gate_stream),
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

    // Check cached proxies
    for rotator in [v6_rotator, v4_rotator].iter().filter_map(|&r| r.as_ref()) {
        if let Some(cached_proxy) = rotator.get_linked(target_addr) {
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

    // Check direct connections
    'direct: for rotator in [v6_rotator, v4_rotator].iter().filter_map(|&r| r.as_ref()) {
        // R5-09: hoist the per-proxy budget check above the build —
        // an exhausted budget must not build another full order.
        if attempts >= max_attempts {
            break 'direct;
        }
        let order = rotator.pick_order();
        for proxy_config in &order {
            let route = route_key(None, proxy_config);
            if dead_proxies.contains(&UpstreamKey(proxy_config.clone()))
                || tried_routes.contains(&route)
            {
                continue;
            }
            if attempts >= max_attempts {
                break 'direct;
            }
            tried_routes.insert(route);
            attempts += 1;
            let t0 = Instant::now();
            match connect_proxy(
                target_addr,
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
                            "attempt target={} via={} path=direct outcome=ok dur={}ms{}",
                            target_addr,
                            print_cfg(proxy_config),
                            ms,
                            ctag
                        )
                    });
                    rotator.record_success(proxy_config);
                    rotator.link_proxy(target_addr.to_string(), proxy_config.clone());
                    logger.cache_write(|| {
                        format!("Cache written for {} directly{}", target_addr, ctag)
                    });
                    return Ok(stream);
                }
                Err(e) => {
                    let ms = t0.elapsed().as_millis();
                    logger.attempt(|| {
                        format!(
                            "attempt target={} via={} path=direct outcome=fail dur={}ms err={}{}",
                            target_addr,
                            print_cfg(proxy_config),
                            ms,
                            e,
                            ctag,
                        )
                    });
                    logger.proxy_failure(|| {
                        format!(
                            "Failed direct: {} - {} - {}{}",
                            target_addr,
                            e,
                            print_cfg(proxy_config),
                            ctag,
                        )
                    });
                    if should_record_failure(&e) {
                        rotator.record_failure(proxy_config);
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
