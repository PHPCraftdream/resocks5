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

/// Returns `false` for cap-hit errors (semaphore full) — those are
/// our own load, not an upstream fault, and must NOT feed the sand
/// model's failure signal.
fn should_record_failure(err: &anyhow::Error) -> bool {
    err.downcast_ref::<resocks5_net::pool::AtCapacity>()
        .is_none()
}

/// Which stage of a gate tunnel failed. Attached to `use_gate` errors
/// as an `anyhow` context value so the caller can penalize only the
/// node actually responsible, while `AtCapacity` stays downcastable
/// through the context chain for `should_record_failure` —
/// `anyhow::Error::downcast_ref` recurses through every context layer
/// down to the concrete error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GateStage {
    /// `pool.acquire(gate_config)` failed: the gate itself was never
    /// usable; the inner proxy was not touched.
    GateConnect,
    /// Reaching the inner proxy through the gate failed: either the
    /// gate refuses to forward or the inner proxy is down — ambiguous
    /// from here by construction.
    GateToProxy,
    /// The gate worked; the inner proxy failed to reach the target.
    ProxyToTarget,
}

impl std::fmt::Display for GateStage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GateStage::GateConnect => write!(f, "gate connect"),
            GateStage::GateToProxy => write!(f, "gate-to-proxy hop"),
            GateStage::ProxyToTarget => write!(f, "proxy-to-target hop"),
        }
    }
}

/// Extract the failing tunnel stage from a `use_gate` error. Uses the
/// anyhow-level `downcast_ref` (recurses through context layers)
/// rather than walking `chain()`: chain elements are plain `dyn Error`
/// objects that cannot see through anyhow's context wrappers.
fn gate_stage_of(err: &anyhow::Error) -> Option<GateStage> {
    err.downcast_ref::<GateStage>().copied()
}

/// Feed one failed route attempt into this call's bookkeeping. Shared
/// by the cached-route retry path and the gates cartesian product so
/// their outcome handling cannot drift apart. Cap-hit errors are our
/// own load and feed nothing. Otherwise the failing [`GateStage`]
/// decides who pays: `GateConnect` penalizes only the gate and
/// dead-lists it, `ProxyToTarget` only the inner proxy (also
/// dead-listed), while `GateToProxy` and untagged errors stay the
/// documented ambiguous double penalty. A non-gate route
/// (`gate_config` is `None` — the error came from `connect_proxy`,
/// which never tags a stage) lands its single failure on the proxy
/// alone. Returns `true` when the attempt proved the gate itself
/// unreachable: the caller can stop pairing this gate with further
/// proxies right away, because `pool.acquire(gate)` does not involve
/// the inner proxy.
fn apply_gate_failure(
    err: &anyhow::Error,
    proxy_rotator: &ProxyRotator,
    proxy_config: &ProxyConfig,
    gate_config: Option<&ProxyConfig>,
    gate_rotator: Option<&ProxyRotator>,
    dead_gates: &mut HashSet<UpstreamId>,
    dead_proxies: &mut HashSet<UpstreamId>,
) -> bool {
    if !should_record_failure(err) {
        return false;
    }
    let Some(gate_config) = gate_config else {
        proxy_rotator.record_failure(proxy_config);
        return false;
    };
    match gate_stage_of(err) {
        Some(GateStage::GateConnect) => {
            // Stage 1: the gate was never usable; the inner proxy was
            // not touched.
            if let Some(gate_rotator) = gate_rotator {
                gate_rotator.record_failure(gate_config);
            }
            dead_gates.insert(upstream_id(gate_config));
            true
        }
        Some(GateStage::GateToProxy) => {
            // Stage 2 is ambiguous by construction: gate refusal to
            // forward vs. a down inner proxy is indistinguishable
            // here, so both stay penalized. The one clear attribution
            // (inner-proxy AtCapacity) is already excluded by
            // `should_record_failure` above.
            proxy_rotator.record_failure(proxy_config);
            if let Some(gate_rotator) = gate_rotator {
                gate_rotator.record_failure(gate_config);
            }
            false
        }
        Some(GateStage::ProxyToTarget) => {
            // Stage 3: the gate worked; the inner proxy failed to
            // reach the target.
            proxy_rotator.record_failure(proxy_config);
            dead_proxies.insert(upstream_id(proxy_config));
            false
        }
        None => {
            // `use_gate` tags every fallible stage; keep the blanket
            // double penalty for anything untagged.
            proxy_rotator.record_failure(proxy_config);
            if let Some(gate_rotator) = gate_rotator {
                gate_rotator.record_failure(gate_config);
            }
            false
        }
    }
}

/// Stable identity of one real upstream within this call: everything
/// that distinguishes genuinely different upstreams (endpoint,
/// protocol, account, gate flag), deliberately excluding `gate` —
/// that field records only how the upstream is reached on this
/// attempt. Mirrors the rating identity `ProxyRotator` uses, so a
/// sticky-cache composite (an inner config with `.gate` set) and the
/// plain inner config from `pick_order()` compare equal here.
type UpstreamId = (String, u16, u8, Option<String>, Option<String>, bool);

/// One access route tried this call: `Some(gate) + inner`, or
/// `None + inner` for the direct path.
type Route = (Option<UpstreamId>, UpstreamId);

fn upstream_id(p: &ProxyConfig) -> UpstreamId {
    (
        p.host.clone(),
        p.port,
        match p.protocol {
            ProxyProtocol::Socks5 => 0u8,
            ProxyProtocol::Http => 1,
            ProxyProtocol::Https => 2,
        },
        p.user.clone(),
        p.password.clone(),
        p.is_gate,
    )
}

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

async fn use_gate(
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
    let mut tried_routes: HashSet<Route> = HashSet::new();
    // Nodes proven unusable THIS call by a classified single-node
    // fault; excluded from later combinations within the same call.
    let mut dead_gates: HashSet<UpstreamId> = HashSet::new();
    let mut dead_proxies: HashSet<UpstreamId> = HashSet::new();
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
            let route: Route = (
                cached_proxy.gate.as_ref().map(|g| upstream_id(g)),
                upstream_id(&cached_proxy),
            );
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
                        cached_proxy.gate.as_deref(),
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
        let gate_order = gate_rotator.pick_order();
        'gates: for gate_config in &gate_order {
            let gate_id = upstream_id(gate_config);
            if dead_gates.contains(&gate_id) {
                continue;
            }
            for rotator in [v6_rotator, v4_rotator].iter().filter_map(|&r| r.as_ref()) {
                let order = rotator.pick_order();
                for proxy_config in &order {
                    let proxy_id = upstream_id(proxy_config);
                    if dead_proxies.contains(&proxy_id)
                        || tried_routes.contains(&(Some(gate_id.clone()), proxy_id.clone()))
                    {
                        continue;
                    }
                    if attempts + direct_reserve >= max_attempts {
                        break 'gates;
                    }
                    tried_routes.insert((Some(gate_id.clone()), proxy_id.clone()));
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
        let order = rotator.pick_order();
        for proxy_config in &order {
            let proxy_id = upstream_id(proxy_config);
            if dead_proxies.contains(&proxy_id) || tried_routes.contains(&(None, proxy_id.clone()))
            {
                continue;
            }
            if attempts >= max_attempts {
                break 'direct;
            }
            tried_routes.insert((None, proxy_id.clone()));
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

#[cfg(test)]
mod tests {
    use super::*;
    use resocks5_net::pool::AtCapacity;
    use std::net::SocketAddr;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn should_record_failure_returns_false_for_at_capacity() {
        let err = anyhow::Error::new(resocks5_net::pool::AtCapacity {
            host: "example.com".to_string(),
            port: 1080,
        });
        assert!(
            !should_record_failure(&err),
            "AtCapacity should NOT be recorded as failure"
        );
    }

    #[test]
    fn should_record_failure_returns_true_for_generic_error() {
        let err = anyhow::anyhow!("connection refused");
        assert!(
            should_record_failure(&err),
            "generic error SHOULD be recorded as failure"
        );
    }

    #[tokio::test]
    async fn gate_capacity_error_retains_its_type() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let gate = ProxyConfig {
            protocol: resocks5_net::types::ProxyProtocol::Socks5,
            ip: resocks5_net::types::IP::V4,
            host: address.ip().to_string(),
            port: address.port(),
            user: None,
            password: None,
            is_gate: true,
            gate: None,
        };
        let pool = ProxyPool::new(Default::default(), Duration::from_secs(2), 1);
        let _busy = pool.acquire(&gate).await.unwrap();
        let error = use_gate(
            "example.com:443",
            &gate,
            &gate,
            &pool,
            Duration::from_secs(2),
            None,
        )
        .await
        .err()
        .expect("gate at capacity must reject the connection");
        assert!(!should_record_failure(&error));
        assert!(error
            .downcast_ref::<resocks5_net::pool::AtCapacity>()
            .is_some());
    }

    /// Minimal no-auth SOCKS5 stub: answers method negotiation and
    /// CONNECT with success, then holds each socket open until the
    /// client drops it. Enough for `use_gate` / `connect_socks5_proxy`
    /// to complete both handshakes; nothing is relayed.
    async fn spawn_socks5_stub() -> SocketAddr {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut sock, _)) = listener.accept().await {
                tokio::spawn(async move {
                    // A gate socket carries one SOCKS5 handshake PER
                    // TUNNEL HOP (gate CONNECT, then inner CONNECT),
                    // so keep answering handshakes on the same
                    // connection until the client drops it — blocking
                    // on the next greeting is what holds the tunnel
                    // "live".
                    loop {
                        let mut greet = [0u8; 3];
                        if sock.read_exact(&mut greet).await.is_err() {
                            return;
                        }
                        if sock.write_all(&[0x05, 0x00]).await.is_err() {
                            return;
                        }
                        let mut head = [0u8; 4];
                        if sock.read_exact(&mut head).await.is_err() {
                            return;
                        }
                        let addr_len = match head[3] {
                            0x01 => 4,
                            0x03 => {
                                let mut l = [0u8; 1];
                                if sock.read_exact(&mut l).await.is_err() {
                                    return;
                                }
                                l[0] as usize
                            }
                            0x04 => 16,
                            _ => return,
                        };
                        let mut rest = vec![0u8; addr_len + 2];
                        if sock.read_exact(&mut rest).await.is_err() {
                            return;
                        }
                        let _ = sock
                            .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                            .await;
                    }
                });
            }
        });
        addr
    }

    fn socks5_config(addr: SocketAddr, is_gate: bool) -> ProxyConfig {
        ProxyConfig {
            protocol: resocks5_net::types::ProxyProtocol::Socks5,
            ip: resocks5_net::types::IP::V4,
            host: addr.ip().to_string(),
            port: addr.port(),
            user: None,
            password: None,
            is_gate,
            gate: None,
        }
    }

    #[tokio::test]
    async fn direct_and_gate_paths_share_one_upstream_cap() {
        // Upstream X serves BOTH paths: one direct connection plus one
        // gate-tunnelled one must exactly fill its cap of 2 — the gate
        // hop consumes a slot even though its socket terminates at the
        // gate. Before the R14 fix the gate path took no X slot.
        let pool = ProxyPool::new(Default::default(), Duration::from_secs(2), 2);
        let upstream = socks5_config(spawn_socks5_stub().await, false);
        let gate = socks5_config(spawn_socks5_stub().await, true);

        let direct = connect_proxy(
            "example.com:443",
            &upstream,
            &pool,
            Duration::from_secs(2),
            None,
        )
        .await
        .expect("direct connect");
        let tunneled = use_gate(
            "example.com:443",
            &gate,
            &upstream,
            &pool,
            Duration::from_secs(2),
            None,
        )
        .await
        .expect("gate tunnel");

        // Combined load is at the cap: BOTH paths must fail fast with
        // AtCapacity (no sand-model penalty, per `should_record_failure`).
        let err = connect_proxy(
            "example.com:443",
            &upstream,
            &pool,
            Duration::from_secs(2),
            None,
        )
        .await
        .err()
        .expect("direct path must hit the cap");
        assert!(
            err.downcast_ref::<AtCapacity>().is_some(),
            "unexpected error: {}",
            err
        );
        assert!(!should_record_failure(&err));

        let err = use_gate(
            "example.com:443",
            &gate,
            &upstream,
            &pool,
            Duration::from_secs(2),
            None,
        )
        .await
        .err()
        .expect("gate path must hit the cap");
        assert!(
            err.downcast_ref::<AtCapacity>().is_some(),
            "unexpected error: {}",
            err
        );
        assert!(!should_record_failure(&err));

        // A freed slot is path-agnostic: the tunnel takes it, the
        // direct path is still shut out.
        drop(direct);
        let _again = use_gate(
            "example.com:443",
            &gate,
            &upstream,
            &pool,
            Duration::from_secs(2),
            None,
        )
        .await
        .expect("freed slot usable via gate");
        assert!(
            connect_proxy(
                "example.com:443",
                &upstream,
                &pool,
                Duration::from_secs(2),
                None,
            )
            .await
            .err()
            .and_then(|e| e.downcast_ref::<AtCapacity>().cloned())
            .is_some(),
            "direct path still at cap"
        );
        drop((_again, tunneled));
    }

    #[tokio::test]
    async fn failed_reservation_releases_gate_permit_and_target_is_identifiable() {
        // Gate step succeeds, but the inner proxy's cap is full: the
        // attempt must abort with AtCapacity FOR THE INNER PROXY (so
        // `should_record_failure` stays false) and release the gate's
        // permit — a leak would exhaust the gate's cap of 1 and the
        // retry loop would start failing at the gate instead.
        let pool = ProxyPool::new(Default::default(), Duration::from_secs(2), 1);
        let gate = socks5_config(spawn_socks5_stub().await, true);
        let saturated = socks5_config(spawn_socks5_stub().await, false);
        let healthy = socks5_config(spawn_socks5_stub().await, false);

        let _holder = pool.acquire(&saturated).await.expect("fill the upstream");

        for _ in 0..5 {
            let err = use_gate(
                "example.com:443",
                &gate,
                &saturated,
                &pool,
                Duration::from_secs(2),
                None,
            )
            .await
            .err()
            .expect("saturated upstream must fail");
            let cap = err
                .downcast_ref::<AtCapacity>()
                .cloned()
                .unwrap_or_else(|| panic!("expected AtCapacity, got: {}", err));
            assert_eq!(
                (cap.host.as_str(), cap.port),
                (&*saturated.host, saturated.port)
            );
            assert!(!should_record_failure(&anyhow::Error::from(cap)));
        }

        // The gate never leaked a permit: a tunnel to a healthy
        // upstream through the same gate still succeeds.
        let _ok = use_gate(
            "example.com:443",
            &gate,
            &healthy,
            &pool,
            Duration::from_secs(2),
            None,
        )
        .await
        .expect("gate reusable after failed attempts");
    }

    /// TCP listener that accepts, reads the SOCKS5 greeting, and
    /// answers with protocol garbage — models a gate whose first
    /// tunnel hop fails.
    async fn spawn_garbage_socks5_stub() -> SocketAddr {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut sock, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut greet = [0u8; 3];
                    if sock.read_exact(&mut greet).await.is_err() {
                        return;
                    }
                    let _ = sock.write_all(&[0xde, 0xad]).await;
                });
            }
        });
        addr
    }

    /// SOCKS5 stub that answers the FIRST CONNECT with success and any
    /// LATER CONNECT on the same socket with a general SOCKS failure —
    /// models a gate whose own endpoint is healthy while the inner
    /// proxy fails to reach the target (hop 2).
    async fn spawn_socks5_second_connect_refused_stub() -> SocketAddr {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut sock, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut first = true;
                    loop {
                        let mut greet = [0u8; 3];
                        if sock.read_exact(&mut greet).await.is_err() {
                            return;
                        }
                        if sock.write_all(&[0x05, 0x00]).await.is_err() {
                            return;
                        }
                        let mut head = [0u8; 4];
                        if sock.read_exact(&mut head).await.is_err() {
                            return;
                        }
                        let addr_len = match head[3] {
                            0x01 => 4,
                            0x03 => {
                                let mut l = [0u8; 1];
                                if sock.read_exact(&mut l).await.is_err() {
                                    return;
                                }
                                l[0] as usize
                            }
                            0x04 => 16,
                            _ => return,
                        };
                        let mut rest = vec![0u8; addr_len + 2];
                        if sock.read_exact(&mut rest).await.is_err() {
                            return;
                        }
                        let rep = if first { 0x00 } else { 0x01 };
                        first = false;
                        if sock
                            .write_all(&[0x05, rep, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                            .await
                            .is_err()
                        {
                            return;
                        }
                    }
                });
            }
        });
        addr
    }

    #[tokio::test]
    async fn use_gate_classifies_gate_connect_failure() {
        // Nothing listens on port 1: the TCP connect to the gate is
        // refused instantly, before the inner proxy is touched.
        let gate = socks5_config(SocketAddr::from(([127, 0, 0, 1], 1)), true);
        let inner = socks5_config(SocketAddr::from(([127, 0, 0, 1], 2)), false);
        let pool = ProxyPool::new(Default::default(), Duration::from_secs(2), 4);
        let err = use_gate(
            "example.com:443",
            &gate,
            &inner,
            &pool,
            Duration::from_secs(2),
            None,
        )
        .await
        .err()
        .expect("dead gate must fail");
        assert_eq!(gate_stage_of(&err), Some(GateStage::GateConnect));
        assert!(
            should_record_failure(&err),
            "refused TCP is an upstream fault"
        );
    }

    #[tokio::test]
    async fn use_gate_classifies_gate_to_proxy_hop_failure() {
        // The gate accepts TCP but answers its first SOCKS5 exchange
        // with garbage: hop 1 (reaching the inner proxy through the
        // gate) fails after the gate itself was acquired.
        let gate = socks5_config(spawn_garbage_socks5_stub().await, true);
        let inner = socks5_config(spawn_socks5_stub().await, false);
        let pool = ProxyPool::new(Default::default(), Duration::from_secs(2), 4);
        let err = use_gate(
            "example.com:443",
            &gate,
            &inner,
            &pool,
            Duration::from_secs(2),
            None,
        )
        .await
        .err()
        .expect("garbage gate hop must fail");
        assert_eq!(gate_stage_of(&err), Some(GateStage::GateToProxy));
    }

    #[tokio::test]
    async fn use_gate_classifies_proxy_to_target_hop_failure() {
        // First CONNECT through the gate succeeds, the second (the
        // inner proxy reaching the target) is answered with a SOCKS
        // failure: the gate worked, the proxy-to-target hop failed.
        let gate = socks5_config(spawn_socks5_second_connect_refused_stub().await, true);
        let inner = socks5_config(spawn_socks5_stub().await, false);
        let pool = ProxyPool::new(Default::default(), Duration::from_secs(2), 4);
        let err = use_gate(
            "example.com:443",
            &gate,
            &inner,
            &pool,
            Duration::from_secs(2),
            None,
        )
        .await
        .err()
        .expect("target-hop failure expected");
        assert_eq!(gate_stage_of(&err), Some(GateStage::ProxyToTarget));
    }

    #[tokio::test]
    async fn inner_capacity_failure_classifies_gate_to_proxy_and_stays_noop() {
        // Inner proxy at cap: the failure must STILL downcast to
        // AtCapacity through the new stage marker (so the sand model
        // sees no failure) and classify as the gate-to-proxy stage.
        let pool = ProxyPool::new(Default::default(), Duration::from_secs(2), 1);
        let gate = socks5_config(spawn_socks5_stub().await, true);
        let saturated = socks5_config(spawn_socks5_stub().await, false);
        let _holder = pool.acquire(&saturated).await.expect("fill the upstream");
        let err = use_gate(
            "example.com:443",
            &gate,
            &saturated,
            &pool,
            Duration::from_secs(2),
            None,
        )
        .await
        .err()
        .expect("saturated upstream must fail");
        assert!(
            err.downcast_ref::<AtCapacity>().is_some(),
            "AtCapacity must stay downcastable through the stage marker, got: {}",
            err
        );
        assert!(!should_record_failure(&err));
        assert_eq!(gate_stage_of(&err), Some(GateStage::GateToProxy));
    }

    fn test_logger() -> Arc<Logger> {
        let (tx, _rx) = tokio::sync::mpsc::channel::<crate::logger::ELog>(64);
        Arc::new(Logger::new(tx, crate::logger::LogConfig::default()))
    }

    #[tokio::test]
    async fn dead_cache_route_is_skipped_and_direct_fallback_survives() {
        // R18: budget 2. The sticky cache holds a composite of the
        // healthy inner proxy reached through a dead gate, and the gate
        // rotator offers the SAME dead gate. Without route tracking the
        // cache attempt and the gates-phase retry of the identical
        // route burn the whole budget and starve the direct path.
        let target = "example.com:443";
        let logger = test_logger();
        let banned = Arc::new(RegexSet::empty());
        let pool = Arc::new(ProxyPool::new(
            Default::default(),
            Duration::from_secs(2),
            4,
        ));
        let network = Arc::new(NetworkConfig {
            handshake_timeout_sec: 2,
            max_upstream_attempts: 2,
            ..Default::default()
        });
        let dead_gate = socks5_config(SocketAddr::from(([127, 0, 0, 1], 1)), true);
        let inner = socks5_config(spawn_socks5_stub().await, false);
        let mut composite = inner.clone();
        composite.gate = Some(Arc::new(dead_gate.clone()));

        let v4 = Arc::new(ProxyRotator::new(vec![inner.clone()]));
        v4.link_proxy(target.to_string(), Arc::new(composite));
        let gates = Arc::new(ProxyRotator::new(vec![dead_gate]));

        let result = establish_connection(
            target,
            &Some(gates),
            &None,
            &Some(v4.clone()),
            &logger,
            &banned,
            &pool,
            &network,
            None,
            None,
        )
        .await;

        assert!(
            result.is_ok(),
            "direct fallback must survive: {:?}",
            result.as_ref().err()
        );
        let linked = v4.get_linked(target).expect("success must link the cache");
        assert!(
            linked.gate.is_none(),
            "the direct path must have served the target"
        );
    }

    #[tokio::test]
    async fn gates_phase_cannot_exhaust_budget_before_direct_fallback() {
        // R18: budget 2, no cache entry. Two dead gates used to burn
        // the whole budget inside the gates cartesian product; the
        // direct phase is owed one attempt and reaches the healthy
        // inner proxy.
        let target = "example.com:443";
        let logger = test_logger();
        let banned = Arc::new(RegexSet::empty());
        let pool = Arc::new(ProxyPool::new(
            Default::default(),
            Duration::from_secs(2),
            4,
        ));
        let network = Arc::new(NetworkConfig {
            handshake_timeout_sec: 2,
            max_upstream_attempts: 2,
            ..Default::default()
        });
        let dead1 = socks5_config(SocketAddr::from(([127, 0, 0, 1], 1)), true);
        let dead2 = socks5_config(SocketAddr::from(([127, 0, 0, 1], 2)), true);
        let inner = socks5_config(spawn_socks5_stub().await, false);

        let gates = Arc::new(ProxyRotator::new(vec![dead1, dead2]));
        let v4 = Arc::new(ProxyRotator::new(vec![inner]));

        let result = establish_connection(
            target,
            &Some(gates),
            &None,
            &Some(v4.clone()),
            &logger,
            &banned,
            &pool,
            &network,
            None,
            None,
        )
        .await;

        assert!(
            result.is_ok(),
            "direct fallback must get its reserved attempt: {:?}",
            result.as_ref().err()
        );
        let linked = v4.get_linked(target).expect("success must link the cache");
        assert!(linked.gate.is_none());
    }

    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine as _;
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::Mutex;
    use tokio::io::{AsyncRead, AsyncWrite};
    use tokio_rustls::rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
    use tokio_rustls::rustls::{ClientConfig, RootCertStore, ServerConfig};
    use tokio_rustls::TlsAcceptor;

    /// TEST-ONLY throwaway material: self-signed ECDSA P-256 end-entity
    /// cert for `localhost` (CA:FALSE, serverAuth), generated 2026-09-08
    /// for these stubs; never used outside `cargo test`.
    const STUB_CERT_PEM: &str = r#"-----BEGIN CERTIFICATE-----
MIIBkTCCATegAwIBAgIUTnhc5opoloJUaX3/qEiEQBaGaj4wCgYIKoZIzj0EAwIw
FDESMBAGA1UEAwwJbG9jYWxob3N0MB4XDTI2MDkwODEwMjAyMVoXDTM2MDkwNTEw
MjAyMVowFDESMBAGA1UEAwwJbG9jYWxob3N0MFkwEwYHKoZIzj0CAQYIKoZIzj0D
AQcDQgAECLJv3u8HBhb3mmHOL/IQi8kHgskR+5uVPiGibOwNB/NesbAFYkEI9lyc
mwPJ6TYI5yOKs6R/YkF1gx7zfqAp26NnMGUwFAYDVR0RBA0wC4IJbG9jYWxob3N0
MAwGA1UdEwEB/wQCMAAwCwYDVR0PBAQDAgWgMBMGA1UdJQQMMAoGCCsGAQUFBwMB
MB0GA1UdDgQWBBQ9VXC74t1ItOQJpFl6tnp+7fLQHTAKBggqhkjOPQQDAgNIADBF
AiEA3zuXe3kNshyz5ke5q6iQZfVCSPQFI00rVKs938C278YCIFrUysrQGFAdsdll
zFEdGqtgbBEr1xadJtJyXJGBvdd0
-----END CERTIFICATE-----
"#;

    const STUB_KEY_PEM: &str = r#"-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgRbNQhRHo9//xljJ5
228sdn61rvXR9Vby6uz92ef6LbKhRANCAAQIsm/e7wcGFveaYc4v8hCLyQeCyRH7
m5U+IaJs7A0H816xsAViQQj2XJybA8npNgjnI4qzpH9iQXWDHvN+oCnb
-----END PRIVATE KEY-----
"#;

    fn pem_der(pem: &str) -> Vec<u8> {
        let b64: String = pem.lines().filter(|l| !l.starts_with("-----")).collect();
        B64.decode(b64).expect("valid base64 PEM body")
    }

    fn stub_tls_acceptor() -> TlsAcceptor {
        let cert = CertificateDer::from(pem_der(STUB_CERT_PEM));
        let key = PrivatePkcs8KeyDer::from(pem_der(STUB_KEY_PEM));
        let config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert], key.into())
            .expect("valid stub server config");
        TlsAcceptor::from(Arc::new(config))
    }

    fn stub_tls_connector() -> TlsConnector {
        let mut roots = RootCertStore::empty();
        roots
            .add(CertificateDer::from(pem_der(STUB_CERT_PEM)))
            .expect("stub cert parses");
        let config = ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        TlsConnector::from(Arc::new(config))
    }

    /// One stub hop: which wire behaviour to expect next on the socket.
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    enum StubPhase {
        /// Answer a SOCKS5 exchange (records the requested target).
        Socks5,
        /// Answer an HTTP CONNECT (records the requested target).
        HttpConnect,
        /// TLS-accept the stream, then continue inside the TLS layer.
        TlsAccept,
    }

    fn stub_phases(proto: ProxyProtocol) -> Vec<StubPhase> {
        match proto {
            ProxyProtocol::Socks5 => vec![StubPhase::Socks5],
            ProxyProtocol::Http => vec![StubPhase::HttpConnect],
            ProxyProtocol::Https => vec![StubPhase::TlsAccept, StubPhase::HttpConnect],
        }
    }

    type StubLog = Arc<Mutex<Vec<(StubPhase, String)>>>;

    /// Serve ONE client connection through its expected phase sequence.
    /// The tunnel is a single socket: both hops' exchanges arrive here,
    /// an Https hop nests the remaining phases inside a TLS layer. After
    /// the last phase, hold the tunnel open until the client drops it.
    trait Stream: AsyncRead + AsyncWrite + Unpin + Send {}
    impl<T: AsyncRead + AsyncWrite + Unpin + Send> Stream for T {}
    type ErasedStream = Box<dyn Stream>;

    fn serve_phases<'a>(
        mut stream: ErasedStream,
        phases: &'a [StubPhase],
        tls: &'a TlsAcceptor,
        log: &'a StubLog,
    ) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>> {
        Box::pin(async move {
            let Some((phase, rest)) = phases.split_first() else {
                let mut buf = [0u8; 512];
                while stream.read(&mut buf).await.unwrap_or(0) != 0 {}
                return;
            };
            match phase {
                StubPhase::TlsAccept => {
                    let Ok(tls_stream) = tls.accept(stream).await else {
                        return;
                    };
                    serve_phases(Box::new(tls_stream), rest, tls, log).await;
                }
                StubPhase::Socks5 => {
                    if let Some(target) = socks5_exchange(&mut stream).await {
                        log.lock().unwrap().push((StubPhase::Socks5, target));
                    }
                    serve_phases(Box::new(stream), rest, tls, log).await;
                }
                StubPhase::HttpConnect => {
                    if let Some(target) = http_connect_exchange(&mut stream).await {
                        log.lock().unwrap().push((StubPhase::HttpConnect, target));
                    }
                    serve_phases(Box::new(stream), rest, tls, log).await;
                }
            }
        })
    }

    /// Answer one no-auth SOCKS5 exchange; returns the requested target.
    async fn socks5_exchange<S>(stream: &mut S) -> Option<String>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send,
    {
        let mut greet = [0u8; 2];
        stream.read_exact(&mut greet).await.ok()?;
        if greet[0] != 0x05 {
            return None;
        }
        let mut methods = vec![0u8; greet[1] as usize];
        stream.read_exact(&mut methods).await.ok()?;
        stream.write_all(&[0x05, 0x00]).await.ok()?;

        let mut head = [0u8; 4];
        stream.read_exact(&mut head).await.ok()?;
        if head[0] != 0x05 || head[1] != 0x01 {
            return None;
        }
        let host = match head[3] {
            0x01 => {
                let mut o = [0u8; 4];
                stream.read_exact(&mut o).await.ok()?;
                std::net::Ipv4Addr::from(o).to_string()
            }
            0x03 => {
                let mut l = [0u8; 1];
                stream.read_exact(&mut l).await.ok()?;
                let mut d = vec![0u8; l[0] as usize];
                stream.read_exact(&mut d).await.ok()?;
                String::from_utf8(d).ok()?
            }
            0x04 => {
                let mut o = [0u8; 16];
                stream.read_exact(&mut o).await.ok()?;
                std::net::Ipv6Addr::from(o).to_string()
            }
            _ => return None,
        };
        let mut port = [0u8; 2];
        stream.read_exact(&mut port).await.ok()?;
        stream
            .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .await
            .ok()?;
        Some(format!("{}:{}", host, u16::from_be_bytes(port)))
    }

    /// Answer one HTTP CONNECT; returns the requested target.
    async fn http_connect_exchange<S>(stream: &mut S) -> Option<String>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send,
    {
        let mut req = Vec::new();
        loop {
            let mut byte = [0u8; 1];
            stream.read_exact(&mut byte).await.ok()?;
            req.push(byte[0]);
            if req.ends_with(b"\r\n\r\n") {
                break;
            }
            if req.len() > 8192 {
                return None;
            }
        }
        let text = std::str::from_utf8(&req).ok()?;
        let line = text.split("\r\n").next()?;
        let target = line
            .strip_prefix("CONNECT ")?
            .split(' ')
            .next()?
            .to_string();
        stream
            .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
            .await
            .ok()?;
        Some(target)
    }

    /// Spawn a stub speaking `gate_proto` then `inner_proto` (in the
    /// same order `use_gate` drives its two hops) on one listener; both
    /// the gate and the inner config point at it. Returns the address
    /// and the log of answered exchanges as (phase, requested target).
    async fn spawn_protocol_stub(
        gate_proto: ProxyProtocol,
        inner_proto: ProxyProtocol,
    ) -> (SocketAddr, StubLog) {
        let phases: Vec<StubPhase> = stub_phases(gate_proto)
            .into_iter()
            .chain(stub_phases(inner_proto))
            .collect();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        // `localhost` may resolve to ::1 first; a stalled IPv6 connect
        // attempt would eat the pool's connect timeout, so serve both
        // loopback families on the same port.
        let v6 = tokio::net::TcpListener::bind(format!("[::1]:{}", addr.port())).await;
        let log: StubLog = Arc::new(Mutex::new(Vec::new()));
        let tls = stub_tls_acceptor();
        let log_task = Arc::clone(&log);
        tokio::spawn(async move {
            if let Ok(v6) = v6 {
                let phases = phases.clone();
                let tls = tls.clone();
                let log6 = Arc::clone(&log_task);
                tokio::spawn(async move {
                    while let Ok((sock, _)) = v6.accept().await {
                        let phases = phases.clone();
                        let tls = tls.clone();
                        let log = Arc::clone(&log6);
                        tokio::spawn(async move {
                            serve_phases(Box::new(sock), &phases, &tls, &log).await;
                        });
                    }
                });
            }
            while let Ok((sock, _)) = listener.accept().await {
                let phases = phases.clone();
                let tls = tls.clone();
                let log = Arc::clone(&log_task);
                tokio::spawn(async move {
                    serve_phases(Box::new(sock), &phases, &tls, &log).await;
                });
            }
        });
        (addr, log)
    }

    fn stub_config(addr: SocketAddr, protocol: ProxyProtocol, is_gate: bool) -> ProxyConfig {
        ProxyConfig {
            protocol,
            ip: resocks5_net::types::IP::V4,
            host: "localhost".to_string(),
            port: addr.port(),
            user: None,
            password: None,
            is_gate,
            gate: None,
        }
    }

    /// One gate×inner combo end to end: `use_gate` must complete both
    /// handshakes speaking each hop's actual wire protocol, in order,
    /// addressed first to the inner proxy and then to the target.
    async fn run_matrix_combo(gate_proto: ProxyProtocol, inner_proto: ProxyProtocol) {
        let (addr, log) = spawn_protocol_stub(gate_proto, inner_proto).await;
        let gate = stub_config(addr, gate_proto, true);
        let inner = stub_config(addr, inner_proto, false);
        let pool = ProxyPool::new(Default::default(), Duration::from_secs(2), 4);
        let connector = stub_tls_connector();
        let tls_connector =
            if gate_proto == ProxyProtocol::Https || inner_proto == ProxyProtocol::Https {
                Some(&connector)
            } else {
                None
            };

        let tunneled = timeout(
            Duration::from_secs(15),
            use_gate(
                "example.com:443",
                &gate,
                &inner,
                &pool,
                Duration::from_secs(5),
                tls_connector,
            ),
        )
        .await
        .expect("combo must not hang")
        .expect("gate tunnel must complete");

        // Socket options must reach the REAL gate socket through the
        // erasure. Across the 9 rows this exercises all three erased
        // shapes — plain (`UpstreamStream`), single TLS, and double
        // TLS — with an observable TCP_NODELAY round-trip, not just a
        // non-error return.
        let gate_socket = tunneled
            .as_tcp()
            .expect("gate tunnel exposes its real socket");
        gate_socket
            .set_nodelay(true)
            .expect("set_nodelay reaches the gate socket");
        assert!(
            gate_socket.nodelay().expect("nodelay readback"),
            "TCP_NODELAY must be observably applied on the gate socket"
        );

        let mut expected = Vec::new();
        for (proto, target) in [
            (gate_proto, format!("localhost:{}", inner.port)),
            (inner_proto, "example.com:443".to_string()),
        ] {
            let phase = match proto {
                ProxyProtocol::Socks5 => StubPhase::Socks5,
                ProxyProtocol::Http | ProxyProtocol::Https => StubPhase::HttpConnect,
            };
            expected.push((phase, target));
        }
        let got = log.lock().unwrap().clone();
        assert_eq!(
            got, expected,
            "wire exchanges for gate={:?} inner={:?}",
            gate_proto, inner_proto
        );
    }

    #[tokio::test]
    async fn matrix_socks5_gate_socks5_inner() {
        run_matrix_combo(ProxyProtocol::Socks5, ProxyProtocol::Socks5).await;
    }

    #[tokio::test]
    async fn matrix_socks5_gate_http_inner() {
        run_matrix_combo(ProxyProtocol::Socks5, ProxyProtocol::Http).await;
    }

    #[tokio::test]
    async fn matrix_socks5_gate_https_inner() {
        run_matrix_combo(ProxyProtocol::Socks5, ProxyProtocol::Https).await;
    }

    #[tokio::test]
    async fn matrix_http_gate_socks5_inner() {
        run_matrix_combo(ProxyProtocol::Http, ProxyProtocol::Socks5).await;
    }

    #[tokio::test]
    async fn matrix_http_gate_http_inner() {
        run_matrix_combo(ProxyProtocol::Http, ProxyProtocol::Http).await;
    }

    #[tokio::test]
    async fn matrix_http_gate_https_inner() {
        run_matrix_combo(ProxyProtocol::Http, ProxyProtocol::Https).await;
    }

    #[tokio::test]
    async fn matrix_https_gate_socks5_inner() {
        run_matrix_combo(ProxyProtocol::Https, ProxyProtocol::Socks5).await;
    }

    #[tokio::test]
    async fn matrix_https_gate_http_inner() {
        run_matrix_combo(ProxyProtocol::Https, ProxyProtocol::Http).await;
    }

    #[tokio::test]
    async fn matrix_https_gate_https_inner() {
        run_matrix_combo(ProxyProtocol::Https, ProxyProtocol::Https).await;
    }

    #[tokio::test]
    async fn https_hop_without_connector_is_rejected_without_credential_leak() {
        let (addr, _log) = spawn_protocol_stub(ProxyProtocol::Https, ProxyProtocol::Socks5).await;
        let mut gate = stub_config(addr, ProxyProtocol::Https, true);
        gate.user = Some("alice".to_string());
        gate.password = Some("s3cret".to_string());
        let inner = stub_config(addr, ProxyProtocol::Socks5, false);
        let pool = ProxyPool::new(Default::default(), Duration::from_secs(2), 4);

        let err = timeout(
            Duration::from_secs(5),
            use_gate(
                "example.com:443",
                &gate,
                &inner,
                &pool,
                Duration::from_secs(2),
                None,
            ),
        )
        .await
        .expect("must not hang")
        .err()
        .expect("HTTPS hop without a TLS connector must fail");

        let chain: Vec<String> = err.chain().map(|c| c.to_string()).collect();
        assert!(
            chain
                .iter()
                .any(|c| c.contains("HTTPS upstream requires TLS connector")),
            "chain must name the missing connector, got: {:?}",
            chain
        );
        let joined = chain.join("\n");
        assert!(!joined.contains("alice"), "username leaked: {}", joined);
        assert!(!joined.contains("s3cret"), "password leaked: {}", joined);
    }

    /// Rating policy where ONE failure saturates the sand completely
    /// (`fail_penalty == sand_max`) and decay is negligible over a test
    /// run: a penalized upstream weighs exactly `min_weight` = 0.01 vs
    /// 1.0 for a pristine one, so sampling `pick_order` separates the
    /// two within a few thousand draws (same technique as the
    /// rotator's own `record_failure_lowers_pick_probability`).
    fn sharp_policy() -> resocks5_net::rating::RatingPolicy {
        resocks5_net::rating::RatingPolicy {
            half_life_sec: 3600.0,
            fail_penalty: 8.0,
            sand_max: 8.0,
            min_weight: 0.01,
            success_factor: 0.5,
        }
    }

    /// Fraction of `n` weighted-random picks that put `proxy` first.
    fn first_pick_fraction(rotator: &ProxyRotator, proxy: &ProxyConfig, n: u32) -> f64 {
        let mut hits = 0u32;
        for _ in 0..n {
            if rotator.pick_order()[0].port == proxy.port {
                hits += 1;
            }
        }
        f64::from(hits) / f64::from(n)
    }

    #[tokio::test]
    async fn cached_gate_connect_failure_penalizes_gate_not_inner_proxy() {
        // R2-19: the cached-route retry of a gate composite must apply
        // the same per-stage classification as the gates phase. The
        // gate is unreachable (GateConnect): the inner proxy — never
        // touched — keeps its rating, while the gate itself takes the
        // penalty (and is excluded from the later gates phase).
        let target = "example.com:443";
        let logger = test_logger();
        let banned = Arc::new(RegexSet::empty());
        let pool = Arc::new(ProxyPool::new(
            Default::default(),
            Duration::from_secs(2),
            4,
        ));
        let network = Arc::new(NetworkConfig {
            handshake_timeout_sec: 2,
            // One cache attempt, then the gates phase must bail before
            // any pairing: budget 2 minus the direct reserve of 1. So
            // the witness gate below is never attempted and its rating
            // stays pristine as the control.
            max_upstream_attempts: 2,
            ..Default::default()
        });
        let dead_gate = socks5_config(SocketAddr::from(([127, 0, 0, 1], 1)), true);
        let witness_gate = socks5_config(SocketAddr::from(([127, 0, 0, 1], 2)), true);
        let inner_a = socks5_config(spawn_socks5_stub().await, false);
        let inner_b = socks5_config(spawn_socks5_stub().await, false);
        let mut composite = inner_a.clone();
        composite.gate = Some(Arc::new(dead_gate.clone()));

        let policy = sharp_policy();
        let v4 = Arc::new(ProxyRotator::with_policy(
            vec![inner_a.clone(), inner_b.clone()],
            policy,
        ));
        v4.link_proxy(target.to_string(), Arc::new(composite));
        let gates = Arc::new(ProxyRotator::with_policy(
            vec![dead_gate, witness_gate.clone()],
            policy,
        ));

        let result = establish_connection(
            target,
            &Some(gates.clone()),
            &None,
            &Some(v4.clone()),
            &logger,
            &banned,
            &pool,
            &network,
            None,
            None,
        )
        .await;
        assert!(
            result.is_ok(),
            "direct fallback must serve the target: {:?}",
            result.as_ref().err()
        );

        // The inner proxy was spared: both inners still weigh ~1.0, so
        // either may be picked first about half the time. Before the
        // fix the cached failure landed on the composite's inner
        // identity (~1% first-pick).
        let frac_a = first_pick_fraction(&v4, &inner_a, 2000);
        assert!(
            frac_a > 0.3,
            "untouched inner proxy picked first only {:.1}%, expected ~50%",
            frac_a * 100.0
        );

        // The gate took the penalty: the never-attempted witness gate
        // must now dominate the gate rotator's picks. Before the fix
        // both gates stayed pristine (~50%).
        let frac_witness = first_pick_fraction(&gates, &witness_gate, 2000);
        assert!(
            frac_witness > 0.7,
            "spared witness gate picked first only {:.1}%, expected ~99%",
            frac_witness * 100.0
        );
    }

    #[tokio::test]
    async fn dead_gate_not_retried_against_second_proxy_within_one_call() {
        // R2-19: once a gate fails at GateConnect against the FIRST
        // proxy, the same call must not burn another attempt pairing
        // it with the NEXT proxy — the dead-gate short-circuit takes
        // effect immediately, not at the next outer-loop entry. The
        // budget is deliberately generous so only the short-circuit
        // (not the budget) can stop the gates phase.
        let target = "example.com:443";
        let banned = Arc::new(RegexSet::empty());
        let pool = Arc::new(ProxyPool::new(
            Default::default(),
            Duration::from_secs(2),
            4,
        ));
        let network = Arc::new(NetworkConfig {
            handshake_timeout_sec: 2,
            max_upstream_attempts: 10,
            ..Default::default()
        });
        let dead_gate = socks5_config(SocketAddr::from(([127, 0, 0, 1], 1)), true);
        let inner_a = socks5_config(spawn_socks5_stub().await, false);
        let inner_b = socks5_config(spawn_socks5_stub().await, false);

        let (tx, mut rx) = tokio::sync::mpsc::channel::<crate::logger::ELog>(64);
        let logger = Arc::new(Logger::new(
            tx,
            crate::logger::LogConfig {
                attempts: true,
                ..Default::default()
            },
        ));

        let gates = Arc::new(ProxyRotator::new(vec![dead_gate]));
        let v4 = Arc::new(ProxyRotator::new(vec![inner_a, inner_b]));

        let result = establish_connection(
            target,
            &Some(gates),
            &None,
            &Some(v4.clone()),
            &logger,
            &banned,
            &pool,
            &network,
            None,
            None,
        )
        .await;
        assert!(
            result.is_ok(),
            "direct fallback must serve the target: {:?}",
            result.as_ref().err()
        );

        // Each `use_gate` attempt logs exactly one `attempt ... path=gate`
        // line; the direct fallback logs `path=direct`.
        let mut gate_attempts = 0u32;
        let mut direct_attempts = 0u32;
        while let Ok(entry) = rx.try_recv() {
            let crate::logger::ELog::Log(msg) = entry else {
                continue;
            };
            if msg.contains("path=gate") {
                gate_attempts += 1;
            } else if msg.contains("path=direct") {
                direct_attempts += 1;
            }
        }
        assert_eq!(
            gate_attempts, 1,
            "a gate proven dead against the first proxy must not be \
             re-tried against the second within the same call"
        );
        assert_eq!(
            direct_attempts, 1,
            "the direct fallback must still run exactly once"
        );
    }
}
