use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Context};
use regex::RegexSet;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;

use crate::config::NetworkConfig;
use crate::logger::Logger;
use crate::server::{get_auth, print_cfg};
use resocks5_net::connect::{connect_proxy, handshake_over_stream};
use resocks5_net::pool::{AnyUpstream, ProxyPool, UpstreamStream};
use resocks5_net::rotator::ProxyRotator;
use resocks5_net::types::ProxyConfig;

/// Returns `false` for cap-hit errors (semaphore full) — those are
/// our own load, not an upstream fault, and must NOT feed the sand
/// model's failure signal.
fn should_record_failure(err: &anyhow::Error) -> bool {
    err.downcast_ref::<resocks5_net::pool::AtCapacity>()
        .is_none()
}

async fn handshake_with_timeout(
    stream: UpstreamStream,
    target: &str,
    auth: Option<(&str, &str)>,
    t: Duration,
) -> anyhow::Result<UpstreamStream> {
    match timeout(t, handshake_over_stream(stream, target, auth)).await {
        Ok(res) => res,
        Err(_) => Err(anyhow!(
            "[SOCKS5] handshake timeout ({}s) for target {}",
            t.as_secs(),
            target
        )),
    }
}

async fn use_gate(
    target_addr: &str,
    gate_config: &ProxyConfig,
    proxy_config: &ProxyConfig,
    pool: &ProxyPool,
    handshake_timeout: Duration,
) -> anyhow::Result<AnyUpstream> {
    let proxy_addr = format!("{}:{}", proxy_config.host, proxy_config.port);

    let gate_stream = pool
        .acquire(gate_config)
        .await
        .with_context(|| format!("Failed to connect to gate {}", print_cfg(gate_config)))?;
    let stream = handshake_with_timeout(
        gate_stream,
        &proxy_addr,
        get_auth(gate_config),
        handshake_timeout,
    )
    .await
    .with_context(|| {
        format!(
            "Failed to connect to proxy {} through gate {}",
            print_cfg(proxy_config),
            print_cfg(gate_config),
        )
    })?;
    let stream = handshake_with_timeout(
        stream,
        target_addr,
        get_auth(proxy_config),
        handshake_timeout,
    )
    .await
    .with_context(|| {
        format!(
            "Failed to connect to target {} by proxy {} with gate {}",
            target_addr,
            print_cfg(proxy_config),
            print_cfg(gate_config),
        )
    })?;
    Ok(AnyUpstream::Plain(stream))
}

async fn try_proxy(
    target_addr: &str,
    proxy_config: &Arc<ProxyConfig>,
    pool: &ProxyPool,
    handshake_timeout: Duration,
    tls_connector: Option<&TlsConnector>,
) -> anyhow::Result<AnyUpstream> {
    if let Some(gate) = &proxy_config.gate {
        use_gate(target_addr, gate, proxy_config, pool, handshake_timeout).await
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
            if attempts >= max_attempts {
                return Err(anyhow!(
                    "max upstream attempts ({}) reached for {}",
                    max_attempts,
                    target_addr
                ));
            }
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
                    if should_record_failure(&e) {
                        rotator.record_failure(&cached_proxy);
                    }
                    rotator.unlink_proxy(target_addr);
                }
            }
        }
    }

    // Check new connections through gates
    if let Some(gate_rotator) = gate_rotator {
        let gate_order = gate_rotator.pick_order();
        'gates: for gate_config in &gate_order {
            for rotator in [v6_rotator, v4_rotator].iter().filter_map(|&r| r.as_ref()) {
                let order = rotator.pick_order();
                for proxy_config in &order {
                    if attempts >= max_attempts {
                        break 'gates;
                    }
                    attempts += 1;
                    let t0 = Instant::now();
                    match use_gate(
                        target_addr,
                        gate_config,
                        proxy_config,
                        pool,
                        handshake_timeout,
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
                            if should_record_failure(&e) {
                                rotator.record_failure(proxy_config);
                                gate_rotator.record_failure(gate_config);
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
            if attempts >= max_attempts {
                break 'direct;
            }
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
        )
        .await
        .err()
        .expect("gate at capacity must reject the connection");
        assert!(!should_record_failure(&error));
        assert!(error
            .downcast_ref::<resocks5_net::pool::AtCapacity>()
            .is_some());
    }
}
