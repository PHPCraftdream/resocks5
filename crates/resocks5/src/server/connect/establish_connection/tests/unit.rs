use super::dial::*;
use super::route::*;
use crate::config::NetworkConfig;
use crate::logger::Logger;
use regex::RegexSet;
use resocks5_net::chain::GateLevels;
use resocks5_net::connect::{connect_chain, connect_proxy, ChainStage};
use resocks5_net::pool::{AtCapacity, ProxyPool};
use resocks5_net::rotator::ProxyRotator;
use resocks5_net::types::{ChainKey, ProxyConfig};
use resocks5_net::ConnectError;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[test]
fn chain_identity_distinguishes_accounts_levels_and_composites() {
    let gate = ProxyConfig::socks5("127.0.0.1", 1000).with_gate_level(1);
    let exit = ProxyConfig::socks5("127.0.0.1", 1001);
    let composite =
        Arc::new(ProxyConfig::chain([Arc::new(gate.clone()), Arc::new(exit.clone())]).unwrap());
    let same =
        Arc::new(ProxyConfig::chain([Arc::new(gate.clone()), Arc::new(exit.clone())]).unwrap());
    assert_eq!(ChainKey::new(composite.clone()), ChainKey::new(same));
    assert_ne!(
        ChainKey::new(composite.clone()),
        ChainKey::new(Arc::new(exit.clone()))
    );
    let account = ProxyConfig::socks5("127.0.0.1", 1001).with_auth("other", "secret");
    let account_chain =
        Arc::new(ProxyConfig::chain([Arc::new(gate.clone()), Arc::new(account)]).unwrap());
    assert_ne!(
        ChainKey::new(composite.clone()),
        ChainKey::new(account_chain)
    );
    let other_level = ProxyConfig::socks5("127.0.0.1", 1000).with_gate_level(2);
    let level_chain =
        Arc::new(ProxyConfig::chain([Arc::new(other_level), Arc::new(exit)]).unwrap());
    assert_ne!(ChainKey::new(composite), ChainKey::new(level_chain));
}

/// Extract the `AtCapacity` payload from either the legacy bare sentinel
/// or the typed `ConnectError::AtCapacity` wrapper the pool API returns.
fn at_capacity_of(err: &anyhow::Error) -> Option<AtCapacity> {
    if let Some(cap) = err.downcast_ref::<AtCapacity>() {
        return Some(cap.clone());
    }
    match err.downcast_ref::<ConnectError>() {
        Some(ConnectError::AtCapacity(cap)) => Some(cap.clone()),
        _ => None,
    }
}

#[tokio::test]
async fn connect_chain_capacity_is_typed_and_composite_holds_exit_permit() {
    use resocks5_net::connect::connect_chain;
    let pool = ProxyPool::new(Default::default(), Duration::from_secs(2), 1);
    let gate = socks5_config(spawn_socks5_stub().await, true);
    let exit = socks5_config(spawn_socks5_stub().await, false);
    let chain = ProxyConfig::chain([Arc::new(gate), Arc::new(exit.clone())]).unwrap();
    let stream = connect_chain(
        &chain,
        "example.com:443",
        &pool,
        Duration::from_secs(2),
        None,
    )
    .await
    .expect("chain succeeds");
    let error = connect_proxy(
        "example.com:443",
        &exit,
        &pool,
        Duration::from_secs(2),
        None,
    )
    .await
    .err()
    .expect("chain reserves exit capacity");
    assert!(at_capacity_of(&anyhow::Error::new(error)).is_some());
    drop(stream);
}

#[tokio::test]
async fn gate_capacity_error_retains_its_type() {
    let gate = socks5_config(spawn_socks5_stub().await, true);
    let pool = ProxyPool::new(Default::default(), Duration::from_secs(2), 1);
    let _busy = pool.acquire(&gate).await.unwrap();
    let error = connect_chain(
        &ProxyConfig::chain([Arc::new(gate)]).unwrap(),
        "example.com:443",
        &pool,
        Duration::from_secs(2),
        None,
    )
    .await
    .err()
    .expect("gate capacity must fail");
    assert!(matches!(error.error(), ConnectError::AtCapacity(_)));
    assert!(!should_record_failure(&anyhow::Error::new(
        error.into_error()
    )));
}

#[tokio::test]
async fn connect_chain_classifies_connect_and_hop_failures() {
    use resocks5_net::connect::{connect_chain, ChainStage};
    let pool = ProxyPool::new(Default::default(), Duration::from_secs(2), 4);
    let dead = socks5_config(SocketAddr::from(([127, 0, 0, 1], 1)), true);
    let exit = socks5_config(spawn_socks5_stub().await, false);
    let chain = ProxyConfig::chain([Arc::new(dead), Arc::new(exit)]).unwrap();
    let error = connect_chain(
        &chain,
        "example.com:443",
        &pool,
        Duration::from_secs(2),
        None,
    )
    .await
    .err()
    .expect("dead gate fails");
    assert_eq!(error.stage(), ChainStage::Connect);

    let gate = socks5_config(spawn_garbage_socks5_stub().await, true);
    let exit = socks5_config(spawn_socks5_stub().await, false);
    let chain = ProxyConfig::chain([Arc::new(gate), Arc::new(exit)]).unwrap();
    let error = connect_chain(
        &chain,
        "example.com:443",
        &pool,
        Duration::from_secs(2),
        None,
    )
    .await
    .err()
    .expect("invalid gate response fails");
    assert_eq!(error.stage(), ChainStage::Hop(0));
}

/// Minimal no-auth SOCKS5 stub: answers method negotiation and
/// CONNECT with success, then holds each socket open until the
/// client drops it. Enough for `use_gate` / `connect_socks5_proxy`
/// to complete both handshakes; nothing is relayed.
pub(super) async fn spawn_socks5_stub() -> SocketAddr {
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

pub(super) fn socks5_config(addr: SocketAddr, is_gate: bool) -> ProxyConfig {
    let cfg = ProxyConfig::socks5(addr.ip().to_string(), addr.port());
    if is_gate {
        cfg.as_gate()
    } else {
        cfg
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
    let tunneled = connect_chain(
        &ProxyConfig::chain([Arc::new(gate.clone()), Arc::new(upstream.clone())]).unwrap(),
        "example.com:443",
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
    .map_err(anyhow::Error::new)
    .err()
    .expect("direct path must hit the cap");
    assert!(at_capacity_of(&err).is_some());
    assert!(!should_record_failure(&err));

    let err = connect_chain(
        &ProxyConfig::chain([Arc::new(gate.clone()), Arc::new(upstream.clone())]).unwrap(),
        "example.com:443",
        &pool,
        Duration::from_secs(2),
        None,
    )
    .await
    .err()
    .expect("gate path must hit the cap");
    assert!(matches!(err.error(), ConnectError::AtCapacity(_)));
    assert!(!err.error().counts_against_upstream());

    // A freed slot is path-agnostic: the tunnel takes it, the
    // direct path is still shut out.
    drop(direct);
    let _again = connect_chain(
        &ProxyConfig::chain([Arc::new(gate.clone()), Arc::new(upstream.clone())]).unwrap(),
        "example.com:443",
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
        .map_err(anyhow::Error::new)
        .err()
        .and_then(|e| at_capacity_of(&e))
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
        let error = connect_chain(
            &ProxyConfig::chain([Arc::new(gate.clone()), Arc::new(saturated.clone())]).unwrap(),
            "example.com:443",
            &pool,
            Duration::from_secs(2),
            None,
        )
        .await
        .err()
        .expect("saturated upstream must fail");
        let cap = match error.error() {
            ConnectError::AtCapacity(cap) => cap.clone(),
            other => panic!("expected AtCapacity, got {other}"),
        };
        assert_eq!(
            (cap.host.as_str(), cap.port),
            (&*saturated.host, saturated.port)
        );
        assert!(!should_record_failure(&anyhow::Error::new(cap.clone())));
        assert!(!should_record_failure(&anyhow::Error::new(
            ConnectError::AtCapacity(cap.clone())
        )));
    }

    // The gate never leaked a permit: a tunnel to a healthy
    // upstream through the same gate still succeeds.
    let _ok = connect_chain(
        &ProxyConfig::chain([Arc::new(gate), Arc::new(healthy)]).unwrap(),
        "example.com:443",
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
    let error = connect_chain(
        &ProxyConfig::chain([Arc::new(gate.clone()), Arc::new(inner.clone())]).unwrap(),
        "example.com:443",
        &pool,
        Duration::from_secs(2),
        None,
    )
    .await
    .err()
    .expect("dead gate must fail");
    assert_eq!(error.stage(), ChainStage::Connect);
    assert!(
        should_record_failure(&anyhow::Error::new(error.into_error())),
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
    let error = connect_chain(
        &ProxyConfig::chain([Arc::new(gate.clone()), Arc::new(inner.clone())]).unwrap(),
        "example.com:443",
        &pool,
        Duration::from_secs(2),
        None,
    )
    .await
    .err()
    .expect("garbage gate hop must fail");
    assert_eq!(error.stage(), ChainStage::Hop(0));
}

#[tokio::test]
async fn use_gate_classifies_proxy_to_target_hop_failure() {
    // First CONNECT through the gate succeeds, the second (the
    // inner proxy reaching the target) is answered with a SOCKS
    // failure: the gate worked, the proxy-to-target hop failed.
    let gate = socks5_config(spawn_socks5_second_connect_refused_stub().await, true);
    let inner = socks5_config(spawn_socks5_stub().await, false);
    let pool = ProxyPool::new(Default::default(), Duration::from_secs(2), 4);
    let error = connect_chain(
        &ProxyConfig::chain([Arc::new(gate.clone()), Arc::new(inner.clone())]).unwrap(),
        "example.com:443",
        &pool,
        Duration::from_secs(2),
        None,
    )
    .await
    .err()
    .expect("target-hop failure expected");
    assert_eq!(error.stage(), ChainStage::Target);
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
    let error = connect_chain(
        &ProxyConfig::chain([Arc::new(gate), Arc::new(saturated.clone())]).unwrap(),
        "example.com:443",
        &pool,
        Duration::from_secs(2),
        None,
    )
    .await
    .err()
    .expect("saturated upstream must fail");
    assert!(matches!(error.error(), ConnectError::AtCapacity(_)));
    assert!(!error.error().counts_against_upstream());
    assert_eq!(error.stage(), ChainStage::Hop(0));
}

pub(super) fn test_logger() -> Arc<Logger> {
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
    let gates = Arc::new(GateLevels::new(vec![(
        1,
        Arc::new(ProxyRotator::new(vec![dead_gate.clone()])),
    )]));
    let result = establish_connection(
        target,
        &gates,
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

    let gates = Arc::new(GateLevels::new(vec![(
        1,
        Arc::new(ProxyRotator::new(vec![dead1.clone(), dead2.clone()])),
    )]));
    let v4 = Arc::new(ProxyRotator::new(vec![inner]));
    let result = establish_connection(
        target,
        &gates,
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

#[tokio::test]
async fn budget_exhausted_by_cache_failure_makes_no_further_attempts() {
    // R5-09: once the cache phase has consumed the budget, the gates
    // and direct phases must not even build their pick orders — and
    // must not make another connection attempt. The healthy direct
    // proxy below therefore has to stay untried: the call fails with
    // exactly the one cache attempt. (A successful extra attempt
    // would turn the result Ok; a failed one would raise the count
    // in the error past 1.)
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
        max_upstream_attempts: 1,
        ..Default::default()
    });
    let dead_gate = socks5_config(SocketAddr::from(([127, 0, 0, 1], 1)), true);
    let inner = socks5_config(spawn_socks5_stub().await, false);
    let mut composite = inner.clone();
    composite.gate = Some(Arc::new(dead_gate.clone()));

    let v4 = Arc::new(ProxyRotator::new(vec![inner.clone()]));
    v4.link_proxy(target.to_string(), Arc::new(composite));
    let gates = Arc::new(GateLevels::new(vec![(
        1,
        Arc::new(ProxyRotator::new(vec![dead_gate.clone()])),
    )]));
    let gate_rotator = gates.iter().next().unwrap().1.clone();
    let gate_orders_before = gate_rotator.pick_order_calls();
    let v4_orders_before = v4.pick_order_calls();

    let result = establish_connection(
        target,
        &gates,
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

    let err = match result {
        Ok(_) => panic!("budget is exhausted after the cache failure"),
        Err(err) => err,
    };
    assert!(
        err.to_string().contains("All 1 upstream attempts"),
        "expected the exhaustion error, got: {err}"
    );
    assert!(
        v4.get_linked(target).is_none(),
        "no phase may attempt (and succeed) after the budget is gone"
    );
    // R6-08: the assertions above hold even for the pre-R5-09
    // code (its internal guards also stopped the dials); what
    // they cannot see is wasted order building. Zero additional
    // `pick_order` calls on both rotators is what actually pins
    // the R5-09 hoist.
    assert_eq!(
        gate_rotator.pick_order_calls(),
        gate_orders_before,
        "budget exhaustion must skip building the gate order"
    );
    assert_eq!(
        v4.pick_order_calls(),
        v4_orders_before,
        "budget exhaustion must skip building the direct order"
    );
}
