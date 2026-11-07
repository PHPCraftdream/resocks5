//! Dial-budget tests for the cached-chain admission reserve (J).
//!
//! Helpers come from `tests_unit`; the sticky chains here always carry a
//! gate, so they hit the admission branch in `dial.rs` that dials or
//! skips full chains before the fresh plan phases run.

use super::dial::establish_connection;
use super::tests_unit::{
    socks5_config, spawn_counting_garbage_stub, spawn_counting_stub, test_logger,
};
use crate::config::NetworkConfig;
use regex::RegexSet;
use resocks5_net::chain::GateLevels;
use resocks5_net::pool::ProxyPool;
use resocks5_net::rotator::ProxyRotator;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

fn banned() -> Arc<RegexSet> {
    Arc::new(RegexSet::empty())
}

fn pool() -> Arc<ProxyPool> {
    Arc::new(ProxyPool::new(
        Default::default(),
        Duration::from_secs(2),
        4,
    ))
}

/// Two exit rotators (v6, v4) each holding a healthy ordinary exit and a
/// sticky full chain for the target through its own garbage gate; the
/// gate level rotator offers both gates. Nothing is quarantined.
struct Rig {
    target: &'static str,
    gates: Arc<GateLevels>,
    v6: Arc<ProxyRotator>,
    v4: Arc<ProxyRotator>,
    gate6_accepts: Arc<AtomicUsize>,
    gate4_accepts: Arc<AtomicUsize>,
    exit6_accepts: Arc<AtomicUsize>,
    exit4_accepts: Arc<AtomicUsize>,
}

async fn bad_gate_rig() -> Rig {
    let target = "reserve.example.com:443";
    let (gate6, gate6_accepts) = spawn_counting_garbage_stub().await;
    let (gate4, gate4_accepts) = spawn_counting_garbage_stub().await;
    let (exit6, exit6_accepts) = spawn_counting_stub().await;
    let (exit4, exit4_accepts) = spawn_counting_stub().await;
    let exit6_cfg = socks5_config(exit6, false);
    let exit4_cfg = socks5_config(exit4, false);
    let gate6_cfg = socks5_config(gate6, true);
    let gate4_cfg = socks5_config(gate4, true);
    let mut chain6 = exit6_cfg.clone();
    chain6.gate = Some(Arc::new(gate6_cfg.clone()));
    let mut chain4 = exit4_cfg.clone();
    chain4.gate = Some(Arc::new(gate4_cfg.clone()));
    let v6 = Arc::new(ProxyRotator::new(vec![exit6_cfg]));
    let v4 = Arc::new(ProxyRotator::new(vec![exit4_cfg]));
    v6.link_proxy(target, Arc::new(chain6));
    v4.link_proxy(target, Arc::new(chain4));
    let gates = Arc::new(GateLevels::new(vec![(
        1,
        Arc::new(ProxyRotator::new(vec![gate6_cfg, gate4_cfg])),
    )]));
    Rig {
        target,
        gates,
        v6,
        v4,
        gate6_accepts,
        gate4_accepts,
        exit6_accepts,
        exit4_accepts,
    }
}

async fn request(
    rig: &Rig,
    max_attempts: usize,
) -> anyhow::Result<resocks5_net::pool::AnyUpstream> {
    let network = Arc::new(NetworkConfig {
        connect_timeout_sec: 2,
        handshake_timeout_sec: 2,
        max_upstream_attempts: max_attempts,
        hedge_delay_ms: 100,
        ..Default::default()
    });
    establish_connection(
        rig.target,
        &rig.gates,
        &Some(rig.v6.clone()),
        &Some(rig.v4.clone()),
        &test_logger(),
        &banned(),
        &pool(),
        &network,
        None,
        None,
    )
    .await
}

#[tokio::test]
async fn second_cached_chain_cannot_spend_the_reserved_fallback_attempt() {
    // J: with budget 2, the v6 sticky chain fails its garbage gate and the
    // v4 sticky chain used to be admitted only against the total cap,
    // spending the fallback's attempt. Admission must keep the direct
    // reserve, so the second chain is skipped and the ordinary exit is
    // dialed directly. Mutation caught: an admission check against the
    // total cap alone dials both chains (gate accepts 2) and the call
    // fails with "All 2 upstream attempts" instead of succeeding.
    let rig = bad_gate_rig().await;
    let stream = request(&rig, 2)
        .await
        .expect("the reserved fallback must serve the target");
    drop(stream);
    let gate_dials =
        rig.gate6_accepts.load(Ordering::SeqCst) + rig.gate4_accepts.load(Ordering::SeqCst);
    assert_eq!(
        gate_dials, 1,
        "both sticky chains were dialed: {gate_dials} gate dials"
    );
    assert_eq!(
        rig.exit6_accepts.load(Ordering::SeqCst),
        1,
        "the fallback must dial the ordinary exit directly"
    );
    assert_eq!(rig.exit4_accepts.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn budget_one_still_serves_the_cache_first() {
    // J exception: `attempts + direct_reserve < max_attempts` is false at
    // budget 1, yet the sticky chain must still be the one permitted
    // attempt. Mutation caught: dropping the exception rejects the cache,
    // the hedged phase dials the plain exit (gate accepts 0, exit
    // accepts 1) and re-links it gateless.
    let target = "cache-first.example.com:443";
    let (gate, gate_accepts) = spawn_counting_stub().await;
    let (exit, exit_accepts) = spawn_counting_stub().await;
    let exit_cfg = socks5_config(exit, false);
    let gate_cfg = socks5_config(gate, true);
    let mut chain = exit_cfg.clone();
    chain.gate = Some(Arc::new(gate_cfg.clone()));
    let v4 = Arc::new(ProxyRotator::new(vec![exit_cfg]));
    v4.link_proxy(target, Arc::new(chain));
    let gates = Arc::new(GateLevels::new(vec![(
        1,
        Arc::new(ProxyRotator::new(vec![gate_cfg])),
    )]));
    let network = Arc::new(NetworkConfig {
        connect_timeout_sec: 2,
        handshake_timeout_sec: 2,
        max_upstream_attempts: 1,
        ..Default::default()
    });
    let stream = establish_connection(
        target,
        &gates,
        &None,
        &Some(v4.clone()),
        &test_logger(),
        &banned(),
        &pool(),
        &network,
        None,
        None,
    )
    .await
    .expect("budget 1 must still serve the cached chain");
    drop(stream);
    // The tunnel's two handshake rounds ride ONE gate socket; a working
    // gate never TCP-dials the exit stub itself.
    assert_eq!(
        gate_accepts.load(Ordering::SeqCst),
        1,
        "the cached chain must be the one attempt"
    );
    assert_eq!(
        exit_accepts.load(Ordering::SeqCst),
        0,
        "the hedged phase must not dial the plain exit"
    );
    let linked = v4.get_linked(target).expect("the cache stays linked");
    assert!(
        linked.gate.is_some(),
        "the direct path re-linked a plain exit: the cache was not served"
    );
}

#[tokio::test]
async fn ample_budget_keeps_the_cache_first() {
    // J regression guard: a budget comfortably above the reserve changes
    // nothing — the sticky chain is served first, one wire attempt, no
    // direct phase. Mutation caught: an inverted or otherwise broken
    // admission comparison rejects the cache when the budget is ample
    // (gate accepts 0, plain exit re-linked).
    let target = "ample.example.com:443";
    let (gate, gate_accepts) = spawn_counting_stub().await;
    let (exit, exit_accepts) = spawn_counting_stub().await;
    let exit_cfg = socks5_config(exit, false);
    let gate_cfg = socks5_config(gate, true);
    let mut chain = exit_cfg.clone();
    chain.gate = Some(Arc::new(gate_cfg.clone()));
    let v4 = Arc::new(ProxyRotator::new(vec![exit_cfg]));
    v4.link_proxy(target, Arc::new(chain));
    let gates = Arc::new(GateLevels::new(vec![(
        1,
        Arc::new(ProxyRotator::new(vec![gate_cfg])),
    )]));
    let network = Arc::new(NetworkConfig {
        connect_timeout_sec: 2,
        handshake_timeout_sec: 2,
        max_upstream_attempts: 3,
        ..Default::default()
    });
    let stream = establish_connection(
        target,
        &gates,
        &None,
        &Some(v4.clone()),
        &test_logger(),
        &banned(),
        &pool(),
        &network,
        None,
        None,
    )
    .await
    .expect("the cached chain must serve within an ample budget");
    drop(stream);
    assert_eq!(gate_accepts.load(Ordering::SeqCst), 1);
    assert_eq!(exit_accepts.load(Ordering::SeqCst), 0);
    let linked = v4.get_linked(target).expect("the cache stays linked");
    assert!(linked.gate.is_some());
}

#[tokio::test]
async fn budget_one_spends_no_second_cached_chain() {
    // J guard: the cache-first exception covers only the FIRST attempt.
    // After the first sticky chain failed, a second one must stay
    // unadmitted. Mutation caught: an exception keyed on
    // `max_attempts == 1` alone (without `attempts == 0`) admits the
    // second chain — gate accepts 2 and the error reports 2 attempts.
    let rig = bad_gate_rig().await;
    let error = request(&rig, 1)
        .await
        .err()
        .expect("budget 1 cannot survive the cache failure");
    assert!(
        error.to_string().contains("All 1 upstream attempts"),
        "expected the exhaustion error, got: {error}"
    );
    let gate_dials =
        rig.gate6_accepts.load(Ordering::SeqCst) + rig.gate4_accepts.load(Ordering::SeqCst);
    assert_eq!(
        gate_dials, 1,
        "the second sticky chain was admitted past the budget"
    );
}
