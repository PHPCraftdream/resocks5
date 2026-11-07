//! Lazy ChainPlan oracles: lazy traversal sequences are verified
//! against a reference built from full `pick_order()` of twin rotators
//! on fixed seeds (the `next_proxy` order provably matches `pick_order`).

use super::{singleton_key, ChainPick, ChainPlan, GateLevels};
use crate::rating::{QuarantinePolicy, RatingPolicy};
use crate::rotator::ProxyRotator;
use crate::types::ProxyConfig;
use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

const TTL: Duration = Duration::from_secs(3600);

/// Twin rotator with a fixed rating RNG seed.
fn seeded(names: &[&str], port: u16, seed: u64) -> Arc<ProxyRotator> {
    Arc::new(
        ProxyRotator::with_rng_seed(
            names
                .iter()
                .map(|n| ProxyConfig::socks5(*n, port))
                .collect(),
            RatingPolicy::default(),
            QuarantinePolicy::default(),
            256,
            TTL,
            seed,
        )
        .unwrap(),
    )
}

fn proxy(host: &str) -> ProxyConfig {
    ProxyConfig::socks5(host, 1080)
}

/// Hosts of the full pick_order — the reference layer order.
fn order_hosts(rotator: &ProxyRotator) -> Vec<String> {
    rotator
        .pick_order()
        .iter()
        .map(|p| p.host.clone())
        .collect()
}

/// Merge orders of several layer rotators with first-owner deduplication
/// by singleton identity (the previous layer build logic).
fn dedup_hosts(parts: &[&[String]]) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for part in parts {
        for host in *part {
            if seen.insert(host.clone()) {
                out.push(host.clone());
            }
        }
    }
    out
}

/// Cartesian product of layers in odometer order (last layer is fastest).
fn cartesian(layers: &[Vec<String>]) -> Vec<Vec<String>> {
    layers.iter().fold(vec![Vec::new()], |acc, layer| {
        let mut next = Vec::new();
        for prefix in &acc {
            for host in layer {
                let mut combo = prefix.clone();
                combo.push(host.clone());
                next.push(combo);
            }
        }
        next
    })
}

/// Combo hosts of each pick (layer position → host).
fn pick_combos(picks: &[ChainPick]) -> Vec<Vec<String>> {
    picks
        .iter()
        .map(|pick| {
            pick.hops()
                .iter()
                .map(|hop| hop.proxy.host.clone())
                .collect()
        })
        .collect()
}

fn names(prefix: &str, count: usize) -> Vec<String> {
    (0..count).map(|i| format!("{prefix}{i}")).collect()
}

#[test]
fn lazy_plan_traverses_eager_reference_sequence_exactly() {
    let g0 = names("g0-", 8);
    let g1 = names("g1-", 4);
    let x = names("x-", 16);
    let y = names("y-", 8);
    let g0_refs: Vec<_> = g0.iter().map(String::as_str).collect();
    let g1_refs: Vec<_> = g1.iter().map(String::as_str).collect();
    let x_refs: Vec<_> = x.iter().map(String::as_str).collect();
    let y_refs: Vec<_> = y.iter().map(String::as_str).collect();
    let gate0 = seeded(&g0_refs, 1080, 101);
    let gate1 = seeded(&g1_refs, 1080, 102);
    let exit_x = seeded(&x_refs, 1080, 103);
    let exit_y = seeded(&y_refs, 1080, 104);
    let twin0 = seeded(&g0_refs, 1080, 101);
    let twin1 = seeded(&g1_refs, 1080, 102);
    let twin_x = seeded(&x_refs, 1080, 103);
    let twin_y = seeded(&y_refs, 1080, 104);

    let gate0_seq = order_hosts(&twin0);
    let gate1_seq = order_hosts(&twin1);
    let exit_seq = dedup_hosts(&[&order_hosts(&twin_x), &order_hosts(&twin_y)]);
    let expected = cartesian(&[gate0_seq, gate1_seq, exit_seq]);
    assert_eq!(expected.len(), 8 * 4 * (16 + 8));

    let gates = GateLevels::new(vec![(2, gate0.clone()), (1, gate1.clone())]);
    let plan = ChainPlan::new(&gates, &[exit_x.clone(), exit_y.clone()]);
    let picks: Vec<_> = plan.collect();
    assert_eq!(picks.len(), expected.len());
    assert_eq!(pick_combos(&picks), expected);
    // Hop owners are the plan's original rotators.
    assert!(picks.iter().all(|pick| {
        Arc::ptr_eq(&pick.hops()[0].rotator, &gate0)
            && Arc::ptr_eq(&pick.hops()[1].rotator, &gate1)
            && (Arc::ptr_eq(&pick.exit().rotator, &exit_x)
                || Arc::ptr_eq(&pick.exit().rotator, &exit_y))
    }));
}

#[test]
fn lazy_plan_first_owner_and_exit_group_merge_order() {
    let first = seeded(&["same", "u1"], 1080, 201);
    let second = seeded(&["same", "o1"], 1080, 202);
    let twin_first = seeded(&["same", "u1"], 1080, 201);
    let twin_second = seeded(&["same", "o1"], 1080, 202);

    let expected = dedup_hosts(&[&order_hosts(&twin_first), &order_hosts(&twin_second)]);
    assert_eq!(expected, ["same", "u1", "o1"]);

    let plan = ChainPlan::new(&GateLevels::default(), &[first.clone(), second.clone()]);
    let picks: Vec<_> = plan.collect();
    let exits: Vec<_> = picks
        .iter()
        .map(|pick| pick.exit().proxy.host.clone())
        .collect();
    assert_eq!(exits, expected);
    let same_picks: Vec<_> = picks
        .iter()
        .filter(|pick| pick.exit().proxy.host == "same")
        .collect();
    assert_eq!(same_picks.len(), 1);
    assert!(Arc::ptr_eq(&same_picks[0].exit().rotator, &first));
}

#[test]
fn lazy_plan_snapshot_stays_frozen_when_quarantine_changes_after_construction() {
    let hosts = ["q0", "q1", "q2", "q3"];
    let gate = seeded(&hosts, 1080, 301);
    let exit = seeded(&["e"], 1080, 302);
    let twin = seeded(&hosts, 1080, 301);
    let snapshot = order_hosts(&twin);
    let victim = ProxyConfig::socks5(&snapshot[1], 1080);

    let gates = GateLevels::new(vec![(1, gate.clone())]);
    let mut plan = ChainPlan::new(&gates, std::slice::from_ref(&exit));
    let first = plan.next().unwrap();
    // Quarantine AFTER plan construction: the lazy cursor snapshot is frozen.
    gate.quarantine_now(&victim);
    assert_eq!(first.hops()[0].proxy.host, snapshot[0]);
    let rest: Vec<_> = plan.collect();
    assert!(rest
        .iter()
        .any(|pick| pick.hops()[0].proxy.host == snapshot[1]));

    // A new plan (fresh twin rotator with the same seed and quarantine) no
    // longer contains the quarantined host and matches the reference pick_order.
    let twin2 = seeded(&hosts, 1080, 301);
    twin2.quarantine_now(&victim);
    let reference = order_hosts(&twin2);
    assert!(!reference.iter().any(|host| host == &snapshot[1]));
    let gate2 = seeded(&hosts, 1080, 301);
    gate2.quarantine_now(&victim);
    let gates = GateLevels::new(vec![(1, gate2.clone())]);
    let fresh: Vec<_> = ChainPlan::new(&gates, std::slice::from_ref(&exit)).collect();
    let fresh_gate: Vec<_> = fresh
        .iter()
        .map(|pick| pick.hops()[0].proxy.host.clone())
        .collect();
    assert_eq!(dedup_hosts(&[&fresh_gate]), reference);
}

#[test]
fn lazy_plan_mark_dead_before_and_during_traversal_matches_reference() {
    let g0 = names("a-", 2);
    let g1 = names("b-", 2);
    let e = names("c-", 2);
    fn to_refs(v: &[String]) -> Vec<&str> {
        v.iter().map(String::as_str).collect()
    }
    let mk = |seed: u64| -> (Arc<ProxyRotator>, Arc<ProxyRotator>, Arc<ProxyRotator>) {
        (
            seeded(&to_refs(&g0), 1080, seed),
            seeded(&to_refs(&g1), 1080, seed + 1),
            seeded(&to_refs(&e), 1080, seed + 2),
        )
    };
    let reference = |dead: &[&str]| -> Vec<Vec<String>> {
        let (t0, t1, t2) = mk(401);
        let seq = cartesian(&[
            order_hosts(&t0),
            order_hosts(&t1),
            dedup_hosts(&[&order_hosts(&t2)]),
        ]);
        seq.into_iter()
            .filter(|combo| !combo.iter().any(|host| dead.contains(&host.as_str())))
            .collect()
    };

    // (a) mark_dead BEFORE traversal: one node per layer.
    let dead: Vec<&str> = vec![&g0[0], &g1[1], &e[0]];
    let expected = reference(&dead);
    let (r0, r1, r2) = mk(401);
    let gates = GateLevels::new(vec![(2, r0.clone()), (1, r1.clone())]);
    let mut before = ChainPlan::new(&gates, std::slice::from_ref(&r2));
    for host in dead {
        before.mark_dead(&proxy(host));
    }
    let picks: Vec<_> = before.collect();
    assert_eq!(pick_combos(&picks), expected);

    // (b) first pick, mark_dead its exit, continue traversal.
    let (r0, r1, r2) = mk(401);
    let gates = GateLevels::new(vec![(2, r0), (1, r1)]);
    let mut during = ChainPlan::new(&gates, &[r2]);
    let first = during.next().unwrap();
    let dead_exit = first.exit().proxy.host.clone();
    during.mark_dead(&proxy(&dead_exit));
    let expected = reference(&[&dead_exit]);
    let rest: Vec<_> = during.collect();
    assert_eq!(pick_combos(&rest), expected);
    assert!(rest.iter().all(|pick| pick.exit().proxy.host != dead_exit));
}

#[test]
fn lazy_plan_all_dead_layer_exhausts_immediately() {
    let gates = GateLevels::new(vec![
        (2, seeded(&["a0", "a1"], 1080, 501)),
        (1, seeded(&["b0", "b1"], 1080, 502)),
    ]);
    let mut plan = ChainPlan::new(&gates, &[seeded(&["e"], 1080, 503)]);
    assert_eq!(plan.next().unwrap().exit().proxy.host, "e");
    plan.mark_dead(&proxy("e"));
    let before = plan.steps;
    assert!(plan.next().is_none());
    assert_eq!(plan.steps - before, 0);
}

#[test]
fn lazy_plan_gate_link_duplicates_share_singleton_identity() {
    let wrapped = proxy("exit").with_gate(proxy("gate"));
    let rotator = Arc::new(
        ProxyRotator::with_rng_seed(
            vec![wrapped.clone(), proxy("other")],
            RatingPolicy::default(),
            QuarantinePolicy::default(),
            256,
            TTL,
            602,
        )
        .unwrap(),
    );
    let twin = Arc::new(
        ProxyRotator::with_rng_seed(
            vec![wrapped.clone(), proxy("other")],
            RatingPolicy::default(),
            QuarantinePolicy::default(),
            256,
            TTL,
            602,
        )
        .unwrap(),
    );
    assert_eq!(singleton_key(&wrapped), singleton_key(&proxy("exit")));

    // Full traversal without mark_dead matches the reference.
    let plan = ChainPlan::new(&GateLevels::default(), std::slice::from_ref(&rotator));
    let picks: Vec<_> = plan.collect();
    assert_eq!(
        dedup_hosts(&[&picks
            .iter()
            .map(|pick| pick.exit().proxy.host.clone())
            .collect::<Vec<_>>()]),
        dedup_hosts(&[&order_hosts(&twin)])
    );

    // mark_dead on the wrapped config removes that identity from the lazy plan.
    let mut plan = ChainPlan::new(&GateLevels::default(), std::slice::from_ref(&rotator));
    plan.mark_dead(&wrapped);
    let rest: Vec<_> = plan.collect();
    assert_eq!(rest.len(), 1);
    assert_eq!(rest[0].exit().proxy.host, "other");
}

/// Singleton fast-path oracle: a plan of one-node layers (1×1×1) with
/// identical semantics materializes and sorts nothing at construction
/// and on repeated next() over an exhausted plan.
#[test]
fn singleton_plan_semantics_and_no_extra_materialization() {
    let gate0 = seeded(&["g0"], 1080, 701); // rank 2, 1 node
    let gate1 = seeded(&["g1"], 1080, 702); // rank 1, 1 node
    let exit = seeded(&["e0"], 1080, 703); // rank 0 (plain socks5), 1 node
    let twin0 = seeded(&["g0"], 1080, 701);
    let twin1 = seeded(&["g1"], 1080, 702);
    let twin_x = seeded(&["e0"], 1080, 703);

    // (a) Full traversal of the singleton plan == Cartesian product of the
    // twin reference orders (1×1×1 = the single pick); hop ranks by positions
    // [2, 1, 0] confirmed by owner rotators (ptr_eq to the originals).
    let expected = cartesian(&[
        order_hosts(&twin0),
        order_hosts(&twin1),
        dedup_hosts(&[&order_hosts(&twin_x)]),
    ]);
    let gates = GateLevels::new(vec![(2, gate0.clone()), (1, gate1.clone())]);
    let build = || ChainPlan::new(&gates, std::slice::from_ref(&exit));
    #[cfg(feature = "test-instrumentation")]
    let (plan, construction) = crate::perf::measure(build);
    #[cfg(not(feature = "test-instrumentation"))]
    let plan = build();
    #[cfg(feature = "test-instrumentation")]
    {
        assert_eq!(construction.chain_builds, 0);
        assert_eq!(construction.config_clones, 0);
        assert_eq!(construction.sort_comparisons, 0);
        assert_eq!(construction.chain_nodes, 0);
    }
    let picks: Vec<_> = plan.collect();
    assert_eq!(pick_combos(&picks), expected);
    assert_eq!(expected.len(), 1);
    let pick = &picks[0];
    assert_eq!(pick.hops().len(), 3);
    assert!(Arc::ptr_eq(&pick.hops()[0].rotator, &gate0));
    assert!(Arc::ptr_eq(&pick.hops()[1].rotator, &gate1));
    assert!(Arc::ptr_eq(&pick.exit().rotator, &exit));

    // (b) Empty plan stays empty: no exits, and a singleton plan with `&[]` exits.
    assert_eq!(ChainPlan::new(&GateLevels::default(), &[]).count(), 0);
    assert_eq!(ChainPlan::new(&gates, &[]).count(), 0);

    // (c) mark_dead BEFORE the first next(): the only exit node is dead → None.
    let gates = GateLevels::new(vec![(2, gate0.clone()), (1, gate1.clone())]);
    let mut before = ChainPlan::new(&gates, std::slice::from_ref(&exit));
    before.mark_dead(&proxy("e0"));
    assert!(before.next().is_none());

    // mark_dead AFTER the first next(): the only pick was emitted, node is dead.
    let gates = GateLevels::new(vec![(2, gate0.clone()), (1, gate1.clone())]);
    let mut after = ChainPlan::new(&gates, std::slice::from_ref(&exit));
    assert!(after.next().is_some());
    after.mark_dead(&proxy("e0"));
    assert!(after.next().is_none());

    // (d) Repeated next() after exhaustion: None twice in a row.
    let mut exhausted = ChainPlan::new(&gates, std::slice::from_ref(&exit));
    assert!(exhausted.next().is_some());
    assert!(exhausted.next().is_none());
    #[cfg(not(feature = "test-instrumentation"))]
    {
        assert!(exhausted.next().is_none());
        assert!(exhausted.next().is_none());
    }
    #[cfg(feature = "test-instrumentation")]
    {
        let (_, drained) = crate::perf::measure(|| {
            assert!(exhausted.next().is_none());
            assert!(exhausted.next().is_none());
        });
        assert_eq!(drained.config_clones, 0);
        assert_eq!(drained.chain_builds, 0);
        assert_eq!(drained.chain_nodes, 0);
        assert_eq!(drained.sort_comparisons, 0);
    }

    // (e) exclude the single key of the pick → next next() is None.
    let gates = GateLevels::new(vec![(2, gate0.clone()), (1, gate1.clone())]);
    let mut excluded = ChainPlan::new(&gates, std::slice::from_ref(&exit));
    let first = excluded.next().expect("один pick");
    let key = first.key();
    excluded.exclude(&key);
    assert!(excluded.next().is_none());
}
