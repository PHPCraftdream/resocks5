use super::{ChainPlan, GateLevels};
use crate::rotator::ProxyRotator;
use crate::types::{ChainKey, ProxyConfig};
use std::collections::HashSet;
use std::sync::Arc;

fn p(host: &str) -> ProxyConfig {
    ProxyConfig::socks5(host, 1080)
}

fn r(names: &[&str]) -> Arc<ProxyRotator> {
    Arc::new(ProxyRotator::new(
        names.iter().map(|name| p(name)).collect(),
    ))
}

fn key(proxy: ProxyConfig) -> ChainKey {
    ChainKey::new(Arc::new(ProxyConfig::chain([Arc::new(proxy)]).unwrap()))
}

#[test]
fn resolve_requires_exact_chain_identity_shape_and_returns_matching_rotators() {
    let gate_proxy = p("gate").with_auth("g-user", "g-pass").with_gate_level(3);
    let exit_proxy = p("exit").with_auth("e-user", "e-pass");
    let gate = Arc::new(ProxyRotator::new(vec![gate_proxy.clone()]));
    let exit = Arc::new(ProxyRotator::new(vec![exit_proxy.clone()]));
    let levels = GateLevels::new(vec![(3, gate.clone())]);
    let config =
        ProxyConfig::chain([Arc::new(gate_proxy.clone()), Arc::new(exit_proxy.clone())]).unwrap();

    let resolved = levels
        .resolve(std::slice::from_ref(&exit), &config)
        .unwrap();
    assert_eq!(resolved.hops().len(), 2);
    assert!(Arc::ptr_eq(&resolved.hops()[0].rotator, &gate));
    assert!(Arc::ptr_eq(&resolved.hops()[1].rotator, &exit));
    assert_eq!(resolved.key(), ChainKey::new(Arc::new(config.clone())));

    let wrong_gate_host = {
        let mut node = gate_proxy.clone();
        node.host = "wrong".to_owned();
        ProxyConfig::chain([Arc::new(node), Arc::new(exit_proxy.clone())]).unwrap()
    };
    assert!(levels
        .resolve(std::slice::from_ref(&exit), &wrong_gate_host)
        .is_none());
    let wrong_gate_port = {
        let mut node = gate_proxy.clone();
        node.port = 1081;
        ProxyConfig::chain([Arc::new(node), Arc::new(exit_proxy.clone())]).unwrap()
    };
    assert!(levels
        .resolve(std::slice::from_ref(&exit), &wrong_gate_port)
        .is_none());
    let wrong_gate_protocol = ProxyConfig::chain([
        Arc::new(
            ProxyConfig::http("gate", 1080)
                .with_auth("g-user", "g-pass")
                .with_gate_level(3),
        ),
        Arc::new(exit_proxy.clone()),
    ])
    .unwrap();
    assert!(levels
        .resolve(std::slice::from_ref(&exit), &wrong_gate_protocol)
        .is_none());
    let wrong_gate_auth = {
        let mut node = gate_proxy.clone();
        node.user = Some("wrong".to_owned());
        ProxyConfig::chain([Arc::new(node), Arc::new(exit_proxy.clone())]).unwrap()
    };
    assert!(levels
        .resolve(std::slice::from_ref(&exit), &wrong_gate_auth)
        .is_none());
    let wrong_exit_auth = ProxyConfig::chain([
        Arc::new(gate_proxy.clone()),
        Arc::new(exit_proxy.clone().with_auth("e-user", "wrong")),
    ])
    .unwrap();
    assert!(levels
        .resolve(std::slice::from_ref(&exit), &wrong_exit_auth)
        .is_none());
    let wrong_exit_user = ProxyConfig::chain([
        Arc::new(gate_proxy.clone()),
        Arc::new(exit_proxy.clone().with_auth("wrong", "e-pass")),
    ])
    .unwrap();
    assert!(levels
        .resolve(std::slice::from_ref(&exit), &wrong_exit_user)
        .is_none());
    let wrong_level = ProxyConfig::chain([
        Arc::new(gate_proxy.clone().with_gate_level(4)),
        Arc::new(exit_proxy.clone()),
    ])
    .unwrap();
    assert!(levels
        .resolve(std::slice::from_ref(&exit), &wrong_level)
        .is_none());
    assert!(levels
        .resolve(std::slice::from_ref(&exit), &exit_proxy)
        .is_none());
    let extra = ProxyConfig::chain([
        Arc::new(gate_proxy.clone()),
        Arc::new(exit_proxy.clone()),
        Arc::new(p("extra")),
    ])
    .unwrap();
    assert!(levels
        .resolve(std::slice::from_ref(&exit), &extra)
        .is_none());

    let no_gate = ProxyConfig::chain([Arc::new(exit_proxy.clone())]).unwrap();
    assert!(GateLevels::default()
        .resolve(std::slice::from_ref(&exit), &no_gate)
        .is_some());
    let three_gates = [
        p("outer").with_gate_level(7),
        p("middle").with_gate_level(4),
        p("inner").with_gate_level(2),
    ];
    let gate_rotators: Vec<_> = three_gates
        .iter()
        .cloned()
        .map(|proxy| Arc::new(ProxyRotator::new(vec![proxy])))
        .collect();
    let three_levels = GateLevels::new(vec![
        (7, gate_rotators[0].clone()),
        (4, gate_rotators[1].clone()),
        (2, gate_rotators[2].clone()),
    ]);
    let three_chain = ProxyConfig::chain([
        Arc::new(three_gates[0].clone()),
        Arc::new(three_gates[1].clone()),
        Arc::new(three_gates[2].clone()),
        Arc::new(exit_proxy.clone()),
    ])
    .unwrap();
    assert_eq!(
        three_levels
            .resolve(std::slice::from_ref(&exit), &three_chain)
            .unwrap()
            .hops()
            .len(),
        4
    );

    let unaccounted_gate = Arc::new(ProxyRotator::new(vec![gate_proxy]));
    let unaccounted_exit = Arc::new(ProxyRotator::new(vec![exit_proxy]));
    gate.quarantine_now(&resolved.hops()[0].proxy);
    exit.quarantine_now(&resolved.hops()[1].proxy);
    unaccounted_gate.quarantine_now(&resolved.hops()[0].proxy);
    unaccounted_exit.quarantine_now(&resolved.hops()[1].proxy);
    assert!(levels
        .resolve(std::slice::from_ref(&exit), &config)
        .is_some());
    let plan = ChainPlan::new(&levels, std::slice::from_ref(&exit));
    plan.record_success(&resolved);
    assert!(!gate.is_quarantined(&resolved.hops()[0].proxy));
    assert!(!exit.is_quarantined(&resolved.hops()[1].proxy));
    assert!(unaccounted_gate.is_quarantined(&resolved.hops()[0].proxy));
    assert!(unaccounted_exit.is_quarantined(&resolved.hops()[1].proxy));
}

#[test]
fn gate_ranks_are_sorted_descending_with_gaps_and_debug_clone() {
    let levels = GateLevels::new(vec![(1, r(&["low"])), (9, r(&["high"])), (4, r(&["mid"]))]);
    assert_eq!(
        levels.iter().map(|(rank, _)| rank).collect::<Vec<_>>(),
        [9, 4, 1]
    );
    assert!(format!("{levels:?}").contains('9'));
    assert_eq!(levels.clone().len(), 3);
    assert!(GateLevels::default().is_empty());
    assert_eq!(GateLevels::default().len(), 0);
    assert_eq!(format!("{:?}", GateLevels::default()), "[]");
}

#[test]
fn cartesian_layers_have_deterministic_grouping_and_ownership() {
    let outer = r(&["a0", "a1"]);
    let middle = r(&["b0", "b1"]);
    let inner = r(&["c0", "c1"]);
    let x = r(&["x0", "x1"]);
    let y = r(&["y0", "y1"]);
    let gates = GateLevels::new(vec![
        (8, outer.clone()),
        (3, inner.clone()),
        (5, middle.clone()),
    ]);
    let picks: Vec<_> = ChainPlan::new(&gates, &[x.clone(), y.clone()]).collect();
    assert_eq!(picks.len(), 32);
    let mut unique = HashSet::new();
    for (index, pick) in picks.iter().enumerate() {
        assert!(unique.insert(pick.key()));
        assert_eq!(pick.hops().len(), 4);
        assert_eq!(pick.config().chain_nodes().len(), 4);
        assert_eq!(pick.key(), ChainKey::new(Arc::new(pick.config())));
        assert!(Arc::ptr_eq(&pick.hops()[0].rotator, &outer));
        assert!(Arc::ptr_eq(&pick.hops()[1].rotator, &middle));
        assert!(Arc::ptr_eq(&pick.hops()[2].rotator, &inner));
        let exit_group = (index / 2) % 2;
        let expected_rotator = if exit_group == 0 { &x } else { &y };
        assert!(Arc::ptr_eq(&pick.exit().rotator, expected_rotator));
        for (actual, hop) in pick.config().chain_nodes().iter().zip(pick.hops()) {
            assert_eq!(key((**actual).clone()), key((*hop.proxy).clone()));
        }
    }
    for group in picks.chunks(16) {
        assert!(group
            .iter()
            .all(|pick| pick.hops()[0].proxy.host == group[0].hops()[0].proxy.host));
        for subgroup in group.chunks(8) {
            assert!(subgroup
                .iter()
                .all(|pick| pick.hops()[1].proxy.host == subgroup[0].hops()[1].proxy.host));
            for inner_group in subgroup.chunks(4) {
                assert!(inner_group
                    .iter()
                    .all(|pick| pick.hops()[2].proxy.host == inner_group[0].hops()[2].proxy.host));
                let exits: Vec<_> = inner_group
                    .iter()
                    .map(|pick| pick.exit().proxy.host.as_str())
                    .collect();
                assert_ne!(exits[0], exits[1]);
                assert_ne!(exits[2], exits[3]);
                assert_eq!(
                    HashSet::from([exits[0], exits[1]]),
                    HashSet::from(["x0", "x1"])
                );
                assert_eq!(
                    HashSet::from([exits[2], exits[3]]),
                    HashSet::from(["y0", "y1"])
                );
            }
        }
    }
}

#[test]
fn singleton_exit_rotators_and_empty_inputs() {
    let x = r(&["x"]);
    let y = r(&["y"]);
    let picks: Vec<_> = ChainPlan::new(&GateLevels::default(), &[x.clone(), y.clone()]).collect();
    assert_eq!(picks.len(), 2);
    assert_eq!(picks[0].exit().proxy.host, "x");
    assert_eq!(picks[1].exit().proxy.host, "y");
    assert!(picks.iter().all(|pick| pick.hops().len() == 1));
    assert_eq!(ChainPlan::new(&GateLevels::default(), &[]).count(), 0);
    assert_eq!(
        ChainPlan::new(&GateLevels::new(vec![(1, r(&["g"]))]), &[]).count(),
        0
    );
}

#[test]
fn overlapping_exits_deduplicate_and_exclusions_use_complete_identity() {
    let no_gates = GateLevels::default();
    let first = r(&["same", "unique"]);
    let second = r(&["same", "other"]);
    let picks: Vec<_> = ChainPlan::new(&no_gates, &[first.clone(), second]).collect();
    assert_eq!(picks.len(), 3);
    let same_pick = picks
        .iter()
        .find(|pick| pick.exit().proxy.host == "same")
        .unwrap();
    assert!(Arc::ptr_eq(&same_pick.exit().rotator, &first));
    let mut plan = ChainPlan::new(&no_gates, &[r(&["same", "unique"])]);
    let excluded = key(p("same"));
    plan.exclude(&excluded);
    let rest: Vec<_> = plan.collect();
    assert_eq!(rest.len(), 1);
    assert_eq!(rest[0].exit().proxy.host, "unique");
}

#[test]
fn mark_dead_prunes_nodes_before_and_after_traversal() {
    let outer_names = ["a0", "a1"];
    let middle_names = ["b0", "b1"];
    let exit_names = ["c0", "c1"];
    for (layer, names) in [outer_names, middle_names, exit_names].iter().enumerate() {
        let gates = GateLevels::new(vec![(2, r(&outer_names)), (1, r(&middle_names))]);
        let mut before = ChainPlan::new(&gates, &[r(&exit_names)]);
        before.mark_dead(&p(names[0]));
        let before_picks: Vec<_> = before.collect();
        assert_eq!(before_picks.len(), 4);
        assert!(before_picks
            .iter()
            .all(|pick| pick.hops()[layer].proxy.host != names[0]));

        let mut after = ChainPlan::new(&gates, &[r(&exit_names)]);
        let first = after.next().unwrap();
        let dead = first.hops()[layer].proxy.clone();
        after.mark_dead(&dead);
        let remaining: Vec<_> = after.collect();
        assert_eq!(remaining.len(), 4);
        assert!(remaining
            .iter()
            .all(|pick| !Arc::ptr_eq(&pick.hops()[layer].proxy, &dead)));
    }
    let shared = p("shared");
    let gates = GateLevels::new(vec![(2, r(&["shared", "a"])), (1, r(&["shared", "b"]))]);
    let mut plan = ChainPlan::new(&gates, &[r(&["shared", "c"])]);
    plan.mark_dead(&shared);
    let picks: Vec<_> = plan.collect();
    assert_eq!(picks.len(), 1);
    assert_eq!(
        picks[0]
            .hops()
            .iter()
            .map(|hop| hop.proxy.host.as_str())
            .collect::<Vec<_>>(),
        ["a", "b", "c"]
    );

    let gate = p("attached");
    let wrapped = p("exit").with_gate(gate.clone());
    let wrapped_list = Arc::new(ProxyRotator::new(vec![wrapped.clone()]));
    let mut plan = ChainPlan::new(&GateLevels::default(), &[wrapped_list]);
    plan.mark_dead(&wrapped);
    assert_eq!(plan.count(), 0);
    assert_eq!(key(p("exit")), key(wrapped));
}

#[test]
fn singleton_identity_fields_remain_distinct_except_is_gate_and_gate_link() {
    let base = p("host").with_auth("user", "password");
    let variants = vec![
        base.clone(),
        ProxyConfig::socks5("other", 1080).with_auth("user", "password"),
        ProxyConfig::socks5("host", 1081).with_auth("user", "password"),
        ProxyConfig::http("host", 1080).with_auth("user", "password"),
        ProxyConfig::socks5("host", 1080).with_auth("other", "password"),
        ProxyConfig::socks5("host", 1080).with_auth("user", "other"),
        base.clone().with_gate_level(1),
    ];
    let picks: Vec<_> = ChainPlan::new(
        &GateLevels::default(),
        &[Arc::new(ProxyRotator::new(variants))],
    )
    .collect();
    assert_eq!(picks.len(), 7);
    let keys: HashSet<_> = picks.iter().map(|pick| pick.key()).collect();
    assert_eq!(keys.len(), 7);
    let gate_link_only = p("host")
        .with_auth("user", "password")
        .with_gate(p("outer"));
    assert_eq!(key(base), key(gate_link_only));
    let mut is_gate_only = p("host");
    is_gate_only.is_gate = true;
    assert_eq!(key(p("host")), key(is_gate_only));
}
