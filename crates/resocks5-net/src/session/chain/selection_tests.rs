use super::{singleton_key, ChainPlan, GateLevels};
use crate::rating::{QuarantinePolicy, RatingPolicy};
use crate::rotator::ProxyRotator;
use crate::types::{ChainKey, ProxyConfig};
use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

fn p(host: &str) -> ProxyConfig {
    ProxyConfig::socks5(host, 1080)
}

fn r(names: &[&str]) -> Arc<ProxyRotator> {
    Arc::new(ProxyRotator::new(
        names.iter().map(|name| p(name)).collect(),
    ))
}

fn quarantining(proxy: ProxyConfig) -> Arc<ProxyRotator> {
    Arc::new(
        ProxyRotator::try_with_quarantine(
            vec![proxy],
            RatingPolicy::default(),
            QuarantinePolicy::default().with_threshold(1),
            16,
            Duration::from_secs(60),
        )
        .unwrap(),
    )
}

fn key(proxy: ProxyConfig) -> ChainKey {
    ChainKey::new(Arc::new(ProxyConfig::chain([Arc::new(proxy)]).unwrap()))
}

#[test]
fn resolve_requires_exact_chain_identity_shape_and_returns_matching_rotators() {
    let gate_proxy = p("gate").with_auth("g-user", "g-pass").with_gate_level(3);
    let exit_proxy = p("exit").with_auth("e-user", "e-pass");
    let gate = quarantining(gate_proxy.clone());
    let exit = quarantining(exit_proxy.clone());
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

    let unaccounted_gate = quarantining(gate_proxy);
    let unaccounted_exit = quarantining(exit_proxy);
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

#[test]
fn fully_dead_exit_layer_ends_plan_without_sweeping_gates() {
    // Mutation caught: removing layer exhaustion re-adds the pre-fix odometer
    // sweep (80 iterations on the 81-combo case below, bound is sum = 13).
    let gates = GateLevels::new(vec![(2, r(&["a0", "a1"])), (1, r(&["b0", "b1"]))]);
    let mut plan = ChainPlan::new(&gates, &[r(&["e"])]);
    assert_eq!(plan.next().unwrap().exit().proxy.host, "e");
    plan.mark_dead(&p("e"));
    let before = plan.steps;
    assert!(plan.next().is_none());
    let spent = plan.steps - before;
    assert!(spent <= 2 + 2 + 1, "work after exhaustion: {spent}");

    let gates = GateLevels::new(vec![
        (9, r(&["a0", "a1", "a2"])),
        (7, r(&["b0", "b1", "b2"])),
        (5, r(&["c0", "c1", "c2"])),
        (3, r(&["d0", "d1", "d2"])),
    ]);
    let mut plan = ChainPlan::new(&gates, &[r(&["e"])]);
    assert_eq!(plan.next().unwrap().exit().proxy.host, "e");
    plan.mark_dead(&p("e"));
    let before = plan.steps;
    assert!(plan.next().is_none());
    let spent = plan.steps - before;
    assert!(spent <= 3 + 3 + 3 + 3 + 1, "work after exhaustion: {spent}");
}

#[test]
fn one_dead_exit_keeps_remaining_exits_in_original_order() {
    // Positive control against over-eager exhaustion: one dead exit must not
    // end a plan whose exit layer still has live candidates.
    let rotators = [r(&["x"]), r(&["y"]), r(&["z"])];
    let mut plan = ChainPlan::new(&GateLevels::default(), &rotators);
    assert_eq!(plan.next().unwrap().exit().proxy.host, "x");
    plan.mark_dead(&p("x"));
    let rest: Vec<_> = plan.collect();
    let remaining: Vec<_> = rest
        .iter()
        .map(|pick| pick.exit().proxy.host.as_str())
        .collect();
    assert_eq!(remaining, ["y", "z"]);
    assert!(rest.iter().all(|pick| pick.hops().len() == 1));
}

#[test]
fn fully_dead_gate_layer_ends_the_plan() {
    // Mutation caught: gate layers skipping the exhaustion check — the deep
    // variant sweeps ~26 odometer states pre-fix, over the sum = 10 bound.
    let gates = GateLevels::new(vec![
        (4, r(&["a0", "a1", "a2"])),
        (3, r(&["b0", "b1", "b2"])),
        (2, r(&["c0", "c1", "c2"])),
    ]);
    let mut plan = ChainPlan::new(&gates, &[r(&["e"])]);
    assert_eq!(plan.next().unwrap().exit().proxy.host, "e");
    for host in ["c0", "c1", "c2"] {
        plan.mark_dead(&p(host));
    }
    let before = plan.steps;
    assert!(plan.next().is_none());
    let spent = plan.steps - before;
    assert!(spent <= 3 + 3 + 3 + 1, "work after exhaustion: {spent}");

    let outer = GateLevels::new(vec![(2, r(&["a0", "a1"])), (1, r(&["g"]))]);
    let mut plan = ChainPlan::new(&outer, &[r(&["e"])]);
    plan.mark_dead(&p("a0"));
    plan.mark_dead(&p("a1"));
    assert!(plan.next().is_none());
}

#[test]
fn partially_dead_gate_layer_still_enumerates_through_the_live_gate() {
    // Guards both directions: the plan must not exhaust on a partial death,
    // and no produced chain may contain the dead gate candidate.
    let gates = GateLevels::new(vec![(2, r(&["a0", "a1"])), (1, r(&["b0", "b1"]))]);
    let mut plan = ChainPlan::new(&gates, &[r(&["e"])]);
    let first = plan.next().unwrap();
    let dead_gate = first.hops()[0].proxy.clone();
    plan.mark_dead(&dead_gate);
    let rest: Vec<_> = plan.collect();
    assert_eq!(rest.len(), 2);
    assert!(rest
        .iter()
        .all(|pick| pick.hops()[0].proxy.host != dead_gate.host));
    let gate_hosts: HashSet<_> = rest
        .iter()
        .map(|pick| pick.hops()[0].proxy.host.clone())
        .collect();
    assert_eq!(gate_hosts.len(), 1);
    assert_eq!(rest[0].hops()[1].proxy.host, first.hops()[1].proxy.host);
    assert_ne!(rest[1].hops()[1].proxy.host, rest[0].hops()[1].proxy.host);
    assert!(rest.iter().all(|pick| pick.exit().proxy.host == "e"));
}

#[test]
fn exclude_and_mark_dead_stay_independent_sets() {
    // Regression pin: exclusion stays in `seen`, death stays in `dead`; one
    // must never trigger the other's pruning or exhaustion path.
    let gates = GateLevels::new(vec![(1, r(&["a0", "a1"]))]);
    let mut plan = ChainPlan::new(&gates, &[r(&["x"]), r(&["y"])]);
    let excluded = plan.next().unwrap().key();
    plan.exclude(&excluded);
    plan.mark_dead(&p("x"));
    let rest: Vec<_> = plan.by_ref().collect();
    assert_eq!(rest.len(), 2);
    assert!(rest
        .iter()
        .all(|pick| pick.hops().iter().all(|hop| hop.proxy.host != "x")));
    assert!(rest.iter().all(|pick| pick.key() != excluded));
    assert_eq!(plan.dead.len(), 1);
    assert!(plan.dead.contains(&singleton_key(&Arc::new(p("x")))));
    assert_eq!(plan.seen.len(), 1);
    assert!(plan.seen.contains(&excluded));
}

/// `config_arc` is the pick's own linked configuration: the very allocation
/// its key holds (no copy), equal to what `config` builds, with the gates
/// shared. Mutation: building a fresh `Arc` from a copy breaks `ptr_eq`.
#[test]
fn config_arc_shares_the_keys_chain_and_matches_config() {
    let gates = GateLevels::new(vec![(2, r(&["outer"])), (1, r(&["inner"]))]);
    let exits = [r(&["exit-a", "exit-b"])];
    let picks: Vec<_> = ChainPlan::new(&gates, &exits).collect();
    assert_eq!(picks.len(), 2);
    for pick in &picks {
        let shared = pick.config_arc();
        assert!(Arc::ptr_eq(&shared, pick.key().exit()));
        assert_eq!(ChainKey::new(shared.clone()), pick.key());
        assert_eq!(ChainKey::new(Arc::new(pick.config())), pick.key());
        assert_eq!(shared.chain_len(), 3);
        // A second call shares again; nothing was copied behind the scenes.
        assert!(Arc::ptr_eq(&shared, &pick.config_arc()));
        // `config` stays an independent owned copy: editing it leaves the
        // shared chain alone.
        let mut owned = pick.config();
        owned.host.push_str("-edited");
        assert_ne!(owned.host, shared.host);
        assert_eq!(ChainKey::new(shared), pick.key());
    }
}

/// The shared configuration keeps the hops' order: gates outermost, exit last.
#[test]
fn config_arc_orders_hops_outermost_first() {
    let gates = GateLevels::new(vec![(2, r(&["outer"])), (1, r(&["inner"]))]);
    let pick = ChainPlan::new(&gates, &[r(&["exit"])]).next().unwrap();
    let hosts: Vec<_> = pick
        .config_arc()
        .chain_nodes()
        .iter()
        .map(|node| node.host.clone())
        .collect();
    assert_eq!(hosts, ["outer", "inner", "exit"]);
}

/// `current_pick` keys stay identical to the legacy construction
/// `ChainKey::new(Arc::new(ProxyConfig::chain(hops)))` for gated and
/// gate-less plans, and the pick still shares the gate-less outermost hop.
#[test]
fn pick_key_equals_the_legacy_chain_construction() {
    let gates = GateLevels::new(vec![(2, r(&["outer"])), (1, r(&["inner"]))]);
    let exits = [r(&["exit-a"]), r(&["exit-b"])];
    for pick in ChainPlan::new(&gates, &exits) {
        let legacy = ChainKey::new(Arc::new(
            ProxyConfig::chain(pick.hops().iter().map(|hop| Arc::clone(&hop.proxy))).unwrap(),
        ));
        assert_eq!(pick.key(), legacy);
        let mut outermost = pick.config_arc();
        while let Some(gate) = outermost.gate.clone() {
            outermost = gate;
        }
        assert!(Arc::ptr_eq(&outermost, &pick.hops()[0].proxy));
    }

    let exits = [r(&["solo"])];
    for pick in ChainPlan::new(&GateLevels::default(), &exits) {
        let legacy = ChainKey::new(Arc::new(
            ProxyConfig::chain(pick.hops().iter().map(|hop| Arc::clone(&hop.proxy))).unwrap(),
        ));
        assert_eq!(pick.key(), legacy);
    }
}
