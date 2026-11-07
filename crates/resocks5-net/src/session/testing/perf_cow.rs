//! Copy-vs-share allocation counters #208 for the dial-path changes:
//! `ChainKey::singleton`, `ChainPick::config_arc`, and the borrowed-address
//! `ProxyRotator::link_proxy`. Every case pairs the new path with a legacy
//! replica as the oracle; fixtures use synthetic `.invalid` hosts.

use std::sync::Arc;

use crate::chain::{ChainPlan, GateLevels};
use crate::perf::{measure, report, Counts};
use crate::rotator::ProxyRotator;
use crate::types::{ChainKey, ProxyConfig};

fn proxy(index: usize) -> ProxyConfig {
    let mut proxy = ProxyConfig::socks5(format!("proxy-{index}.invalid"), 1080);
    proxy.user = Some("synthetic-user".to_owned());
    proxy.password = Some("synthetic-password".to_owned());
    proxy
}

/// The allocator-call total the zero-copy assertions are stated against.
fn allocator_calls(counts: &Counts) -> u64 {
    counts.alloc + counts.alloc_zeroed + counts.realloc
}

/// `ChainKey::singleton` vs the legacy replica
/// `ChainKey::new(Arc::new(ProxyConfig::chain([node.clone()]).unwrap()))`.
#[test]
fn perf208_singleton_key_shares_gateless_and_copies_gated_once() {
    // Gate-less node with credentials: refcount only, zero allocator calls.
    let mut first = None;
    for run_case in 0..2 {
        let plain = Arc::new(proxy(0));
        let (key, new) = measure(|| ChainKey::singleton(&plain));
        let (legacy_key, legacy) =
            measure(|| ChainKey::new(Arc::new(ProxyConfig::chain([Arc::clone(&plain)]).unwrap())));
        assert_eq!(key, legacy_key, "run={run_case}: singleton identity");
        assert!(
            Arc::ptr_eq(key.exit(), &plain),
            "run={run_case}: input shared"
        );
        assert_eq!(allocator_calls(&new), 0, "run={run_case}: {new:?}");
        assert_eq!(new.config_clones + new.chain_builds, 0);
        assert!(allocator_calls(&legacy) > 0, "run={run_case}: {legacy:?}");
        assert_eq!(legacy.chain_builds, 1);
        assert_eq!(legacy.config_clones, 1);
        let counts = (new, legacy);
        if run_case == 0 {
            report("singleton_key/gateless", counts.0);
            report("singleton_key/gateless_legacy", counts.1);
            first = Some(counts);
        } else {
            assert_eq!(counts, first.unwrap(), "repeat must match");
        }
    }

    // Gated node: both paths copy once and drop the gate link, so the new
    // path may not allocate more; the input keeps its gate link either way.
    let mut first = None;
    for run_case in 0..2 {
        let gated = Arc::new(proxy(1).with_gate(proxy(2)));
        let before = (*gated).clone();
        let (key, new) = measure(|| ChainKey::singleton(&gated));
        let (legacy_key, legacy) =
            measure(|| ChainKey::new(Arc::new(ProxyConfig::chain([Arc::clone(&gated)]).unwrap())));
        assert_eq!(key, legacy_key, "run={run_case}: singleton identity");
        assert!(key.exit().gate.is_none());
        assert!(legacy_key.exit().gate.is_none());
        assert!(
            allocator_calls(&new) <= allocator_calls(&legacy),
            "run={run_case}: {new:?} vs {legacy:?}"
        );
        assert_eq!(new.config_clones, 1);
        assert_eq!(new.chain_builds, 0);
        assert_eq!(legacy.chain_builds, 1);
        assert!(Arc::ptr_eq(
            gated.gate.as_ref().expect("gate link kept"),
            before.gate.as_ref().expect("gate link kept")
        ));
        assert_eq!(gated.host, before.host);
        assert_eq!(gated.user, before.user);
        assert_eq!(gated.password, before.password);
        assert_eq!(gated.gate_level, before.gate_level);
        let counts = (new, legacy);
        if run_case == 0 {
            report("singleton_key/gated", counts.0);
            report("singleton_key/gated_legacy", counts.1);
            first = Some(counts);
        } else {
            assert_eq!(counts, first.unwrap(), "repeat must match");
        }
    }
}

/// `ChainPick::config_arc` (Arc::clone of the pick's key) vs the legacy
/// replica `Arc::new(pick.config())`, which copies the exit node.
#[test]
fn perf208_config_arc_zero_alloc_vs_legacy_materialization() {
    for depth in [1usize, 4, 16] {
        let gates = GateLevels::new(
            (1..depth)
                .map(|rank| {
                    let node = proxy(rank).with_gate_level(rank as u8);
                    (rank as u8, Arc::new(ProxyRotator::new(vec![node])))
                })
                .collect(),
        );
        let exits = [Arc::new(ProxyRotator::new(vec![proxy(0)]))];
        let pick = ChainPlan::new(&gates, &exits)
            .next()
            .expect("configured plan yields a pick");
        assert_eq!(pick.config_arc().chain_len(), depth);
        assert_eq!(pick.exit().proxy.host, "proxy-0.invalid");

        let (shared, new) = measure(|| pick.config_arc());
        let (legacy_config, legacy) = measure(|| Arc::new(pick.config()));
        assert!(Arc::ptr_eq(&shared, pick.key().exit()));
        assert_eq!(ChainKey::new(Arc::clone(&legacy_config)), pick.key());
        assert_eq!(allocator_calls(&new), 0, "depth={depth}: {new:?}");
        assert_eq!(new.config_clones, 0);
        assert!(allocator_calls(&legacy) > 0, "depth={depth}: {legacy:?}");
        assert_eq!(legacy.config_clones, 1);
        assert!(legacy.requested_bytes > new.requested_bytes);
        report(&format!("config_arc/depth={depth}"), new);
        report(&format!("config_arc_legacy/depth={depth}"), legacy);
    }
}

/// `link_proxy(impl AsRef<str>)` vs the legacy replica that materializes a
/// `String` first. The sticky cache copies the address into `Arc<str>` only
/// for a new entry, so the borrowed path saves at least the legacy String.
// The `to_string()` call is the measured legacy cost; clippy cannot see
// the String materialization is intentional.
#[allow(clippy::unnecessary_to_owned)]
#[test]
fn perf208_link_proxy_borrowed_address_saves_the_legacy_string() {
    const UPDATE_ADDR: &str = "target.invalid:443";
    const FRESH_ADDR: &str = "fresh.invalid:443";
    let fresh_rotator = || ProxyRotator::new(vec![proxy(0)]);

    // (i) Updating an existing address: the key Arc<str> is reused, the
    // legacy replica pays one extra String for the identical operation.
    let mut first = None;
    for run_case in 0..2 {
        let new_rotator = fresh_rotator();
        let legacy_rotator = fresh_rotator();
        let initial = Arc::new(proxy(1));
        new_rotator.link_proxy(UPDATE_ADDR, Arc::clone(&initial));
        legacy_rotator.link_proxy(UPDATE_ADDR, Arc::clone(&initial));
        let replacement = Arc::new(proxy(2));
        let (_, new) = measure(|| new_rotator.link_proxy(UPDATE_ADDR, Arc::clone(&replacement)));
        let (_, legacy) = measure(|| {
            legacy_rotator.link_proxy(UPDATE_ADDR.to_string(), Arc::clone(&replacement))
        });
        assert!(
            legacy.alloc > new.alloc,
            "run={run_case}: update saves the String: {new:?} vs {legacy:?}"
        );
        assert_eq!(
            legacy.requested_bytes.saturating_sub(new.requested_bytes),
            UPDATE_ADDR.len() as u64,
            "run={run_case}: the saved request is exactly the address String"
        );
        assert_eq!(
            new_rotator
                .get_linked(UPDATE_ADDR)
                .expect("updated entry")
                .host,
            "proxy-2.invalid"
        );
        assert_eq!(
            legacy_rotator
                .get_linked(UPDATE_ADDR)
                .expect("updated entry")
                .host,
            "proxy-2.invalid"
        );
        let counts = (new, legacy);
        if run_case == 0 {
            report("link_proxy/update", counts.0);
            report("link_proxy/update/legacy", counts.1);
            first = Some(counts);
        } else {
            assert_eq!(counts, first.unwrap(), "repeat must match");
        }
    }

    // (ii) First link of a new address: both paths pay one Arc<str> key,
    // the legacy replica pays the String on top.
    let mut first = None;
    for run_case in 0..2 {
        let new_rotator = fresh_rotator();
        let legacy_rotator = fresh_rotator();
        let linked = Arc::new(proxy(3));
        let (_, new) = measure(|| new_rotator.link_proxy(FRESH_ADDR, Arc::clone(&linked)));
        let (_, legacy) =
            measure(|| legacy_rotator.link_proxy(FRESH_ADDR.to_string(), Arc::clone(&linked)));
        assert!(
            legacy.alloc > new.alloc,
            "run={run_case}: fresh link saves the String: {new:?} vs {legacy:?}"
        );
        assert_eq!(
            legacy.requested_bytes.saturating_sub(new.requested_bytes),
            FRESH_ADDR.len() as u64,
            "run={run_case}: the saved request is exactly the address String"
        );
        assert!(new_rotator.get_linked(FRESH_ADDR).is_some());
        assert!(legacy_rotator.get_linked(FRESH_ADDR).is_some());
        let counts = (new, legacy);
        if run_case == 0 {
            report("link_proxy/new_addr", counts.0);
            report("link_proxy/new_addr/legacy", counts.1);
            first = Some(counts);
        } else {
            assert_eq!(counts, first.unwrap(), "repeat must match");
        }
    }
}

/// `ProxyConfig::chain_arc` vs the legacy replica
/// `Arc::new(ProxyConfig::chain(nodes.clone()).unwrap())`: the first node is
/// shared, later nodes are copied once, and the `Arc` is returned directly.
#[test]
fn perf208_chain_arc_shares_first_node_and_skips_the_unwrap_round_trip() {
    for size in [1usize, 4] {
        let nodes: Vec<_> = (0..size).map(|index| Arc::new(proxy(index))).collect();
        let (built, new) = measure(|| ProxyConfig::chain_arc(nodes.iter().cloned()));
        let (legacy_key, legacy) =
            measure(|| ChainKey::new(Arc::new(ProxyConfig::chain(nodes.clone()).unwrap())));
        let built = built.expect("chain_arc of a non-empty iterator");
        assert_eq!(ChainKey::new(Arc::clone(&built)), legacy_key);
        assert_eq!(new.chain_builds, 1);
        assert_eq!(legacy.chain_builds, 1);
        assert_eq!(new.chain_nodes, size as u64);
        assert_eq!(legacy.chain_nodes, size as u64);
        assert_eq!(new.config_clones, size as u64 - 1);
        assert_eq!(legacy.config_clones, size as u64);
        assert!(
            allocator_calls(&new) < allocator_calls(&legacy),
            "nodes={size}: {new:?} vs {legacy:?}"
        );
        if size == 1 {
            assert!(Arc::ptr_eq(&built, &nodes[0]));
            assert_eq!(allocator_calls(&new), 0, "nodes=1: {new:?}");
        } else {
            let mut outermost = Arc::clone(&built);
            while let Some(gate) = outermost.gate.clone() {
                outermost = gate;
            }
            assert!(Arc::ptr_eq(&outermost, &nodes[0]), "first node shared");
            assert!(!Arc::ptr_eq(&built, &nodes[size - 1]), "exit is a copy");
        }
        report(&format!("chain_arc/nodes={size}"), new);
        report(&format!("chain_arc_legacy/nodes={size}"), legacy);
    }
}
