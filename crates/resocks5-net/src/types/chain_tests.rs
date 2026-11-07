use std::collections::HashSet;
use std::hash::{Hash, Hasher};
use std::sync::Arc;

use super::{ChainKey, ProxyConfig, ProxyProtocol};

fn node(host: &str, port: u16, level: u8) -> Arc<ProxyConfig> {
    Arc::new(
        ProxyConfig::new(ProxyProtocol::Socks5, host, port)
            .with_auth("chain-user", "chain-password")
            .with_gate_level(level),
    )
}

fn hash(key: &ChainKey) -> u64 {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    key.hash(&mut hasher);
    hasher.finish()
}

#[test]
fn chain_empty_singleton_and_multi_node_discard_input_gates() {
    assert!(ProxyConfig::chain(Vec::<Arc<ProxyConfig>>::new()).is_none());

    let one = Arc::new(ProxyConfig::socks5("single", 1).with_gate(ProxyConfig::http("discard", 2)));
    let singleton = ProxyConfig::chain([one]).unwrap();
    assert_eq!(singleton.host, "single");
    assert!(singleton.gate.is_none());
    assert_eq!(singleton.chain_nodes().len(), 1);
    assert_eq!(singleton.chain_len(), 1);

    let inputs = [
        Arc::new(
            ProxyConfig::http("outer", 10)
                .as_gate()
                .with_gate(ProxyConfig::https("discard-a", 11)),
        ),
        Arc::new(ProxyConfig::https("middle", 20).with_gate(ProxyConfig::http("discard-b", 21))),
        Arc::new(ProxyConfig::socks5("exit", 30).with_gate(ProxyConfig::http("discard-c", 31))),
    ];
    let chain = ProxyConfig::chain(inputs).unwrap();
    let nodes = chain.chain_nodes();
    assert_eq!(
        nodes.iter().map(|n| n.host.as_str()).collect::<Vec<_>>(),
        ["outer", "middle", "exit"]
    );
    assert_eq!(chain.chain_len(), 3);
    assert_eq!(chain.host, "exit");
    let middle = chain.gate.as_deref().unwrap();
    assert_eq!(middle.host, "middle");
    let outer = middle.gate.as_deref().unwrap();
    assert_eq!(outer.host, "outer");
    assert!(outer.gate.is_none());
    assert_eq!(nodes[0].gate_level, 1);
    assert_eq!(nodes[1].gate_level, 0);
    assert_eq!(nodes[2].gate_level, 0);
    assert_eq!(nodes[2].protocol, ProxyProtocol::Socks5);
}

#[test]
fn traversal_roundtrips_through_builder_preserving_key_identity() {
    let original = ProxyConfig::chain([
        Arc::new(
            ProxyConfig::http("outer", 10)
                .with_auth("u0", "p0")
                .with_gate_level(3),
        ),
        Arc::new(
            ProxyConfig::https("middle", 20)
                .with_auth("u1", "p1")
                .with_gate_level(2),
        ),
        Arc::new(ProxyConfig::socks5("exit", 30).with_auth("u2", "p2")),
    ])
    .unwrap();
    let rebuilt = ProxyConfig::chain(
        original
            .chain_nodes()
            .iter()
            .map(|node| Arc::new((*node).clone())),
    )
    .unwrap();
    assert_eq!(
        ChainKey::new(Arc::new(original)),
        ChainKey::new(Arc::new(rebuilt))
    );
}

#[test]
fn chain_builder_orders_one_through_three_nodes() {
    for len in 1..=3 {
        let inputs: Vec<_> = (0..len)
            .map(|index| node(&format!("node-{index}"), index as u16, 0))
            .collect();
        let chain = ProxyConfig::chain(inputs).unwrap();
        let expected: Vec<_> = (0..len).map(|index| format!("node-{index}")).collect();
        assert_eq!(
            chain
                .chain_nodes()
                .iter()
                .map(|n| n.host.as_str())
                .collect::<Vec<_>>(),
            expected.iter().map(String::as_str).collect::<Vec<_>>()
        );
        assert_eq!(chain.chain_len(), len);
    }
}

#[test]
fn accessors_preserve_nodes_order_ports_and_outer_identity() {
    for len in 1..=3 {
        let mut chain = node("node-0", 1000, 0).as_ref().clone();
        for index in 1..len {
            chain = node(&format!("node-{index}"), 1000 + index as u16, 0)
                .as_ref()
                .clone()
                .with_gate(chain);
        }
        let outermost = chain.outermost();
        let nodes = chain.nodes();
        let chain_nodes = chain.chain_nodes();
        assert_eq!(nodes.len(), len);
        assert_eq!(chain_nodes.len(), len);
        assert!(nodes
            .iter()
            .zip(&chain_nodes)
            .all(|(a, b)| std::ptr::eq(*a, *b)));
        assert_eq!(
            nodes
                .iter()
                .map(|n| (n.host.as_str(), n.port))
                .collect::<Vec<_>>(),
            (0..len)
                .map(|i| (format!("node-{i}"), 1000 + i as u16))
                .collect::<Vec<_>>()
                .iter()
                .map(|(h, p)| (h.as_str(), *p))
                .collect::<Vec<_>>()
        );
        assert!(std::ptr::eq(*nodes.last().unwrap(), &chain));
        assert!(std::ptr::eq(*nodes.first().unwrap(), outermost));
    }
}

#[test]
fn chain_key_identity_includes_fields_order_length_and_gate_level() {
    let outer = node("outer", 1, 1);
    let exit = node("exit", 2, 0);
    let key = ChainKey::new(Arc::new((*exit).clone().with_gate((*outer).clone())));
    let equal = ChainKey::new(Arc::new(
        ProxyConfig::socks5("exit", 2)
            .with_auth("chain-user", "chain-password")
            .with_gate(
                ProxyConfig::socks5("outer", 1)
                    .with_auth("chain-user", "chain-password")
                    .with_gate_level(1),
            ),
    ));
    assert_eq!(key, equal);
    assert_eq!(hash(&key), hash(&equal));

    let changed_outer = [
        ProxyConfig::http("outer", 1)
            .with_auth("chain-user", "chain-password")
            .with_gate_level(1),
        ProxyConfig::socks5("other-host", 1)
            .with_auth("chain-user", "chain-password")
            .with_gate_level(1),
        ProxyConfig::socks5("outer", 9)
            .with_auth("chain-user", "chain-password")
            .with_gate_level(1),
        ProxyConfig::socks5("outer", 1)
            .with_auth("other-user", "chain-password")
            .with_gate_level(1),
        ProxyConfig::socks5("outer", 1)
            .with_auth("chain-user", "other-password")
            .with_gate_level(1),
        ProxyConfig::socks5("outer", 1)
            .with_auth("chain-user", "chain-password")
            .with_gate_level(2),
    ];
    for changed in changed_outer {
        let candidate = ChainKey::new(Arc::new((*exit).clone().with_gate(changed)));
        assert_ne!(key, candidate);
    }

    let changed_exit = ProxyConfig::socks5("different-exit", 2)
        .with_auth("chain-user", "chain-password")
        .with_gate(
            ProxyConfig::socks5("outer", 1)
                .with_auth("chain-user", "chain-password")
                .with_gate_level(1),
        );
    assert_ne!(key, ChainKey::new(Arc::new(changed_exit)));

    let one_node = ChainKey::new(Arc::new((*exit).clone()));
    assert_ne!(key, one_node);

    let middle = ProxyConfig::http("middle", 3).with_gate((*outer).clone());
    let three_nodes = ChainKey::new(Arc::new((*exit).clone().with_gate(middle)));
    assert_ne!(key, three_nodes);

    let reversed = ChainKey::new(Arc::new((*outer).clone().with_gate((*exit).clone())));
    assert_ne!(key, reversed);
}

#[test]
fn is_gate_is_derived_but_actual_gate_nodes_are_identity() {
    let left = ProxyConfig::socks5("same", 1)
        .with_auth("u", "p")
        .with_gate_level(1);
    let mut right = left.clone();
    right.is_gate = false;
    let left = ChainKey::new(Arc::new(left));
    let right = ChainKey::new(Arc::new(right));
    assert_eq!(left, right);
    assert_eq!(hash(&left), hash(&right));

    let first = ProxyConfig::socks5("same", 1)
        .with_auth("u", "p")
        .with_gate(ProxyConfig::http("hidden-a", 2));
    let second = ProxyConfig::socks5("same", 1)
        .with_auth("u", "p")
        .with_gate(ProxyConfig::https("hidden-b", 3));
    assert_ne!(
        ChainKey::new(Arc::new(first)),
        ChainKey::new(Arc::new(second))
    );
}

#[test]
fn hash_set_deduplicates_equal_chains() {
    let first = ProxyConfig::socks5("exit", 2)
        .with_auth("chain-user", "chain-password")
        .with_gate(
            ProxyConfig::socks5("outer", 1)
                .with_auth("chain-user", "chain-password")
                .with_gate_level(1),
        );
    let second = ProxyConfig::socks5("exit", 2)
        .with_auth("chain-user", "chain-password")
        .with_gate(
            ProxyConfig::socks5("outer", 1)
                .with_auth("chain-user", "chain-password")
                .with_gate_level(1),
        );
    let mut keys = HashSet::new();
    keys.insert(ChainKey::new(Arc::new(first)));
    keys.insert(ChainKey::new(Arc::new(second)));
    assert_eq!(keys.len(), 1);
}

#[test]
fn debug_redacts_key_and_chain_passwords_at_every_depth() {
    let nodes = [
        Arc::new(ProxyConfig::socks5("outer", 1).with_auth("outer-user", "outer-secret")),
        Arc::new(ProxyConfig::http("middle", 2).with_auth("middle-user", "middle-secret")),
        Arc::new(ProxyConfig::https("exit", 3).with_auth("exit-user", "exit-secret")),
    ];
    let chain = ProxyConfig::chain(nodes).unwrap();
    let key = ChainKey::new(Arc::new(chain.clone()));
    for rendered in [format!("{key:?}"), format!("{chain:?}")] {
        for secret in [
            "outer-secret",
            "middle-secret",
            "exit-secret",
            "outer-user",
            "middle-user",
            "exit-user",
        ] {
            assert!(!rendered.contains(secret), "leaked {secret}: {rendered}");
        }
        assert_eq!(rendered.matches("<redacted>").count(), 6);
    }
}

#[test]
fn chain_matches_manual_with_gate_dial_chain_shape() {
    let outer = node("outer", 1, 1);
    let exit = node("exit", 2, 0);
    let built = ProxyConfig::chain([outer.clone(), exit.clone()]).unwrap();
    let manual = (*exit).clone().with_gate((*outer).clone());
    assert_eq!(
        ChainKey::new(Arc::new(built.clone())),
        ChainKey::new(Arc::new(manual))
    );
    assert_eq!(built.host, "exit");
    assert_eq!(built.gate.as_ref().unwrap().host, "outer");
    assert!(built.gate.as_ref().unwrap().gate.is_none());

    let middle = node("middle", 3, 2);
    let three_node = ProxyConfig::chain([outer.clone(), middle.clone(), exit.clone()]).unwrap();
    let manual = (*exit)
        .clone()
        .with_gate((*middle).clone().with_gate((*outer).clone()));
    assert_eq!(
        ChainKey::new(Arc::new(three_node.clone())),
        ChainKey::new(Arc::new(manual))
    );
    assert_eq!(three_node.gate.as_ref().unwrap().host, "middle");
    assert_eq!(
        three_node
            .gate
            .as_ref()
            .unwrap()
            .gate
            .as_ref()
            .unwrap()
            .host,
        "outer"
    );
}

/// A gate-less node is shared, not copied. Mutation: copying it anyway keeps
/// the equality below but fails the pointer check.
#[test]
fn singleton_key_shares_a_gateless_node() {
    let exit = node("exit", 1, 0);
    let key = ChainKey::singleton(&exit);
    assert!(Arc::ptr_eq(key.exit(), &exit));
    assert_eq!(Arc::strong_count(&exit), 2);
}

/// The key equals the key of a one-node `chain`, hash included, so the two
/// ways of building a route key can sit in one set.
#[test]
fn singleton_key_equals_the_chain_key_of_the_same_node() {
    let nodes = [
        node("plain", 1, 0),
        node("leveled", 2, 3),
        Arc::new(ProxyConfig::https("anon", 3)),
        Arc::new(ProxyConfig::socks5("::1", 4).with_auth("u", "")),
    ];
    for exit in nodes {
        let via_chain = ChainKey::new(Arc::new(ProxyConfig::chain([exit.clone()]).unwrap()));
        let singleton = ChainKey::singleton(&exit);
        assert_eq!(singleton, via_chain, "{exit:?}");
        assert_eq!(hash(&singleton), hash(&via_chain), "{exit:?}");
        assert_eq!(HashSet::from([singleton, via_chain]).len(), 1);
    }
}

/// A node that carries a gate is keyed without it and the input is left
/// untouched. Mutation: sharing the node as is keeps the gate in the key and
/// makes it differ from the one-node chain.
#[test]
fn singleton_key_drops_the_gate_link_without_touching_the_node() {
    let exit = Arc::new(ProxyConfig::socks5("exit", 9).with_gate((*node("gate", 8, 1)).clone()));
    let key = ChainKey::singleton(&exit);
    assert!(key.exit().gate.is_none());
    assert!(!Arc::ptr_eq(key.exit(), &exit));
    assert!(exit.gate.is_some(), "the input keeps its gate");
    let alone = ChainKey::new(Arc::new(ProxyConfig::chain([exit.clone()]).unwrap()));
    assert_eq!(key, alone);
    assert_ne!(
        key,
        ChainKey::new(exit.clone()),
        "the gate is part of the full key"
    );
}

/// Identity fields still tell singletons apart.
#[test]
fn singleton_keys_differ_by_identity_fields() {
    let base = node("h", 1, 0);
    let others = [
        node("other", 1, 0),
        node("h", 2, 0),
        node("h", 1, 1),
        Arc::new(ProxyConfig::socks5("h", 1).with_auth("chain-user", "different")),
        Arc::new(ProxyConfig::http("h", 1).with_auth("chain-user", "chain-password")),
    ];
    for other in others {
        assert_ne!(
            ChainKey::singleton(&base),
            ChainKey::singleton(&other),
            "{other:?}"
        );
    }
}

/// `chain_arc` builds the same key, node order and gate levels as `chain`
/// for every length, discarding stray input gates.
#[test]
fn chain_arc_matches_chain_for_lengths_up_to_sixteen() {
    for len in [0usize, 1, 2, 3, 16] {
        let inputs: Vec<_> = (0..len)
            .map(|index| {
                Arc::new(
                    node(&format!("node-{index}"), index as u16, (index as u8) % 8)
                        .as_ref()
                        .clone()
                        .with_gate(ProxyConfig::http("discard", 9)),
                )
            })
            .collect();
        let via_arc = ProxyConfig::chain_arc(inputs.clone());
        let owned = ProxyConfig::chain(inputs).map(Arc::new);
        assert_eq!(via_arc.is_none(), len == 0);
        assert_eq!(owned.is_none(), len == 0);
        let Some(via_arc) = via_arc else {
            continue;
        };
        let owned = owned.unwrap();
        assert_eq!(
            ChainKey::new(Arc::clone(&via_arc)),
            ChainKey::new(Arc::clone(&owned))
        );
        assert_eq!(
            hash(&ChainKey::new(Arc::clone(&via_arc))),
            hash(&ChainKey::new(Arc::clone(&owned)))
        );
        assert_eq!(via_arc.chain_nodes().len(), owned.chain_nodes().len());
        assert!(via_arc
            .chain_nodes()
            .iter()
            .zip(owned.chain_nodes())
            .all(|(a, b)| a.host == b.host && a.port == b.port && a.gate_level == b.gate_level));
    }
}

/// A gate-less singleton comes back as the same `Arc`; a gated one is
/// copied once with the gate dropped and the input left untouched.
#[test]
fn chain_arc_shares_gateless_and_copies_gated_singletons() {
    let plain = node("plain", 1, 0);
    let shared = ProxyConfig::chain_arc([Arc::clone(&plain)]).unwrap();
    assert!(Arc::ptr_eq(&shared, &plain));
    assert_eq!(Arc::strong_count(&plain), 2);

    let gated =
        Arc::new(ProxyConfig::socks5("exit", 9).with_gate(node("gate", 2, 1).as_ref().clone()));
    let copied = ProxyConfig::chain_arc([Arc::clone(&gated)]).unwrap();
    assert!(!Arc::ptr_eq(&copied, &gated));
    assert!(copied.gate.is_none());
    assert_eq!(copied.host, "exit");
    assert!(gated.gate.is_some(), "the input keeps its gate");
    assert_eq!(
        gated.gate.as_deref().map(|gate| gate.host.as_str()),
        Some("gate")
    );
    assert_eq!(
        ChainKey::new(copied),
        ChainKey::new(Arc::new(ProxyConfig::chain([Arc::clone(&gated)]).unwrap()))
    );
}

/// Only the first node of a multi-node chain is shared (found through the
/// gate links); every later node is a copy because its gate link changes.
#[test]
fn chain_arc_shares_only_the_first_node_of_a_multi_node_chain() {
    let first = Arc::new(ProxyConfig::http("outer", 10));
    let second = Arc::new(ProxyConfig::https("middle", 20).as_gate());
    let exit = Arc::new(ProxyConfig::socks5("exit", 30));
    let built =
        ProxyConfig::chain_arc([Arc::clone(&first), Arc::clone(&second), Arc::clone(&exit)])
            .unwrap();
    let mut outermost = Arc::clone(&built);
    while let Some(gate) = outermost.gate.clone() {
        outermost = gate;
    }
    assert!(Arc::ptr_eq(&outermost, &first), "first node shared");
    drop(outermost);
    assert!(
        !Arc::ptr_eq(built.gate.as_ref().unwrap(), &second),
        "later nodes are copies"
    );
    assert!(!Arc::ptr_eq(&built, &exit));
    assert_eq!(Arc::strong_count(&first), 2);
    assert_eq!(
        ChainKey::new(Arc::clone(&built)),
        ChainKey::new(Arc::new(ProxyConfig::chain([first, second, exit]).unwrap()))
    );
}
