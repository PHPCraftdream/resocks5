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
