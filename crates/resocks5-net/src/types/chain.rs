//! Proxy-chain construction and identity keys.

use std::hash::{Hash, Hasher};
use std::sync::Arc;

use super::ProxyConfig;

impl ProxyConfig {
    /// Build a chain from outermost node to exit, discarding input gates.
    ///
    /// Returns `None` for an empty iterator; a single node has no gate.
    pub fn chain<I>(nodes: I) -> Option<Self>
    where
        I: IntoIterator<Item = Arc<ProxyConfig>>,
    {
        #[cfg(all(test, feature = "test-instrumentation"))]
        crate::perf::operation(|c| c.chain_builds += 1);
        let mut chain: Option<Arc<ProxyConfig>> = None;
        for node in nodes {
            #[cfg(all(test, feature = "test-instrumentation"))]
            crate::perf::operation(|c| {
                c.chain_nodes += 1;
                c.config_clones += 1;
            });
            let mut linked = (*node).clone();
            linked.gate = chain;
            chain = Some(Arc::new(linked));
        }
        chain.map(|chain| Arc::try_unwrap(chain).unwrap_or_else(|shared| (*shared).clone()))
    }

    /// Borrow this chain's nodes, outermost first and exit last.
    pub fn chain_nodes(&self) -> Vec<&ProxyConfig> {
        self.nodes()
    }

    /// Return the number of nodes in this chain.
    pub fn chain_len(&self) -> usize {
        let mut len = 0;
        let mut current = Some(self);
        while let Some(node) = current {
            len += 1;
            current = node.gate.as_deref();
        }
        len
    }
}

/// Identity key for a proxy chain, compared by each node's host, port,
/// protocol, username, password, and gate level.
/// Chain length and node order are significant; derived `is_gate` is ignored.
/// Debug output reuses `ProxyConfig`'s credential-redacting formatter.
#[derive(Clone, Debug)]
pub struct ChainKey(Arc<ProxyConfig>);

impl ChainKey {
    /// Create a key rooted at the exit configuration.
    pub fn new(exit: Arc<ProxyConfig>) -> Self {
        Self(exit)
    }

    /// Key of one node on its own, without its gate link.
    ///
    /// A gate-less node is shared as is (refcount only); a node with a gate
    /// is copied once with the link dropped. Equal to the key of
    /// `ProxyConfig::chain([node])`, without that call's copies.
    pub fn singleton(node: &Arc<ProxyConfig>) -> Self {
        if node.gate.is_none() {
            return Self(Arc::clone(node));
        }
        #[cfg(all(test, feature = "test-instrumentation"))]
        crate::perf::operation(|c| c.config_clones += 1);
        let mut plain = (**node).clone();
        plain.gate = None;
        Self(Arc::new(plain))
    }

    /// Return the exit configuration.
    pub fn exit(&self) -> &Arc<ProxyConfig> {
        &self.0
    }
}

impl PartialEq for ChainKey {
    fn eq(&self, other: &Self) -> bool {
        let mut left = Some(self.0.as_ref());
        let mut right = Some(other.0.as_ref());
        loop {
            match (left, right) {
                (Some(a), Some(b)) => {
                    if a.protocol != b.protocol
                        || a.host != b.host
                        || a.port != b.port
                        || a.user != b.user
                        || a.password != b.password
                        || a.gate_level != b.gate_level
                    {
                        return false;
                    }
                    left = a.gate.as_deref();
                    right = b.gate.as_deref();
                }
                (None, None) => return true,
                _ => return false,
            }
        }
    }
}

impl Eq for ChainKey {}

impl Hash for ChainKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        let mut nodes = [None; super::MAX_CHAIN_NODES];
        let mut len = 0;
        let mut current = Some(self.0.as_ref());
        while let Some(node) = current {
            if len == nodes.len() {
                // Over-long chains that failed validate are still valid keys.
                let nodes = self.0.nodes();
                nodes.len().hash(state);
                for node in nodes {
                    hash_node(node, state);
                }
                return;
            }
            nodes[len] = Some(node);
            len += 1;
            current = node.gate.as_deref();
        }
        len.hash(state);
        for node in nodes[..len].iter().rev().flatten() {
            hash_node(node, state);
        }
    }
}

fn hash_node<H: Hasher>(node: &ProxyConfig, state: &mut H) {
    #[cfg(all(test, feature = "test-instrumentation"))]
    crate::perf::operation(|c| c.hash_nodes += 1);
    (
        std::mem::discriminant(&node.protocol),
        &node.host,
        node.port,
        &node.user,
        &node.password,
        node.gate_level,
    )
        .hash(state);
}
