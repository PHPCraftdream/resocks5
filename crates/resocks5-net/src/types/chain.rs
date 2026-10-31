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
        let mut chain: Option<Arc<ProxyConfig>> = None;
        for node in nodes {
            let mut linked = (*node).clone();
            linked.gate = chain;
            chain = Some(Arc::new(linked));
        }
        chain.map(|chain| Arc::try_unwrap(chain).unwrap_or_else(|shared| (*shared).clone()))
    }

    /// Borrow this chain's nodes, outermost first and exit last.
    pub fn chain_nodes(&self) -> Vec<&ProxyConfig> {
        let mut nodes = Vec::new();
        let mut current = Some(self);
        while let Some(node) = current {
            nodes.push(node);
            current = node.gate.as_deref();
        }
        nodes.reverse();
        nodes
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
        let nodes = self.0.chain_nodes();
        nodes.len().hash(state);
        for node in nodes {
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
    }
}
