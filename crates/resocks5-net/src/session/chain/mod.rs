//! Lazy Cartesian plans for multi-hop proxy chains.
//!
//! Gate levels are ordered outermost first by descending rank, with exits in
//! the final (fastest) layer. Rank gaps are allowed. With no gates, chains
//! consist of exits alone. Connect failures implicate the first hop; hard
//! failures at a gate handshake implicate that gate, while ambiguous handshake
//! failures softly penalize both adjacent hops. Target failures implicate the
//! exit. A layer whose candidates are all marked dead ends the plan at once.
//! Only explicit complete-chain exclusions are retained.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use crate::connect::{ChainError, ChainStage};
use crate::error::ConnectError;
use crate::rotator::ProxyRotator;
use crate::types::{ChainKey, ProxyConfig};

/// Ranked proxy rotators used as chain gates.
#[derive(Clone, Default)]
pub struct GateLevels {
    levels: Vec<(u8, Arc<ProxyRotator>)>,
}

/// Why [`GateLevels::try_new`] rejected the configured levels.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GateLevelsError {
    duplicated_rank: u8,
}

impl GateLevelsError {
    /// The rank that appeared at more than one level.
    #[must_use]
    pub fn duplicated_rank(&self) -> u8 {
        self.duplicated_rank
    }
}

impl std::fmt::Display for GateLevelsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "duplicate gate rank {}", self.duplicated_rank)
    }
}

impl std::error::Error for GateLevelsError {}

impl GateLevels {
    /// Sort gates by descending rank.
    ///
    /// Duplicate ranks are only rejected in debug builds: release builds
    /// keep them, with the order among equal ranks left to the sort. Use
    /// [`GateLevels::try_new`] to reject duplicates in release builds too.
    pub fn new(mut levels: Vec<(u8, Arc<ProxyRotator>)>) -> Self {
        levels.sort_by_key(|(rank, _)| std::cmp::Reverse(*rank));
        debug_assert!(levels.windows(2).all(|pair| pair[0].0 != pair[1].0));
        Self { levels }
    }
    /// Fallible [`GateLevels::new`]: sorts gates by descending rank and
    /// rejects duplicate ranks in release builds too. The sort happens
    /// first, so equal ranks are adjacent when checked.
    ///
    /// # Errors
    ///
    /// Returns [`GateLevelsError`] naming the duplicated rank; the error
    /// carries no proxy or credential data.
    pub fn try_new(mut levels: Vec<(u8, Arc<ProxyRotator>)>) -> Result<Self, GateLevelsError> {
        levels.sort_by_key(|(rank, _)| std::cmp::Reverse(*rank));
        if let Some(pair) = levels.windows(2).find(|pair| pair[0].0 == pair[1].0) {
            return Err(GateLevelsError {
                duplicated_rank: pair[0].0,
            });
        }
        Ok(Self { levels })
    }
    /// Return whether no gate levels were configured.
    pub fn is_empty(&self) -> bool {
        self.levels.is_empty()
    }
    /// Return the number of gate levels.
    pub fn len(&self) -> usize {
        self.levels.len()
    }
    /// Iterate over ranks and rotators in descending rank order.
    pub fn iter(&self) -> impl Iterator<Item = (u8, &Arc<ProxyRotator>)> {
        self.levels.iter().map(|(rank, rotator)| (*rank, rotator))
    }

    /// Resolve an existing chain to the rotators configured for its exact nodes.
    ///
    /// `chain` is ordered outermost first; gate levels must match the configured
    /// ranks and the final node must match one of the supplied exit rotators.
    pub fn resolve(&self, exits: &[Arc<ProxyRotator>], chain: &ProxyConfig) -> Option<ChainPick> {
        let nodes = chain.nodes();
        if nodes.len() != self.levels.len() + 1 {
            return None;
        }
        let mut hops = Vec::with_capacity(nodes.len());
        for ((rank, rotator), node) in self.levels.iter().zip(nodes.iter().take(self.levels.len()))
        {
            if node.gate_level != *rank {
                return None;
            }
            let proxy = rotator
                .all_proxies()
                .iter()
                .find(|candidate| same_node(candidate, node))?
                .clone();
            hops.push(Hop {
                rotator: rotator.clone(),
                proxy,
            });
        }
        let exit_node = nodes.last()?;
        for rotator in exits {
            if let Some(proxy) = rotator
                .all_proxies()
                .iter()
                .find(|candidate| same_node(candidate, exit_node))
                .cloned()
            {
                hops.push(Hop {
                    rotator: rotator.clone(),
                    proxy,
                });
                let key = ChainKey::new(Arc::new(ProxyConfig::chain(
                    hops.iter().map(|hop| hop.proxy.clone()),
                )?));
                return Some(ChainPick { hops, key });
            }
        }
        None
    }
}

impl std::fmt::Debug for GateLevels {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_list()
            .entries(self.levels.iter().map(|(rank, _)| rank))
            .finish()
    }
}

fn same_node(a: &ProxyConfig, b: &ProxyConfig) -> bool {
    a.protocol == b.protocol
        && a.host == b.host
        && a.port == b.port
        && a.user == b.user
        && a.password == b.password
        && a.gate_level == b.gate_level
}

/// One selected node and its source rotator.
#[derive(Clone)]
pub struct Hop {
    /// Rotator which selected this proxy.
    pub rotator: Arc<ProxyRotator>,
    /// Selected proxy configuration.
    pub proxy: Arc<ProxyConfig>,
}

#[derive(Clone)]
struct Candidate {
    hop: Hop,
    key: ChainKey,
}
struct Layer {
    candidates: Vec<Candidate>,
    /// Candidates not yet marked dead; zero means no chain can exist.
    live: usize,
    index: usize,
}

/// One complete chain candidate, gates outermost and exit last.
#[derive(Clone)]
pub struct ChainPick {
    hops: Vec<Hop>,
    key: ChainKey,
}

impl ChainPick {
    /// Return selected chain hops in dial order.
    pub fn hops(&self) -> &[Hop] {
        &self.hops
    }
    /// Return an owned identity key for this chain.
    pub fn key(&self) -> ChainKey {
        self.key.clone()
    }
    /// Build the linked configuration for this chain.
    pub fn config(&self) -> ProxyConfig {
        ProxyConfig::chain(self.hops.iter().map(|hop| hop.proxy.clone()))
            .expect("a chain pick always has an exit")
    }
    /// Record a success on every hop; needs no plan, so a cached chain can use it.
    pub fn record_success(&self) {
        for hop in &self.hops {
            hop.rotator.record_success(&hop.proxy);
        }
    }
    /// Return the final proxy in the chain.
    pub fn exit(&self) -> &Hop {
        self.hops.last().expect("a chain pick always has an exit")
    }
}

/// A proxy and the quarantine duration caused by a chain failure.
#[derive(Clone, Debug)]
pub struct Quarantined {
    /// Proxy whose failure threshold was tripped.
    pub proxy: Arc<ProxyConfig>,
    /// Duration of its new quarantine.
    pub length: Duration,
}

/// Lazy, identity-deduplicated Cartesian traversal of gates and exits.
pub struct ChainPlan {
    layers: Vec<Layer>,
    seen: HashSet<ChainKey>,
    dead: HashSet<ChainKey>,
    done: bool,
    /// Test-only count of `next_pick` loop iterations for work-bound oracles.
    #[cfg(test)]
    steps: u64,
}

impl ChainPlan {
    /// Snapshot weighted-random gate orders and concatenate exit candidates into one layer.
    pub fn new(gates: &GateLevels, exits: &[Arc<ProxyRotator>]) -> Self {
        let mut layers: Vec<_> = gates
            .iter()
            .map(|(_, rotator)| {
                let candidates = deduplicate(
                    rotator
                        .pick_order()
                        .into_iter()
                        .map(|proxy| (rotator.clone(), proxy)),
                );
                Layer {
                    live: candidates.len(),
                    candidates,
                    index: 0,
                }
            })
            .collect();
        let mut candidates = Vec::new();
        let mut keys = HashSet::new();
        for rotator in exits {
            for proxy in rotator.pick_order() {
                let key = singleton_key(&proxy);
                if keys.insert(key.clone()) {
                    candidates.push(Candidate {
                        hop: Hop {
                            rotator: rotator.clone(),
                            proxy,
                        },
                        key,
                    });
                }
            }
        }
        let live = candidates.len();
        layers.push(Layer {
            live,
            candidates,
            index: 0,
        });
        let done = layers.iter().any(|layer| layer.candidates.is_empty());
        Self {
            layers,
            seen: HashSet::new(),
            dead: HashSet::new(),
            done,
            #[cfg(test)]
            steps: 0,
        }
    }

    /// Return the next unseen candidate chain.
    fn next_pick(&mut self) -> Option<ChainPick> {
        while !self.done {
            self.count_step();
            let dead_layer = self
                .layers
                .iter()
                .position(|layer| self.dead.contains(&layer.candidates[layer.index].key));
            if let Some(index) = dead_layer {
                self.jump_subtree(index);
                continue;
            }
            let pick = self.current_pick();
            self.advance();
            if !self.seen.contains(&pick.key) {
                return Some(pick);
            }
        }
        None
    }

    /// Deterministic work counter for the exhaustion work-bound tests.
    #[cfg(test)]
    fn count_step(&mut self) {
        self.steps += 1;
    }
    #[cfg(not(test))]
    fn count_step(&mut self) {}

    /// Exclude every combination containing this singleton proxy, now and later.
    ///
    /// When the last live candidate of any layer dies, the plan is exhausted:
    /// every remaining combination would contain a dead node.
    pub fn mark_dead(&mut self, proxy: &ProxyConfig) {
        let key = singleton_key(&Arc::new(proxy.clone()));
        if !self.dead.insert(key.clone()) {
            return;
        }
        for layer in &mut self.layers {
            if layer
                .candidates
                .iter()
                .any(|candidate| candidate.key == key)
            {
                layer.live -= 1;
                if layer.live == 0 {
                    self.done = true;
                }
            }
        }
    }
    /// Exclude a complete chain identity from future results.
    pub fn exclude(&mut self, key: &ChainKey) {
        self.seen.insert(key.clone());
    }

    fn current_pick(&self) -> ChainPick {
        let hops: Vec<_> = self
            .layers
            .iter()
            .map(|layer| layer.candidates[layer.index].hop.clone())
            .collect();
        let key = ChainKey::new(Arc::new(
            ProxyConfig::chain(hops.iter().map(|hop| hop.proxy.clone()))
                .expect("layers are non-empty"),
        ));
        ChainPick { hops, key }
    }
    fn advance(&mut self) {
        for layer in self.layers.iter_mut().rev() {
            layer.index += 1;
            if layer.index < layer.candidates.len() {
                return;
            }
            layer.index = 0;
        }
        self.done = true;
    }
    fn jump_subtree(&mut self, index: usize) {
        for layer in self.layers.iter_mut().skip(index + 1) {
            layer.index = 0;
        }
        let mut i = index;
        loop {
            self.layers[i].index += 1;
            if self.layers[i].index < self.layers[i].candidates.len() {
                return;
            }
            self.layers[i].index = 0;
            let Some(parent) = i.checked_sub(1) else {
                self.done = true;
                return;
            };
            i = parent;
        }
    }
}

fn deduplicate(
    candidates: impl IntoIterator<Item = (Arc<ProxyRotator>, Arc<ProxyConfig>)>,
) -> Vec<Candidate> {
    let mut seen = HashSet::new();
    candidates
        .into_iter()
        .filter_map(|(rotator, proxy)| {
            let key = singleton_key(&proxy);
            seen.insert(key.clone()).then_some(Candidate {
                hop: Hop { rotator, proxy },
                key,
            })
        })
        .collect()
}

fn singleton_key(proxy: &Arc<ProxyConfig>) -> ChainKey {
    let mut plain = (**proxy).clone();
    plain.gate = None;
    ChainKey::new(Arc::new(plain))
}

impl ChainPlan {
    /// Record a successful chain on every hop.
    pub fn record_success(&self, pick: &ChainPick) {
        pick.record_success();
    }
    /// Attribute a failure and return newly quarantined nodes.
    pub fn record_failure(&mut self, pick: &ChainPick, err: &ChainError) -> Vec<Quarantined> {
        self.record_failure_inner(pick, err.stage(), err.error())
    }
    fn record_failure_inner(
        &mut self,
        pick: &ChainPick,
        stage: ChainStage,
        err: &ConnectError,
    ) -> Vec<Quarantined> {
        if !err.counts_against_upstream() {
            return Vec::new();
        }
        let hops = &pick.hops;
        let mut quarantined = Vec::new();
        let mut hard = |hop: &Hop| {
            if let Some(length) = hop.rotator.record_error(&hop.proxy, err) {
                quarantined.push(Quarantined {
                    proxy: hop.proxy.clone(),
                    length,
                });
            }
        };
        let soft = |hop: &Hop| hop.rotator.record_failure(&hop.proxy);
        match stage {
            ChainStage::Connect => {
                hard(&hops[0]);
                self.mark_dead(&hops[0].proxy);
            }
            ChainStage::Hop(i)
                if i.checked_add(1).filter(|next| *next < hops.len()).is_some()
                    && err.is_upstream_down() =>
            {
                hard(&hops[i]);
                self.mark_dead(&hops[i].proxy);
            }
            ChainStage::Hop(i) if i.checked_add(1).filter(|next| *next < hops.len()).is_some() => {
                soft(&hops[i]);
                soft(&hops[i + 1]);
            }
            ChainStage::Target => {
                let exit = hops.last().expect("chain has exit");
                hard(exit);
                self.mark_dead(&exit.proxy);
            }
            _ => {
                for hop in hops {
                    soft(hop);
                }
            }
        }
        quarantined
    }
}

impl Iterator for ChainPlan {
    type Item = ChainPick;

    fn next(&mut self) -> Option<Self::Item> {
        self.next_pick()
    }
}

#[cfg(test)]
mod accounting_tests;
#[cfg(test)]
mod selection_tests;

impl std::fmt::Debug for ChainPlan {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChainPlan")
            .field("layers", &self.layers.len())
            .field("done", &self.done)
            .finish()
    }
}

#[cfg(test)]
mod gate_levels_tests {
    use std::sync::Arc;

    use crate::rotator::ProxyRotator;
    use crate::types::ProxyConfig;

    use super::GateLevels;

    fn rotator(host: &str) -> Arc<ProxyRotator> {
        Arc::new(ProxyRotator::new(vec![ProxyConfig::socks5(host, 1)]))
    }

    /// Mutation caught: removing the duplicate check from `try_new` (or
    /// leaving it debug-only) fails this in release test builds.
    #[test]
    fn try_new_rejects_duplicate_ranks() {
        let err = GateLevels::try_new(vec![
            (2, rotator("dup-a")),
            (5, rotator("high")),
            (2, rotator("dup-b")),
        ])
        .unwrap_err();
        assert_eq!(err.duplicated_rank(), 2);
        assert_eq!(err.to_string(), "duplicate gate rank 2");
        assert!(GateLevels::try_new(vec![(2, rotator("a")), (5, rotator("b"))]).is_ok());
        assert!(GateLevels::try_new(vec![(7, rotator("solo"))]).is_ok());
    }

    /// Mutation caught: removing the descending sort from `try_new`
    /// leaves the input order and the `[3, 2, 1]` assertion fails.
    #[test]
    fn try_new_sorts_descending() {
        let levels = GateLevels::try_new(vec![
            (1, rotator("low")),
            (3, rotator("high")),
            (2, rotator("mid")),
        ])
        .expect("distinct ranks are accepted");
        let ranks: Vec<u8> = levels.iter().map(|(rank, _)| rank).collect();
        assert_eq!(ranks, [3, 2, 1]);
    }

    /// Mutation caught: rejecting or panicking on empty levels in
    /// `try_new` fails this.
    #[test]
    fn try_new_accepts_empty_levels() {
        let levels = GateLevels::try_new(Vec::new()).expect("empty is fine");
        assert!(levels.is_empty());
        assert_eq!(levels.len(), 0);
    }
}
