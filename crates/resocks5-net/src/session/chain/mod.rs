//! Lazy Cartesian plans for multi-hop proxy chains.
//!
//! Gate levels are ordered outermost first by descending rank, with exits in
//! the final (fastest) layer. Rank gaps are allowed. With no gates, chains
//! consist of exits alone. Connect failures implicate the first hop; hard
//! failures at a gate handshake implicate that gate, while ambiguous handshake
//! failures softly penalize both adjacent hops. Target failures implicate the
//! exit. Only explicit complete-chain exclusions are retained.

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

impl GateLevels {
    /// Sort gates by descending rank. Duplicate ranks trigger a debug assertion.
    pub fn new(mut levels: Vec<(u8, Arc<ProxyRotator>)>) -> Self {
        levels.sort_by_key(|(rank, _)| std::cmp::Reverse(*rank));
        debug_assert!(levels.windows(2).all(|pair| pair[0].0 != pair[1].0));
        Self { levels }
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
}

impl std::fmt::Debug for GateLevels {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_list()
            .entries(self.levels.iter().map(|(rank, _)| rank))
            .finish()
    }
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
}

impl ChainPlan {
    /// Snapshot weighted-random gate orders and concatenate exit candidates into one layer.
    pub fn new(gates: &GateLevels, exits: &[Arc<ProxyRotator>]) -> Self {
        let mut layers: Vec<_> = gates
            .iter()
            .map(|(_, rotator)| Layer {
                candidates: deduplicate(
                    rotator
                        .pick_order()
                        .into_iter()
                        .map(|proxy| (rotator.clone(), proxy)),
                ),
                index: 0,
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
        layers.push(Layer {
            candidates,
            index: 0,
        });
        let done = layers.iter().any(|layer| layer.candidates.is_empty());
        Self {
            layers,
            seen: HashSet::new(),
            dead: HashSet::new(),
            done,
        }
    }

    /// Return the next unseen candidate chain.
    fn next_pick(&mut self) -> Option<ChainPick> {
        while !self.done {
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

    /// Exclude every combination containing this singleton proxy, now and later.
    pub fn mark_dead(&mut self, proxy: &ProxyConfig) {
        self.dead.insert(singleton_key(&Arc::new(proxy.clone())));
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
        for hop in &pick.hops {
            hop.rotator.record_success(&hop.proxy);
        }
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
