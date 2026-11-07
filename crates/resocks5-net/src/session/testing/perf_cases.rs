//! Component-level baseline scenarios #208, no sockets or timers.

use std::collections::hash_map::DefaultHasher;
use std::collections::HashSet;
use std::hash::{Hash, Hasher};
use std::sync::Arc;

use crate::chain::{ChainPlan, GateLevels};
use crate::perf::{measure, report, Counts};
use crate::rating::{select::weighted_order, QuarantinePolicy, RatingPolicy, SmallRng};
use crate::rotator::ProxyRotator;
use crate::types::{ChainKey, ProxyConfig};

/// Rotator with deterministic ratings RNG (seed defines the weighted pick order).
fn seeded_rotator(size: usize, seed: u64) -> Arc<ProxyRotator> {
    Arc::new(
        ProxyRotator::with_rng_seed(
            (0..size).map(proxy).collect(),
            RatingPolicy::default(),
            QuarantinePolicy::disabled(),
            16,
            std::time::Duration::from_secs(60),
            seed,
        )
        .unwrap(),
    )
}

/// Rotator with deterministic RNG and a real gate-level rank on all nodes.
fn seeded_ranked_rotator(size: usize, seed: u64, rank: u8) -> Arc<ProxyRotator> {
    Arc::new(
        ProxyRotator::with_rng_seed(
            (0..size).map(|i| proxy(i).with_gate_level(rank)).collect(),
            RatingPolicy::default(),
            QuarantinePolicy::disabled(),
            16,
            std::time::Duration::from_secs(60),
            seed,
        )
        .unwrap(),
    )
}

/// Budget label for report: 1, 3, or `full` (full exhaustion).
fn budget_label(budget: usize) -> String {
    if budget == usize::MAX {
        "full".to_owned()
    } else {
        budget.to_string()
    }
}

fn proxy(index: usize) -> ProxyConfig {
    let mut proxy = ProxyConfig::socks5(format!("proxy-{index}.invalid"), 1080);
    proxy.user = Some("synthetic-user".to_owned());
    proxy.password = Some("synthetic-password".to_owned());
    proxy
}

fn hash(key: &ChainKey) -> u64 {
    let mut state = DefaultHasher::new();
    key.hash(&mut state);
    state.finish()
}

#[test]
fn perf208_mark_dead_first_and_duplicate() {
    let dead = proxy(0);
    let exits = [Arc::new(ProxyRotator::new(vec![dead.clone(), proxy(1)]))];
    let mut plan = ChainPlan::new(&GateLevels::default(), &exits);
    let (_, first) = measure(|| plan.mark_dead(&dead));
    let (_, duplicate) = measure(|| plan.mark_dead(&dead));
    report("mark_dead/first", first);
    report("mark_dead/duplicate", duplicate);
    // After baseline, the temporary owned config was removed before singleton_key.
    assert_eq!(first.config_clones, 1);
    assert_eq!(duplicate.config_clones, 1);
    assert!(plan.all(|pick| pick.exit().proxy.host != dead.host));
}

#[test]
fn perf208_chain_hash_by_depth() {
    for depth in [1, 4, 16, 64] {
        let nodes: Vec<_> = (0..depth).map(|i| Arc::new(proxy(i))).collect();
        let key = ChainKey::new(Arc::new(ProxyConfig::chain(nodes).unwrap()));
        let (value, first) = measure(|| hash(&key));
        let (again, second) = measure(|| hash(&key));
        assert_eq!(value, again);
        assert_eq!(first, second);
        assert_eq!(first.hash_nodes, depth as u64);
        assert_eq!(first.alloc + first.alloc_zeroed + first.realloc, 0);
        report(&format!("chain_hash/depth={depth}"), first);
    }
}

#[test]
fn perf208_pick_then_config_materialization() {
    for depth in [1, 4, 16] {
        let gates = GateLevels::new(
            (1..depth)
                .map(|rank| {
                    let mut node = proxy(rank as usize);
                    node.gate_level = rank;
                    node.is_gate = true;
                    (rank, Arc::new(ProxyRotator::new(vec![node])))
                })
                .collect(),
        );
        let exits = [Arc::new(ProxyRotator::new(vec![proxy(0)]))];
        let mut plan = ChainPlan::new(&gates, &exits);
        let (pick, selection) = measure(|| plan.next().unwrap());
        let (config, materialization) = measure(|| pick.config());
        assert_eq!(selection.chain_builds, 1);
        assert_eq!(materialization.chain_builds, 0);
        assert_eq!(selection.chain_nodes, u64::from(depth));
        assert_eq!(materialization.chain_nodes, 0);
        assert_eq!(materialization.config_clones, 1);
        assert_eq!(materialization.alloc, 3);
        assert_eq!(config.chain_len(), usize::from(depth));
        assert!(plan.next().is_none());
        report(&format!("pick/depth={depth}"), selection);
        report(&format!("pick_config/depth={depth}"), materialization);
    }
}

/// Oracle — identity_scan_expectation: position of the matched slot in bucket
/// (hit) or bucket length (miss); correct for arbitrary collisions and
/// early match. resolve_comparisons must equal the oracle: this catches
/// both a linear-scan fallback and a counter walk-through.
#[test]
fn perf208_cached_resolve_first_last_and_miss() {
    for size in [1, 8, 64, 256] {
        let rotator = Arc::new(ProxyRotator::new((0..size).map(proxy).collect()));
        let exits = [rotator];
        let gates = GateLevels::default();
        for (label, index) in [("first", 0), ("last", size - 1)] {
            let node = proxy(index);
            let expected = exits[0].identity_scan_expectation(&node);
            let (pick, counts) = measure(|| gates.resolve(&exits, &node));
            assert_eq!(pick.unwrap().exit().proxy.host, node.host);
            assert_eq!(counts.resolve_comparisons, expected as u64);
            report(&format!("resolve/{label}/n={size}"), counts);
        }
        let missing = proxy(size);
        let expected = exits[0].identity_scan_expectation(&missing);
        let (pick, counts) = measure(|| gates.resolve(&exits, &missing));
        assert!(pick.is_none());
        assert_eq!(counts.resolve_comparisons, expected as u64);
        report(&format!("resolve/miss/n={size}"), counts);
    }
}

#[test]
fn perf208_resolve_gate_levels_exit_owner_and_cached_composite() {
    let mut outer = proxy(1);
    outer.gate_level = 2;
    outer.is_gate = true;
    let mut inner = proxy(2);
    inner.gate_level = 1;
    inner.is_gate = true;
    let outer_rot = Arc::new(ProxyRotator::new(vec![outer.clone()]));
    let inner_rot = Arc::new(ProxyRotator::new(vec![inner.clone()]));
    let gates = GateLevels::new(vec![
        (2, Arc::clone(&outer_rot)),
        (1, Arc::clone(&inner_rot)),
    ]);
    let first = Arc::new(ProxyRotator::new(vec![proxy(3)]));
    let second = Arc::new(ProxyRotator::new(vec![proxy(4)]));
    let exits = [Arc::clone(&first), Arc::clone(&second)];
    let chain_with = |exit: ProxyConfig| {
        ProxyConfig::chain([
            Arc::new(outer.clone()),
            Arc::new(inner.clone()),
            Arc::new(exit),
        ])
        .unwrap()
    };

    // Owner — first exit-rotator slice containing the node's identity.
    let config = chain_with(proxy(3));
    let expected = (outer_rot.identity_scan_expectation(&outer)
        + inner_rot.identity_scan_expectation(&inner)
        + first.identity_scan_expectation(&proxy(3))) as u64;
    let (pick, counts) = measure(|| gates.resolve(&exits, &config));
    assert!(Arc::ptr_eq(&pick.as_ref().unwrap().exit().rotator, &first));
    assert_eq!(counts.resolve_comparisons, expected);
    report("resolve/gates2_owner=first", counts);

    // Owner — the second one: the first does not contain the node (empty bucket, 0 comparisons).
    let config = chain_with(proxy(4));
    let expected = (outer_rot.identity_scan_expectation(&outer)
        + inner_rot.identity_scan_expectation(&inner)
        + first.identity_scan_expectation(&proxy(4))
        + second.identity_scan_expectation(&proxy(4))) as u64;
    let (pick, counts) = measure(|| gates.resolve(&exits, &config));
    assert!(Arc::ptr_eq(&pick.as_ref().unwrap().exit().rotator, &second));
    assert_eq!(counts.resolve_comparisons, expected);
    report("resolve/gates2_owner=second", counts);

    // Real cached-chain shape: exit node carries the gate ref (LINK),
    // identity ignores it — the node matches the rotator's plain proxy.
    let config = chain_with(proxy(3).with_gate(proxy(9)));
    let expected = (outer_rot.identity_scan_expectation(&outer)
        + inner_rot.identity_scan_expectation(&inner)
        + first.identity_scan_expectation(&proxy(3))) as u64;
    let (pick, counts) = measure(|| gates.resolve(&exits, &config));
    let pick = pick.unwrap();
    assert_eq!(pick.exit().proxy.host, "proxy-3.invalid");
    assert_eq!(counts.resolve_comparisons, expected);
    report("resolve/exit/cached_gate_composite", counts);

    // Wrong gate rank is cut off before lookup: zero comparisons.
    let mut wrong_rank = outer.clone();
    wrong_rank.gate_level = 5;
    let config = ProxyConfig::chain([
        Arc::new(wrong_rank),
        Arc::new(inner.clone()),
        Arc::new(proxy(3)),
    ])
    .unwrap();
    let (pick, counts) = measure(|| gates.resolve(&exits, &config));
    assert!(pick.is_none());
    assert_eq!(counts.resolve_comparisons, 0);

    // Wrong exit-node password: gate levels scanned, exit-hash buckets empty.
    let mut wrong_pass = proxy(3);
    wrong_pass.password = Some("wrong".to_owned());
    let config = chain_with(wrong_pass.clone());
    let expected = (outer_rot.identity_scan_expectation(&outer)
        + inner_rot.identity_scan_expectation(&inner)
        + first.identity_scan_expectation(&wrong_pass)
        + second.identity_scan_expectation(&wrong_pass)) as u64;
    let (pick, counts) = measure(|| gates.resolve(&exits, &config));
    assert!(pick.is_none());
    assert_eq!(counts.resolve_comparisons, expected);
}

#[test]
fn perf208_full_weighted_order_with_small_consumption_budget() {
    for size in [1, 8, 64, 256] {
        let weights: Vec<_> = (0..size).map(|i| 1.0 + (i % 7) as f64).collect();
        for budget in [1, 3] {
            let run = || {
                let mut rng = SmallRng::from_seed(208);
                measure(|| weighted_order(&weights, &mut rng))
            };
            let (order, counts) = run();
            let (again, repeated) = run();
            assert_eq!(order, again);
            assert_eq!(counts, repeated);
            assert_eq!(counts.weighted_keys, size as u64);
            let consumed = std::hint::black_box(&order[..budget.min(size)]);
            assert_eq!(consumed.len(), budget.min(size));
            let mut sorted = order;
            sorted.sort_unstable();
            assert_eq!(sorted, (0..size).collect::<Vec<_>>());
            report(
                &format!("weighted_order/n={size}/consumed={budget}"),
                counts,
            );
        }
    }
}

#[test]
fn perf208_hash_preserves_legacy_bytes_at_inline_boundary() {
    #[derive(Default)]
    struct Recorder(Vec<u8>);
    impl Hasher for Recorder {
        fn finish(&self) -> u64 {
            0
        }
        fn write(&mut self, bytes: &[u8]) {
            self.0.extend_from_slice(bytes);
        }
    }
    for depth in [1, 4, 16, 64, 65, 128] {
        let key = ChainKey::new(Arc::new(
            ProxyConfig::chain((0..depth).map(|i| Arc::new(proxy(i)))).unwrap(),
        ));
        let mut actual = Recorder::default();
        key.hash(&mut actual);
        let mut legacy = Recorder::default();
        let nodes = key.exit().chain_nodes();
        nodes.len().hash(&mut legacy);
        for node in nodes {
            (
                std::mem::discriminant(&node.protocol),
                &node.host,
                node.port,
                &node.user,
                &node.password,
                node.gate_level,
            )
                .hash(&mut legacy);
        }
        assert_eq!(actual.0, legacy.0, "depth={depth}");
    }
}

#[test]
fn perf208_pick_config_remains_owned_and_copy_on_write() {
    let mut gate = proxy(1);
    gate.gate_level = 1;
    gate.is_gate = true;
    let gates = GateLevels::new(vec![(1, Arc::new(ProxyRotator::new(vec![gate])))]);
    let exits = [Arc::new(ProxyRotator::new(vec![proxy(0)]))];
    let pick = ChainPlan::new(&gates, &exits).next().unwrap();
    let mut config = pick.config();
    assert_eq!(ChainKey::new(Arc::new(config.clone())), pick.key());
    config.host.push_str("-changed");
    Arc::make_mut(config.gate.as_mut().unwrap())
        .host
        .push_str("-changed");
    let unchanged = pick.config();
    assert_eq!(unchanged.host, "proxy-0.invalid");
    assert_eq!(unchanged.gate.as_ref().unwrap().host, "proxy-1.invalid");
    assert_eq!(ChainKey::new(Arc::new(unchanged)), pick.key());
}

#[cfg(feature = "pool")]
#[test]
fn perf208_pool_reservation_cold_warm_and_capacity() {
    use std::time::Duration;

    use crate::pool::{PoolConfig, ProxyPool};

    let node = proxy(0);
    let pool = ProxyPool::new(PoolConfig::default(), Duration::from_secs(1), 1);
    let (cold, cold_counts) = measure(|| pool.reserve_permit(&node).unwrap());
    drop(cold);
    let (warm, warm_counts) = measure(|| pool.reserve_permit(&node).unwrap());
    let (refused, capacity_counts) = measure(|| pool.reserve_permit(&node));
    assert!(matches!(
        refused,
        Err(crate::error::ConnectError::AtCapacity(_))
    ));
    drop(warm);
    let (again, repeated) = measure(|| pool.reserve_permit(&node).unwrap());
    assert_eq!(warm_counts, repeated);
    drop(again);
    report("pool/reserve/cold", cold_counts);
    report("pool/reserve/warm", warm_counts);
    report("pool/reserve/capacity", capacity_counts);

    let enabled = ProxyPool::new(
        PoolConfig {
            enabled: true,
            ..PoolConfig::default()
        },
        Duration::from_secs(1),
        1,
    );
    drop(enabled.reserve_permit(&node).unwrap());
    let (miss, checkout_counts) = measure(|| enabled.checkout(&node));
    assert!(miss.is_none());
    let (permit, fallback_counts) = measure(|| {
        assert!(enabled.checkout(&node).is_none());
        enabled.reserve_permit(&node).unwrap()
    });
    drop(permit);
    report("pool/checkout/empty", checkout_counts);
    report("pool/checkout_then_reserve/warm", fallback_counts);
}

/// Lazy weighted order: snapshot consumes exactly N keys,
/// Arc configs materialize on consumption.
#[test]
fn perf208_lazy_weighted_order_end_to_end() {
    for size in [1usize, 8, 64, 256] {
        for budget in [1usize, 3, usize::MAX] {
            // Recreating the rotator resets the RNG (reseed happens only at
            // construction) — determinism across runs.
            let run = || {
                let rotator = seeded_rotator(size, 208);
                measure(|| {
                    let mut stream = rotator.pick_order_lazy();
                    let mut got = Vec::new();
                    for _ in 0..budget {
                        match stream.next_proxy() {
                            Some(p) => got.push(p),
                            None => break,
                        }
                    }
                    std::hint::black_box(&got);
                    got
                })
            };
            let (order, counts) = run();
            let (again, repeated) = run();
            // ProxyConfig lacks PartialEq — compare determinism by hosts.
            assert_eq!(
                order.iter().map(|p| p.host.clone()).collect::<Vec<_>>(),
                again.iter().map(|p| p.host.clone()).collect::<Vec<_>>()
            );
            assert_eq!(counts, repeated);
            // Snapshot consumed all N rating keys regardless of budget.
            assert_eq!(counts.weighted_keys, size as u64);
            assert_eq!(order.len(), size.min(budget));
            if budget == 1 && size == 256 {
                // Relative control: full path on the same input spends
                // more comparator comparisons than lazy consumption of 1 element.
                let rotator = seeded_rotator(size, 208);
                let (_, full) = measure(|| rotator.pick_order());
                assert!(counts.sort_comparisons < full.sort_comparisons);
            }
            report(
                &format!("weighted_lazy/n={size}/consumed={}", budget_label(budget)),
                counts,
            );
        }
    }
}

/// Rotator-level full control (full pick_order sort).
#[test]
fn perf208_full_pick_order_rotator_control() {
    for size in [1usize, 8, 64, 256] {
        // Recreating the rotator resets the RNG — determinism across runs.
        let run = || {
            let rotator = seeded_rotator(size, 208);
            measure(|| rotator.pick_order())
        };
        let (order, counts) = run();
        let (again, repeated) = run();
        assert_eq!(
            order.iter().map(|p| p.host.clone()).collect::<Vec<_>>(),
            again.iter().map(|p| p.host.clone()).collect::<Vec<_>>()
        );
        assert_eq!(counts, repeated);
        assert_eq!(counts.weighted_keys, size as u64);
        report(&format!("weighted_full/n={size}/full_sort_control"), counts);
    }
}

/// Test reference of the old eager path #208 for a fair total-cost A/B.
/// Verbatim replica of baseline `ChainPlan` (structures/allocation steps/
/// lifetime of returned picks); production path is `ChainPlan`. Only for
/// total-cost measurements; this code is not used in production.
#[derive(Clone)]
struct LegacyHop {
    // Read in baseline via pick.record_success (not measured) and the
    // Hop.clone in current_pick; derive(Clone) does not silence dead_code analysis.
    #[allow(dead_code)]
    rotator: Arc<ProxyRotator>,
    proxy: Arc<ProxyConfig>,
}
#[derive(Clone)]
struct LegacyCandidate {
    hop: LegacyHop,
    key: ChainKey,
}
struct LegacyLayer {
    candidates: Vec<LegacyCandidate>,
    // Replica of a baseline field (read in mark_dead, which is not measured).
    #[allow(dead_code)]
    live: usize,
    index: usize,
}
struct LegacyChainPick {
    // Replica of a baseline field (read in hops()/exit(); the returned pick
    // is created and dropped on every iteration — dealloc in the measurement).
    #[allow(dead_code)]
    hops: Vec<LegacyHop>,
    key: ChainKey,
}
struct LegacyChainPlan {
    layers: Vec<LegacyLayer>,
    seen: HashSet<ChainKey>,
    dead: HashSet<ChainKey>,
    done: bool,
    steps: u64,
}

impl LegacyChainPlan {
    /// Verbatim replica of baseline `ChainPlan::new`.
    fn legacy_new(gates: &GateLevels, exits: &[Arc<ProxyRotator>]) -> Self {
        let mut layers: Vec<_> = gates
            .iter()
            .map(|(_, rotator)| {
                let candidates = legacy_deduplicate(
                    rotator
                        .pick_order()
                        .into_iter()
                        .map(|proxy| (rotator.clone(), proxy)),
                );
                LegacyLayer {
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
                let key = legacy_singleton_key(&proxy);
                if keys.insert(key.clone()) {
                    candidates.push(LegacyCandidate {
                        hop: LegacyHop {
                            rotator: rotator.clone(),
                            proxy,
                        },
                        key,
                    });
                }
            }
        }
        let live = candidates.len();
        layers.push(LegacyLayer {
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
            steps: 0,
        }
    }

    /// Verbatim replica of baseline `ChainPlan::next_pick`: the basic IMMEDIATE
    /// advance after `current_pick` (old behavior, not the new need_advance).
    fn legacy_next_pick(&mut self) -> Option<LegacyChainPick> {
        while !self.done {
            self.legacy_count_step();
            let dead_layer = self
                .layers
                .iter()
                .position(|layer| self.dead.contains(&layer.candidates[layer.index].key));
            if let Some(index) = dead_layer {
                self.legacy_jump_subtree(index);
                continue;
            }
            let pick = self.legacy_current_pick();
            self.legacy_advance();
            if !self.seen.contains(&pick.key) {
                return Some(pick);
            }
        }
        None
    }

    fn legacy_count_step(&mut self) {
        self.steps += 1;
    }

    /// Verbatim replica of baseline `current_pick`: cloning BOTH Arc
    /// (`rotator` and `proxy`) of every `Hop` into a fresh Vec on each pick.
    fn legacy_current_pick(&self) -> LegacyChainPick {
        let hops: Vec<_> = self
            .layers
            .iter()
            .map(|layer| layer.candidates[layer.index].hop.clone())
            .collect();
        let key = ChainKey::new(Arc::new(
            ProxyConfig::chain(hops.iter().map(|hop| hop.proxy.clone()))
                .expect("layers are non-empty"),
        ));
        LegacyChainPick { hops, key }
    }

    /// Verbatim replica of baseline `advance`.
    fn legacy_advance(&mut self) {
        for layer in self.layers.iter_mut().rev() {
            layer.index += 1;
            if layer.index < layer.candidates.len() {
                return;
            }
            layer.index = 0;
        }
        self.done = true;
    }

    /// Verbatim replica of baseline `jump_subtree` (no-op in dead measurements —
    /// never fires; carried over for completeness).
    fn legacy_jump_subtree(&mut self, index: usize) {
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

/// Verbatim replica of baseline `deduplicate`.
fn legacy_deduplicate(
    candidates: impl IntoIterator<Item = (Arc<ProxyRotator>, Arc<ProxyConfig>)>,
) -> Vec<LegacyCandidate> {
    let mut seen = HashSet::new();
    candidates
        .into_iter()
        .filter_map(|(rotator, proxy)| {
            let key = legacy_singleton_key(&proxy);
            seen.insert(key.clone()).then_some(LegacyCandidate {
                hop: LegacyHop { rotator, proxy },
                key,
            })
        })
        .collect()
}

/// Verbatim replica of the old singleton_key from baseline (same instrumentation
/// config_clones).
fn legacy_singleton_key(proxy: &ProxyConfig) -> ChainKey {
    crate::perf::operation(|c| c.config_clones += 1);
    let mut plain = proxy.clone();
    plain.gate = None;
    ChainKey::new(Arc::new(plain))
}

/// Fair total-cost A/B: legacy eager path vs lazy ChainPlan on the same
/// inputs. The report orchestrator aggregates the numbers; no cross-test comparisons.
#[test]
fn perf208_chain_plan_legacy_total_cost() {
    let gates_default = GateLevels::default();
    // (A) exits-only: one layer, full size matrix.
    for size in [1usize, 8, 64, 256] {
        for budget in [1usize, 3, usize::MAX] {
            // Recreating the rotator resets the RNG — determinism across runs.
            let run = || {
                let exits = [seeded_rotator(size, 208)];
                measure(|| {
                    let mut plan = LegacyChainPlan::legacy_new(&gates_default, &exits);
                    let mut picks = 0usize;
                    while picks < budget {
                        match plan.legacy_next_pick() {
                            Some(pick) => {
                                std::hint::black_box(&pick);
                                picks += 1;
                            }
                            None => break,
                        }
                    }
                    std::hint::black_box(picks);
                    picks
                })
            };
            let (picks, counts) = run();
            let (again, repeated) = run();
            assert_eq!(picks, again);
            assert_eq!(counts, repeated);
            // Legacy's full pick_order always consumes all keys.
            assert_eq!(counts.weighted_keys, size as u64);
            report(
                &format!(
                    "chain_plan_legacy/n={size}/consumed={}",
                    budget_label(budget)
                ),
                counts,
            );
        }
    }

    // (B) Multilayer: 2 gate levels of 16 + exit 16, product 4096.
    for budget in [1usize, usize::MAX] {
        // Recreating the rotators resets the RNG — determinism.
        let run = || {
            let gates = GateLevels::new(vec![
                (2, seeded_ranked_rotator(16, 209, 2)),
                (1, seeded_ranked_rotator(16, 210, 1)),
            ]);
            let exits = [seeded_rotator(16, 211)];
            measure(|| {
                let mut plan = LegacyChainPlan::legacy_new(&gates, &exits);
                let mut picks = 0usize;
                while picks < budget {
                    match plan.legacy_next_pick() {
                        Some(pick) => {
                            std::hint::black_box(&pick);
                            picks += 1;
                        }
                        None => break,
                    }
                }
                std::hint::black_box(picks);
                picks
            })
        };
        let (picks, counts) = run();
        let (again, repeated) = run();
        assert_eq!(picks, again);
        assert_eq!(counts, repeated);
        if budget == usize::MAX {
            assert_eq!(picks, 16 * 16 * 16);
        }
        report(
            &format!(
                "chain_plan_legacy/gates2x16/consumed={}",
                budget_label(budget)
            ),
            counts,
        );
    }
}

/// Chains on the lazy path: candidates materialize as the odometer
/// advances, not all at once at plan construction.
#[test]
fn perf208_chain_plan_lazy_small_consumption_end_to_end() {
    // (A) exits-only: one layer, full size matrix.
    for size in [1usize, 8, 64, 256] {
        for budget in [1usize, 3, usize::MAX] {
            let gates = GateLevels::default();
            // Recreating the rotators resets the RNG — determinism.
            let run = || {
                let exits = [seeded_rotator(size, 208)];
                measure(|| {
                    let mut plan = ChainPlan::new(&gates, &exits);
                    let mut n = 0;
                    for _ in 0..budget {
                        if plan.next().is_none() {
                            break;
                        }
                        n += 1;
                    }
                    std::hint::black_box(n);
                    n
                })
            };
            let (picks, counts) = run();
            let (again, repeated) = run();
            assert_eq!(picks, again);
            assert_eq!(counts, repeated);
            // Each pick built a chain; a 1-layer plan has exactly one per pick.
            assert_eq!(counts.chain_builds, picks as u64);
            if budget == 1 && size == 256 {
                // The eager path materialized all 257 configs at once;
                // the lazy one builds a chain only for a single pick.
                assert!(counts.config_clones <= 4);
            }
            if budget == usize::MAX {
                // Full exhaustion: without duplicates all candidates are unique.
                assert_eq!(picks, size);
            }
            report(
                &format!("chain_plan/n={size}/consumed={}", budget_label(budget)),
                counts,
            );
        }
    }

    // (B) Multilayer: 2 gate levels of 16 + exit 16, product 4096.
    for budget in [1usize, usize::MAX] {
        // Recreating the rotators resets the RNG — determinism.
        let run = || {
            let gates = GateLevels::new(vec![
                (2, seeded_ranked_rotator(16, 209, 2)),
                (1, seeded_ranked_rotator(16, 210, 1)),
            ]);
            let exits = [seeded_rotator(16, 211)];
            measure(|| {
                let mut plan = ChainPlan::new(&gates, &exits);
                let mut n = 0;
                for _ in 0..budget {
                    if plan.next().is_none() {
                        break;
                    }
                    n += 1;
                }
                std::hint::black_box(n);
                n
            })
        };
        let (picks, counts) = run();
        let (again, repeated) = run();
        assert_eq!(picks, again);
        assert_eq!(counts, repeated);
        // Each pick built a chain; at full exhaustion the whole product
        // 16*16*16 without duplicates.
        assert!(counts.chain_builds >= picks as u64);
        if budget == usize::MAX {
            assert_eq!(picks, 16 * 16 * 16);
        }
        report(
            &format!("chain_plan/gates2x16/consumed={}", budget_label(budget)),
            counts,
        );
    }
}

/// Singleton-gates: control against lazy-ChainPlan regression
/// relative to faithful legacy on degenerate inputs (1 node per layer).
/// Goal — a singleton plan with no regression vs faithful legacy
/// (after removing singleton-plan overhead in chain/mod.rs).
#[test]
fn perf208_chain_plan_singleton_gates_no_regression() {
    // (A) App-style singleton gates: ranks 2/1/0, one node per layer.
    //    Fresh rotators per measurement — determinism (RNG resets).
    let mut first = (Counts::default(), Counts::default());
    for run_case in 0..2 {
        let gates = GateLevels::new(vec![
            (2, seeded_ranked_rotator(1, 209, 2)),
            (1, seeded_ranked_rotator(1, 210, 1)),
        ]);
        let exits = [seeded_rotator(1, 211)];
        // new: construction + one pick, as in existing chain_plan rows.
        let (picked_new, new) = measure(|| {
            let mut plan = ChainPlan::new(&gates, &exits);
            let got = plan.next().is_some();
            std::hint::black_box(got);
            got
        });
        // legacy: construction + one pick on the verbatim baseline replica.
        let (picked_legacy, legacy) = measure(|| {
            let mut plan = LegacyChainPlan::legacy_new(&gates, &exits);
            let got = plan.legacy_next_pick().is_some();
            std::hint::black_box(got);
            got
        });
        assert!(picked_new, "run={run_case}: new path must yield 1 pick");
        assert!(
            picked_legacy,
            "run={run_case}: legacy path must yield 1 pick"
        );
        // Comparison direction — "no worse than legacy": we do not weaken rows.
        assert!(
            new.alloc <= legacy.alloc,
            "run={run_case} {new:?} vs {legacy:?}"
        );
        assert!(
            new.realloc <= legacy.realloc,
            "run={run_case} {new:?} vs {legacy:?}"
        );
        assert!(
            new.requested_bytes <= legacy.requested_bytes,
            "run={run_case} {new:?} vs {legacy:?}"
        );
        assert!(
            new.sort_comparisons <= legacy.sort_comparisons,
            "run={run_case} {new:?} vs {legacy:?}"
        );
        assert!(
            new.config_clones <= legacy.config_clones,
            "run={run_case} {new:?} vs {legacy:?}"
        );
        assert_eq!(new.chain_builds, legacy.chain_builds);
        if run_case == 0 {
            first = (new, legacy);
            report("chain_plan/singleton_gates/consumed=1", new);
            report("chain_plan_legacy/singleton_gates/consumed=1", legacy);
        } else {
            // Determinism: double run of each side, equal Counts.
            assert_eq!(new, first.0);
            assert_eq!(legacy, first.1);
        }
    }

    // (B) Exits-only N=1: a single exit-rotator without gate layers (rank 0).
    //    No rows reported for block B: exactly 2 new rows — singleton_gates.
    let mut first_b = (Counts::default(), Counts::default());
    for run_case in 0..2 {
        let gates = GateLevels::default();
        let exits = [seeded_rotator(1, 208)];
        let (picked_new, new) = measure(|| {
            let mut plan = ChainPlan::new(&gates, &exits);
            let got = plan.next().is_some();
            std::hint::black_box(got);
            got
        });
        let (picked_legacy, legacy) = measure(|| {
            let mut plan = LegacyChainPlan::legacy_new(&gates, &exits);
            let got = plan.legacy_next_pick().is_some();
            std::hint::black_box(got);
            got
        });
        assert!(picked_new, "run={run_case}: new path must yield 1 pick");
        assert!(
            picked_legacy,
            "run={run_case}: legacy path must yield 1 pick"
        );
        assert!(
            new.alloc <= legacy.alloc,
            "run={run_case} {new:?} vs {legacy:?}"
        );
        assert!(
            new.realloc <= legacy.realloc,
            "run={run_case} {new:?} vs {legacy:?}"
        );
        assert!(
            new.requested_bytes <= legacy.requested_bytes,
            "run={run_case} {new:?} vs {legacy:?}"
        );
        assert!(
            new.sort_comparisons <= legacy.sort_comparisons,
            "run={run_case} {new:?} vs {legacy:?}"
        );
        assert!(
            new.config_clones <= legacy.config_clones,
            "run={run_case} {new:?} vs {legacy:?}"
        );
        assert_eq!(new.chain_builds, legacy.chain_builds);
        if run_case == 0 {
            first_b = (new, legacy);
        } else {
            // Determinism: double run of each side, equal Counts.
            assert_eq!(new, first_b.0);
            assert_eq!(legacy, first_b.1);
        }
    }
}
