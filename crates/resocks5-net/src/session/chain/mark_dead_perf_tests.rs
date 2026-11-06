//! Детерминированные PERF208-сценарии смерти кандидатов и singleton-слоёв.

use std::sync::Arc;
use std::time::Duration;

use crate::chain::{ChainPlan, GateLevels};
use crate::perf::{measure, report};
use crate::rating::{QuarantinePolicy, RatingPolicy};
use crate::rotator::{same_upstream, ProxyRotator};
use crate::types::ProxyConfig;

fn p(id: usize) -> ProxyConfig {
    ProxyConfig::socks5(format!("perf-mark-{id}.invalid"), 1080)
}

fn rotator(proxies: Vec<ProxyConfig>) -> Arc<ProxyRotator> {
    Arc::new(
        ProxyRotator::with_rng_seed(
            proxies,
            RatingPolicy::default(),
            QuarantinePolicy::disabled(),
            16,
            Duration::from_secs(60),
            208,
        )
        .unwrap(),
    )
}

fn gate_levels(levels: usize, width: usize) -> GateLevels {
    GateLevels::new(
        (0..levels)
            .map(|level| {
                let rank = (levels - level) as u8;
                let proxies = (0..width)
                    .map(|candidate| p(10_000 + level * 1_000 + candidate).with_gate_level(rank))
                    .collect();
                (rank, rotator(proxies))
            })
            .collect(),
    )
}

#[test]
fn perf208_mark_dead_layered_repeated_pruning_and_exhaustion() {
    for (levels, width) in [(1usize, 2usize), (3, 8), (8, 64)] {
        let gates = gate_levels(levels, width);
        let exits = [rotator((0..width).map(|i| p(100_000 + i)).collect())];
        let mut plan = ChainPlan::new(&gates, &exits);
        let first = plan.next().expect("configured plan has a candidate");
        let dead_gate = first.hops()[0].proxy.as_ref().clone();
        let dead_exit = p(100_000);

        let (_, gate_death) = measure(|| plan.mark_dead(&dead_gate));
        let (_, gate_repeat) = measure(|| plan.mark_dead(&dead_gate));
        let (_, exit_death) = measure(|| plan.mark_dead(&dead_exit));
        let absent_gate = p(999_999).with_gate_level(dead_gate.gate_level);
        let (_, absent_gate_counts) = measure(|| plan.mark_dead(&absent_gate));
        let absent_exit = p(999_998);
        let (_, absent_exit_counts) = measure(|| plan.mark_dead(&absent_exit));
        assert_eq!(gate_death.mark_dead_calls, 1);
        assert_eq!(gate_death.mark_dead_layer_visits, (levels + 1) as u64);
        assert_eq!(gate_death.mark_dead_cursor_visits, (levels + 1) as u64);
        assert_eq!(gate_death.mark_dead_index_lookups, (levels + 1) as u64);
        assert!(gate_death.mark_dead_eligible_checks <= width as u64);
        assert_eq!(
            gate_repeat.alloc + gate_repeat.alloc_zeroed + gate_repeat.realloc,
            2
        );
        assert_eq!(gate_repeat.config_clones, 1);
        assert_eq!(gate_repeat.mark_dead_layer_visits, 0);
        assert_eq!(gate_repeat.mark_dead_cursor_visits, 0);
        assert_eq!(gate_repeat.mark_dead_index_lookups, 0);
        assert_eq!(exit_death.mark_dead_layer_visits, (levels + 1) as u64);
        assert!(exit_death.mark_dead_cursor_visits > 0);
        assert!(exit_death.mark_dead_index_lookups > 0);
        assert!(exit_death.mark_dead_eligible_checks > 0);
        assert_eq!(exit_death.mark_dead_layer_visits, (levels + 1) as u64);
        assert_eq!(absent_gate_counts.mark_dead_eligible_checks, 0);
        assert_eq!(absent_exit_counts.mark_dead_eligible_checks, 0);

        // Оставляем план частично живым: размерные случаи не перечисляют декартово произведение.
        let mut sampled = Vec::new();
        let ((), prune_steps) = measure(|| {
            for _ in 0..width.min(8) {
                match plan.next() {
                    Some(pick) => sampled.push(pick),
                    None => break,
                }
            }
        });
        assert!(!sampled.is_empty(), "partial deaths must retain candidates");
        assert!(sampled.iter().all(|pick| pick.hops().iter().all(|hop| {
            !same_upstream(&hop.proxy, &dead_gate) && !same_upstream(&hop.proxy, &dead_exit)
        })));
        assert!(prune_steps.chain_plan_steps <= width.min(8) as u64 + 3);
        report(
            &format!("mark_dead/layers={levels}/width={width}/gate"),
            gate_death,
        );
        report(
            &format!("mark_dead/layers={levels}/width={width}/repeat"),
            gate_repeat,
        );
        report(
            &format!("mark_dead/layers={levels}/width={width}/exit"),
            exit_death,
        );
        report(
            &format!("mark_dead/layers={levels}/width={width}/absent-gate"),
            absent_gate_counts,
        );
        report(
            &format!("mark_dead/layers={levels}/width={width}/absent-exit"),
            absent_exit_counts,
        );
        report(
            &format!("mark_dead/layers={levels}/width={width}/prune"),
            prune_steps,
        );
    }

    // Полный небольшой план закрепляет отвод одометра после частичной смерти и после исключения.
    let gates = gate_levels(3, 2);
    let exits = [rotator(vec![p(200_000), p(200_001)])];
    let mut prune = ChainPlan::new(&gates, &exits);
    let first = prune.next().expect("configured plan has a candidate");
    let excluded_key = first.key();
    let first_gate = first.hops()[0].proxy.clone();
    prune.exclude(&excluded_key);
    let (_, gate_death) = measure(|| prune.mark_dead(&first_gate));
    let (remaining, reset) = measure(|| prune.by_ref().collect::<Vec<_>>());
    assert_eq!(remaining.len(), 8);
    let remaining_keys: std::collections::HashSet<_> =
        remaining.iter().map(|pick| pick.key()).collect();
    assert_eq!(remaining_keys.len(), 8);
    assert!(remaining.iter().all(|pick| pick
        .hops()
        .iter()
        .all(|hop| { !same_upstream(&hop.proxy, &first_gate) })));
    assert!(reset.chain_plan_steps <= 12);
    report("mark_dead/reset-excluded/layers=3/width=2", reset);
    report("mark_dead/reset-gate", gate_death);

    let mut excluded_only = ChainPlan::new(&gates, &exits);
    let not_emitted = excluded_only.next().expect("exclusion fixture").key();
    excluded_only.need_advance = false;
    excluded_only.exclude(&not_emitted);
    let (after_exclusion, exclusion_work) = measure(|| excluded_only.by_ref().collect::<Vec<_>>());
    assert_eq!(after_exclusion.len(), 15);
    assert!(!after_exclusion.iter().any(|pick| pick.key() == not_emitted));
    assert_eq!(exclusion_work.chain_plan_steps, 17);
    report("mark_dead/exclude-only-control", exclusion_work);

    let mut exhausted = ChainPlan::new(&gates, &exits);
    let _first = exhausted.next().expect("configured plan has a candidate");
    let ((), death_a) = measure(|| exhausted.mark_dead(&p(200_000)));
    let ((), death_b) = measure(|| exhausted.mark_dead(&p(200_001)));
    assert_eq!(death_a.mark_dead_layer_visits, 4);
    assert_eq!(death_b.mark_dead_layer_visits, 4);
    let (end, no_sweep) = measure(|| exhausted.next());
    assert!(end.is_none());
    assert_eq!(no_sweep.chain_plan_steps, 0);
    report("mark_dead/exhausted-exit/layers=3/width=2", no_sweep);
}

fn exit_rotators(size: usize, overlap: bool) -> Vec<Arc<ProxyRotator>> {
    (0..size)
        .map(|i| rotator(vec![p(if overlap { 300_000 } else { 300_000 + i })]))
        .collect()
}

#[test]
fn perf208_singleton_exit_scaling_boundary_and_owner() {
    for size in [2usize, 3, 8, 64, 256] {
        for overlap in [false, true] {
            // Фикстуры исключены из measured construction.
            let exits = exit_rotators(size, overlap);
            let gates = GateLevels::default();
            let (plan, construction) = measure(|| ChainPlan::new(&gates, &exits));
            let unique = if overlap { 1 } else { size };
            assert_eq!(plan.layers[0].live, unique);
            assert_eq!(
                construction.singleton_cursor_candidates,
                if size > 2 { size as u64 } else { 0 }
            );
            assert_eq!(
                construction.singleton_candidates_inserted,
                if size <= 2 { unique as u64 } else { 0 }
            );
            assert_eq!(
                construction.singleton_candidates_skipped,
                if size <= 2 { (size - unique) as u64 } else { 0 }
            );
            assert_eq!(construction.singleton_emitted_inserts, 0);

            // Независимый oracle считает фактические identity comparisons reference-eager пути.
            let mut reference_comparisons = 0u64;
            let mut owners: Vec<&ProxyConfig> = Vec::new();
            for exit in &exits {
                let proxy = &exit.all_proxies()[0];
                let mut duplicate = false;
                for owner in &owners {
                    reference_comparisons += 1;
                    if same_upstream(owner, proxy) {
                        duplicate = true;
                        break;
                    }
                }
                if !duplicate {
                    owners.push(proxy);
                }
            }
            let expected_reference = if overlap {
                size as u64 - 1
            } else {
                size as u64 * (size as u64 - 1) / 2
            };
            assert_eq!(reference_comparisons, expected_reference);
            assert_eq!(owners.len(), unique);

            if size <= 2 {
                assert_eq!(
                    construction.singleton_dedup_comparisons,
                    reference_comparisons
                );
                assert_eq!(construction.singleton_cursor_candidates, 0);
            } else {
                assert_eq!(construction.singleton_candidates_inserted, 0);
                if overlap {
                    assert_eq!(construction.singleton_cursor_comparisons, size as u64 - 1);
                } else {
                    assert!(construction.singleton_cursor_comparisons <= size as u64);
                }
                assert_eq!(construction.singleton_emitted_inserts, 0);
            }
            if size >= 8 && !overlap {
                assert!(reference_comparisons > size as u64 * 2);
                assert!(construction.singleton_cursor_comparisons < reference_comparisons);
            }

            let mut plan = plan;
            let mut all_plan = ChainPlan::new(&gates, &exits);
            let (all, all_counts) = measure(|| all_plan.by_ref().collect::<Vec<_>>());
            assert_eq!(all.len(), unique);
            for (index, pick) in all.iter().enumerate() {
                let owner = if overlap { 0 } else { index };
                assert!(Arc::ptr_eq(&pick.exit().rotator, &exits[owner]));
                assert!(same_upstream(
                    &pick.exit().proxy,
                    &exits[owner].all_proxies()[0]
                ));
            }
            assert_eq!(
                all_counts.singleton_emitted_duplicates,
                if overlap && size > 2 {
                    size as u64 - 1
                } else {
                    0
                }
            );
            let (first, first_work) = measure(|| plan.next().expect("first exit candidate"));
            assert!(Arc::ptr_eq(&first.exit().rotator, &exits[0]));
            assert_eq!(first.exit().proxy.host, exits[0].all_proxies()[0].host);
            assert_eq!(
                first_work.singleton_emitted_inserts,
                if size <= 2 { 0 } else { 1 }
            );
            if size > 2 {
                assert!(first_work.alloc + first_work.alloc_zeroed + first_work.realloc > 0);
            }
            let ((), death) = measure(|| plan.mark_dead(&first.exit().proxy));
            assert_eq!(death.mark_dead_calls, 1);
            assert_eq!(death.mark_dead_layer_visits, 1);
            assert!(death.alloc + death.alloc_zeroed + death.realloc > 0);
            if size <= 2 {
                assert_eq!(death.mark_dead_membership_checks, 1);
            } else {
                assert!(death.mark_dead_index_lookups > 0);
            }
            let (_, repeat) = measure(|| plan.mark_dead(&first.exit().proxy));
            assert_eq!(repeat.mark_dead_calls, 1);
            assert_eq!(repeat.mark_dead_layer_visits, 0);
            let (remaining, rest_counts) = measure(|| plan.by_ref().count());
            assert_eq!(remaining, if overlap { 0 } else { size - 1 });
            assert_eq!(rest_counts.singleton_emitted_duplicates, 0);

            let label = format!("singleton-exits/r={size}/overlap={overlap}");
            let mut late_plan = ChainPlan::new(&gates, &exits);
            let (_, late) = measure(|| late_plan.mark_dead(&exits[size - 1].all_proxies()[0]));
            if size > 2 {
                assert_eq!(
                    late.mark_dead_index_lookups,
                    if overlap { 1 } else { size as u64 }
                );
                assert_eq!(late.mark_dead_eligible_checks, 1);
            } else {
                assert_eq!(
                    late.mark_dead_membership_checks,
                    if overlap { 1 } else { 2 }
                );
            }
            report(&format!("{label}/late-owner"), late);
            report(&format!("{label}/construction"), construction);
            report(&format!("{label}/first-owner"), first_work);
            report(&format!("{label}/all-drain"), all_counts);
            report(&format!("{label}/mark_dead"), death);
            report(&format!("{label}/repeat"), repeat);
            report(&format!("{label}/after-death"), rest_counts);
        }
    }
}
