use super::{singleton_key, ChainPlan, GateLevels};
use crate::connect::ChainStage;
use crate::error::{ConnectError, ProtocolViolation, Stage, TimeoutKind};
use crate::rating::{QuarantinePolicy, RatingPolicy};
use crate::rotator::ProxyRotator;
use crate::types::ProxyConfig;
use std::sync::Arc;
use std::time::Duration;

const QUARANTINE: Duration = Duration::from_secs(30);

fn p(host: &str) -> ProxyConfig {
    ProxyConfig::socks5(host, 1080)
}

fn r(host: &str) -> Arc<ProxyRotator> {
    Arc::new(
        ProxyRotator::try_with_quarantine(
            vec![p(host)],
            RatingPolicy::default(),
            QuarantinePolicy::default().with_threshold(1),
            16,
            Duration::from_secs(60),
        )
        .unwrap(),
    )
}

struct Fixture {
    plan: ChainPlan,
    rotators: [Arc<ProxyRotator>; 3],
}

fn fixture() -> Fixture {
    let rotators = [r("g0"), r("g1"), r("exit")];
    let gates = GateLevels::new(vec![(2, rotators[0].clone()), (1, rotators[1].clone())]);
    let plan = ChainPlan::new(&gates, &[rotators[2].clone()]);
    Fixture { plan, rotators }
}

fn err(kind: ErrorKind) -> ConnectError {
    match kind {
        ErrorKind::Connect => ConnectError::Timeout {
            stage: Stage::Connect,
            kind: TimeoutKind::TcpConnect,
            endpoint: "proxy:1080".into(),
            after: Duration::from_secs(1),
        },
        ErrorKind::Timeout => ConnectError::Timeout {
            stage: Stage::Handshake,
            kind: TimeoutKind::Socks5Handshake,
            endpoint: "proxy:1080".into(),
            after: Duration::from_secs(1),
        },
        ErrorKind::Auth => ConnectError::AuthFailed { status: 1 },
        ErrorKind::Protocol => {
            ConnectError::Protocol(ProtocolViolation::Socks5BadVersion { got: 4 })
        }
        ErrorKind::Rejected => ConnectError::ProxyRejected {
            protocol: crate::types::ProxyProtocol::Socks5,
            code: Some(5),
            response: String::new(),
        },
        ErrorKind::Io => ConnectError::Io {
            stage: Stage::Handshake,
            endpoint: None,
            source: std::io::Error::other("handshake"),
        },
    }
}

#[derive(Clone, Copy)]
enum ErrorKind {
    Connect,
    Timeout,
    Auth,
    Protocol,
    Rejected,
    Io,
}

fn assert_dead(plan: &ChainPlan, expected: &[usize], nodes: &[ProxyConfig; 3]) {
    let actual: Vec<_> = plan.dead.iter().cloned().collect();
    assert_eq!(actual.len(), expected.len());
    for &i in expected {
        assert!(actual.contains(&singleton_key(&Arc::new(nodes[i].clone()))));
    }
}

fn nodes() -> [ProxyConfig; 3] {
    [p("g0"), p("g1"), p("exit")]
}

fn exercise(
    stage: ChainStage,
    kind: ErrorKind,
    expected_dead: Option<usize>,
    expected_quarantine: Option<usize>,
) {
    let mut f = fixture();
    let pick = f.plan.next().unwrap();
    let nodes = nodes();
    let result = f.plan.record_failure_inner(&pick, stage, &err(kind));
    let quarantined: Vec<_> = f
        .rotators
        .iter()
        .enumerate()
        .filter_map(|(i, rotator)| rotator.is_quarantined(&nodes[i]).then_some(i))
        .collect();
    assert_eq!(
        quarantined,
        expected_quarantine.into_iter().collect::<Vec<_>>()
    );
    assert_dead(
        &f.plan,
        &expected_dead.into_iter().collect::<Vec<_>>(),
        &nodes,
    );
    match expected_quarantine {
        Some(blamed) => {
            assert_eq!(result.len(), 1);
            assert_eq!(result[0].length, QUARANTINE);
            assert_eq!(
                singleton_key(&result[0].proxy),
                singleton_key(&Arc::new(nodes[blamed].clone()))
            );
        }
        None => assert!(result.is_empty()),
    }
}

#[test]
fn accounting_matrix_attributes_failures_exactly() {
    let hard = |kind: ErrorKind| {
        matches!(
            kind,
            ErrorKind::Connect | ErrorKind::Auth | ErrorKind::Protocol
        )
    };
    let kinds = [
        ErrorKind::Connect,
        ErrorKind::Timeout,
        ErrorKind::Auth,
        ErrorKind::Protocol,
        ErrorKind::Rejected,
        ErrorKind::Io,
    ];
    for kind in kinds {
        exercise(ChainStage::Connect, kind, Some(0), hard(kind).then_some(0));
        for (stage, node) in [
            (ChainStage::Hop(0), 0),
            (ChainStage::Hop(1), 1),
            (ChainStage::Target, 2),
        ] {
            let dead = match stage {
                ChainStage::Hop(_) => hard(kind).then_some(node),
                ChainStage::Target => Some(node),
                _ => unreachable!(),
            };
            let quarantine = match stage {
                ChainStage::Hop(_) => hard(kind).then_some(node),
                ChainStage::Target => hard(kind).then_some(node),
                _ => unreachable!(),
            };
            exercise(stage, kind, dead, quarantine);
        }
    }
}

#[test]
fn invalid_hop_index_is_soft_for_all_hops() {
    let mut f = fixture();
    let pick = f.plan.next().unwrap();
    assert!(f
        .plan
        .record_failure_inner(
            &pick,
            ChainStage::Hop(usize::MAX),
            &err(ErrorKind::Protocol)
        )
        .is_empty());
    assert!(f
        .rotators
        .iter()
        .zip(nodes().iter())
        .all(|(r, p)| !r.is_quarantined(p)));
    assert_dead(&f.plan, &[], &nodes());
}

#[test]
fn success_clears_quarantine_on_every_selected_hop() {
    let mut f = fixture();
    let pick = f.plan.next().unwrap();
    for (rotator, proxy) in f.rotators.iter().zip(nodes().iter()) {
        assert_eq!(rotator.record_hard_failure(proxy), Some(QUARANTINE));
        assert!(rotator.is_quarantined(proxy));
    }
    f.plan.record_success(&pick);
    assert!(f
        .rotators
        .iter()
        .zip(nodes().iter())
        .all(|(r, p)| !r.is_quarantined(p)));
}

#[test]
fn rotator_quarantine_changes_new_plan_but_not_existing_snapshot_until_dead_marked() {
    let multi = Arc::new(
        ProxyRotator::try_with_quarantine(
            vec![p("bad"), p("healthy")],
            RatingPolicy::default(),
            QuarantinePolicy::default().with_threshold(1),
            16,
            Duration::from_secs(60),
        )
        .unwrap(),
    );
    let mut original = ChainPlan::new(&GateLevels::default(), std::slice::from_ref(&multi));
    let mut pruned = ChainPlan::new(&GateLevels::default(), std::slice::from_ref(&multi));
    multi.record_hard_failure(&p("bad"));
    assert!(multi.is_quarantined(&p("bad")));
    let mut fresh = ChainPlan::new(&GateLevels::default(), std::slice::from_ref(&multi));
    let fresh_hosts: Vec<_> = std::iter::from_fn(|| fresh.next())
        .map(|pick| pick.exit().proxy.host.clone())
        .collect();
    assert_eq!(fresh_hosts, vec!["healthy"]);
    let original_hosts: std::collections::HashSet<String> = std::iter::from_fn(|| original.next())
        .map(|pick| pick.exit().proxy.host.clone())
        .collect();
    assert_eq!(
        original_hosts,
        std::collections::HashSet::from(["bad".to_owned(), "healthy".to_owned()])
    );
    pruned.mark_dead(&p("bad"));
    let pruned_hosts: Vec<_> = std::iter::from_fn(|| pruned.next())
        .map(|pick| pick.exit().proxy.host.clone())
        .collect();
    assert_eq!(pruned_hosts, vec!["healthy"]);
}

#[cfg(feature = "pool")]
#[test]
fn at_capacity_never_changes_accounting() {
    // AtCapacity is a non-upstream error: classification occurs before stage attribution.
    let capacity = ConnectError::AtCapacity(crate::pool::AtCapacity {
        host: "proxy".into(),
        port: 1080,
    });
    for stage in [
        ChainStage::Connect,
        ChainStage::Hop(0),
        ChainStage::Hop(1),
        ChainStage::Target,
    ] {
        let mut f = fixture();
        let pick = f.plan.next().unwrap();
        assert!(f
            .plan
            .record_failure_inner(&pick, stage, &capacity)
            .is_empty());
        assert!(f
            .rotators
            .iter()
            .zip(nodes().iter())
            .all(|(r, p)| !r.is_quarantined(p)));
        assert_dead(&f.plan, &[], &nodes());
    }
}
