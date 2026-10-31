use super::tests_chains::*;
use crate::logger::LogConfig;
use resocks5_net::pool::ProxyPool;
use resocks5_net::rating::{QuarantinePolicy, RatingPolicy};
use resocks5_net::rotator::ProxyRotator;
use resocks5_net::types::ProxyConfig;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;
use tokio::time::timeout;

#[tokio::test]
async fn dead_chain_node_alternatives_and_quarantine_by_position() {
    let ranks = [3, 2, 1, 0];
    for failed in 0..4 {
        let (tx, _rx) = mpsc::channel(128);
        let mut healthy = Vec::new();
        for _ in 0..8 {
            healthy.push(spawn_stub(tx.clone()).await);
        }
        let refusing = spawn_refusing_stub().await;
        let (target, target_task) = echo_target().await;
        let target_key = format!("{}:{}", target.ip(), target.port());

        let mut rotators = Vec::new();
        for level in 0..4 {
            let primary = config(healthy[level].addr, ranks[level]);
            let secondary = config(healthy[4 + level].addr, ranks[level]);
            let configs = if level == failed {
                vec![primary, config(refusing.addr, ranks[level])]
            } else {
                vec![primary, secondary]
            };
            rotators.push(Arc::new(
                ProxyRotator::try_with_quarantine(
                    configs,
                    RatingPolicy::default(),
                    QuarantinePolicy::default()
                        .with_threshold(1)
                        .with_initial(Duration::from_millis(200))
                        .with_max(Duration::from_millis(200)),
                    8,
                    Duration::from_secs(60),
                )
                .unwrap(),
            ));
        }
        let gates = Arc::new(resocks5_net::chain::GateLevels::new(
            (0..3)
                .map(|level| (ranks[level], rotators[level].clone()))
                .collect(),
        ));
        let exits = rotators[3].clone();
        let initial_nodes: Vec<_> = (0..4)
            .map(|level| {
                Arc::new(if level == failed {
                    config(refusing.addr, ranks[level])
                } else {
                    config(healthy[level].addr, ranks[level])
                })
            })
            .collect();
        exits.link_proxy(
            target_key.clone(),
            Arc::new(ProxyConfig::chain(initial_nodes).unwrap()),
        );
        let pool = Arc::new(ProxyPool::new(
            Default::default(),
            Duration::from_secs(3),
            16,
        ));
        let (mut stream, mut logs) = timeout(
            Duration::from_secs(8),
            connect_echo(
                &gates,
                &exits,
                &pool,
                target,
                LogConfig {
                    attempts: true,
                    ..Default::default()
                },
            ),
        )
        .await
        .unwrap();
        stream.write_all(b"marker!").await.unwrap();
        let mut echoed = [0; 7];
        timeout(Duration::from_secs(4), stream.read_exact(&mut echoed))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&echoed, b"marker!");

        let replacement = exits.get_linked(&target_key).unwrap();
        let replacement_nodes = replacement.chain_nodes();
        assert_eq!(replacement_nodes.len(), 4);
        assert_ne!(replacement_nodes[failed].port, refusing.addr.port());
        assert!(rotators[failed].is_quarantined(&config(refusing.addr, ranks[failed])));
        for level in 0..3 {
            assert!(!rotators[level].is_quarantined(&config(healthy[level].addr, ranks[level])));
        }
        assert!(!rotators[3].is_quarantined(&config(healthy[3].addr, ranks[3])));
        let mut attempts = 0;
        while let Ok(event) = logs.try_recv() {
            if let crate::logger::ELog::Log(line) = event {
                if line.contains("attempt target=") {
                    attempts += 1;
                }
            }
        }
        assert!(
            attempts <= crate::config::NetworkConfig::default().max_upstream_attempts,
            "attempt logs exceeded configured budget: {attempts}"
        );
        drop(stream);
        target_task.abort();
    }
}

#[tokio::test]
async fn one_level_gate_is_logged_as_gate_path() {
    let (tx, _rx) = mpsc::channel(8);
    let gate = spawn_stub(tx.clone()).await;
    let exit = spawn_stub(tx).await;
    let (target, task) = echo_target().await;
    let gates = Arc::new(resocks5_net::chain::GateLevels::new(vec![(
        1,
        Arc::new(ProxyRotator::new(vec![config(gate.addr, 1)])),
    )]));
    let exits = Arc::new(ProxyRotator::new(vec![ProxyConfig::socks5(
        exit.addr.ip().to_string(),
        exit.addr.port(),
    )]));
    let pool = Arc::new(ProxyPool::new(
        Default::default(),
        Duration::from_secs(3),
        8,
    ));
    let key = format!("{}:{}", target.ip(), target.port());
    let (mut stream, mut logs) = timeout(
        Duration::from_secs(5),
        connect_echo(
            &gates,
            &exits,
            &pool,
            target,
            LogConfig {
                attempts: true,
                ..Default::default()
            },
        ),
    )
    .await
    .unwrap();
    stream.write_all(b"marker!").await.unwrap();
    let mut echo = [0; 7];
    timeout(Duration::from_secs(3), stream.read_exact(&mut echo))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&echo, b"marker!");
    let entry = timeout(Duration::from_secs(3), logs.recv())
        .await
        .unwrap()
        .unwrap();
    assert!(
        matches!(entry,crate::logger::ELog::Log(ref s) if s.contains("path=gate")&&s.contains(&format!("gate={}",crate::server::print_cfg(&config(gate.addr,1)))))
    );
    let cached = exits.get_linked(&key).unwrap();
    assert_eq!(cached.chain_nodes().len(), 2);
    assert_eq!(cached.chain_nodes()[0].host, gate.addr.ip().to_string());
    assert_eq!(cached.chain_nodes()[0].port, gate.addr.port());
    assert_eq!(cached.chain_nodes()[1].host, exit.addr.ip().to_string());
    assert_eq!(cached.chain_nodes()[1].port, exit.addr.port());
    task.abort();
}
