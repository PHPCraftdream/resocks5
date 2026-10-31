use super::dial::*;
use super::route::*;
use super::tests_unit::{socks5_config, spawn_socks5_stub, test_logger};
use crate::config::NetworkConfig;
use regex::RegexSet;
use resocks5_net::pool::ProxyPool;
use resocks5_net::rating::QuarantinePolicy;
use resocks5_net::rotator::ProxyRotator;
use resocks5_net::types::ProxyProtocol;
use resocks5_net::{ConnectError, ProtocolViolation, Stage, TimeoutKind};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

fn timeout(stage: Stage, kind: TimeoutKind) -> ConnectError {
    ConnectError::Timeout {
        stage,
        kind,
        endpoint: "203.0.113.1:1080".to_string(),
        after: Duration::from_secs(10),
    }
}

fn io(stage: Stage) -> ConnectError {
    ConnectError::Io {
        stage,
        endpoint: None,
        source: std::io::Error::from(std::io::ErrorKind::ConnectionRefused),
    }
}

fn hard(err: ConnectError) -> bool {
    is_hard_failure(&anyhow::Error::new(err))
}

#[test]
fn upstream_down_signals_are_hard_failures() {
    assert!(hard(timeout(Stage::Connect, TimeoutKind::TcpConnect)));
    assert!(hard(timeout(
        Stage::Handshake,
        TimeoutKind::HttpsTlsHandshake
    )));
    assert!(hard(io(Stage::Connect)));
    assert!(hard(ConnectError::AuthFailed { status: 1 }));
    assert!(hard(ConnectError::MethodUnsupported {
        got: 0xff,
        with_auth: false
    }));
    assert!(hard(ConnectError::Protocol(
        ProtocolViolation::Socks5BadVersion { got: 4 }
    )));
    assert!(hard(ConnectError::Tls {
        message: "tls".to_string(),
        source: None
    }));
}

#[test]
fn target_side_or_ambiguous_failures_are_not_hard() {
    // A stalled or refused CONNECT looks the same for a dead destination.
    assert!(!hard(timeout(
        Stage::Handshake,
        TimeoutKind::Socks5Handshake
    )));
    assert!(!hard(timeout(Stage::Handshake, TimeoutKind::HttpHandshake)));
    assert!(!hard(timeout(
        Stage::Handshake,
        TimeoutKind::HttpsConnectHandshake
    )));
    assert!(!hard(io(Stage::Handshake)));
    assert!(!hard(ConnectError::ProxyRejected {
        protocol: ProxyProtocol::Socks5,
        code: Some(5),
        response: String::new()
    }));
    assert!(!hard(ConnectError::Protocol(
        ProtocolViolation::HttpClosedEarly
    )));
    assert!(!hard(ConnectError::InvalidTarget("x".to_string())));
    assert!(!is_hard_failure(&anyhow::anyhow!("something else")));
}

#[test]
fn classification_sees_through_gate_stage_context() {
    let err = anyhow::Error::new(io(Stage::Connect)).context(GateStage::GateConnect);
    assert!(is_hard_failure(&err));
}

#[tokio::test]
async fn dead_upstream_is_quarantined_and_requests_keep_succeeding() {
    let logger = test_logger();
    let banned = Arc::new(RegexSet::empty());
    let pool = Arc::new(ProxyPool::new(
        Default::default(),
        Duration::from_secs(2),
        4,
    ));
    let network = Arc::new(NetworkConfig {
        handshake_timeout_sec: 2,
        ..Default::default()
    });
    // Port 0 is refused immediately everywhere.
    let dead = socks5_config(SocketAddr::from(([127, 0, 0, 1], 0)), false);
    let live = socks5_config(spawn_socks5_stub().await, false);
    let v4 = Arc::new(
        ProxyRotator::try_with_quarantine(
            vec![dead.clone(), live.clone()],
            Default::default(),
            QuarantinePolicy::default().with_threshold(2),
            16,
            Duration::from_secs(60),
        )
        .unwrap(),
    );

    // A distinct target per request: a success links the target to its
    // upstream in the sticky cache and the next call would skip the walk.
    let mut quarantined = false;
    for i in 0..80 {
        let target = format!("t{i}.example.com:443");
        let stream = establish_connection(
            &target,
            &None,
            &None,
            &Some(v4.clone()),
            &logger,
            &banned,
            &pool,
            &network,
            None,
            None,
        )
        .await
        .expect("a live upstream exists, so the request must succeed");
        drop(stream);
        if v4.is_quarantined(&dead) {
            quarantined = true;
            break;
        }
    }
    assert!(quarantined, "dead upstream was never quarantined");
    assert!(!v4.is_quarantined(&live));

    // From now on the dead upstream is not even in the order.
    for _ in 0..50 {
        let order = v4.pick_order();
        assert_eq!(order.len(), 1);
        assert_eq!(order[0].port, live.port);
    }
    for i in 0..10 {
        let target = format!("after{i}.example.com:443");
        drop(
            establish_connection(
                &target,
                &None,
                &None,
                &Some(v4.clone()),
                &logger,
                &banned,
                &pool,
                &network,
                None,
                None,
            )
            .await
            .expect("still served by the live upstream"),
        );
    }
}
