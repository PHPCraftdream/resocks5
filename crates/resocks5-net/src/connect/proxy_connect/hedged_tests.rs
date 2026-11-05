use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio::task::{JoinHandle, JoinSet};

use super::*;
use crate::pool::{PoolConfig, ProxyPool};
use crate::types::ProxyConfig;

pub(super) fn proxy(host: impl Into<String>, port: u16) -> Arc<ProxyConfig> {
    Arc::new(ProxyConfig::socks5(host, port))
}

pub(super) fn pool(connect_timeout: Duration) -> Arc<ProxyPool> {
    Arc::new(ProxyPool::new(PoolConfig::default(), connect_timeout, 8))
}

pub(super) fn opts(delay: Duration) -> HedgeOptions {
    HedgeOptions::default()
        .with_hedge_delay(delay)
        .with_handshake_timeout(Duration::from_secs(2))
}

pub(super) async fn loopback() -> (TcpListener, Arc<ProxyConfig>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    (listener, proxy(addr.ip().to_string(), addr.port()))
}

async fn read_request(stream: &mut TcpStream) {
    let mut greeting = [0; 3];
    stream.read_exact(&mut greeting).await.unwrap();
    assert_eq!(greeting, [5, 1, 0]);
    stream.write_all(&[5, 0]).await.unwrap();
    let mut head = [0; 4];
    stream.read_exact(&mut head).await.unwrap();
    let rest = match head[3] {
        1 => 6,
        3 => usize::from(stream.read_u8().await.unwrap()) + 2,
        4 => 18,
        other => panic!("unexpected address type {other}"),
    };
    let mut tail = vec![0; rest];
    stream.read_exact(&mut tail).await.unwrap();
}

pub(super) async fn accept_socks(listener: TcpListener, payload: &'static [u8]) -> JoinHandle<()> {
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        read_request(&mut stream).await;
        stream
            .write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0])
            .await
            .unwrap();
        stream.write_all(payload).await.unwrap();
        let _ = stream.read_u8().await;
    })
}

#[derive(Debug, PartialEq, Eq)]
pub(super) struct Observed {
    pub(super) index: usize,
    pub(super) after_win: bool,
    pub(super) outcome: &'static str,
}

fn outcome_name(outcome: &AttemptOutcome) -> &'static str {
    match outcome {
        AttemptOutcome::Won => "won",
        AttemptOutcome::LateSuccess => "late-success",
        AttemptOutcome::Lost => "lost",
        AttemptOutcome::Failed(_) => "failed",
    }
}

pub(super) async fn receive_reports(
    receiver: &mut mpsc::Receiver<Observed>,
    count: usize,
    deadline: Duration,
) -> Vec<Observed> {
    let mut reports = Vec::with_capacity(count);
    for _ in 0..count {
        reports.push(
            tokio::time::timeout(deadline, receiver.recv())
                .await
                .expect("report deadline")
                .expect("report channel closed early"),
        );
    }
    assert!(
        tokio::time::timeout(deadline, receiver.recv())
            .await
            .expect("report closure deadline")
            .is_none(),
        "extra or duplicate attempt report"
    );
    reports.sort_by_key(|report| report.index);
    reports
}

pub(super) fn send_report(tx: &mpsc::Sender<Observed>, report: &AttemptReport) {
    tx.try_send(Observed {
        index: report.index,
        after_win: report.after_win,
        outcome: outcome_name(&report.outcome),
    })
    .expect("report channel capacity");
}

#[test]
fn options_defaults_and_builders() {
    let defaults = HedgeOptions::default();
    assert_eq!(defaults.hedge_delay, Duration::from_secs(2));
    assert_eq!(defaults.handshake_timeout, Duration::from_secs(10));
    let configured = defaults
        .with_hedge_delay(Duration::from_millis(20))
        .with_handshake_timeout(Duration::from_secs(3));
    assert_eq!(configured.hedge_delay, Duration::from_millis(20));
    assert_eq!(configured.handshake_timeout, Duration::from_secs(3));
}

#[tokio::test]
async fn dead_first_candidate_hedges_to_live_candidate_and_reports_both() {
    let (listener, live) = loopback().await;
    let server = accept_socks(listener, b"ok").await;
    let dead = proxy("192.0.2.1", 9);
    let (tx, mut rx) = mpsc::channel(4);
    let result = tokio::time::timeout(
        Duration::from_secs(1),
        connect_hedged(
            &[dead, live],
            "example.com:443",
            &pool(Duration::from_secs(2)),
            None,
            &opts(Duration::from_millis(40)),
            move |report| send_report(&tx, report),
        ),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(result.winner, 1);
    drop(result.stream);
    server.await.unwrap();
    let reports = receive_reports(&mut rx, 2, Duration::from_secs(3)).await;
    assert!(reports
        .iter()
        .any(|r| r.index == 1 && !r.after_win && r.outcome == "won"));
    assert!(reports
        .iter()
        .any(|r| r.index == 0 && r.outcome == "failed"));
}

#[tokio::test]
async fn zero_delay_is_strictly_sequential_in_candidate_order() {
    let (first_listener, first) = loopback().await;
    let (second_listener, second) = loopback().await;
    let first_server = accept_socks(first_listener, b"first").await;
    let second_server = accept_socks(second_listener, b"second").await;
    let (tx, mut rx) = mpsc::channel(2);
    let result = tokio::time::timeout(
        Duration::from_secs(2),
        connect_hedged(
            &[first, second],
            "example.com:80",
            &pool(Duration::from_secs(1)),
            None,
            &opts(Duration::ZERO),
            move |report| send_report(&tx, report),
        ),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(result.winner, 0);
    drop(result.stream);
    first_server.await.unwrap();
    assert_eq!(
        receive_reports(&mut rx, 1, Duration::from_secs(1)).await,
        [Observed {
            index: 0,
            after_win: false,
            outcome: "won"
        }]
    );
    second_server.abort();
}

#[tokio::test]
async fn zero_delay_waits_for_first_tcp_failure_before_second_candidate() {
    let (live_listener, live) = loopback().await;
    let live_server = accept_socks(live_listener, b"alive").await;
    let dead = proxy("192.0.2.1", 9);
    let (tx, mut rx) = mpsc::channel(3);
    let result = tokio::time::timeout(
        Duration::from_secs(3),
        connect_hedged(
            &[dead, live],
            "example.com:443",
            &pool(Duration::from_secs(1)),
            None,
            &opts(Duration::ZERO),
            move |report| send_report(&tx, report),
        ),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(result.winner, 1);
    drop(result.stream);
    live_server.await.unwrap();
    let reports = receive_reports(&mut rx, 2, Duration::from_secs(1)).await;
    assert_eq!(
        reports[0],
        Observed {
            index: 0,
            after_win: false,
            outcome: "failed"
        }
    );
    assert_eq!(
        reports[1],
        Observed {
            index: 1,
            after_win: false,
            outcome: "won"
        }
    );
}

#[tokio::test]
async fn slow_handshake_suppresses_second_candidate_until_first_fails() {
    let (first_listener, first) = loopback().await;
    let (second_listener, second) = loopback().await;
    let (first_greeting_tx, first_greeting_rx) = tokio::sync::oneshot::channel();
    let (release_first_tx, release_first_rx) = tokio::sync::oneshot::channel();
    let first_server = tokio::spawn(async move {
        let (mut stream, _) = first_listener.accept().await.unwrap();
        let mut greeting = [0; 3];
        stream.read_exact(&mut greeting).await.unwrap();
        let _ = first_greeting_tx.send(());
        let _ = release_first_rx.await;
        stream.shutdown().await.unwrap();
    });
    let second_accepts = Arc::new(AtomicUsize::new(0));
    let observed_accepts = second_accepts.clone();
    let second_server = tokio::spawn(async move {
        let (mut stream, _) = second_listener.accept().await.unwrap();
        observed_accepts.fetch_add(1, Ordering::SeqCst);
        read_request(&mut stream).await;
        stream
            .write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0])
            .await
            .unwrap();
        let _ = stream.read_u8().await;
    });
    let (tx, mut rx) = mpsc::channel(4);
    let task_pool = pool(Duration::from_secs(1));
    let connect = tokio::spawn(async move {
        connect_hedged(
            &[first, second],
            "example.com:443",
            &task_pool,
            None,
            &opts(Duration::from_millis(40)),
            move |report| send_report(&tx, report),
        )
        .await
    });
    tokio::time::timeout(Duration::from_secs(1), first_greeting_rx)
        .await
        .unwrap()
        .unwrap();
    tokio::time::sleep(Duration::from_millis(120)).await;
    assert_eq!(second_accepts.load(Ordering::SeqCst), 0);
    let _ = release_first_tx.send(());
    let result = tokio::time::timeout(Duration::from_secs(2), connect)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(result.winner, 1);
    drop(result.stream);
    let reports = receive_reports(&mut rx, 2, Duration::from_secs(2)).await;
    assert_eq!(
        reports[0],
        Observed {
            index: 0,
            after_win: false,
            outcome: "failed"
        }
    );
    assert_eq!(
        reports[1],
        Observed {
            index: 1,
            after_win: false,
            outcome: "won"
        }
    );
    first_server.await.unwrap();
    second_server.await.unwrap();
}

#[tokio::test]
async fn failures_fall_through_and_tunnel_reaches_target() {
    let target_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target_addr = target_listener.local_addr().unwrap();
    let target = tokio::spawn(async move {
        let (mut stream, _) = target_listener.accept().await.unwrap();
        let mut input = [0; 7];
        stream.read_exact(&mut input).await.unwrap();
        assert_eq!(&input, b"request");
        stream.write_all(b"response").await.unwrap();
    });
    let (listener, proxy_cfg) = loopback().await;
    let (upstream_ready_tx, upstream_ready_rx) = tokio::sync::oneshot::channel();
    let upstream = tokio::spawn(async move {
        let (mut client, _) = listener.accept().await.unwrap();
        read_request(&mut client).await;
        let target = TcpStream::connect(target_addr).await.unwrap();
        client
            .write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0])
            .await
            .unwrap();
        let _ = upstream_ready_tx.send(());
        let (mut cr, mut cw) = client.into_split();
        let (mut tr, mut tw) = target.into_split();
        let forward = tokio::spawn(async move { tokio::io::copy(&mut cr, &mut tw).await });
        let backward = tokio::spawn(async move { tokio::io::copy(&mut tr, &mut cw).await });
        let _ = forward.await;
        let _ = backward.await;
    });
    let (tx, mut rx) = mpsc::channel(4);
    let candidates = [proxy("192.0.2.1", 9), proxy("192.0.2.2", 9), proxy_cfg];
    let result = tokio::time::timeout(
        Duration::from_secs(4),
        connect_hedged(
            &candidates,
            &format!("{}:{}", target_addr.ip(), target_addr.port()),
            &pool(Duration::from_secs(1)),
            None,
            &opts(Duration::from_secs(2)),
            move |report| send_report(&tx, report),
        ),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(result.winner, 2);
    let mut tunnel = result.stream;
    tokio::time::timeout(Duration::from_secs(1), upstream_ready_rx)
        .await
        .unwrap()
        .unwrap();
    tunnel.write_all(b"request").await.unwrap();
    let mut response = [0; 8];
    tunnel.read_exact(&mut response).await.unwrap();
    assert_eq!(&response, b"response");
    drop(tunnel);
    target.await.unwrap();
    upstream.abort();
    let reports = receive_reports(&mut rx, 3, Duration::from_secs(2)).await;
    assert_eq!(
        reports.iter().map(|r| r.index).collect::<Vec<_>>(),
        [0, 1, 2]
    );
}

#[tokio::test]
async fn all_dead_and_invalid_target_report_every_launched_failure() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let unused_port = listener.local_addr().unwrap().port();
    drop(listener);
    let dead = [
        proxy("127.0.0.1", unused_port),
        proxy("127.0.0.1", unused_port),
    ];
    let (tx, mut rx) = mpsc::channel(2);
    let error = tokio::time::timeout(
        Duration::from_secs(3),
        connect_hedged(
            &dead,
            "example.com:80",
            &pool(Duration::from_secs(1)),
            None,
            &opts(Duration::ZERO),
            move |report| send_report(&tx, report),
        ),
    )
    .await
    .unwrap()
    .unwrap_err();
    assert_eq!(error.attempts, 2);
    assert!(error.last.is_some());
    assert_eq!(
        receive_reports(&mut rx, 2, Duration::from_secs(1)).await,
        [
            Observed {
                index: 0,
                after_win: false,
                outcome: "failed"
            },
            Observed {
                index: 1,
                after_win: false,
                outcome: "failed"
            },
        ]
    );

    let (listener, valid) = loopback().await;
    let server = tokio::spawn(async move {
        for _ in 0..2 {
            let (mut stream, _) = listener.accept().await.unwrap();
            assert_eq!(stream.read(&mut [0; 1]).await.unwrap(), 0);
        }
    });
    let (tx, mut rx) = mpsc::channel(2);
    let candidates = [valid.clone(), valid];
    let error = tokio::time::timeout(
        Duration::from_secs(2),
        connect_hedged(
            &candidates,
            "invalid target",
            &pool(Duration::from_secs(1)),
            None,
            &opts(Duration::ZERO),
            move |report| {
                let outcome = if matches!(
                    report.outcome,
                    AttemptOutcome::Failed(ConnectError::InvalidTarget(_))
                ) {
                    "invalid-target"
                } else {
                    outcome_name(&report.outcome)
                };
                tx.try_send(Observed {
                    index: report.index,
                    after_win: report.after_win,
                    outcome,
                })
                .expect("report capacity");
            },
        ),
    )
    .await
    .unwrap()
    .unwrap_err();
    assert_eq!(error.attempts, 2);
    assert_eq!(
        receive_reports(&mut rx, 2, Duration::from_secs(1)).await,
        [
            Observed {
                index: 0,
                after_win: false,
                outcome: "invalid-target"
            },
            Observed {
                index: 1,
                after_win: false,
                outcome: "invalid-target"
            },
        ]
    );
    server.await.unwrap();
}

#[tokio::test]
async fn empty_candidates_return_zero_attempts() {
    let error = tokio::time::timeout(
        Duration::from_secs(1),
        connect_hedged(
            &[],
            "example.com:80",
            &pool(Duration::from_secs(1)),
            None,
            &HedgeOptions::default(),
            |_| {},
        ),
    )
    .await
    .unwrap()
    .unwrap_err();
    assert_eq!(error.attempts, 0);
    assert!(error.last.is_none());
}

#[tokio::test]
async fn reaching_upstream_after_win_reports_lost_without_greeting() {
    let (listener, candidate) = loopback().await;
    let race = Arc::new(RaceState::default());
    race.won.store(true, Ordering::Release);
    let mut running = JoinSet::new();
    let mut launched = Vec::new();
    launch(
        &mut running,
        &mut launched,
        0,
        candidate,
        race,
        "target:80".to_owned(),
        pool(Duration::from_secs(1)),
        Duration::from_secs(1),
        None,
    );
    let (tx, mut rx) = mpsc::channel(1);
    let drain = tokio::spawn(drain(
        running,
        launched,
        Arc::new(move |report: &AttemptReport| send_report(&tx, report)),
    ));
    let (mut stream, _) = tokio::time::timeout(Duration::from_secs(1), listener.accept())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(1), stream.read(&mut [0; 1]))
            .await
            .unwrap()
            .unwrap(),
        0
    );
    assert_eq!(
        receive_reports(&mut rx, 1, Duration::from_secs(1)).await,
        [Observed {
            index: 0,
            after_win: true,
            outcome: "lost"
        }]
    );
    tokio::time::timeout(Duration::from_secs(1), drain)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn already_handshaking_attempt_reports_late_success_and_closes_socket() {
    let (listener, candidate) = loopback().await;
    let (handshake_tx, handshake_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut greeting = [0; 3];
        stream.read_exact(&mut greeting).await.unwrap();
        stream.write_all(&[5, 0]).await.unwrap();
        let mut head = [0; 4];
        stream.read_exact(&mut head).await.unwrap();
        let rest = if head[3] == 3 {
            usize::from(stream.read_u8().await.unwrap()) + 2
        } else {
            6
        };
        let mut tail = vec![0; rest];
        stream.read_exact(&mut tail).await.unwrap();
        let _ = handshake_tx.send(());
        let _ = release_rx.await;
        stream
            .write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0])
            .await
            .unwrap();
        assert_eq!(stream.read(&mut [0; 1]).await.unwrap(), 0);
    });
    let race = Arc::new(RaceState::default());
    let mut running = JoinSet::new();
    let mut launched = Vec::new();
    launch(
        &mut running,
        &mut launched,
        0,
        candidate,
        race.clone(),
        "example.com:80".to_owned(),
        pool(Duration::from_secs(1)),
        Duration::from_secs(1),
        None,
    );
    tokio::time::timeout(Duration::from_secs(1), handshake_rx)
        .await
        .unwrap()
        .unwrap();
    race.won.store(true, Ordering::Release);
    let (tx, mut rx) = mpsc::channel(1);
    let drain = tokio::spawn(drain(
        running,
        launched,
        Arc::new(move |report: &AttemptReport| send_report(&tx, report)),
    ));
    let _ = release_tx.send(());
    assert_eq!(
        receive_reports(&mut rx, 1, Duration::from_secs(1)).await,
        [Observed {
            index: 0,
            after_win: true,
            outcome: "late-success"
        }]
    );
    tokio::time::timeout(Duration::from_secs(1), drain)
        .await
        .unwrap()
        .unwrap();
    tokio::time::timeout(Duration::from_secs(1), server)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn holder_success_reports_tcp_ready_sibling_lost_without_connect() {
    // Mutation catches: non-exclusive handshake admission (the sibling would
    // send a greeting while the holder holds the slot), a win not published
    // by the holder itself, and a missing post-admission `won` re-check —
    // each would let the sibling send its own CONNECT here.
    let (holder_listener, holder) = loopback().await;
    let (sibling_listener, sibling) = loopback().await;
    let (request_read_tx, request_read_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = tokio::sync::oneshot::channel();
    let holder_server = tokio::spawn(async move {
        let (mut stream, _) = holder_listener.accept().await.unwrap();
        read_request(&mut stream).await;
        let _ = request_read_tx.send(());
        let _ = release_rx.await;
        stream
            .write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0])
            .await
            .unwrap();
        let _ = stream.read_u8().await;
    });
    let race = Arc::new(RaceState::default());
    let mut running = JoinSet::new();
    let mut launched = Vec::new();
    launch(
        &mut running,
        &mut launched,
        0,
        holder,
        race.clone(),
        "example.com:80".to_owned(),
        pool(Duration::from_secs(1)),
        Duration::from_secs(1),
        None,
    );
    tokio::time::timeout(Duration::from_secs(1), request_read_rx)
        .await
        .unwrap()
        .unwrap();
    // The holder sent its greeting plus CONNECT, so it holds the slot; the
    // sibling must wait instead of handshaking beside it.
    launch(
        &mut running,
        &mut launched,
        1,
        sibling,
        race,
        "example.com:80".to_owned(),
        pool(Duration::from_secs(1)),
        Duration::from_secs(1),
        None,
    );
    let (mut sibling_stream, _) =
        tokio::time::timeout(Duration::from_secs(1), sibling_listener.accept())
            .await
            .unwrap()
            .unwrap();
    match tokio::time::timeout(Duration::from_millis(150), sibling_stream.read_u8()).await {
        Err(_) => {}
        Ok(Ok(byte)) => panic!("sibling sent byte {byte} while the holder held the handshake slot"),
        Ok(Err(error)) => panic!("sibling socket closed while waiting for the slot: {error}"),
    }
    let _ = release_tx.send(());
    match tokio::time::timeout(Duration::from_secs(1), sibling_stream.read_u8())
        .await
        .unwrap()
    {
        Err(error) => assert_eq!(
            error.kind(),
            std::io::ErrorKind::UnexpectedEof,
            "sibling must close its silent socket once the holder wins"
        ),
        Ok(byte) => panic!("sibling sent byte {byte} after the holder won"),
    }
    let (tx, mut rx) = mpsc::channel(2);
    let drain = tokio::spawn(drain(
        running,
        launched,
        Arc::new(move |report: &AttemptReport| send_report(&tx, report)),
    ));
    assert_eq!(
        receive_reports(&mut rx, 2, Duration::from_secs(2)).await,
        [
            Observed {
                index: 0,
                after_win: true,
                outcome: "late-success"
            },
            Observed {
                index: 1,
                after_win: true,
                outcome: "lost"
            },
        ]
    );
    tokio::time::timeout(Duration::from_secs(1), drain)
        .await
        .unwrap()
        .unwrap();
    tokio::time::timeout(Duration::from_secs(1), holder_server)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn holder_failure_lets_waiting_sibling_perform_its_own_connect() {
    // Mutation catches: a TCP-ready sibling giving up (Lost) instead of
    // waiting for a failed slot-holder, a slot not freed on the failure
    // path, and a failure wrongly published as a win — the sibling must go
    // on to complete its own CONNECT and succeed.
    let (holder_listener, holder) = loopback().await;
    let (sibling_listener, sibling) = loopback().await;
    let (request_read_tx, request_read_rx) = tokio::sync::oneshot::channel();
    let (close_tx, close_rx) = tokio::sync::oneshot::channel();
    let (sibling_accepted_tx, sibling_accepted_rx) = tokio::sync::oneshot::channel();
    let holder_server = tokio::spawn(async move {
        let (mut stream, _) = holder_listener.accept().await.unwrap();
        read_request(&mut stream).await;
        let _ = request_read_tx.send(());
        let _ = close_rx.await;
        drop(stream);
    });
    let sibling_server = tokio::spawn(async move {
        let (mut stream, _) = sibling_listener.accept().await.unwrap();
        let _ = sibling_accepted_tx.send(());
        read_request(&mut stream).await;
        stream
            .write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0])
            .await
            .unwrap();
        let _ = stream.read_u8().await;
    });
    let race = Arc::new(RaceState::default());
    let mut running = JoinSet::new();
    let mut launched = Vec::new();
    launch(
        &mut running,
        &mut launched,
        0,
        holder,
        race.clone(),
        "example.com:80".to_owned(),
        pool(Duration::from_secs(1)),
        Duration::from_secs(1),
        None,
    );
    tokio::time::timeout(Duration::from_secs(1), request_read_rx)
        .await
        .unwrap()
        .unwrap();
    launch(
        &mut running,
        &mut launched,
        1,
        sibling,
        race,
        "example.com:80".to_owned(),
        pool(Duration::from_secs(1)),
        Duration::from_secs(1),
        None,
    );
    tokio::time::timeout(Duration::from_secs(1), sibling_accepted_rx)
        .await
        .unwrap()
        .unwrap();
    let _ = close_tx.send(());
    let first = tokio::time::timeout(Duration::from_secs(2), running.join_next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(first.index, 0);
    assert!(matches!(first.result, Err(AttemptFailure::Failed(_))));
    let second = tokio::time::timeout(Duration::from_secs(2), running.join_next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(second.index, 1);
    assert!(
        second.result.is_ok(),
        "sibling must proceed and succeed after the holder fails"
    );
    drop(second.result);
    tokio::time::timeout(Duration::from_secs(1), holder_server)
        .await
        .unwrap()
        .unwrap();
    tokio::time::timeout(Duration::from_secs(1), sibling_server)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn max_hedge_delay_never_panics_and_never_hedges() {
    // Mutation catches: arming the hedge deadline with plain `now() + delay`
    // (panics on `Duration::MAX`) and launching a second candidate despite
    // an unarmable timer.
    let (listener, candidate) = loopback().await;
    let (unused_listener, unused) = loopback().await;
    let server = accept_socks(listener, b"ok").await;
    let (tx, mut rx) = mpsc::channel(2);
    let result = tokio::time::timeout(
        Duration::from_secs(1),
        connect_hedged(
            &[candidate, unused],
            "example.com:80",
            &pool(Duration::from_secs(1)),
            None,
            &opts(Duration::MAX),
            move |report| send_report(&tx, report),
        ),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(result.winner, 0);
    drop(result.stream);
    server.await.unwrap();
    assert_eq!(
        receive_reports(&mut rx, 1, Duration::from_secs(1)).await,
        [Observed {
            index: 0,
            after_win: false,
            outcome: "won"
        }]
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(150), unused_listener.accept())
            .await
            .is_err(),
        "an unhedgeable delay must not launch the second candidate"
    );
}

#[tokio::test]
async fn max_hedge_delay_with_single_candidate_wins_without_timer() {
    // Mutation catches: computing the hedge deadline after the (only)
    // launch even when no candidate remains — the old `now() + delay`
    // panicked here although no timer was ever needed.
    let (listener, candidate) = loopback().await;
    let server = accept_socks(listener, b"ok").await;
    let (tx, mut rx) = mpsc::channel(1);
    let result = tokio::time::timeout(
        Duration::from_secs(1),
        connect_hedged(
            &[candidate],
            "example.com:80",
            &pool(Duration::from_secs(1)),
            None,
            &opts(Duration::MAX),
            move |report| send_report(&tx, report),
        ),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(result.winner, 0);
    drop(result.stream);
    server.await.unwrap();
    assert_eq!(
        receive_reports(&mut rx, 1, Duration::from_secs(1)).await,
        [Observed {
            index: 0,
            after_win: false,
            outcome: "won"
        }]
    );
}
