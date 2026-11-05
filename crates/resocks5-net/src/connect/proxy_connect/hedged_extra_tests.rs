use std::error::Error;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use tokio::io::AsyncReadExt;
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio::task::JoinSet;

use super::tests::{
    accept_socks, loopback, opts, pool, proxy, receive_reports, send_report, Observed,
};
use super::*;

/// Wraps a future so that every internal wake schedules the real wake
/// `delay` later. Armed hedge deadlines then expire while the coordinator
/// stays parked, so its next poll can observe the tick branch beside an
/// already completed winner.
struct DelayedWakes<F: Future> {
    inner: Pin<Box<F>>,
    delay: Duration,
}

impl<F: Future> DelayedWakes<F> {
    fn new(inner: F, delay: Duration) -> Self {
        Self {
            inner: Box::pin(inner),
            delay,
        }
    }
}

impl<F: Future> Future for DelayedWakes<F> {
    type Output = F::Output;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        let delayed = Waker::from(Arc::new(DelayWake {
            real: cx.waker().clone(),
            delay: this.delay,
        }));
        let mut delayed_cx = Context::from_waker(&delayed);
        this.inner.as_mut().poll(&mut delayed_cx)
    }
}

struct DelayWake {
    real: Waker,
    delay: Duration,
}

impl std::task::Wake for DelayWake {
    fn wake(self: Arc<Self>) {
        let real = self.real.clone();
        let delay = self.delay;
        tokio::spawn(async move {
            tokio::time::sleep(delay).await;
            real.wake();
        });
    }
}

#[tokio::test]
async fn hedge_tick_after_published_win_does_not_launch_pending_candidate() {
    // Mutation catches: a hedge tick without a `won` re-check. Once the
    // winner published its win and freed the handshake slot, a tick observed
    // before the coordinator joins the winner would launch the pending
    // candidate (an extra acquire/TCP connect). Delaying every coordinator
    // wake past the next hedge deadline opens that window deterministically;
    // tokio polls ready select branches in random order, so each run catches
    // the mutation with probability 1/2 and twelve runs miss it with
    // probability 2^-12.
    for _ in 0..12 {
        let (winner_listener, winner) = loopback().await;
        let (unused_listener, pending) = loopback().await;
        let server = accept_socks(winner_listener, b"ok").await;
        let (tx, mut rx) = mpsc::channel(2);
        let connect = tokio::spawn(DelayedWakes::new(
            async move {
                connect_hedged(
                    &[winner, pending],
                    "example.com:80",
                    &pool(Duration::from_secs(1)),
                    None,
                    &opts(Duration::from_millis(40)),
                    move |report| send_report(&tx, report),
                )
                .await
            },
            Duration::from_millis(100),
        ));
        let result = tokio::time::timeout(Duration::from_secs(5), connect)
            .await
            .expect("hedged connect deadline")
            .expect("connect task panicked")
            .expect("connect_hedged must succeed");
        assert_eq!(result.winner, 0);
        drop(result.stream);
        tokio::time::timeout(Duration::from_secs(1), server)
            .await
            .expect("stub deadline")
            .unwrap();
        let mut reports = Vec::new();
        while let Some(report) = rx.recv().await {
            reports.push(report);
        }
        assert_eq!(
            reports,
            [Observed {
                index: 0,
                after_win: false,
                outcome: "won"
            }],
            "a tick after the published win must not launch the pending candidate"
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(150), unused_listener.accept())
                .await
                .is_err(),
            "the pending candidate must never be acquired after the win"
        );
    }
}

#[tokio::test]
async fn drain_catches_callback_panic_and_still_delivers_remaining_reports() {
    // Mutation catches: an uncaught callback panic inside the detached
    // drain — the task would die on the first report, the remaining report
    // would never be delivered and the drain would end panicked instead of
    // finishing.
    let (listener, live) = loopback().await;
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        assert_eq!(stream.read(&mut [0; 1]).await.unwrap(), 0);
    });
    let race = Arc::new(RaceState::default());
    // Published up front so the live candidate drops its socket right after
    // its acquire and the failing candidate stays the only slow one.
    race.won.store(true, Ordering::Release);
    let mut running = JoinSet::new();
    let mut launched = Vec::new();
    // A closed loopback port: this candidate fails (refused or timed out);
    // the report order of the two candidates is deliberately not pinned.
    let dead = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let dead_addr = dead.local_addr().unwrap();
    drop(dead);
    launch(
        &mut running,
        &mut launched,
        0,
        proxy(dead_addr.ip().to_string(), dead_addr.port()),
        race.clone(),
        "example.com:80".to_owned(),
        pool(Duration::from_millis(300)),
        Duration::from_secs(1),
        None,
    );
    launch(
        &mut running,
        &mut launched,
        1,
        live,
        race,
        "example.com:80".to_owned(),
        pool(Duration::from_secs(1)),
        Duration::from_secs(1),
        None,
    );
    let (tx, mut rx) = mpsc::channel(2);
    let invocations = Arc::new(AtomicUsize::new(0));
    let callback_invocations = invocations.clone();
    tokio::time::timeout(
        Duration::from_secs(5),
        tokio::spawn(drain(
            running,
            launched,
            Arc::new(move |report: &AttemptReport| {
                if callback_invocations.fetch_add(1, Ordering::SeqCst) == 0 {
                    panic!("drain callback panic on the first report");
                }
                send_report(&tx, report);
            }),
        )),
    )
    .await
    .expect("drain deadline")
    .expect("drain must finish without a panic");
    assert_eq!(
        invocations.load(Ordering::SeqCst),
        2,
        "the callback must run once per drained report"
    );
    // The first report panicked; the other one must still arrive.
    let delivered = receive_reports(&mut rx, 1, Duration::from_secs(1)).await;
    assert_eq!(delivered.len(), 1);
    assert!(delivered[0].after_win);
    tokio::time::timeout(Duration::from_secs(1), server)
        .await
        .expect("stub deadline")
        .unwrap();
}

#[tokio::test]
async fn caller_path_callback_panic_still_unwinds_the_caller() {
    // Mutation catches: swallowing the caller's own callback panics — those
    // must unwind the caller, not be caught like the drain's.
    let (listener, live) = loopback().await;
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        assert_eq!(stream.read(&mut [0; 1]).await.unwrap(), 0);
    });
    let candidates = [live];
    let task_pool = pool(Duration::from_secs(1));
    let task_opts = opts(Duration::ZERO);
    let connect = tokio::spawn(async move {
        connect_hedged(
            &candidates,
            "invalid target",
            &task_pool,
            None,
            &task_opts,
            |_: &AttemptReport| panic!("caller path callback panic"),
        )
        .await
    });
    let joined = tokio::time::timeout(Duration::from_secs(5), connect)
        .await
        .expect("connect deadline");
    // The task must end in a JoinError (the panic unwound), not return.
    let join_error =
        joined.expect_err("a caller path callback panic must unwind, not be swallowed");
    assert!(join_error.is_panic());
    tokio::time::timeout(Duration::from_secs(1), server)
        .await
        .expect("stub deadline")
        .unwrap();
}

#[test]
fn hedge_error_source_exposes_last_error_only() {
    // Mutation catches: a missing `Error::source` implementation — the last
    // connection error must be reachable as the error's source, and an empty
    // summary must have no source.
    let error = HedgeError {
        attempts: 2,
        last: Some(ConnectError::InvalidTarget("bad target".to_owned())),
    };
    let source = error
        .source()
        .expect("the last error must be exposed as source");
    let mapped = source
        .downcast_ref::<ConnectError>()
        .expect("source must be the stored ConnectError");
    match mapped {
        ConnectError::InvalidTarget(target) => assert_eq!(target, "bad target"),
        other => panic!("unexpected source {other:?}"),
    }
    let empty = HedgeError {
        attempts: 0,
        last: None,
    };
    assert!(empty.source().is_none());
}
