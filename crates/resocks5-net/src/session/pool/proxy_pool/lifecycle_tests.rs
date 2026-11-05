//! Tests for the `spawn_refill_for` / `forget` lifecycle
//! serialization (audit V17): queue publication, task spawn and
//! handle registration are one step under the `refill_tasks` lock,
//! so no generation's task can be lost — a dropped `JoinHandle`
//! detaches the task instead of aborting it, and a task that loses
//! its registered handle re-connects forever, invisible to `forget`
//! and to `Drop`.

use super::tests::{counting_listener, make_proxy, pool_cfg, quiesce, Counters};
use super::*;

/// Mutation caught: registering the handle OUTSIDE the lifecycle
/// lock (the pre-fix shape) lets a concurrent `forget` remove the
/// queue while finding no handle to abort; the stale late
/// registration then replaces the next generation's handle, which
/// DETACHES that task. A detached task keeps re-connecting at least
/// once per `max_session_age_sec` (its age-recycle branch drains the
/// stale spare and tops the queue up again) — so with
/// `max_session_age_sec = 1`, ">1.8s with zero new accepts after the
/// final forget" plus "no task left registered" fails exactly when a
/// task survived without its handle.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn forget_spawn_race_never_leaves_an_orphaned_refill_task() {
    let counters = Arc::new(Counters::default());
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(counting_listener(l, counters.clone()));

    // Real (non-paused) time: the oracle needs the orphan's real 1s
    // age-recycle to fire. Cap 2 > spare 1 so permits never bind;
    // each generation's task connects exactly one spare.
    let pool = Arc::new(ProxyPool::new(
        PoolConfig {
            enabled: true,
            spare_per_proxy: 1,
            max_session_age_sec: 1,
        },
        Duration::from_secs(30),
        2,
    ));
    let proxy = Arc::new(make_proxy("127.0.0.1", port));

    // Hammer spawn and forget concurrently. Under the fix each call
    // is atomic with respect to the other, so every task a spawn
    // registers is aborted by exactly one forget.
    const ITERS: usize = 200;
    let spawner = {
        let pool = pool.clone();
        let proxy = proxy.clone();
        tokio::spawn(async move {
            for _ in 0..ITERS {
                pool.spawn_refill_for(proxy.clone());
                tokio::task::yield_now().await;
            }
        })
    };
    let forgetter = {
        let pool = pool.clone();
        let proxy = proxy.clone();
        tokio::spawn(async move {
            for _ in 0..ITERS {
                pool.forget(&proxy);
                tokio::task::yield_now().await;
            }
        })
    };
    spawner.await.unwrap();
    forgetter.await.unwrap();

    // Retire whatever the interleaving left behind.
    pool.forget(&proxy);
    assert_eq!(
        pool.endpoint_state(&proxy),
        (false, false, false),
        "final forget must clear the endpoint completely"
    );
    assert!(
        pool.refill_tasks
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .is_empty(),
        "no refill task may survive the final forget"
    );

    // Settle: a connect aborted mid-handshake can still land in the
    // listener's backlog afterwards — give it a bounded window to be
    // counted BEFORE the baseline.
    for _ in 0..50 {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let baseline = counters.accepted();

    // Oracle: >1.8s with zero new accepts. An orphaned task cannot
    // sit still — its max_session_age_sec = 1 recycle keeps it
    // reconnecting forever, so any accept here names a task that
    // lost its registered handle.
    for _ in 0..60 {
        tokio::time::sleep(Duration::from_millis(30)).await;
        assert_eq!(
            counters.accepted(),
            baseline,
            "connection accepted after the final forget: orphaned refill task"
        );
    }
}

/// Mutation caught: `forget` that removes the queue without aborting
/// its task (the aborted task's queue Arc is owned by the task
/// future, so its spare sockets die only when the future is
/// dropped), or a respawn that fails to register exactly one live
/// task. Expected values: generation 1 settles at accepted=2,
/// open=2, queue=2; after forget + respawn, generation 2 settles at
/// accepted=4, open=2, queue=2, exactly 1 registered live handle.
#[tokio::test(start_paused = true)]
async fn forget_then_respawn_leaves_exactly_one_live_task() {
    let counters = Arc::new(Counters::default());
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(counting_listener(l, counters.clone()));

    // See `tests::concurrent_spawn_refill_for_races_to_single_task`
    // for why a generous connect_timeout is needed under paused time.
    let pool = ProxyPool::new(pool_cfg(2), Duration::from_secs(120), 4);
    let proxy = make_proxy("127.0.0.1", port);
    let key = (proxy.host.clone(), proxy.port);

    // Generation 1 steady state: 2 spares connected and queued.
    pool.spawn_refill_for(Arc::new(proxy.clone()));
    quiesce(|| {
        counters.accepted() == 2 && pool.pools.get(&key).map(|s| s.queue.len()).unwrap_or(0) == 2
    })
    .await;
    assert!(
        !pool.refill_task_finished(&proxy),
        "generation 1 must be registered and running before forget"
    );

    // forget aborts generation 1; its queued spares die with the
    // aborted task future.
    pool.forget(&proxy);
    quiesce(|| counters.open() == 0).await;
    assert_eq!(
        counters.accepted(),
        2,
        "generation 1 must not connect beyond its two spares"
    );

    // Generation 2: exactly one registered LIVE task refills the
    // fresh queue.
    pool.spawn_refill_for(Arc::new(proxy.clone()));
    quiesce(|| {
        counters.accepted() == 4 && pool.pools.get(&key).map(|s| s.queue.len()).unwrap_or(0) == 2
    })
    .await;
    let registered = pool
        .refill_tasks
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .len();
    assert_eq!(registered, 1, "exactly one task registered after respawn");
    assert!(
        !pool.refill_task_finished(&proxy),
        "the registered generation-2 task must be live"
    );
    assert_eq!(counters.accepted(), 4);
    assert_eq!(counters.open(), 2, "only generation 2's spares are open");
}
