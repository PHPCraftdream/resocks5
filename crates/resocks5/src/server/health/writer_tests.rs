//! Writer-lifecycle tests: the cross-process health lock, the per-write
//! temp reclaim, the pre-probe saver baseline, the logger-channel
//! shutdown reports, lock ownership across blocking writes, the dirty
//! baseline after failed commits, the expiry-aware signature and the
//! alias/duplicate restore policy. Pure-state tests live in `tests.rs`.

use super::tests::{
    counting_listener, drain, file, group, grouped, logger, p, rotator, test_pool, unique_dir,
    until, NOW,
};
use super::*;
use std::sync::atomic::Ordering;

// P2 №1: the health file's cross-process lock must be held BEFORE any
// cleanup or write. With the lock held by another process, `start` must not
// write, must not touch a foreign temp, must warn once through the logger
// and must hand back a saver whose `finish` is a no-op; once the lock is
// free a new `start` writes normally (mutation: cleanup or write without
// the lock).
#[tokio::test]
async fn a_held_health_lock_disables_persistence_and_touches_nothing() {
    let dir = unique_dir("locked_out");
    let path = dir.join("health.ktav");
    let temp = sibling_path(&path, ".tmp");
    std::fs::write(&temp, "foreign temp of another writer").unwrap();
    let holder = UsersFileLock::acquire_with_timeout(&path, Duration::from_millis(200)).unwrap();
    let r = rotator(vec![p("a")]);
    let (log, mut rx) = logger();

    let (saver, found) = start(
        vec![group("v4", r.clone())],
        Vec::new(),
        test_pool(),
        path.clone(),
        Duration::from_millis(50),
        Duration::from_secs(1),
        log,
    );
    assert!(!found, "nothing was saved yet");

    // Half a second: a running saver would have written within two ticks.
    for _ in 0..25 {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(!path.exists(), "nothing may be written without the lock");
    assert_eq!(
        std::fs::read_to_string(&temp).unwrap(),
        "foreign temp of another writer",
        "a foreign temp must not be deleted"
    );
    let lines = drain(&mut rx);
    assert_eq!(
        lines.len(),
        1,
        "exactly one warning, through the logger: {lines:?}"
    );
    assert!(lines[0].contains("locked by another process"), "{lines:?}");
    tokio::time::timeout(
        Duration::from_secs(1),
        saver.finish(&[group("v4", r.clone())], &path),
    )
    .await
    .expect("a disabled saver finishes at once");
    assert!(!path.exists(), "a disabled saver never writes at finish");
    drop(holder);

    // Lock free again: a new start writes normally and reclaims the
    // foreign temp as the file's sole owner.
    let (log, mut rx2) = logger();
    let (saver, found) = start(
        vec![group("v4", r.clone())],
        Vec::new(),
        test_pool(),
        path.clone(),
        Duration::from_millis(50),
        Duration::from_secs(1),
        log,
    );
    assert!(!found);
    until(|| matches!(load(&path), Ok(Some(_)))).await;
    assert!(
        !temp.exists(),
        "the foreign temp was reclaimed under the lock"
    );
    let lines = drain(&mut rx2);
    assert!(
        !lines
            .iter()
            .any(|line| line.contains("locked by another process")),
        "the free lock must not warn: {lines:?}"
    );
    saver.finish(&[group("v4", r)], &path).await;
    let _ = std::fs::remove_dir_all(&dir);
}

// P2 №6: Windows keeps `<health>.tmp` behind when `ReplaceFileW` fails with
// the unable-to-move codes, and `write_atomic` creates its temp with
// `create_new` — so the write path must reclaim the health's own stale temp
// before EVERY attempt, not only at start (mutation: removal only at start
// — the first mid-run write then fails forever).
#[tokio::test]
async fn a_temp_that_appears_midrun_is_reclaimed_before_the_next_write() {
    let dir = unique_dir("midrun_temp");
    let path = dir.join("health.ktav");
    let temp = sibling_path(&path, ".tmp");
    let r = rotator(vec![p("a")]);
    let (log, _rx) = logger();
    let (saver, found) = start(
        vec![group("v4", r.clone())],
        Vec::new(),
        test_pool(),
        path.clone(),
        Duration::from_millis(100),
        Duration::from_secs(1),
        log,
    );
    assert!(!found);
    until(|| matches!(load(&path), Ok(Some(_)))).await;
    assert_eq!(
        load(&path).unwrap().unwrap().upstreams[0].state,
        STATE_ALIVE
    );

    // Simulate the kept recovery temp of a failed Windows commit.
    std::fs::write(&temp, "kept recovery temp").unwrap();
    r.record_hard_failure(&p("a"));
    until(|| {
        load(&path)
            .ok()
            .flatten()
            .is_some_and(|now| now.upstreams[0].state == STATE_QUARANTINED)
    })
    .await;
    assert!(
        !temp.exists(),
        "the kept temp was reclaimed before the write"
    );
    saver.finish(&[group("v4", r)], &path).await;
    assert!(!temp.exists(), "no temp is left after the final write");
    let _ = std::fs::remove_dir_all(&dir);
}

// P2 №7: the saver's baseline must be the restored on-disk state taken
// BEFORE the post-restore probes are dispatched. The filler groups make
// `snapshot` deliberately slow (tens of ms), so under the mutation
// (baseline after dispatch) the quick loopback probe has long finished by
// the time the snapshot reaches the last group: the recovered state becomes
// its own baseline and no round ever writes (the file stays on probation).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_early_probe_result_is_still_persisted_on_a_later_round() {
    let (port, hits, accepts) = counting_listener().await;
    let alive = ProxyConfig::socks5("127.0.0.1", port);
    let label = upstream_label(&alive);
    let dir = unique_dir("baseline");
    let path = dir.join("health.ktav");

    // Hundreds of filler groups over one shared rotator weigh the snapshot
    // down; the probed group is pushed last, so it is read only after the
    // probe can have completed.
    let filler = rotator((0..25).map(|i| p(&format!("f{i}"))).collect());
    let mut groups: Vec<HealthGroup> = (0..400)
        .map(|i| group(&format!("g{i}"), filler.clone()))
        .collect();
    let r = rotator(vec![alive.clone()]);
    groups.push(group("v4", r.clone()));

    let mut saved = file(vec![grouped(&label, 0, "v4", STATE_PROBATION, 0, 1)]);
    saved.saved_at = unix_now();
    save(&path, &saved).unwrap();
    let (log, _rx) = logger();

    let finish_groups = groups.clone();
    let (saver, found) = start(
        groups,
        vec![r.clone()],
        test_pool(),
        path.clone(),
        Duration::from_millis(50),
        Duration::from_secs(2),
        log,
    );
    assert!(found, "a saved picture was read");

    for _ in 0..100 {
        if hits.load(Ordering::Relaxed) >= 1 && !r.is_quarantined(&alive) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(hits.load(Ordering::Relaxed) >= 1, "the direct probe ran");
    assert!(!r.is_quarantined(&alive), "the probe freed the upstream");

    until(|| {
        load(&path).ok().flatten().is_some_and(|now| {
            let ours: Vec<_> = now
                .upstreams
                .iter()
                .filter(|e| e.upstream == label)
                .collect();
            !ours.is_empty() && ours.iter().all(|e| e.state == STATE_ALIVE)
        })
    })
    .await;
    saver.finish(&finish_groups, &path).await;
    accepts.abort();
    let _ = std::fs::remove_dir_all(&dir);
}

// P2 №8: shutdown reporting is best-effort over the logger's non-blocking
// channel. A closed or full channel must not make `finish` panic or block,
// even when the final write fails fast (the target below is a directory)
// (mutation: any blocking or panicking send — the 1 s cap fires).
#[tokio::test]
async fn finish_survives_a_dead_or_full_logger_channel() {
    let dir = unique_dir("finish_dead_channel");
    // A directory as the target: the lock works, every write fails fast.
    let path = dir.join("health.ktav");
    std::fs::create_dir_all(&path).unwrap();
    let r = rotator(vec![p("a")]);

    let (tx, rx) = tokio::sync::mpsc::channel::<crate::logger::ELog>(8);
    drop(rx);
    let (saver, found) = start(
        vec![group("v4", r.clone())],
        Vec::new(),
        test_pool(),
        path.clone(),
        Duration::from_secs(3600),
        Duration::from_secs(1),
        Arc::new(Logger::new(tx, crate::logger::LogConfig::default())),
    );
    assert!(!found);
    tokio::time::timeout(
        Duration::from_secs(1),
        saver.finish(&[group("v4", r.clone())], &path),
    )
    .await
    .expect("finish must not hang when the logger channel is closed");

    let (tx, rx) = tokio::sync::mpsc::channel::<crate::logger::ELog>(1);
    tx.send(crate::logger::ELog::Log("occupant".to_owned()))
        .await
        .unwrap();
    let (saver, found) = start(
        vec![group("v4", r.clone())],
        Vec::new(),
        test_pool(),
        path.clone(),
        Duration::from_secs(3600),
        Duration::from_secs(1),
        Arc::new(Logger::new(tx, crate::logger::LogConfig::default())),
    );
    assert!(!found);
    tokio::time::timeout(
        Duration::from_secs(1),
        saver.finish(&[group("v4", r)], &path),
    )
    .await
    .expect("finish must not hang when the logger channel is full");
    drop(rx);
    let _ = std::fs::remove_dir_all(&dir);
}

// P2 №8: the final-save failure must surface on the logger channel, not on
// stderr — a full stderr pipe with no reader would block the shutdown path
// (mutation: eprintln — no message reaches the channel).
#[tokio::test]
async fn finish_reports_a_failed_final_save_through_the_logger() {
    let dir = unique_dir("finish_logger");
    let path = dir.join("health.ktav");
    std::fs::create_dir_all(&path).unwrap();
    let r = rotator(vec![p("a")]);
    let (log, mut rx) = logger();
    let (saver, found) = start(
        vec![group("v4", r.clone())],
        Vec::new(),
        test_pool(),
        path.clone(),
        Duration::from_secs(3600),
        Duration::from_secs(1),
        log,
    );
    assert!(!found);
    saver.finish(&[group("v4", r)], &path).await;
    let lines = drain(&mut rx);
    assert_eq!(
        lines.len(),
        1,
        "exactly the save failure is reported: {lines:?}"
    );
    assert!(lines[0].contains("could not save"), "{lines:?}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn start_with_a_broken_file_still_runs_and_overwrites_it() {
    let r = rotator(vec![p("a")]);
    let dir = unique_dir("start_bad");
    let path = dir.join("health.ktav");
    std::fs::write(&path, "saved_at: nope\n").unwrap();
    let (log, _rx) = logger();
    let (saver, found) = start(
        vec![group("v4", r.clone())],
        Vec::new(),
        test_pool(),
        path.clone(),
        Duration::from_millis(30),
        Duration::from_secs(1),
        log,
    );
    assert!(!found, "an unreadable file is not a picture");
    for _ in 0..100 {
        // The blocking writer replaces the file concurrently: only a readable
        // file counts, not one that is momentarily absent.
        if matches!(load(&path), Ok(Some(_))) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        load(&path).unwrap().is_some(),
        "the broken file is replaced"
    );
    saver.finish(&[group("v4", r)], &path).await;
    let _ = std::fs::remove_dir_all(&dir);
}

/// Spawn `run_saver` the way production start-up does: the loop holds a
/// share of the health file lock. Returns the task handle, the stop
/// signal and the lock; the first-tick acknowledgement has fired before
/// returning (explicit ack instead of settle() yields).
pub(super) async fn spawn_saver(
    groups: Vec<HealthGroup>,
    path: &Path,
    every: Duration,
    initial: Option<HealthFile>,
    log: Arc<Logger>,
) -> (
    tokio::task::JoinHandle<()>,
    Arc<tokio::sync::Notify>,
    Arc<UsersFileLock>,
) {
    let lock = acquired(path);
    let stop = Arc::new(tokio::sync::Notify::new());
    let started = Arc::new(tokio::sync::Notify::new());
    let handle = tokio::spawn(run_saver(
        groups,
        path.to_path_buf(),
        every,
        initial,
        log,
        Arc::clone(&stop),
        Arc::clone(&lock),
        Some(Arc::clone(&started)),
    ));
    started.notified().await;
    (handle, stop, lock)
}

/// A lock a test holds directly on its own directory path.
pub(super) fn acquired(path: &Path) -> Arc<UsersFileLock> {
    Arc::new(
        UsersFileLock::acquire_with_timeout(path, Duration::from_millis(200))
            .expect("the test owns its directory"),
    )
}

// (A) The lock must outlive the blocking write: a spawn_blocking body
// cannot be cancelled, so after `finish` gave up waiting (and aborted the
// loop) the parked writer still owns the OS lock, and a contender is
// admitted only once the write really finished. Mutation: the guard only
// in the async owner — `finish` releases the lock at its timeout and the
// contender acquires immediately.
#[tokio::test]
async fn a_parked_round_write_keeps_the_lock_after_finish_gave_up() {
    let dir = unique_dir("park_round");
    let path = dir.join("health.ktav");
    let r = rotator(vec![p("a")]);
    r.record_hard_failure(&p("a"));
    let (log, _rx) = logger();
    let park = arm_write_park(&path);
    let (saver, found) = start(
        vec![group("v4", r.clone())],
        Vec::new(),
        test_pool(),
        path.clone(),
        Duration::from_millis(50),
        Duration::from_secs(1),
        log,
    );
    assert!(!found);
    until(|| park.reached()).await;

    // `finish` waits its whole budget, aborts the loop and returns; the
    // parked write must not have published anything, and the lock must
    // still be held by its blocking closure.
    tokio::time::timeout(
        Duration::from_secs(10),
        saver.finish(&[group("v4", r.clone())], &path),
    )
    .await
    .expect("finish returns after its budget");
    assert!(
        !path.exists(),
        "the parked write has not published anything"
    );
    assert!(
        !sibling_path(&path, ".tmp").exists(),
        "no temp while parked"
    );
    assert!(
        UsersFileLock::acquire_with_timeout(&path, Duration::from_millis(300)).is_err(),
        "the in-flight blocking write still owns the lock"
    );

    park.release();
    disarm_write_park(&path);
    until(|| path.exists()).await;
    let loaded = load(&path).unwrap().unwrap();
    assert_eq!(loaded.upstreams[0].state, STATE_QUARANTINED);
    assert!(!sibling_path(&path, ".tmp").exists(), "the write committed");
    // Only after the write really ended does a contender get the lock.
    UsersFileLock::acquire_with_timeout(&path, Duration::from_millis(200))
        .expect("the finished write released the lock");
    let _ = std::fs::remove_dir_all(&dir);
}

// (A), final-snapshot variant: `finish` returns after the final write
// timed out, but the parked final writer still owns the lock until it
// really ends. Mutation: same as above — the owner-only guard frees the
// lock when `finish` returns.
#[tokio::test]
async fn a_parked_final_write_keeps_the_lock_after_finish_returned() {
    let dir = unique_dir("park_final");
    let path = dir.join("health.ktav");
    let r = rotator(vec![p("a")]);
    r.record_hard_failure(&p("a"));
    let (log, _rx) = logger();
    let park = arm_write_park(&path);
    let (saver, found) = start(
        vec![group("v4", r.clone())],
        Vec::new(),
        test_pool(),
        path.clone(),
        Duration::from_secs(3600),
        Duration::from_secs(1),
        log,
    );
    assert!(!found);
    saver.finish(&[group("v4", r.clone())], &path).await;
    assert!(!path.exists(), "the parked final write has not committed");
    assert!(
        UsersFileLock::acquire_with_timeout(&path, Duration::from_millis(300)).is_err(),
        "the parked final write still owns the lock"
    );
    park.release();
    disarm_write_park(&path);
    until(|| path.exists()).await;
    let loaded = load(&path).unwrap().unwrap();
    assert_eq!(loaded.upstreams[0].state, STATE_QUARANTINED);
    UsersFileLock::acquire_with_timeout(&path, Duration::from_millis(200))
        .expect("the finished final write released the lock");
    let _ = std::fs::remove_dir_all(&dir);
}

// Regression pin for (A): a contender is refused while a blocking write is
// in flight (and while the saver lives), and admitted once the saver has
// finished and the write has committed; no clone is kept forever.
#[tokio::test]
async fn the_lock_is_ours_again_right_after_a_round_write_completes() {
    let dir = unique_dir("park_hold_release");
    let path = dir.join("health.ktav");
    let r = rotator(vec![p("a")]);
    r.record_hard_failure(&p("a"));
    let (log, _rx) = logger();
    let park = arm_write_park(&path);
    let (saver, found) = start(
        vec![group("v4", r.clone())],
        Vec::new(),
        test_pool(),
        path.clone(),
        Duration::from_millis(50),
        Duration::from_secs(1),
        log,
    );
    assert!(!found);
    until(|| park.reached()).await;
    assert!(
        UsersFileLock::acquire_with_timeout(&path, Duration::from_millis(200)).is_err(),
        "the in-flight write holds the lock"
    );
    park.release();
    disarm_write_park(&path);
    until(|| path.exists()).await;
    saver.finish(&[group("v4", r)], &path).await;
    UsersFileLock::acquire_with_timeout(&path, Duration::from_millis(200))
        .expect("the finished saver and its writes released the lock");
    let _ = std::fs::remove_dir_all(&dir);
}

// (B) A failed commit may still have published its content (unix dir-sync
// failure, windows 1176/1177). When the picture later returns to the last
// SUCCESSFUL baseline, the dirty state must force a rewrite: with the
// baseline kept, the equality skip fires and the file keeps the failed
// round's quarantined content forever. Mutation: no `last = None` on the
// save error path.
#[tokio::test(start_paused = true)]
async fn a_failed_commit_forces_a_rewrite_when_the_picture_returns() {
    let dir = unique_dir("dirty_baseline");
    let path = dir.join("health.ktav");
    let r = rotator(vec![p("a")]);
    let (log, mut rx) = logger();
    let (handle, stop, _lock) = spawn_saver(
        vec![group("v4", r.clone())],
        &path,
        Duration::from_secs(10),
        None,
        log,
    )
    .await;

    // Round 1: the first picture (alive) is written.
    tokio::time::advance(Duration::from_secs(10)).await;
    until(|| matches!(load(&path), Ok(Some(_)))).await;
    assert_eq!(
        load(&path).unwrap().unwrap().upstreams[0].state,
        STATE_ALIVE
    );

    // Round 2: the upstream dies; the commit "fails" after the new content
    // reached the target — the undetermined outcome of a real commit.
    arm_commit_failure(&path, InjectedFailure::Publish);
    r.record_hard_failure(&p("a"));
    tokio::time::advance(Duration::from_secs(10)).await;
    until(|| {
        matches!(load(&path), Ok(Some(ref file)) if file.upstreams.first().is_some_and(|u| u.state == STATE_QUARANTINED))
    })
    .await;
    let mut saw_failure = false;
    until(|| {
        for line in drain(&mut rx) {
            if line.contains("Could not save") {
                saw_failure = true;
            }
        }
        saw_failure
    })
    .await;
    disarm_commit_failure(&path);

    // Round 3: the upstream recovers into exactly the last successful
    // baseline (a success forgets the counters) — the write must happen
    // anyway, over the published-but-uncommitted content.
    r.record_success(&p("a"));
    tokio::time::advance(Duration::from_secs(10)).await;
    until(|| matches!(load(&path), Ok(Some(ref file)) if file.upstreams.first().is_some_and(|u| u.state == STATE_ALIVE)))
        .await;
    stop.notify_one();
    handle.await.unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

// (B), missing-target variant: a failed commit can also leave NO target
// (windows 1176 removes the replaced file). The dirty baseline must still
// force the next write. Mutation: the skip fires while failing and the
// target is never recreated.
#[tokio::test(start_paused = true)]
async fn a_failed_commit_that_removed_the_target_still_rewrites() {
    let dir = unique_dir("dirty_baseline_vanish");
    let path = dir.join("health.ktav");
    let r = rotator(vec![p("a")]);
    let (log, _rx) = logger();
    let (handle, stop, _lock) = spawn_saver(
        vec![group("v4", r.clone())],
        &path,
        Duration::from_secs(10),
        None,
        log,
    )
    .await;

    tokio::time::advance(Duration::from_secs(10)).await;
    until(|| matches!(load(&path), Ok(Some(_)))).await;

    // The commit fails and the target is gone.
    arm_commit_failure(&path, InjectedFailure::Vanish);
    r.record_hard_failure(&p("a"));
    tokio::time::advance(Duration::from_secs(10)).await;
    until(|| load(&path).map(|file| file.is_none()).unwrap_or(true)).await;
    disarm_commit_failure(&path);

    // Back to the baseline picture: the write must recreate the file.
    r.record_success(&p("a"));
    tokio::time::advance(Duration::from_secs(10)).await;
    until(|| matches!(load(&path), Ok(Some(ref file)) if file.upstreams.first().is_some_and(|u| u.state == STATE_ALIVE)))
        .await;
    stop.notify_one();
    handle.await.unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

// (C) The compared state must include the quarantine deadline: a reset +
// re-trip between two ticks keeps trips/failures identical, so without
// the expiry the write is skipped and a restart would restore the old
// deadline. Mutation: expiry missing from the compared state.
#[tokio::test(start_paused = true)]
async fn a_retrip_with_identical_counters_still_writes_the_new_deadline() {
    let dir = unique_dir("retrip_deadline");
    let path = dir.join("health.ktav");
    let r = rotator(vec![p("a")]);
    // Reset + re-trip: identical trips/failures counters, a fresh deadline.
    r.record_hard_failure(&p("a"));
    r.record_success(&p("a"));
    r.record_hard_failure(&p("a"));
    // The saved baseline: same compared fields, an ancient deadline — as
    // if the file was written long before the re-trip.
    let mut initial = file(vec![grouped(
        &upstream_label(&p("a")),
        0,
        "v4",
        STATE_QUARANTINED,
        500,
        1,
    )]);
    initial.saved_at = 0;
    let (log, _rx) = logger();
    let (handle, stop, _lock) = spawn_saver(
        vec![group("v4", r.clone())],
        &path,
        Duration::from_secs(10),
        Some(initial),
        log,
    )
    .await;
    tokio::time::advance(Duration::from_secs(11)).await;
    until(|| matches!(load(&path), Ok(Some(_)))).await;
    let loaded = load(&path).unwrap().unwrap();
    let saved = &loaded.upstreams[0];
    assert_eq!(saved.state, STATE_QUARANTINED);
    assert_eq!(saved.trips, 1);
    assert!(
        saved.remaining_sec > 0 && saved.remaining_sec <= 30,
        "the fresh deadline is persisted, not the ancient one: {saved:?}"
    );
    // The fresh deadline restores as a live quarantine, not as probation.
    let (restored, _warnings) = restore(&[group("v4", r.clone())], &loaded, unix_now());
    assert_eq!(restored.quarantined, 1);
    stop.notify_one();
    handle.await.unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

// (C), positive control: plain passage of time (the countdown ticking
// inside an unchanged picture) must stay write-free — the absolute
// deadline is stable and within the one-interval tolerance. Mutation:
// the countdown (or a too-tight deadline comparison) turning time into
// change.
#[tokio::test(start_paused = true)]
async fn a_quarantine_countdown_alone_writes_nothing() {
    let dir = unique_dir("countdown_quiet");
    let path = dir.join("health.ktav");
    let r = rotator(vec![p("a")]);
    r.record_hard_failure(&p("a"));
    let initial = snapshot(&[group("v4", r.clone())], unix_now());
    let (log, _rx) = logger();
    let skips = arm_skip_counter(&path);
    let (handle, stop, _lock) = spawn_saver(
        vec![group("v4", r.clone())],
        &path,
        Duration::from_secs(10),
        Some(initial),
        log,
    )
    .await;
    for _ in 0..3 {
        tokio::time::advance(Duration::from_secs(10)).await;
    }
    // Every tick was decided as "unchanged": a write would leave the count
    // short and `until` panics (no sleeping on a blocking write).
    until(|| skips.load(std::sync::atomic::Ordering::SeqCst) >= 3).await;
    assert!(!path.exists(), "passage of time alone must not write");
    stop.notify_one();
    handle.await.unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

// (D) Duplicate records under one persisted key are unattributable: the
// whole key is dropped (not last-wins), other keys still restore, and
// exactly one warning is logged per duplicated key. Mutation: the plain
// HashMap last-wins collect.
#[test]
fn duplicate_records_are_dropped_whole_with_one_warning() {
    let r = rotator(vec![p("a"), p("b")]);
    let saved = file(vec![
        grouped("socks5://a:1080", 0, "v4", STATE_QUARANTINED, 500, 2),
        grouped("socks5://a:1080", 0, "v4", STATE_PROBATION, 0, 5),
        grouped("socks5://a:1080", 0, "v4", STATE_ALIVE, 0, 0),
        grouped("socks5://b:1080", 0, "v4", STATE_QUARANTINED, 100, 1),
    ]);
    let (restored, warnings) = restore(&[group("v4", r.clone())], &saved, NOW);
    assert_eq!(restored.quarantined, 1, "only b is restored: {warnings:?}");
    assert!(r.is_quarantined(&p("b")));
    assert!(
        !r.is_quarantined(&p("a")),
        "no copy of a duplicated key wins"
    );
    assert_eq!(
        warnings.len(),
        1,
        "one warning per duplicated key: {warnings:?}"
    );
    assert!(warnings[0].contains("socks5://a:1080"), "{warnings:?}");
}

// (D) A persisted key matching MORE THAN ONE upstream of a group (same
// label, different secrets) is restored for none of them, with exactly
// one warning per ambiguous key. Mutation: the first live match wins and
// both upstreams get the same health cell.
#[test]
fn an_ambiguous_record_is_restored_for_no_upstream_and_warned_once() {
    let r = rotator(vec![
        p("h").with_auth("alice", "pw-one"),
        p("h").with_auth("alice", "pw-two"),
    ]);
    let saved = file(vec![grouped(
        "socks5://alice@h:1080",
        0,
        "v4",
        STATE_QUARANTINED,
        500,
        3,
    )]);
    let (restored, warnings) = restore(&[group("v4", r.clone())], &saved, NOW);
    assert_eq!(
        restored,
        Restored::default(),
        "nothing restored: {warnings:?}"
    );
    assert!(
        r.health()
            .iter()
            .all(|h| h.health.state == UpstreamState::Alive),
        "neither alias takes the record"
    );
    assert_eq!(
        warnings.len(),
        1,
        "one warning per ambiguous key: {warnings:?}"
    );
    assert!(
        warnings[0].contains("socks5://alice@h:1080"),
        "{warnings:?}"
    );
}

// (D), save side: aliasing upstreams (same label, different secrets) are
// saved WITHOUT their secrets, and the round trip restores nothing for
// their duplicated key. Mutation: writing a password or a digest into
// the file, or a last-wins restore.
#[test]
fn aliasing_upstreams_are_saved_without_secrets_and_never_restored() {
    let dir = unique_dir("alias_roundtrip");
    let path = dir.join("health.ktav");
    let r = rotator(vec![
        p("x").with_auth("alice", "secret-one"),
        p("x").with_auth("alice", "secret-two"),
    ]);
    r.record_hard_failure(&p("x").with_auth("alice", "secret-one"));
    let snap = snapshot(&[group("v4", r.clone())], NOW);
    save(&path, &snap).unwrap();
    let text = std::fs::read_to_string(&path).unwrap();
    assert!(
        !text.contains("secret-one") && !text.contains("secret-two"),
        "no secret reaches the file: {text}"
    );
    let loaded = load(&path).unwrap().unwrap();
    let (restored, warnings) = restore(&[group("v4", r.clone())], &loaded, NOW + 1);
    assert_eq!(restored.total(), 0, "identical keys cannot be attributed");
    assert_eq!(
        warnings.len(),
        1,
        "one warning for the duplicated key: {warnings:?}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

// (C) the compared deadline is stable: plain passage of time (or the
// whole-second truncation jitter) is "unchanged", a different expiry with the
// same counters is a re-trip and must be written, whatever the save interval.
// Mutations: tolerance 0 fails the first two asserts; an interval-sized
// tolerance (the old behaviour: expiry 40 -> 48 with a 30 s interval) fails
// the last one.
#[test]
fn unchanged_compares_the_deadline_stably() {
    let build = |saved_at: u64, remaining: u64| {
        let mut f = file(vec![grouped(
            &upstream_label(&p("a")),
            0,
            "v4",
            STATE_QUARANTINED,
            remaining,
            1,
        )]);
        f.saved_at = saved_at;
        f
    };
    let last = build(1000, 40); // deadline 1040
    assert!(
        unchanged(&last, &build(1010, 30)),
        "time passed, same deadline"
    );
    assert!(
        unchanged(&last, &build(1011, 30)),
        "1 s of truncation jitter"
    );
    assert!(
        unchanged(&last, &build(1010, 32)),
        "2 s of truncation jitter"
    );
    assert!(!unchanged(&last, &build(1000, 48)), "a re-trip 8 s later");
    assert!(!unchanged(&last, &build(1000, 43)), "beyond the jitter");
}
