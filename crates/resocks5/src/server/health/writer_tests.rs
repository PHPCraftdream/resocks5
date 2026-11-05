//! Writer-lifecycle tests: the cross-process health lock, the per-write
//! temp reclaim, the pre-probe saver baseline and the logger-channel
//! shutdown reports. Pure-state tests live in `tests.rs`.

use super::tests::{
    counting_listener, drain, file, group, grouped, logger, p, rotator, test_pool, unique_dir,
    until,
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
    assert!(lines[0].contains("locked"), "{lines:?}");
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
        !lines.iter().any(|line| line.contains("locked")),
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
