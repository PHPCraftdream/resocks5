use super::writer_tests::{acquired, spawn_saver};
use super::*;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use resocks5_net::rating::{QuarantinePolicy, RatingPolicy};
use resocks5_net::types::ProxyConfig;

pub(super) const NOW: u64 = 1_000_000;

pub(super) fn rotator(proxies: Vec<ProxyConfig>) -> Arc<ProxyRotator> {
    Arc::new(
        ProxyRotator::try_with_quarantine(
            proxies,
            RatingPolicy::default(),
            QuarantinePolicy::default()
                .with_threshold(1)
                .with_initial(Duration::from_secs(30))
                .with_max(Duration::from_secs(600)),
            16,
            Duration::from_secs(60),
        )
        .unwrap(),
    )
}

/// A fresh pool with free permits: `start` reserves one per direct probe.
pub(super) fn test_pool() -> Arc<resocks5_net::pool::ProxyPool> {
    Arc::new(resocks5_net::pool::ProxyPool::new(
        Default::default(),
        Duration::from_secs(2),
        4,
    ))
}

pub(super) fn p(host: &str) -> ProxyConfig {
    ProxyConfig::socks5(host, 1080)
}

pub(super) fn unique_dir(tag: &str) -> PathBuf {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let dir = std::env::temp_dir().join(format!(
        "resocks5_health_{}_{}_{}",
        std::process::id(),
        tag,
        COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn entry(upstream: &str, gate: u8, state: &str, remaining_sec: u64, trips: u32) -> HealthEntry {
    grouped(upstream, gate, "", state, remaining_sec, trips)
}

pub(super) fn grouped(
    upstream: &str,
    gate: u8,
    group: &str,
    state: &str,
    remaining_sec: u64,
    trips: u32,
) -> HealthEntry {
    HealthEntry {
        upstream: upstream.to_owned(),
        gate,
        group: group.to_owned(),
        state: state.to_owned(),
        remaining_sec,
        trips,
        failures: trips,
    }
}

pub(super) fn group(name: &str, rotator: Arc<ProxyRotator>) -> HealthGroup {
    HealthGroup {
        name: name.to_owned(),
        rotator,
    }
}

pub(super) fn file(entries: Vec<HealthEntry>) -> HealthFile {
    HealthFile {
        saved_at: NOW,
        upstreams: entries,
    }
}

pub(super) fn logger() -> (
    Arc<Logger>,
    tokio::sync::mpsc::Receiver<crate::logger::ELog>,
) {
    let (tx, rx) = tokio::sync::mpsc::channel(64);
    (
        Arc::new(Logger::new(tx, crate::logger::LogConfig::default())),
        rx,
    )
}

#[test]
fn label_shows_protocol_and_user_but_never_the_password() {
    let proxy = p("1.2.3.4").with_auth("alice", "s3cret");
    assert_eq!(upstream_label(&proxy), "socks5://alice@1.2.3.4:1080");
    assert_eq!(upstream_label(&p("1.2.3.4")), "socks5://1.2.3.4:1080");
    assert_eq!(
        upstream_label(&ProxyConfig::https("h.example", 443)),
        "https://h.example:443"
    );
    assert_eq!(
        upstream_label(&ProxyConfig::http("h.example", 8080)),
        "http://h.example:8080"
    );
}

#[test]
fn snapshot_lists_every_upstream_with_state_gate_and_counters() {
    let exits = rotator(vec![p("a"), p("b")]);
    let gates = rotator(vec![p("g").with_gate_level(2)]);
    exits.record_hard_failure(&p("b"));
    let snap = snapshot(
        &[group("gate2", gates.clone()), group("v4", exits.clone())],
        NOW,
    );
    assert_eq!(snap.saved_at, NOW);
    let labels: Vec<_> = snap.upstreams.iter().map(|e| e.upstream.as_str()).collect();
    assert_eq!(
        labels,
        ["socks5://g:1080", "socks5://a:1080", "socks5://b:1080"]
    );
    assert_eq!(snap.upstreams[0].gate, 2);
    assert_eq!(snap.upstreams[1].state, STATE_ALIVE);
    assert_eq!(snap.upstreams[2].state, STATE_QUARANTINED);
    assert!(snap.upstreams[2].remaining_sec > 0);
    assert_eq!(snap.upstreams[2].trips, 1);
    assert_eq!(snap.upstreams[2].failures, 1);
}

#[test]
fn the_file_round_trips_through_ktav_without_passwords() {
    let dir = unique_dir("roundtrip");
    let path = dir.join("resocks5.health.ktav");
    let r = rotator(vec![p("a").with_auth("alice", "s3cret"), p("b")]);
    r.record_hard_failure(&p("b"));
    let snap = snapshot(&[group("v4", r)], NOW);
    assert_eq!(snap.upstreams[0].group, "v4");
    save(&path, &snap).unwrap();
    let text = std::fs::read_to_string(&path).unwrap();
    assert!(!text.contains("s3cret"), "{text}");
    assert!(text.contains("socks5://alice@a:1080"), "{text}");
    assert_eq!(load(&path).unwrap(), Some(snap));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn loading_a_missing_file_is_a_normal_first_start() {
    let dir = unique_dir("missing");
    assert_eq!(load(&dir.join("nope.ktav")).unwrap(), None);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn loading_a_garbage_file_is_an_error() {
    let dir = unique_dir("garbage");
    let path = dir.join("health.ktav");
    std::fs::write(&path, "saved_at: not-a-number\n").unwrap();
    assert!(load(&path).is_err());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn optional_fields_default_when_absent() {
    let parsed: HealthFile = ktav::from_str(
        "upstreams: [\n    {\n        upstream: socks5://a:1080\n        state: alive\n    }\n]\n",
    )
    .unwrap();
    assert_eq!(parsed.saved_at, 0);
    assert_eq!(parsed.upstreams[0].gate, 0);
    assert_eq!(parsed.upstreams[0].group, "");
    assert_eq!(parsed.upstreams[0].trips, 0);
    assert_eq!(parsed.upstreams[0].remaining_sec, 0);
}

#[test]
fn restore_puts_quarantine_probation_and_the_countdown_back() {
    let r = rotator(vec![p("a"), p("b"), p("c"), p("d"), p("e")]);
    let saved = file(vec![
        entry("socks5://a:1080", 0, STATE_QUARANTINED, 100, 2),
        entry("socks5://b:1080", 0, STATE_QUARANTINED, 20, 1),
        entry("socks5://c:1080", 0, STATE_PROBATION, 0, 3),
        entry("socks5://d:1080", 0, STATE_ALIVE, 0, 0),
    ]);
    // 30 s of downtime: a keeps 70 s, b ran out and goes to probation.
    let restored = restore(&[group("v4", r.clone())], &saved, NOW + 30).0;
    assert_eq!(
        restored,
        Restored {
            quarantined: 1,
            probation: 2
        }
    );
    assert_eq!(restored.total(), 3);
    let health = r.health();
    assert_eq!(health[0].health.state, UpstreamState::Quarantined);
    assert!(health[0].health.remaining <= Duration::from_secs(70));
    assert!(health[0].health.remaining > Duration::from_secs(65));
    assert_eq!(health[0].health.trips, 2);
    assert_eq!(health[1].health.state, UpstreamState::Probation);
    assert_eq!(health[2].health.state, UpstreamState::Probation);
    assert_eq!(health[2].health.trips, 3);
    assert_eq!(health[3].health.state, UpstreamState::Alive);
    assert_eq!(health[4].health.state, UpstreamState::Alive);
}

#[test]
fn restored_dead_upstreams_leave_the_order_and_probation_is_probed() {
    let r = rotator(vec![p("a"), p("b"), p("c")]);
    let saved = file(vec![
        entry("socks5://a:1080", 0, STATE_QUARANTINED, 500, 1),
        entry("socks5://b:1080", 0, STATE_PROBATION, 0, 1),
    ]);
    restore(&[group("v4", r.clone())], &saved, NOW);
    for _ in 0..50 {
        let order = r.pick_order();
        assert_eq!(order.len(), 1);
        assert_eq!(order[0].host, "c");
    }
    let probes = r.take_probes();
    assert_eq!(probes.len(), 1);
    assert_eq!(probes[0].host, "b");
}

#[test]
fn unknown_upstreams_and_states_are_skipped() {
    let r = rotator(vec![p("a"), p("b")]);
    let saved = file(vec![
        entry("socks5://gone:1080", 0, STATE_QUARANTINED, 500, 1),
        entry("socks5://a:1080", 0, "exploded", 500, 1),
        entry("socks5://b:1080", 0, STATE_ALIVE, 0, 0),
    ]);
    assert_eq!(
        restore(&[group("v4", r.clone())], &saved, NOW).0,
        Restored::default()
    );
    assert!(r
        .health()
        .iter()
        .all(|h| h.health.state == UpstreamState::Alive));
}

#[test]
fn same_address_at_another_gate_level_is_a_different_upstream() {
    let plain = rotator(vec![p("x")]);
    let gate = rotator(vec![p("x").with_gate_level(2)]);
    let saved = file(vec![entry("socks5://x:1080", 2, STATE_QUARANTINED, 500, 1)]);
    let restored = restore(
        &[group("v4", plain.clone()), group("gate2", gate.clone())],
        &saved,
        NOW,
    )
    .0;
    assert_eq!(restored.total(), 1);
    assert!(!plain.is_quarantined(&p("x")));
    assert!(gate.is_quarantined(&p("x").with_gate_level(2)));
}

#[test]
fn the_same_upstream_in_two_groups_keeps_two_health_cells() {
    // V10: one endpoint in the v6 and v4 groups, opposite states. The round
    // trip must give each fresh rotator its own cell in both declaration
    // orders; dropping `group` from the restore key lets the last written
    // record win for both groups.
    let v6 = rotator(vec![p("x")]);
    let v4 = rotator(vec![p("x")]);
    let seeded = file(vec![grouped(
        "socks5://x:1080",
        0,
        "v6",
        STATE_QUARANTINED,
        500,
        2,
    )]);
    let both = [group("v6", v6.clone()), group("v4", v4.clone())];
    assert_eq!(
        restore(&both, &seeded, NOW).0.quarantined,
        1,
        "only the v6 cell takes the record"
    );
    let dir = unique_dir("two_groups");
    let path = dir.join("health.ktav");
    for flip in [false, true] {
        let snap = if flip {
            snapshot(&[group("v4", v4.clone()), group("v6", v6.clone())], NOW)
        } else {
            snapshot(&[group("v6", v6.clone()), group("v4", v4.clone())], NOW)
        };
        save(&path, &snap).unwrap();
        let loaded = load(&path).unwrap().unwrap();
        assert_eq!(loaded, snap, "the file round-trips");

        let fresh_v6 = rotator(vec![p("x")]);
        let fresh_v4 = rotator(vec![p("x")]);
        let (restored, order) = if flip {
            (
                restore(
                    &[group("v4", fresh_v4.clone()), group("v6", fresh_v6.clone())],
                    &loaded,
                    NOW,
                )
                .0,
                "v4 first",
            )
        } else {
            (
                restore(
                    &[group("v6", fresh_v6.clone()), group("v4", fresh_v4.clone())],
                    &loaded,
                    NOW,
                )
                .0,
                "v6 first",
            )
        };
        assert_eq!(
            restored.quarantined, 1,
            "only the v6 cell is dead ({order})"
        );
        assert!(
            fresh_v6.is_quarantined(&p("x")),
            "v6 keeps its quarantine ({order})"
        );
        assert_eq!(fresh_v6.health()[0].health.trips, 2);
        assert!(
            !fresh_v4.is_quarantined(&p("x")),
            "v4 stays alive ({order})"
        );
        assert_eq!(fresh_v4.health()[0].health.state, UpstreamState::Alive);
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn an_old_record_without_a_group_applies_to_every_matching_group() {
    // A file saved before the `group` field existed: the record is applied
    // to every rotator holding the (upstream, gate) pair — the old
    // behaviour (mutation: rejecting or skipping empty-group records).
    let dir = unique_dir("old_format");
    let path = dir.join("health.ktav");
    std::fs::write(
        &path,
        "saved_at: 1000000\nupstreams: [\n    {\n        upstream: socks5://x:1080\n        state: quarantined\n        remaining_sec: 500\n        trips: 2\n    }\n]\n",
    )
    .unwrap();
    let loaded = load(&path).unwrap().unwrap();
    assert_eq!(loaded.upstreams[0].group, "", "an old file has no group");
    let a = rotator(vec![p("x")]);
    let b = rotator(vec![p("x")]);
    let restored = restore(
        &[group("v6", a.clone()), group("v4", b.clone())],
        &loaded,
        NOW,
    )
    .0;
    assert_eq!(
        restored.quarantined, 2,
        "both groups take the legacy record"
    );
    assert!(a.is_quarantined(&p("x")));
    assert!(b.is_quarantined(&p("x")));
    assert_eq!(a.health()[0].health.trips, 2);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_different_user_at_the_same_address_is_a_different_upstream() {
    let r = rotator(vec![p("x").with_auth("alice", "pw")]);
    let saved = file(vec![entry(
        "socks5://bob@x:1080",
        0,
        STATE_QUARANTINED,
        500,
        1,
    )]);
    assert_eq!(
        restore(&[group("v4", r)], &saved, NOW).0,
        Restored::default()
    );
}

#[test]
fn a_saved_time_in_the_future_counts_as_no_downtime() {
    let r = rotator(vec![p("a")]);
    let mut saved = file(vec![entry("socks5://a:1080", 0, STATE_QUARANTINED, 100, 1)]);
    saved.saved_at = NOW + 5_000;
    restore(&[group("v4", r.clone())], &saved, NOW);
    assert!(r.health()[0].health.remaining > Duration::from_secs(95));
}

#[test]
fn a_success_after_restore_brings_the_upstream_back() {
    let r = rotator(vec![p("a"), p("b")]);
    let saved = file(vec![entry("socks5://a:1080", 0, STATE_PROBATION, 0, 4)]);
    restore(&[group("v4", r.clone())], &saved, NOW);
    r.record_success(&p("a"));
    assert!(!r.is_quarantined(&p("a")));
    assert_eq!(r.pick_order().len(), 2);
}

#[test]
fn resume_reads_the_file_and_restores() {
    let dir = unique_dir("resume");
    let path = dir.join("health.ktav");
    let before = rotator(vec![p("a"), p("b")]);
    before.record_hard_failure(&p("a"));
    save(&path, &snapshot(&[group("v4", before.clone())], NOW)).unwrap();

    let after = rotator(vec![p("a"), p("b")]);
    let resumed = resume(&[group("v4", after.clone())], &path, NOW + 1);
    assert!(resumed.saved.is_some());
    assert!(resumed.warning.is_none());
    assert_eq!(resumed.restored.quarantined, 1);
    assert!(after.is_quarantined(&p("a")));
    assert!(!after.is_quarantined(&p("b")));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn resume_without_a_file_changes_nothing() {
    let dir = unique_dir("resume_none");
    let r = rotator(vec![p("a")]);
    let resumed = resume(&[group("v4", r.clone())], &dir.join("nope.ktav"), NOW);
    assert!(resumed.saved.is_none());
    assert!(resumed.warning.is_none());
    assert_eq!(resumed.restored, Restored::default());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn resume_with_a_broken_file_warns_and_starts_clean() {
    let dir = unique_dir("resume_bad");
    let path = dir.join("health.ktav");
    std::fs::write(&path, "saved_at: nope\n").unwrap();
    let r = rotator(vec![p("a")]);
    let resumed = resume(&[group("v4", r.clone())], &path, NOW);
    assert!(resumed.saved.is_none());
    assert!(resumed.warning.unwrap().contains("health.ktav"));
    assert_eq!(resumed.restored, Restored::default());
    assert!(!r.is_quarantined(&p("a")));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn save_now_writes_a_loadable_snapshot() {
    let dir = unique_dir("save_now");
    let path = dir.join("health.ktav");
    let r = rotator(vec![p("a")]);
    r.record_hard_failure(&p("a"));
    save_now(&[group("v4", r)], &path);
    let loaded = load(&path).unwrap().unwrap();
    assert_eq!(loaded.upstreams[0].state, STATE_QUARANTINED);
    assert!(loaded.saved_at > 0);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn save_now_into_a_missing_directory_only_warns() {
    let dir = unique_dir("save_now_bad");
    let r = rotator(vec![p("a")]);
    save_now(
        &[group("v4", r)],
        &dir.join("no_such_dir").join("health.ktav"),
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn signature_ignores_the_countdown_and_the_timestamp() {
    let a = file(vec![entry("socks5://a:1080", 0, STATE_QUARANTINED, 100, 1)]);
    let mut b = file(vec![entry("socks5://a:1080", 0, STATE_QUARANTINED, 40, 1)]);
    b.saved_at += 60;
    assert_eq!(signature(&a), signature(&b));
    let c = file(vec![entry("socks5://a:1080", 0, STATE_PROBATION, 0, 1)]);
    assert_ne!(signature(&a), signature(&c));
}

#[test]
fn signature_changes_when_only_the_group_differs() {
    // Two records differing only in the routing group are a real change
    // (mutation: dropping `group` from the signature tuple).
    let v6 = file(vec![grouped(
        "socks5://x:1080",
        0,
        "v6",
        STATE_QUARANTINED,
        500,
        2,
    )]);
    let v4 = file(vec![grouped(
        "socks5://x:1080",
        0,
        "v4",
        STATE_QUARANTINED,
        500,
        2,
    )]);
    assert_ne!(signature(&v6), signature(&v4));
    let again = file(vec![grouped(
        "socks5://x:1080",
        0,
        "v6",
        STATE_QUARANTINED,
        100,
        2,
    )]);
    assert_eq!(
        signature(&v6),
        signature(&again),
        "the countdown still does not matter"
    );
}

pub(super) async fn settle() {
    for _ in 0..8 {
        tokio::task::yield_now().await;
    }
}

/// Yield until `check` holds (bounded): lets an offloaded write land. Pure
/// yields first so paused-clock tests stay deterministic; the slow path
/// sleeps (≤ 2 s total), which under a paused clock auto-advances time —
/// every paused call site keeps ≥ 10 s of ticker slack, so no tick fires.
/// Never a way to wait for a tick — ticks come from `advance`.
pub(super) async fn until(mut check: impl FnMut() -> bool) {
    for _ in 0..100 {
        if check() {
            return;
        }
        tokio::task::yield_now().await;
    }
    for _ in 0..100 {
        if check() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("condition never became true");
}

#[tokio::test(start_paused = true)]
async fn the_saver_writes_on_change_and_stays_quiet_otherwise() {
    let dir = unique_dir("saver");
    let path = dir.join("health.ktav");
    let r = rotator(vec![p("a"), p("b")]);
    let (log, _rx) = logger();
    let (handle, stop, _lock) = spawn_saver(
        vec![group("v4", r.clone())],
        &path,
        Duration::from_secs(10),
        None,
        log,
    )
    .await;

    tokio::time::advance(Duration::from_secs(11)).await;
    until(|| path.exists()).await;
    let first = load(&path).unwrap().unwrap();
    assert!(first.upstreams.iter().all(|e| e.state == STATE_ALIVE));

    // Nothing changed: the file is not rewritten.
    std::fs::remove_file(&path).unwrap();
    tokio::time::advance(Duration::from_secs(10)).await;
    settle().await;
    assert!(!path.exists());

    // A death is saved on the next round.
    r.record_hard_failure(&p("b"));
    tokio::time::advance(Duration::from_secs(10)).await;
    until(|| path.exists()).await;
    let second = load(&path).unwrap().unwrap();
    assert_eq!(second.upstreams[1].state, STATE_QUARANTINED);
    assert_eq!(second.upstreams[0].state, STATE_ALIVE);

    stop.notify_one();
    handle.await.unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test(start_paused = true)]
async fn the_saver_skips_the_write_when_the_restored_picture_is_unchanged() {
    let dir = unique_dir("saver_initial");
    let path = dir.join("health.ktav");
    let r = rotator(vec![p("a")]);
    r.record_hard_failure(&p("a"));
    // Same clock as the saver.
    let initial = snapshot(&[group("v4", r.clone())], unix_now());
    let (log, _rx) = logger();
    let skips = arm_skip_counter(&path);
    let (handle, stop, _lock) = spawn_saver(
        vec![group("v4", r)],
        &path,
        Duration::from_secs(10),
        Some(initial),
        log,
    )
    .await;
    // One tick per advance (the interval delays missed ticks, so a single
    // long jump would be one tick). Each tick must be skipped as unchanged,
    // not merely "no file yet": a write leaves the count short and `until`
    // panics.
    for round in 1..=2u64 {
        tokio::time::advance(Duration::from_secs(10)).await;
        until(|| skips.load(std::sync::atomic::Ordering::SeqCst) >= round).await;
    }
    assert!(!path.exists());
    stop.notify_one();
    handle.await.unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test(start_paused = true)]
async fn a_failing_save_is_logged_once_and_retried() {
    let dir = unique_dir("saver_fail");
    let missing = dir.join("later");
    let path = missing.join("health.ktav");
    let r = rotator(vec![p("a")]);
    let (log, mut rx) = logger();
    let stop = Arc::new(tokio::sync::Notify::new());
    // The lock sits on the existing directory: the saver's path has no
    // parent yet — that is the injected failure.
    let lock = acquired(&dir);
    let started = Arc::new(tokio::sync::Notify::new());
    let handle = tokio::spawn(run_saver(
        vec![group("v4", r)],
        path.clone(),
        Duration::from_secs(10),
        None,
        log,
        Arc::clone(&stop),
        Arc::clone(&lock),
        Some(Arc::clone(&started)),
    ));
    // Explicit first-tick acknowledgement instead of settle() yields.
    started.notified().await;

    for _ in 0..3 {
        tokio::time::advance(Duration::from_secs(10)).await;
        settle().await;
    }
    let mut messages = 0;
    until(|| {
        while rx.try_recv().is_ok() {
            messages += 1;
        }
        messages > 0
    })
    .await;
    assert_eq!(messages, 1, "one log line per failure streak");
    assert!(!path.exists());

    std::fs::create_dir_all(&missing).unwrap();
    tokio::time::advance(Duration::from_secs(10)).await;
    until(|| path.exists()).await;
    assert!(path.exists(), "the save is retried after the failure");

    stop.notify_one();
    handle.await.unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

pub(super) fn drain(rx: &mut tokio::sync::mpsc::Receiver<crate::logger::ELog>) -> Vec<String> {
    let mut lines = Vec::new();
    while let Ok(line) = rx.try_recv() {
        match line {
            crate::logger::ELog::Log(text) | crate::logger::ELog::Error(text) => lines.push(text),
        }
    }
    lines
}

#[tokio::test]
async fn the_final_snapshot_writes_a_loadable_file() {
    let dir = unique_dir("save_final");
    let path = dir.join("health.ktav");
    let r = rotator(vec![p("a")]);
    r.record_hard_failure(&p("a"));
    let (log, _rx) = logger();
    save_final(&[group("v4", r)], &path, &log, acquired(&path)).await;
    let loaded = load(&path).unwrap().unwrap();
    assert_eq!(loaded.upstreams[0].state, STATE_QUARANTINED);
    assert!(loaded.saved_at > 0);
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn a_final_snapshot_into_a_missing_directory_only_warns() {
    let dir = unique_dir("save_final_bad");
    let r = rotator(vec![p("a")]);
    let (log, mut rx) = logger();
    let path = dir.join("no_such_dir").join("health.ktav");
    save_final(&[group("v4", r)], &path, &log, acquired(&dir)).await;
    // The failure is reported, not raised, and nothing is created.
    let lines = drain(&mut rx).join(
        "
",
    );
    assert!(lines.contains("could not save"), "warned: {lines:?}");
    assert!(!path.exists() && !dir.join("no_such_dir").exists());
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn start_restores_probes_the_due_ones_and_keeps_saving() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let alive = ProxyConfig::socks5("127.0.0.1", listener.local_addr().unwrap().port());
    let dead = p("zzz");
    let r = rotator(vec![alive.clone(), dead.clone()]);
    let dir = unique_dir("start");
    let path = dir.join("health.ktav");
    let mut saved = file(vec![
        entry(&upstream_label(&alive), 0, STATE_PROBATION, 0, 2),
        entry("socks5://zzz:1080", 0, STATE_QUARANTINED, 500, 1),
    ]);
    saved.saved_at = unix_now();
    save(&path, &saved).unwrap();
    let (log, mut rx) = logger();

    let (saver, found) = start(
        vec![group("v4", r.clone())],
        vec![r.clone()],
        test_pool(),
        path.clone(),
        Duration::from_millis(50),
        Duration::from_secs(2),
        log,
    );
    assert!(found, "a saved picture was read");
    // Both are held back at once; the background probe frees the reachable one.
    assert!(r.is_quarantined(&dead));
    for _ in 0..100 {
        if !r.is_quarantined(&alive) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(!r.is_quarantined(&alive), "the probe never freed it");
    assert!(r.is_quarantined(&dead));

    let lines = drain(&mut rx).join("\n");
    assert!(lines.contains("restored 2 dead upstream(s)"), "{lines}");
    assert!(lines.contains("reachable again"), "{lines}");

    // The recovery is written out by the running saver.
    for _ in 0..100 {
        // Tolerate the writer replacing the file under the read.
        if load(&path)
            .ok()
            .flatten()
            .is_some_and(|now| now.upstreams[0].state == STATE_ALIVE)
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let now = load(&path).unwrap().unwrap();
    assert_eq!(now.upstreams[0].state, STATE_ALIVE);
    assert_eq!(now.upstreams[1].state, STATE_QUARANTINED);

    saver.finish(&[group("v4", r)], &path).await;
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn start_without_a_file_creates_it_and_logs_nothing_about_restoring() {
    let r = rotator(vec![p("a")]);
    let dir = unique_dir("start_none");
    let path = dir.join("health.ktav");
    let (log, mut rx) = logger();
    let (saver, found) = start(
        vec![group("v4", r.clone())],
        Vec::new(),
        test_pool(),
        path.clone(),
        Duration::from_millis(30),
        Duration::from_secs(1),
        log,
    );
    assert!(!found, "nothing was saved yet");
    for _ in 0..100 {
        if path.exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(path.exists(), "a first start writes the file");
    assert!(!drain(&mut rx).join("\n").contains("restored"));
    saver.finish(&[group("v4", r)], &path).await;
    let _ = std::fs::remove_dir_all(&dir);
}

/// A listener that counts accepted connections; a reachability probe only
/// needs the TCP handshake, so one count equals one direct probe.
pub(super) async fn counting_listener() -> (u16, Arc<AtomicUsize>, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let hits = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&hits);
    let task = tokio::spawn(async move {
        while let Ok((_stream, _)) = listener.accept().await {
            counter.fetch_add(1, Ordering::Relaxed);
        }
    });
    (port, hits, task)
}

#[tokio::test]
async fn start_probes_only_the_directly_dialed_rotators() {
    // V09: the restored probation of an inner gate must not be handed to a
    // direct probe — the gate is only reachable through its prefix, and the
    // direct connect would falsely re-quarantine it. Only the `direct`
    // rotators (outermost gate, exits) are probed.
    let (gate_port, gate_hits, gate_accepts) = counting_listener().await;
    let (exit_port, exit_hits, exit_accepts) = counting_listener().await;
    let gate_proxy = ProxyConfig::socks5("127.0.0.1", gate_port).with_gate_level(1);
    let exit_proxy = ProxyConfig::socks5("127.0.0.1", exit_port);
    let gate_rotator = rotator(vec![gate_proxy.clone()]);
    let exit_rotator = rotator(vec![exit_proxy.clone()]);
    let dir = unique_dir("start_direct_only");
    let path = dir.join("health.ktav");
    let mut saved = file(vec![
        grouped(
            &upstream_label(&gate_proxy),
            1,
            "gate1",
            STATE_PROBATION,
            0,
            1,
        ),
        grouped(&upstream_label(&exit_proxy), 0, "v4", STATE_PROBATION, 0, 1),
    ]);
    saved.saved_at = unix_now();
    save(&path, &saved).unwrap();
    let (log, _rx) = logger();

    let (saver, found) = start(
        vec![
            group("gate1", gate_rotator.clone()),
            group("v4", exit_rotator.clone()),
        ],
        vec![exit_rotator.clone()],
        test_pool(),
        path.clone(),
        Duration::from_secs(60),
        Duration::from_secs(2),
        log,
    );
    assert!(found, "a saved picture was read");

    // >= 200 ms of slack for the spawned probes (Windows ~15.6 ms tick).
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        gate_hits.load(Ordering::Relaxed),
        0,
        "the inner gate must not be probed directly"
    );
    assert!(
        exit_hits.load(Ordering::Relaxed) >= 1,
        "the directly dialed exit is probed"
    );
    // The gate keeps its probation slot for the chain probe; the exit's own
    // probe freed it.
    assert!(gate_rotator.is_quarantined(&gate_proxy));
    assert!(!exit_rotator.is_quarantined(&exit_proxy));

    saver
        .finish(
            &[
                group("gate1", gate_rotator.clone()),
                group("v4", exit_rotator.clone()),
            ],
            &path,
        )
        .await;
    gate_accepts.abort();
    exit_accepts.abort();
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn a_stale_temp_from_a_crashed_run_is_reclaimed_instead_of_blocking_saves() {
    // V02 orphan recovery: write_atomic creates its temp with create_new, so
    // a temp left by a crashed run would fail every later save forever
    // (mutation: removing the reclaim leaves the file unwritten).
    let dir = unique_dir("orphan_temp");
    let path = dir.join("health.ktav");
    let temp = sibling_path(&path, ".tmp");
    std::fs::write(&temp, "orphan of a crashed run").unwrap();
    let r = rotator(vec![p("a")]);
    r.record_hard_failure(&p("a"));
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
    assert!(!found, "a temp is not a saved picture");
    for _ in 0..100 {
        if path.exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        path.exists(),
        "the orphan temp did not block the first save"
    );
    assert!(!temp.exists(), "the orphan temp was reclaimed");
    let loaded = load(&path).unwrap().unwrap();
    assert_eq!(loaded.upstreams[0].state, STATE_QUARANTINED);
    saver.finish(&[group("v4", r)], &path).await;
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn finish_writes_the_final_snapshot_without_waiting_for_a_tick() {
    // V02 shutdown: the last picture must reach the disk through the single
    // writer, even when no round ever fired (mutation: dropping the final
    // save leaves no file at all).
    let dir = unique_dir("finish_final");
    let path = dir.join("health.ktav");
    let r = rotator(vec![p("a"), p("b")]);
    let (log, _rx) = logger();
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
    r.record_hard_failure(&p("b"));
    saver.finish(&[group("v4", r.clone())], &path).await;
    let loaded = load(&path).unwrap().unwrap();
    assert_eq!(loaded.upstreams[1].state, STATE_QUARANTINED);
    assert!(!sibling_path(&path, ".tmp").exists(), "no temp is left");
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn repeated_finish_cycles_leave_a_valid_file_and_no_temp() {
    // V02 stop protocol: the loop must be joined before the final write, so
    // a round writer can never collide with the final one over the shared
    // temp (mutation: finishing without awaiting the task races the two
    // writers and leaves a stale picture or a leftover temp).
    let dir = unique_dir("finish_cycles");
    let path = dir.join("health.ktav");
    let r = rotator(vec![p("a"), p("b")]);
    r.record_hard_failure(&p("b"));
    let (log, _rx) = logger();
    for round in 0u32..3 {
        let (saver, found) = start(
            vec![group("v4", r.clone())],
            Vec::new(),
            test_pool(),
            path.clone(),
            Duration::from_millis(20),
            Duration::from_secs(1),
            log.clone(),
        );
        assert_eq!(found, round > 0, "round {round} finds the previous file");
        // Flip b so every cycle has a real change to persist.
        if round % 2 == 0 {
            r.record_success(&p("b"));
        } else {
            r.record_hard_failure(&p("b"));
        }
        saver.finish(&[group("v4", r.clone())], &path).await;
        let loaded = load(&path)
            .unwrap()
            .unwrap_or_else(|| panic!("round {round}: no file"));
        let expected = if round % 2 == 0 {
            STATE_ALIVE
        } else {
            STATE_QUARANTINED
        };
        assert_eq!(loaded.upstreams[1].state, expected, "round {round}");
        assert!(
            !sibling_path(&path, ".tmp").exists(),
            "round {round}: no temp is left"
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
}
