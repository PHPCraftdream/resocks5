use super::*;
use std::sync::atomic::{AtomicU64, Ordering};

use resocks5_net::rating::{QuarantinePolicy, RatingPolicy};
use resocks5_net::types::ProxyConfig;

const NOW: u64 = 1_000_000;

fn rotator(proxies: Vec<ProxyConfig>) -> Arc<ProxyRotator> {
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

fn p(host: &str) -> ProxyConfig {
    ProxyConfig::socks5(host, 1080)
}

fn unique_dir(tag: &str) -> PathBuf {
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
    HealthEntry {
        upstream: upstream.to_owned(),
        gate,
        state: state.to_owned(),
        remaining_sec,
        trips,
        failures: trips,
    }
}

fn file(entries: Vec<HealthEntry>) -> HealthFile {
    HealthFile {
        saved_at: NOW,
        upstreams: entries,
    }
}

fn logger() -> (
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
    let snap = snapshot(&[gates, exits], NOW);
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
    let snap = snapshot(&[r], NOW);
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
    let restored = restore(std::slice::from_ref(&r), &saved, NOW + 30);
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
    restore(std::slice::from_ref(&r), &saved, NOW);
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
        restore(std::slice::from_ref(&r), &saved, NOW),
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
    let restored = restore(&[plain.clone(), gate.clone()], &saved, NOW);
    assert_eq!(restored.total(), 1);
    assert!(!plain.is_quarantined(&p("x")));
    assert!(gate.is_quarantined(&p("x").with_gate_level(2)));
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
    assert_eq!(restore(&[r], &saved, NOW), Restored::default());
}

#[test]
fn a_saved_time_in_the_future_counts_as_no_downtime() {
    let r = rotator(vec![p("a")]);
    let mut saved = file(vec![entry("socks5://a:1080", 0, STATE_QUARANTINED, 100, 1)]);
    saved.saved_at = NOW + 5_000;
    restore(std::slice::from_ref(&r), &saved, NOW);
    assert!(r.health()[0].health.remaining > Duration::from_secs(95));
}

#[test]
fn a_success_after_restore_brings_the_upstream_back() {
    let r = rotator(vec![p("a"), p("b")]);
    let saved = file(vec![entry("socks5://a:1080", 0, STATE_PROBATION, 0, 4)]);
    restore(std::slice::from_ref(&r), &saved, NOW);
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
    save(&path, &snapshot(&[before], NOW)).unwrap();

    let after = rotator(vec![p("a"), p("b")]);
    let resumed = resume(std::slice::from_ref(&after), &path, NOW + 1);
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
    let resumed = resume(std::slice::from_ref(&r), &dir.join("nope.ktav"), NOW);
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
    let resumed = resume(std::slice::from_ref(&r), &path, NOW);
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
    save_now(std::slice::from_ref(&r), &path);
    let loaded = load(&path).unwrap().unwrap();
    assert_eq!(loaded.upstreams[0].state, STATE_QUARANTINED);
    assert!(loaded.saved_at > 0);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn save_now_into_a_missing_directory_only_warns() {
    let dir = unique_dir("save_now_bad");
    let r = rotator(vec![p("a")]);
    save_now(&[r], &dir.join("no_such_dir").join("health.ktav"));
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

async fn settle() {
    for _ in 0..8 {
        tokio::task::yield_now().await;
    }
}

#[tokio::test(start_paused = true)]
async fn the_saver_writes_on_change_and_stays_quiet_otherwise() {
    let dir = unique_dir("saver");
    let path = dir.join("health.ktav");
    let r = rotator(vec![p("a"), p("b")]);
    let (log, _rx) = logger();
    let handle = tokio::spawn(run_saver(
        vec![r.clone()],
        path.clone(),
        Duration::from_secs(10),
        None,
        log,
    ));
    // The task creates its interval at the current (paused) time: let it start first.
    settle().await;

    tokio::time::advance(Duration::from_secs(11)).await;
    settle().await;
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
    settle().await;
    let second = load(&path).unwrap().unwrap();
    assert_eq!(second.upstreams[1].state, STATE_QUARANTINED);
    assert_eq!(second.upstreams[0].state, STATE_ALIVE);

    handle.abort();
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test(start_paused = true)]
async fn the_saver_skips_the_write_when_the_restored_picture_is_unchanged() {
    let dir = unique_dir("saver_initial");
    let path = dir.join("health.ktav");
    let r = rotator(vec![p("a")]);
    r.record_hard_failure(&p("a"));
    let initial = snapshot(std::slice::from_ref(&r), NOW);
    let (log, _rx) = logger();
    let handle = tokio::spawn(run_saver(
        vec![r],
        path.clone(),
        Duration::from_secs(10),
        Some(initial),
        log,
    ));
    // The task creates its interval at the current (paused) time: let it start first.
    settle().await;
    tokio::time::advance(Duration::from_secs(25)).await;
    settle().await;
    assert!(!path.exists());
    handle.abort();
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test(start_paused = true)]
async fn a_failing_save_is_logged_once_and_retried() {
    let dir = unique_dir("saver_fail");
    let missing = dir.join("later");
    let path = missing.join("health.ktav");
    let r = rotator(vec![p("a")]);
    let (log, mut rx) = logger();
    let handle = tokio::spawn(run_saver(
        vec![r],
        path.clone(),
        Duration::from_secs(10),
        None,
        log,
    ));
    // The task creates its interval at the current (paused) time: let it start first.
    settle().await;

    for _ in 0..3 {
        tokio::time::advance(Duration::from_secs(10)).await;
        settle().await;
    }
    let mut messages = 0;
    while rx.try_recv().is_ok() {
        messages += 1;
    }
    assert_eq!(messages, 1, "one log line per failure streak");
    assert!(!path.exists());

    std::fs::create_dir_all(&missing).unwrap();
    tokio::time::advance(Duration::from_secs(10)).await;
    settle().await;
    assert!(path.exists(), "the save is retried after the failure");

    handle.abort();
    let _ = std::fs::remove_dir_all(&dir);
}

fn drain(rx: &mut tokio::sync::mpsc::Receiver<crate::logger::ELog>) -> Vec<String> {
    let mut lines = Vec::new();
    while let Ok(line) = rx.try_recv() {
        match line {
            crate::logger::ELog::Log(text) | crate::logger::ELog::Error(text) => lines.push(text),
        }
    }
    lines
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

    let handle = start(
        vec![r.clone()],
        path.clone(),
        Duration::from_millis(50),
        Duration::from_secs(2),
        log,
    );
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
        let now = load(&path).unwrap().unwrap();
        if now.upstreams[0].state == STATE_ALIVE {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let now = load(&path).unwrap().unwrap();
    assert_eq!(now.upstreams[0].state, STATE_ALIVE);
    assert_eq!(now.upstreams[1].state, STATE_QUARANTINED);

    handle.abort();
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn start_without_a_file_creates_it_and_logs_nothing_about_restoring() {
    let r = rotator(vec![p("a")]);
    let dir = unique_dir("start_none");
    let path = dir.join("health.ktav");
    let (log, mut rx) = logger();
    let handle = start(
        vec![r],
        path.clone(),
        Duration::from_millis(30),
        Duration::from_secs(1),
        log,
    );
    for _ in 0..100 {
        if path.exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(path.exists(), "a first start writes the file");
    assert!(!drain(&mut rx).join("\n").contains("restored"));
    handle.abort();
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn start_with_a_broken_file_still_runs_and_overwrites_it() {
    let r = rotator(vec![p("a")]);
    let dir = unique_dir("start_bad");
    let path = dir.join("health.ktav");
    std::fs::write(&path, "saved_at: nope\n").unwrap();
    let (log, _rx) = logger();
    let handle = start(
        vec![r],
        path.clone(),
        Duration::from_millis(30),
        Duration::from_secs(1),
        log,
    );
    for _ in 0..100 {
        if load(&path).is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        load(&path).unwrap().is_some(),
        "the broken file is replaced"
    );
    handle.abort();
    let _ = std::fs::remove_dir_all(&dir);
}
