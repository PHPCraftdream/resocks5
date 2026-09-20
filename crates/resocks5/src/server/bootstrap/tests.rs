use std::sync::Arc;
use std::time::Duration;

use tokio::spawn;
use tokio::sync::mpsc;

use crate::logger::ELog;
use resocks5_net::connect::parse_proxy_str;
use resocks5_net::types::{ProxyConfig, ProxyProtocol, IP};

use super::*;
use crate::config::{User, UsersConfig};

fn user(name: &str, enabled: bool, direct: bool) -> User {
    User {
        name: name.to_string(),
        hash: String::new(),
        is_enabled: enabled,
        direct,
    }
}

fn users_cfg(users: Vec<User>) -> UsersConfig {
    UsersConfig { users }
}

#[test]
fn empty_pool_no_users_bails() {
    assert!(should_bail_no_upstreams(true, &users_cfg(vec![])));
}

#[test]
fn empty_pool_active_direct_user_does_not_bail() {
    let u = users_cfg(vec![user("alice", true, true)]);
    assert!(!should_bail_no_upstreams(true, &u));
}

#[test]
fn empty_pool_only_disabled_direct_user_bails() {
    let u = users_cfg(vec![user("alice", false, true)]);
    assert!(should_bail_no_upstreams(true, &u));
}

#[test]
fn empty_pool_only_pool_user_bails() {
    let u = users_cfg(vec![user("bob", true, false)]);
    assert!(should_bail_no_upstreams(true, &u));
}

#[test]
fn non_empty_pool_never_bails() {
    assert!(!should_bail_no_upstreams(false, &users_cfg(vec![])));
    let u = users_cfg(vec![user("alice", true, true)]);
    assert!(!should_bail_no_upstreams(false, &u));
}

#[test]
fn skipped_line_diagnostic_identifies_line_without_credentials() {
    let list = vec![
        "alice:s3cret@198.51.100.7:1080".to_string(),
        "not-a-proxy".to_string(),
        "bob:hunter2@[::1]:1080".to_string(),
    ];
    let (parsed, failed) = parse_proxy_list_checked(&list, ProxyProtocol::Socks5, IP::V4);
    assert_eq!(parsed.len(), 2);
    assert_eq!(failed, vec![2]);
    let msg = skipped_line_message("socks5_v4", failed[0]);
    assert!(
        msg.contains("socks5_v4") && msg.contains("[2]"),
        "diagnostic must identify list and line: {msg}"
    );
    for secret in [
        "alice",
        "s3cret",
        "hunter2",
        "198.51.100.7",
        "not-a-proxy",
        "[::1]",
    ] {
        assert!(!msg.contains(secret), "diagnostic leaked {secret:?}: {msg}");
    }
}

#[test]
fn comment_lines_are_skipped_silently() {
    let list = vec!["# comment".to_string(), "1.2.3.4:1080".to_string()];
    let (parsed, failed) = parse_proxy_list_checked(&list, ProxyProtocol::Socks5, IP::V4);
    assert_eq!(parsed.len(), 1);
    assert!(
        failed.is_empty(),
        "comments must not be reported: {failed:?}"
    );
}

/// Clone-counting stand-in for [`ProxyConfig`]: the group splitter
/// must MOVE entries (R8-07), so any `clone()` of a plain entry is
/// a failure. There is no `Arc<ProxyConfig>` anywhere in the
/// startup path (plain `Vec<ProxyConfig>` until rotator
/// construction), so a counting wrapper is the observable
/// mechanism here.
#[derive(Debug)]
struct CloneCountingProxy {
    gate: bool,
    id: usize,
    clones: Arc<std::sync::atomic::AtomicUsize>,
}

impl Clone for CloneCountingProxy {
    fn clone(&self) -> Self {
        self.clones
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Self {
            gate: self.gate,
            id: self.id,
            clones: Arc::clone(&self.clones),
        }
    }
}

impl GateSplit for CloneCountingProxy {
    fn is_gate(&self) -> bool {
        self.gate
    }
}

#[test]
fn partition_proxy_groups_moves_plain_entries_without_cloning() {
    let clones = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let entry = |gate: bool, id: usize| CloneCountingProxy {
        gate,
        id,
        clones: Arc::clone(&clones),
    };
    // Interleave gates and plains in both source lists.
    let all_v6 = vec![entry(false, 0), entry(true, 1), entry(false, 2)];
    let all_v4 = vec![
        entry(false, 3),
        entry(true, 4),
        entry(false, 5),
        entry(true, 6),
    ];

    let (v6, v4, gates) = partition_proxy_groups(all_v6, all_v4);

    assert_eq!(
        clones.load(std::sync::atomic::Ordering::Relaxed),
        0,
        "group construction must move owned entries, never clone them"
    );
    let ids = |group: &[CloneCountingProxy]| group.iter().map(|p| p.id).collect::<Vec<_>>();
    assert_eq!(ids(&v6), vec![0, 2], "plain v6 entries keep list order");
    assert_eq!(ids(&v4), vec![3, 5], "plain v4 entries keep list order");
    assert_eq!(
        ids(&gates),
        vec![1, 4, 6],
        "gates keep v6-list order first, then v4-list order"
    );
}

/// Pin the splitter's composition and order on the real
/// [`ProxyConfig`] type, matching the previous construction: plains
/// keep their list order; gates are v6-list gates then v4-list
/// gates, with credentials moved intact.
#[test]
fn partition_proxy_groups_preserves_composition_and_order_on_proxy_config() {
    let parse = |line: &str, ip: IP| {
        parse_proxy_str(line, ProxyProtocol::Socks5, ip).expect("test proxy line must parse")
    };
    let all_v6 = vec![
        parse("[2001:db8::1]:1080", IP::V6),
        parse("*u1:p1@[2001:db8::2]:1080", IP::V6),
        parse("[2001:db8::3]:1080", IP::V6),
    ];
    let all_v4 = vec![
        parse("10.0.0.1:1080", IP::V4),
        parse("*u2:p2@10.0.0.2:1080", IP::V4),
        parse("10.0.0.3:1080", IP::V4),
        parse("*u3:p3@10.0.0.4:1080", IP::V4),
    ];

    let (v6, v4, gates) = partition_proxy_groups(all_v6, all_v4);

    // Expected groups re-derived from the same source lines so the
    // assertions don't depend on host-string formatting details.
    let hosts =
        |group: &[ProxyConfig]| -> Vec<String> { group.iter().map(|p| p.host.clone()).collect() };
    assert_eq!(
        hosts(&v6),
        hosts(&[
            parse("[2001:db8::1]:1080", IP::V6),
            parse("[2001:db8::3]:1080", IP::V6)
        ])
    );
    assert_eq!(
        hosts(&v4),
        hosts(&[
            parse("10.0.0.1:1080", IP::V4),
            parse("10.0.0.3:1080", IP::V4)
        ])
    );
    assert_eq!(
        hosts(&gates),
        hosts(&[
            parse("*u1:p1@[2001:db8::2]:1080", IP::V6),
            parse("*u2:p2@10.0.0.2:1080", IP::V4),
            parse("*u3:p3@10.0.0.4:1080", IP::V4)
        ])
    );
    assert!(gates.iter().all(|p| p.is_gate));
    assert!(v6.iter().chain(v4.iter()).all(|p| !p.is_gate));
    // Credentials moved into the gate group intact, not copied.
    assert_eq!(gates[0].user.as_deref(), Some("u1"));
    assert_eq!(gates[0].password.as_deref(), Some("p1"));
}

/// A gates-only config (no plain v4/v6 upstream, no direct user) must
/// bail at startup: gates alone carry no traffic.
#[test]
fn gates_only_configuration_bails_at_startup() {
    assert!(!has_usable_route(false, false));
    assert!(has_usable_route(true, false));
    assert!(has_usable_route(false, true));
    let no_route = !has_usable_route(false, false);
    assert!(should_bail_no_upstreams(no_route, &users_cfg(vec![])));
    let direct = users_cfg(vec![user("alice", true, true)]);
    assert!(!should_bail_no_upstreams(no_route, &direct));
}

#[test]
fn obsolete_cb_keys_are_detected() {
    let text = "network: {\n  connect_timeout_sec: 10\n  cb_fail_threshold: 0\n  cb_open_initial_sec: 1200\n}\n";
    assert_eq!(
        obsolete_cb_keys(text),
        vec!["cb_fail_threshold", "cb_open_initial_sec"]
    );
    // Quoted values (banned patterns) and key-less lines never match.
    let clean = "banned_patterns: [\n  \"^cb_x$\"\n]\nnetwork: {\n  sand_max: 8.0\n}\n";
    assert!(obsolete_cb_keys(clean).is_empty());
}

#[tokio::test]
async fn shutdown_drain_flushes_queued_message_to_file() {
    static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let path = std::env::temp_dir().join(format!(
        "resocks5-drain-flush-{}-{}.log",
        std::process::id(),
        NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    let _ = std::fs::remove_file(&path);

    let (tx, rx) = mpsc::channel::<ELog>(16);
    let file_cfg = crate::config::FileLogConfig {
        enabled: true,
        path: path.to_string_lossy().into_owned(),
        also_console: false,
    };
    let logger = Arc::new(crate::logger::Logger::new(
        tx,
        crate::logger::LogConfig {
            lifecycle: true,
            ..Default::default()
        },
    ));
    logger.lifecycle(|| "shutdown-flush-marker-R25".to_string());

    let drain = spawn_log_drain(rx, file_cfg);
    // Dropping `logger` inside the helper closes the channel; the
    // join must flush the queued line to disk before returning.
    shutdown_log_drain(logger, drain).await;

    let contents =
        std::fs::read_to_string(&path).expect("file logger must have created the log file");
    assert!(
        contents.contains("shutdown-flush-marker-R25"),
        "queued message must be flushed before shutdown completes, got: {contents:?}"
    );
    let _ = std::fs::remove_file(&path);
}

#[test]
fn file_write_error_diagnostic_names_path_and_recovery() {
    let err = std::io::Error::other("simulated failure");
    let msg = file_write_error_message("resocks5.log", &err);
    assert!(msg.contains("resocks5.log"), "must name the path: {msg}");
    assert!(
        msg.contains("simulated failure"),
        "must name the error: {msg}"
    );
    assert!(
        msg.contains("console-only"),
        "must tell the operator the fallback: {msg}"
    );
}

/// The R5-06 root cause as a test, driven through the production
/// wrapper: a blocking-pool operation that never finishes (exactly
/// what a `tokio::io::stdout` write to a stopped pipe becomes —
/// `Blocking::poll_write` parks it in this pool) must not extend
/// process exit. Unlike the pre-R6-09 version this calls
/// [`run_with_bounded_teardown`] — the function production code
/// actually runs — instead of building a private runtime and
/// calling `shutdown_timeout` directly, so reverting the wrapper to
/// an unbounded `Runtime::drop` fails here.
#[test]
fn runtime_teardown_is_bounded_with_a_stuck_blocking_write() {
    let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
    let (exited_tx, exited_rx) = std::sync::mpsc::channel::<()>();
    let (done_tx, done_rx) = std::sync::mpsc::channel::<Duration>();

    let helper = std::thread::spawn(move || {
        // Measure at the real boundaries of the work (review
        // R7-07): a parent-side `Instant::now()` starts whenever the
        // parent is next scheduled, which can be long after this
        // thread began the teardown — parent lag must not shrink
        // the measured interval and reject a full-duration teardown
        // as "too fast".
        let start = std::time::Instant::now();
        let outcome = run_with_bounded_teardown(async move {
            let (started_tx, started_rx) = tokio::sync::oneshot::channel::<()>();
            // Stuck sink stand-in: a blocking-pool op that parks
            // until the test releases it. The `JoinHandle` is
            // deliberately dropped — the op must outlive the
            // wrapper's polite shutdown for this test to mean
            // anything (fire-and-forget by design).
            tokio::task::spawn_blocking(move || {
                // Prove the op STARTED executing before teardown
                // runs: a merely queued task could be cancelled
                // without ever running, which would not exercise
                // teardown at all.
                let _ = started_tx.send(());
                // Park on a release signal, NOT `loop { park() }` —
                // the latter has no release path and would leak the
                // thread past the test.
                let _ = release_rx.recv();
                let _ = exited_tx.send(());
            });
            started_rx
                .await
                .expect("stuck blocking op must start before teardown");
        });
        let elapsed = start.elapsed();
        done_tx
            .send(elapsed)
            .expect("test harness: done channel must be alive");
        outcome
    });

    // Generous hang-detector cap only, not the measurement (the
    // helper measures the teardown at its true boundaries — R7-07):
    // a wrapper reverted to unbounded `Runtime::drop` would block
    // the helper thread forever and trip this cap. Seconds of
    // headroom, because wall-clock bounds flake under CPU load.
    let cap = Duration::from_secs(SHUTDOWN_TEARDOWN_TIMEOUT_SEC + 20);
    let elapsed = done_rx
        .recv_timeout(cap)
        .expect("run_with_bounded_teardown must return despite the stuck blocking op");
    // The stuck op is released only after the wrapper returned, so a
    // correct wrapper must have waited out (at least) its budget;
    // an over-eager teardown that abandons the op immediately would
    // undershoot. A tight lower bound is safe now that the helper
    // itself measured (R7-07): one second of slack for clock
    // granularity.
    assert!(
        elapsed >= Duration::from_secs(SHUTDOWN_TEARDOWN_TIMEOUT_SEC.saturating_sub(1)),
        "teardown must wait out its budget while the blocking op is stuck, \
         helper measured {elapsed:?}"
    );
    assert!(
        elapsed < cap,
        "teardown must abandon the stuck blocking op within its budget, took {elapsed:?}"
    );

    let outcome = helper.join().expect("helper thread must not panic");
    assert!(
        outcome.is_ok(),
        "async body must complete normally, got {outcome:?}"
    );

    // Release the stuck op and prove its thread actually exits, so
    // the test leaks neither a parked thread nor a stuck runtime.
    release_tx
        .send(())
        .expect("test harness: release channel must be alive");
    exited_rx
        .recv_timeout(cap)
        .expect("stuck blocking op must exit once released");
}

/// Same stuck-op setup, but the async body panics after the op
/// started: the wrapper must still run the bounded teardown (proved
/// by the same started/release/exited protocol) AND re-raise the
/// panic instead of swallowing it.
#[test]
fn panic_in_body_still_tears_down_bounded_and_reraises() {
    let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
    let (exited_tx, exited_rx) = std::sync::mpsc::channel::<()>();
    let (done_tx, done_rx) = std::sync::mpsc::channel::<Duration>();

    let helper = std::thread::spawn(move || {
        // Measure at the real boundaries of the work (review
        // R7-07), around the whole wrapper call: its teardown waits
        // out the budget while the op is still parked, and the
        // re-raised unwind is caught right after it returns.
        let start = std::time::Instant::now();
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            run_with_bounded_teardown(async move {
                let (started_tx, started_rx) = tokio::sync::oneshot::channel::<()>();
                tokio::task::spawn_blocking(move || {
                    let _ = started_tx.send(());
                    let _ = release_rx.recv();
                    let _ = exited_tx.send(());
                });
                started_rx
                    .await
                    .expect("stuck blocking op must start before teardown");
                panic!("body panic: the bounded teardown must still run");
            })
        }));
        let elapsed = start.elapsed();
        done_tx
            .send(elapsed)
            .expect("test harness: done channel must be alive");
        outcome
    });

    // Generous hang-detector cap only, not the measurement (see the
    // companion test): boundedness is asserted on the helper's own
    // measurement so parent scheduling delay cannot distort it.
    let cap = Duration::from_secs(SHUTDOWN_TEARDOWN_TIMEOUT_SEC + 20);
    let elapsed = done_rx
        .recv_timeout(cap)
        .expect("panicking body must still return from run_with_bounded_teardown");
    // The op is still parked when the teardown runs, so it must wait
    // out its budget here too (R7-07: measured inside the helper).
    assert!(
        elapsed >= Duration::from_secs(SHUTDOWN_TEARDOWN_TIMEOUT_SEC.saturating_sub(1)),
        "teardown must still wait out its budget after a body panic, \
         helper measured {elapsed:?}"
    );
    assert!(
        elapsed < cap,
        "panicking body teardown must remain bounded, took {elapsed:?}"
    );
    let outcome = helper.join().expect("helper thread must not panic");
    assert!(
        outcome.is_err(),
        "body panic must be re-raised by the wrapper, not swallowed"
    );

    // Teardown ran while the op was still parked, so the op must
    // still be alive and releasable afterwards.
    release_tx
        .send(())
        .expect("test harness: release channel must be alive");
    exited_rx
        .recv_timeout(cap)
        .expect("stuck blocking op must exit once released");
}

/// A drain task that never completes (sink wedged mid-write) must be
/// given up on after the budget, not awaited forever; the timeout
/// diagnostic must not hang either (it is itself a bounded write).
/// Paused time lets the 5 s budget and the 1 s diagnostic budget
/// elapse via auto-advance, proving the give-up structure returns
/// without real wall-clock cost.
#[tokio::test(start_paused = true)]
async fn shutdown_drain_gives_up_on_never_completing_drain() {
    let start = std::time::Instant::now();
    let (tx, _rx) = mpsc::channel::<ELog>(4);
    let logger = Arc::new(crate::logger::Logger::new(
        tx,
        crate::logger::LogConfig {
            lifecycle: true,
            ..Default::default()
        },
    ));
    let drain = spawn(std::future::pending::<()>());
    shutdown_log_drain(logger, drain).await;
    assert!(
        start.elapsed() < Duration::from_secs(1),
        "give-up path must not wait in real time, took {:?}",
        start.elapsed()
    );
}
