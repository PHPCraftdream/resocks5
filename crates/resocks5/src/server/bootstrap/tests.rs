use std::sync::Arc;
use std::time::Duration;

use tokio::sync::mpsc;

use crate::logger::ELog;
use resocks5_net::connect::parse_proxy_str;
use resocks5_net::types::{ProxyConfig, ProxyProtocol};

use super::startup::{
    apply_upstream_auth, directly_dialed_rotators, group_gate_levels, has_usable_route,
    obsolete_gssapi_keys, parse_proxy_list_checked, partition_proxy_groups, secure_only_conflict,
    should_bail_no_upstreams, split_secure_only_option, validate_admission, GateSplit,
};
use super::*;
use crate::config::{User, UsersConfig};

fn user(name: &str, enabled: bool, direct: bool) -> User {
    User {
        name: name.to_string(),
        hash: String::new(),
        is_enabled: enabled,
        direct,
        allowed_clients: None,
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
    let (parsed, failed) = parse_proxy_list_checked(&list, ProxyProtocol::Socks5, false);
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
    let (parsed, failed) = parse_proxy_list_checked(&list, ProxyProtocol::Socks5, false);
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
    rank: u8,
    id: usize,
    clones: Arc<std::sync::atomic::AtomicUsize>,
}

impl Clone for CloneCountingProxy {
    fn clone(&self) -> Self {
        self.clones
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Self {
            gate: self.gate,
            rank: self.rank,
            id: self.id,
            clones: Arc::clone(&self.clones),
        }
    }
}

impl GateSplit for CloneCountingProxy {
    fn is_gate(&self) -> bool {
        self.gate
    }
    fn gate_level(&self) -> u8 {
        self.rank
    }
}

#[test]
fn group_gate_levels_moves_owned_entries_without_cloning_and_keeps_gaps() {
    let clones = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let entry = |rank, id| CloneCountingProxy {
        gate: true,
        rank,
        id,
        clones: Arc::clone(&clones),
    };
    let levels = group_gate_levels(vec![entry(1, 10), entry(3, 30), entry(1, 11), entry(5, 50)]);
    assert_eq!(levels.keys().copied().collect::<Vec<_>>(), vec![1, 3, 5]);
    assert_eq!(
        levels[&1].iter().map(|p| p.id).collect::<Vec<_>>(),
        vec![10, 11]
    );
    assert_eq!(
        levels[&3].iter().map(|p| p.id).collect::<Vec<_>>(),
        vec![30]
    );
    assert_eq!(
        levels[&5].iter().map(|p| p.id).collect::<Vec<_>>(),
        vec![50]
    );
    assert_eq!(clones.load(std::sync::atomic::Ordering::Relaxed), 0);
}

#[test]
fn parsed_star_prefix_accepts_255_and_groups_at_exact_rank() {
    let raw = format!("{}v4:p@10.0.0.255:1080", "*".repeat(255));
    let (parsed, failed) = parse_proxy_list_checked(&[raw], ProxyProtocol::Socks5, false);
    assert!(failed.is_empty());
    assert_eq!(parsed.len(), 1);
    let (_, _, gates) = partition_proxy_groups(Vec::new(), parsed);
    let levels = group_gate_levels(gates);
    assert_eq!(levels.keys().copied().collect::<Vec<_>>(), vec![255]);
    assert_eq!(levels[&255][0].host, "10.0.0.255");
}

#[test]
fn parsed_v4_and_v6_gates_merge_by_level_preserving_source_order() {
    let v6 = vec![
        "**v6a:p@[2001:db8::1]:1080".to_string(),
        "*v6b:p@[2001:db8::2]:1080".to_string(),
    ];
    let v4 = vec![
        "**v4a:p@10.0.0.1:1080".to_string(),
        "**v4b:p@10.0.0.2:1080".to_string(),
    ];
    let (v6, failed_v6) = parse_proxy_list_checked(&v6, ProxyProtocol::Socks5, false);
    let (v4, failed_v4) = parse_proxy_list_checked(&v4, ProxyProtocol::Socks5, false);
    assert!(failed_v6.is_empty() && failed_v4.is_empty());
    let (_, _, gates) = partition_proxy_groups(v6, v4);
    let levels = group_gate_levels(gates);
    assert_eq!(levels.keys().copied().collect::<Vec<_>>(), vec![1, 2]);
    let hosts = |rank| {
        levels[&rank]
            .iter()
            .map(|p| p.host.as_str())
            .collect::<Vec<_>>()
    };
    assert_eq!(hosts(1), vec!["2001:db8::2"]);
    assert_eq!(hosts(2), vec!["2001:db8::1", "10.0.0.1", "10.0.0.2"]);
}

#[test]
fn parsed_three_stars_plus_one_star_yields_exact_levels_one_and_three() {
    let parsed_v6 = parse_proxy_list_checked(
        &["***v6:p@[2001:db8::3]:1080".to_string()],
        ProxyProtocol::Socks5,
        false,
    );
    let parsed_v4 = parse_proxy_list_checked(
        &["*v4:p@10.0.0.1:1080".to_string()],
        ProxyProtocol::Socks5,
        false,
    );
    assert!(parsed_v6.1.is_empty() && parsed_v4.1.is_empty());
    let (_, _, gates) = partition_proxy_groups(parsed_v6.0, parsed_v4.0);
    let levels = group_gate_levels(gates);
    assert_eq!(levels.keys().copied().collect::<Vec<_>>(), vec![1, 3]);
    assert_eq!(levels[&1][0].host, "10.0.0.1");
    assert_eq!(levels[&3][0].host, "2001:db8::3");
}

#[test]
fn star_prefix_256_is_rejected_with_redacted_failed_line_diagnostic() {
    let raw = format!("{}alice:s3cret@secret.example:1080", "*".repeat(256));
    let (parsed, failed) =
        parse_proxy_list_checked(std::slice::from_ref(&raw), ProxyProtocol::Socks5, false);
    assert!(parsed.is_empty());
    assert_eq!(failed, vec![1]);
    let msg = skipped_line_message("socks5_v4", failed[0]);
    assert!(msg.contains("[1]") && msg.contains("skipped (entry redacted)"));
    for secret in [raw.as_str(), "alice", "s3cret", "secret.example"] {
        assert!(!msg.contains(secret), "diagnostic leaked {secret:?}: {msg}");
    }
}

#[test]
fn parsed_star_prefixes_group_by_rank_across_ipv4_and_ipv6_lists() {
    let parse = |line| parse_proxy_str(line, ProxyProtocol::Socks5).expect("valid test proxy");
    let (v6, v4, gates) = partition_proxy_groups(
        vec![
            parse("***v6:p@[2001:db8::1]:1080"),
            parse("[2001:db8::2]:1080"),
        ],
        vec![
            parse("**v4:p@10.0.0.1:1080"),
            parse("*v4low:p@10.0.0.2:1080"),
            parse("10.0.0.3:1080"),
        ],
    );
    assert_eq!(v6.len(), 1);
    assert_eq!(v4.len(), 1);
    let levels = group_gate_levels(gates);
    assert_eq!(levels.keys().copied().collect::<Vec<_>>(), vec![1, 2, 3]);
    assert_eq!(levels[&1][0].host, "10.0.0.2");
    assert_eq!(levels[&2][0].host, "10.0.0.1");
    assert_eq!(levels[&3][0].host, "2001:db8::1");
}
#[test]
fn partition_proxy_groups_moves_plain_entries_without_cloning() {
    let clones = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let entry = |gate: bool, rank: u8, id: usize| CloneCountingProxy {
        gate,
        rank,
        id,
        clones: Arc::clone(&clones),
    };
    // Interleave gates and plains in both source lists.
    let all_v6 = vec![entry(false, 0, 0), entry(true, 1, 1), entry(false, 0, 2)];
    let all_v4 = vec![
        entry(false, 0, 3),
        entry(true, 2, 4),
        entry(false, 0, 5),
        entry(true, 3, 6),
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

#[test]
fn directly_dialed_rotators_are_outermost_gate_then_all_exits() {
    use resocks5_net::chain::GateLevels;
    use resocks5_net::rotator::ProxyRotator;
    let rotator = |host: &str| Arc::new(ProxyRotator::new(vec![ProxyConfig::socks5(host, 1080)]));
    let gates = GateLevels::new(vec![(1, rotator("gate-low")), (3, rotator("gate-high"))]);
    let exits = [Some(rotator("exit-v6")), None, Some(rotator("exit-v4"))];
    let direct = directly_dialed_rotators(&gates, &exits);
    let hosts = direct
        .iter()
        .flat_map(|r| r.all_proxies())
        .map(|p| p.host.clone())
        .collect::<Vec<_>>();
    assert_eq!(hosts, vec!["gate-high", "exit-v6", "exit-v4"]);
}

#[test]
fn partition_proxy_groups_preserves_composition_and_order_on_proxy_config() {
    let parse = |line: &str| {
        parse_proxy_str(line, ProxyProtocol::Socks5).expect("test proxy line must parse")
    };
    let all_v6 = vec![
        parse("[2001:db8::1]:1080"),
        parse("*u1:p1@[2001:db8::2]:1080"),
        parse("[2001:db8::3]:1080"),
    ];
    let all_v4 = vec![
        parse("10.0.0.1:1080"),
        parse("*u2:p2@10.0.0.2:1080"),
        parse("10.0.0.3:1080"),
        parse("*u3:p3@10.0.0.4:1080"),
    ];
    let (v6, v4, gates) = partition_proxy_groups(all_v6, all_v4);
    let hosts = |group: &[ProxyConfig]| group.iter().map(|p| p.host.clone()).collect::<Vec<_>>();
    assert_eq!(hosts(&v6), vec!["2001:db8::1", "2001:db8::3"]);
    assert_eq!(hosts(&v4), vec!["10.0.0.1", "10.0.0.3"]);
    assert_eq!(hosts(&gates), vec!["2001:db8::2", "10.0.0.2", "10.0.0.4"]);
    assert!(gates.iter().all(|p| p.is_gate));
    assert!(v6.iter().chain(v4.iter()).all(|p| !p.is_gate));
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

/// Configuration for checking the shared `allowed_clients` validation point.
/// The tests check rule errors, not the call order of the whole startup.
fn main_cfg_with_allowed(rule: &str) -> crate::config::MainConfig {
    crate::config::MainConfig {
        port: 20082,
        listen_host: "127.0.0.1".to_string(),
        banned_patterns: Vec::new(),
        auth: crate::config::AuthConfig {
            allow_anonymous: false,
            ..Default::default()
        },
        upstream_auth: Default::default(),
        log: crate::logger::LogConfig::default(),
        pool: Default::default(),
        tls_fragment: Default::default(),
        network: Default::default(),
        file_log: Default::default(),
        allowed_clients: rule.to_string(),
    }
}

fn user_with_rule(name: &str, rule: Option<&str>) -> User {
    User {
        name: name.to_string(),
        hash: String::new(),
        is_enabled: true,
        direct: false,
        allowed_clients: rule.map(str::to_string),
    }
}

#[test]
fn invalid_global_allowed_clients_fails_before_route_bailout() {
    let cfg = main_cfg_with_allowed("10.*.0");
    let err = validate_allowed_clients(&cfg, &users_cfg(vec![]))
        .err()
        .expect("невалидная глобальная строка обязана дать ошибку");
    let text = err.to_string();
    assert!(
        text.contains("allowed_clients"),
        "ожидалась контекстная allowed_clients-ошибка, получено: {text}"
    );
}

#[test]
fn invalid_user_allowed_clients_fails_before_route_bailout() {
    let cfg = main_cfg_with_allowed("*");
    let err = validate_allowed_clients(
        &cfg,
        &users_cfg(vec![user_with_rule("alice", Some("2001:db8:*"))]),
    )
    .err()
    .expect("невалидная user-строка обязана дать ошибку");
    let text = err.to_string();
    assert!(
        text.contains("allowed_clients") && text.contains("alice"),
        "ожидалась контекстная allowed_clients-ошибка с именем пользователя, получено: {text}"
    );
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

// The never-completing-drain give-up (5 s budget, virtual clock) is pinned in
// `log_drain.rs`: `shutdown_drain_gives_up_exactly_at_the_budget`.

#[test]
fn all_rotators_lists_every_gate_level_then_exits() {
    use resocks5_net::chain::GateLevels;
    use resocks5_net::rotator::ProxyRotator;
    let rotator = |host: &str| Arc::new(ProxyRotator::new(vec![ProxyConfig::socks5(host, 1080)]));
    let gates = GateLevels::new(vec![(1, rotator("gate-low")), (3, rotator("gate-high"))]);
    let exits = [Some(rotator("exit-v6")), None, Some(rotator("exit-v4"))];
    let hosts = super::startup::all_rotators(&gates, &exits)
        .iter()
        .flat_map(|r| r.all_proxies())
        .map(|p| p.host.clone())
        .collect::<Vec<_>>();
    assert_eq!(hosts, vec!["gate-high", "gate-low", "exit-v6", "exit-v4"]);
    assert!(super::startup::all_rotators(&GateLevels::default(), &[None, None]).is_empty());
}

// ── outbound (upstream) auth: `;secure_only`, gssapi drop, admission ──

/// A 0.4.x `;gssapi=` entry must not survive parsing: GSSAPI was removed
/// in 0.5.0, so dialing it would hit an upstream that was meant to be
/// Kerberos-authenticated. Mutation: keeping the entry would dial an
/// upstream that was meant to be Kerberos-authenticated.
#[test]
fn a_gssapi_entry_is_dropped_with_a_warning() {
    let list = vec![
        "1.2.3.4:1080;gssapi=socks@h".to_string(),
        "5.6.7.8:1080".to_string(),
    ];
    let (parsed, failed) = parse_proxy_list_checked(&list, ProxyProtocol::Socks5, false);
    assert_eq!(parsed.len(), 1);
    assert_eq!(parsed[0].host, "5.6.7.8");
    assert_eq!(failed, vec![1]);
}

/// `;secure_only` must sit at the very end of the line: anything after it
/// makes the auth policy unparseable. Mutation: accepting a value after
/// the flag silently ignores it.
#[test]
fn secure_only_option_splits_off_the_line_end() {
    assert_eq!(
        split_secure_only_option("u:p@h:1;secure_only"),
        Ok(("u:p@h:1", true))
    );
    assert_eq!(split_secure_only_option("u:p@h:1"), Ok(("u:p@h:1", false)));
    assert_eq!(split_secure_only_option("u:p@h:1;secure_only=yes"), Err(()));
}

/// The resolution function must not wipe the parsed credentials when
/// neither switch is on — the clear-text fallback contract depends on
/// them staying. Mutation: an implementation that wiped user/password
/// would break the clear-text fallback contract.
#[test]
fn the_global_switch_is_overridden_per_entry() {
    let cfg = || parse_proxy_str("u:p@10.0.0.1:1080", ProxyProtocol::Socks5).unwrap();
    let untouched = apply_upstream_auth(cfg(), false, false);
    assert_eq!(untouched.user.as_deref(), Some("u"));
    assert_eq!(untouched.password.as_deref(), Some("p"));
    // secure-only passthrough must not clear the credentials either
    // (the user name stays as the upstream identity).
    let forced = apply_upstream_auth(cfg(), true, false);
    assert_eq!(forced.user.as_deref(), Some("u"));
    let global = apply_upstream_auth(cfg(), false, true);
    assert_eq!(global.user.as_deref(), Some("u"));
    // The e2e dial behaviour of the secure-only switch is pinned in
    // upstream_auth_tests.rs.
}

/// Mutation: a typo'd prefix missing one key fails.
#[test]
fn obsolete_gssapi_keys_are_detected() {
    let text = "auth: {\n  allow_anonymous: true\n  gssapi_service: \"x\"\n  gssapi_protection: \"none\"\n}\n";
    assert_eq!(
        obsolete_gssapi_keys(text),
        vec!["gssapi_service", "gssapi_protection"]
    );
    let clean = "auth: {\n  allow_anonymous: true\n  secure_only: false\n}\n";
    assert!(obsolete_gssapi_keys(clean).is_empty());
}

fn auth_state(
    users: Vec<User>,
    allow_anonymous: bool,
    secure_only: bool,
) -> Arc<crate::auth::AuthState> {
    Arc::new(
        crate::auth::AuthState::build(
            &crate::config::AuthConfig {
                allow_anonymous,
                secure_only,
                argon2: Default::default(),
            },
            &UsersConfig { users },
            "test-users.ktav",
        )
        .expect("valid auth state"),
    )
}

/// A server that no client could ever enter must be refused at startup.
/// Mutation: dropping the `is_empty` bail lets a server start that no
/// client can enter.
#[test]
fn a_server_that_cannot_admit_anyone_is_refused_at_startup() {
    // Anonymous off, no users: refused, and the message names the fix.
    let err = validate_admission(&auth_state(vec![], false, false))
        .expect_err("no users + no anonymous must be refused");
    assert!(err.to_string().contains("users add"), "{err}");
    // Anonymous on, no users: fine.
    assert!(validate_admission(&auth_state(vec![], true, false)).is_ok());
    // Anonymous on, one user: fine.
    assert!(validate_admission(&auth_state(vec![user("alice", true, false)], true, false)).is_ok());
    // Anonymous off but secure_only on, one user: fine (users still enter
    // with the secure method).
    assert!(validate_admission(&auth_state(vec![user("alice", true, false)], false, true)).is_ok());
    // secure_only on, no users: anonymous is silenced, so refused.
    assert!(validate_admission(&auth_state(vec![], true, true)).is_err());
    // secure_only + allow_anonymous is the only conflict combination.
    assert!(secure_only_conflict(&auth_state(vec![], true, true)));
    assert!(!secure_only_conflict(&auth_state(vec![], false, true)));
    assert!(!secure_only_conflict(&auth_state(vec![], true, false)));
    assert!(!secure_only_conflict(&auth_state(vec![], false, false)));
}
