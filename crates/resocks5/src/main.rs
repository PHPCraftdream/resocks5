mod auth;
mod cli;
mod config;
mod http_proxy;
mod logger;
mod server;

use crate::logger::ELog;
use anyhow::Result;
use chrono::Local;
use clap::Parser;
use regex::RegexSet;
use resocks5_net::connect::parse_proxy_str;
use resocks5_net::rotator::ProxyRotator;
use resocks5_net::types::{ProxyConfig, ProxyProtocol, IP};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::spawn;
use tokio::sync::mpsc;

/// Decide whether startup should abort for lack of a usable route.
///
/// `no_usable_route` must be computed WITHOUT counting gate rotators:
/// gates are meaningless without a plain v4/v6 upstream to tunnel to
/// (see [`has_usable_route`]). Returns `true` (bail) when there is no
/// usable route AND no enabled direct user — i.e. no client could
/// possibly route traffic. Returns `false` when at least one enabled
/// direct user exists, which means the server can still be useful even
/// without upstreams.
pub(crate) fn should_bail_no_upstreams(
    no_usable_route: bool,
    users: &crate::config::UsersConfig,
) -> bool {
    if !no_usable_route {
        return false;
    }
    let has_active_direct = users.users.iter().any(|u| u.is_enabled && u.direct);
    !has_active_direct
}

/// Whether at least one plain (non-gate) upstream rotator exists.
///
/// A gate rotator does NOT count: the gates phase tunnels each gate
/// together with an entry from the v4/v6 rotators, so a gates-only
/// configuration has no route at all and every client request would fail
/// at request time. Direct-enabled users are handled separately by
/// [`should_bail_no_upstreams`].
pub(crate) fn has_usable_route(has_v4_rotator: bool, has_v6_rotator: bool) -> bool {
    has_v4_rotator || has_v6_rotator
}

/// Parse one upstream list, printing a warning for every line that was
/// dropped because it failed to parse. The warning names the list and the
/// 1-based line number only — never the line's text, which can carry
/// `user:pass` credentials.
fn parse_proxy_list(
    list_name: &str,
    list: &[String],
    proto: ProxyProtocol,
    ip: IP,
) -> Vec<ProxyConfig> {
    let (parsed, failed) = parse_proxy_list_checked(list, proto, ip);
    for line_no in &failed {
        println!("{}", skipped_line_message(list_name, *line_no));
    }
    parsed
}

/// Pure part of [`parse_proxy_list`]: parsed configs plus the 1-based
/// numbers of dropped lines. `#` comment lines are skipped silently (the
/// parser rejects them by design).
fn parse_proxy_list_checked(
    list: &[String],
    proto: ProxyProtocol,
    ip: IP,
) -> (Vec<ProxyConfig>, Vec<usize>) {
    let mut parsed = Vec::with_capacity(list.len());
    let mut failed = Vec::new();
    for (idx, line) in list.iter().enumerate() {
        if line.starts_with('#') {
            continue;
        }
        match parse_proxy_str(line, proto, ip) {
            Some(config) => parsed.push(config),
            None => failed.push(idx + 1),
        }
    }
    (parsed, failed)
}

/// Diagnostic for one dropped line. Deliberately receives only the list
/// name and line number: the raw line can be `user:pass@host:port`, and
/// credentials must never reach the log.
fn skipped_line_message(list_name: &str, line_no: usize) -> String {
    format!(
        "warning: {list_name}[{line_no}]: failed to parse proxy entry — line skipped (entry redacted)"
    )
}

/// `cb_*` key names found in the raw main-config text, in file order.
/// Pure so the detection is unit-testable; matching is deliberately
/// textual (ktav drops unknown keys during deserialize without
/// reporting them): a key line starts (after indentation) with `cb_`
/// and contains `:`. Quoted values such as banned patterns never match.
fn obsolete_cb_keys(text: &str) -> Vec<String> {
    text.lines()
        .filter_map(|line| {
            let rest = line.trim_start().strip_prefix("cb_")?;
            let (name, _) = rest.split_once(':')?;
            Some(format!("cb_{}", name.trim()))
        })
        .collect()
}

/// Startup warning for settings this binary no longer understands.
fn warn_obsolete_cb_keys() {
    let Ok(text) = std::fs::read_to_string(crate::config::MAIN_PATH) else {
        return;
    };
    let ignored = obsolete_cb_keys(&text);
    if !ignored.is_empty() {
        println!(
            "warning: {} contains settings this version ignores (unknown keys): {}\n\
             These obsolete `cb_*` circuit-breaker knobs have NO effect. \
             Remove them from the `network:` section.",
            crate::config::MAIN_PATH,
            ignored.join(", ")
        );
    }
}

fn main() -> Result<()> {
    let args = cli::Cli::parse();
    match args.command {
        Some(cli::Command::Users { action }) => cli::run_user_command(action),
        Some(cli::Command::Config) => {
            cli::print_config_docs();
            Ok(())
        }
        None => run_server(),
    }
}

#[tokio::main]
async fn run_server() -> Result<()> {
    let configs = config::load_or_init()?;
    let cfg_main = &configs.main;

    warn_obsolete_cb_keys();

    // Compile all banned patterns into one DFA — single-pass match per
    // connection regardless of how many patterns are configured.
    let banned = Arc::new(
        RegexSet::new(&cfg_main.banned_patterns).expect("Invalid regex pattern in banned_patterns"),
    );

    // Log banned patterns for debugging
    for pattern in &cfg_main.banned_patterns {
        println!("Banned pattern: {}", pattern);
    }

    let pl = &configs.proxy_list;
    let mut all_v6: Vec<ProxyConfig> =
        parse_proxy_list("socks5_v6", &pl.socks5_v6, ProxyProtocol::Socks5, IP::V6);
    all_v6.extend(parse_proxy_list(
        "http_v6",
        &pl.http_v6,
        ProxyProtocol::Http,
        IP::V6,
    ));
    all_v6.extend(parse_proxy_list(
        "https_v6",
        &pl.https_v6,
        ProxyProtocol::Https,
        IP::V6,
    ));

    let mut all_v4: Vec<ProxyConfig> =
        parse_proxy_list("socks5_v4", &pl.socks5_v4, ProxyProtocol::Socks5, IP::V4);
    all_v4.extend(parse_proxy_list(
        "http_v4",
        &pl.http_v4,
        ProxyProtocol::Http,
        IP::V4,
    ));
    all_v4.extend(parse_proxy_list(
        "https_v4",
        &pl.https_v4,
        ProxyProtocol::Https,
        IP::V4,
    ));

    let v6_proxies: Vec<ProxyConfig> = all_v6.iter().filter(|p| !p.is_gate).cloned().collect();
    let v4_proxies: Vec<ProxyConfig> = all_v4.iter().filter(|p| !p.is_gate).cloned().collect();

    let gate_proxies: Vec<ProxyConfig> = all_v6
        .into_iter()
        .chain(all_v4)
        .filter(|p| p.is_gate)
        .collect();

    let has_https = !pl.https_v4.is_empty() || !pl.https_v6.is_empty();

    println!("proxies v4:");
    for p in &v4_proxies {
        println!("{:?}://{}:{}", p.protocol, p.host, p.port);
    }

    println!();

    println!("proxies v6:");
    for p in &v6_proxies {
        println!("{:?}://{}:{}", p.protocol, p.host, p.port);
    }

    println!();

    println!("gates:");
    for p in &gate_proxies {
        println!("{:?}://{}:{} - {:?}", p.protocol, p.host, p.port, p.ip,);
    }

    // Bounded log channel — under sudden bursts (e.g. cache_hits=true
    // on a flood) the producer falls back to dropping via `try_send`
    // rather than growing memory or blocking the hot path. 2048 slots
    // is generous for non-pathological log volumes.
    let (log_sender, log_receiver) = mpsc::channel::<ELog>(2048);
    let logger: Arc<logger::Logger> =
        Arc::new(logger::Logger::new(log_sender, cfg_main.log.clone()));

    let rating_policy = resocks5_net::rating::RatingPolicy {
        half_life_sec: cfg_main.network.sand_half_life_sec,
        fail_penalty: cfg_main.network.sand_fail_penalty,
        sand_max: cfg_main.network.sand_max,
        min_weight: cfg_main.network.sand_min_weight,
        success_factor: cfg_main.network.sand_success_factor,
    };

    rating_policy.validate().map_err(|e| {
        anyhow::anyhow!(
            "invalid sand rating configuration in `{}` (network section): {e}",
            crate::config::MAIN_PATH
        )
    })?;

    let v6_rotator = if !v6_proxies.is_empty() {
        Some(Arc::new(ProxyRotator::with_policy(
            v6_proxies,
            rating_policy,
        )))
    } else {
        None
    };

    let gate_rotator = if !gate_proxies.is_empty() {
        Some(Arc::new(ProxyRotator::with_policy(
            gate_proxies,
            rating_policy,
        )))
    } else {
        None
    };

    let v4_rotator = if !v4_proxies.is_empty() {
        Some(Arc::new(ProxyRotator::with_policy(
            v4_proxies,
            rating_policy,
        )))
    } else {
        None
    };

    let no_usable_route = !has_usable_route(v4_rotator.is_some(), v6_rotator.is_some());
    if should_bail_no_upstreams(no_usable_route, &configs.users) {
        anyhow::bail!(
            "no upstream proxies configured.\n\
             \n\
             Add SOCKS5 entries to `{}` under `socks5_v4: [...]` or\n\
             `socks5_v6: [...]`. Each line is `[*]user:pass@host:port`;\n\
             a leading `*` marks a gate.\n\
             \n\
             Example:\n\
                 socks5_v4: [\n\
                     alice:s3cret@1.2.3.4:1080\n\
                 ]\n\
             \n\
             Run `resocks5 --help` for the full configuration overview.",
            crate::config::PROXY_LIST_PATH
        );
    }
    if no_usable_route {
        println!(
            "note: no upstream proxies configured — only direct users \
             will be able to connect through this server"
        );
    }

    // Build auth state BEFORE spawning the log-drain task: its `?` is
    // the only fallible early-return left after that spawn, and an
    // early return there would skip the shutdown drain-join below.
    let auth = Arc::new(auth::AuthState::build(
        &cfg_main.auth,
        &configs.users,
        crate::config::USERS_PATH,
    )?);

    // Async drain of the log channel.
    //
    // `println!`/`eprintln!` take `stdout().lock()` (a `std::sync::Mutex`)
    // and do a synchronous `write()` syscall — on a slow tty or a
    // pipe whose reader is stalled (journald, tee, etc.) that blocks
    // the entire Tokio worker thread. We instead write via
    // `tokio::io::stdout()`/`stderr()`, whose `write_all().await`
    // yields to the runtime: the worker is free to drive other tasks
    // while the kernel finishes the write.
    let file_log_cfg = cfg_main.file_log.clone();
    let log_drain = spawn_log_drain(log_receiver, file_log_cfg);
    let local_addr = format!("{}:{}", cfg_main.listen_host, cfg_main.port);

    println!();
    println!("port:{}", cfg_main.port);
    println!();

    // Pre-connect TCP pool. Spawns one refill task per unique upstream
    // proxy `(host, port)` — `spawn_refill_for` deduplicates internally,
    // so calling it for every proxy in every rotator (gates + v4 + v6)
    // is safe.
    let pool = Arc::new(resocks5_net::pool::ProxyPool::new(
        cfg_main.pool.clone(),
        Duration::from_secs(cfg_main.network.connect_timeout_sec),
        cfg_main.network.max_per_upstream,
    ));
    if pool.enabled() {
        let mut count = 0usize;
        for r in [&gate_rotator, &v6_rotator, &v4_rotator]
            .iter()
            .filter_map(|r| r.as_ref())
        {
            for proxy in r.all_proxies() {
                pool.spawn_refill_for(proxy.clone());
                count += 1;
            }
        }
        logger.lifecycle(move || {
            format!(
                "TCP pool enabled: {} refill task(s), {} spare/proxy, {}s max session age",
                count, cfg_main.pool.spare_per_proxy, cfg_main.pool.max_session_age_sec,
            )
        });
    }

    {
        let rp = rating_policy;
        logger.lifecycle(move || {
            format!(
                "sand rating: half_life={}s penalty={} max={} min_weight={} success_factor={} enabled={}",
                rp.half_life_sec, rp.fail_penalty, rp.sand_max, rp.min_weight, rp.success_factor, rp.enabled()
            )
        });
    }

    let frag = Arc::new(cfg_main.tls_fragment.clone());
    let network = Arc::new(cfg_main.network.clone());

    let tls_connector = if has_https {
        Some(Arc::new(resocks5_net::connect::make_tls_connector()))
    } else {
        None
    };

    let result = server::run_server(
        auth,
        gate_rotator,
        v6_rotator,
        v4_rotator,
        &local_addr,
        &logger,
        banned,
        pool,
        frag,
        network,
        tls_connector,
    )
    .await;

    // Flush whatever is still queued — run_server's own shutdown lines
    // included — before the runtime tears down: drop the last
    // `Arc<Logger>` (closing the channel) and join the drain task with
    // a bounded wait.
    shutdown_log_drain(logger, log_drain).await;
    result
}

/// Bound on joining the log-drain task at shutdown. The normal path
/// needs microseconds: dropping the last `Arc<Logger>` closes the
/// channel and the drain loop exits on `recv() == None`. Five seconds
/// is ample headroom for flushing a full 2048-slot backlog plus the
/// `BufWriter`, while keeping the worst case far below the 30 s tunnel
/// drain (`SHUTDOWN_DRAIN_SEC`) — a log flush must never dominate
/// shutdown.
const LOG_DRAIN_TIMEOUT_SEC: u64 = 5;

/// Body of the async log-drain task, spawned by `run_server`. Returns
/// the `JoinHandle` so shutdown can wait for the queue to flush instead
/// of letting `#[tokio::main]`'s runtime teardown silently cancel the
/// task mid-`recv()`.
///
/// A file write/flush failure is NOT swallowed: the first failure is
/// reported on stderr and the task falls back to console-only for the
/// rest of the run — mirroring the open-failure path above and avoiding
/// one stderr line per queued message once the disk is full or a
/// network share has dropped.
fn spawn_log_drain(
    mut log_receiver: mpsc::Receiver<ELog>,
    file_log_cfg: crate::config::FileLogConfig,
) -> tokio::task::JoinHandle<()> {
    spawn(async move {
        let mut out = tokio::io::stdout();
        let mut err = tokio::io::stderr();

        let mut file: Option<tokio::io::BufWriter<tokio::fs::File>> = if file_log_cfg.enabled {
            match tokio::fs::OpenOptions::new()
                .append(true)
                .create(true)
                .open(&file_log_cfg.path)
                .await
            {
                Ok(f) => Some(tokio::io::BufWriter::new(f)),
                Err(e) => {
                    eprintln!(
                        "file logger: failed to open {}: {} — continuing in console-only mode",
                        file_log_cfg.path, e
                    );
                    None
                }
            }
        } else {
            None
        };

        while let Some(log_message) = log_receiver.recv().await {
            let now = Local::now().format("%Y-%m-%d %H:%M:%S");
            let line = match &log_message {
                ELog::Log(message) | ELog::Error(message) => {
                    format!("{}: {}\n", now, message)
                }
            };

            let write_err = match file.as_mut() {
                Some(f) => write_and_flush_line(f, &line).await.err(),
                None => None,
            };
            if let Some(e) = write_err {
                eprintln!("{}", file_write_error_message(&file_log_cfg.path, &e));
                file = None;
            }

            if file.is_none() || file_log_cfg.also_console {
                match log_message {
                    ELog::Log(_) => {
                        let _ = out.write_all(line.as_bytes()).await;
                    }
                    ELog::Error(_) => {
                        let _ = err.write_all(line.as_bytes()).await;
                    }
                }
            }
        }
    })
}

/// Join the log-drain task at shutdown. Dropping `logger` (the last
/// `Arc<Logger>`) closes the log channel, letting the drain task finish
/// flushing whatever is still queued — including messages logged during
/// `server::run_server`'s own shutdown sequence. Bounded so a channel
/// that somehow never closes can't hang the process; on timeout we
/// complain on stderr because the file logger itself may be what's
/// stuck.
async fn shutdown_log_drain(logger: Arc<logger::Logger>, drain: tokio::task::JoinHandle<()>) {
    drop(logger);
    match tokio::time::timeout(Duration::from_secs(LOG_DRAIN_TIMEOUT_SEC), drain).await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => eprintln!("log drain task failed: {e}"),
        Err(_) => eprintln!(
            "warning: log drain did not finish within {LOG_DRAIN_TIMEOUT_SEC}s — \
             recently queued log lines may have been lost"
        ),
    }
}

/// One write+flush of a formatted log line. Flushed per line (existing
/// behavior — review R27 re-evaluates that separately); the flush error
/// must surface, not vanish into `let _ =`.
async fn write_and_flush_line(
    f: &mut tokio::io::BufWriter<tokio::fs::File>,
    line: &str,
) -> std::io::Result<()> {
    f.write_all(line.as_bytes()).await?;
    f.flush().await
}

/// Pure diagnostic for a failed file-log write/flush, so it can be
/// unit-tested without capturing process stderr.
fn file_write_error_message(path: &str, err: &std::io::Error) -> String {
    format!(
        "file logger: write to {path} failed: {err} — \
         falling back to console-only logging for the rest of this run"
    )
}

#[cfg(test)]
mod tests {
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
}
