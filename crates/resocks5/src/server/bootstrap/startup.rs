use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use regex::RegexSet;
use tokio::sync::mpsc;

use crate::auth;
use crate::config;
use crate::logger::{self, ELog};
use crate::server;
use resocks5_net::connect::parse_proxy_str;
use resocks5_net::rotator::ProxyRotator;
use resocks5_net::types::{ProxyConfig, ProxyProtocol, IP};

use super::log_drain::{shutdown_log_drain, spawn_log_drain};

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
pub(super) fn parse_proxy_list_checked(
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
pub(super) fn skipped_line_message(list_name: &str, line_no: usize) -> String {
    format!(
        "warning: {list_name}[{line_no}]: failed to parse proxy entry — line skipped (entry redacted)"
    )
}

/// Which routing group an owned proxy entry belongs to. A trait, not a
/// direct `ProxyConfig` field read, only so [`partition_proxy_groups`]
/// can be unit-tested with a clone-counting stand-in: with no `Clone`
/// bound the helper structurally cannot copy entries (review R8-07).
pub(super) trait GateSplit {
    fn is_gate(&self) -> bool;
}

impl GateSplit for ProxyConfig {
    fn is_gate(&self) -> bool {
        self.is_gate
    }
}

/// Split owned upstream entries into (plain v6, plain v4, gates) by
/// MOVING each entry into exactly one group — no clone of any plain
/// descriptor, so `host`/username/password Strings are never copied
/// just to have their originals dropped (review R8-07: the previous
/// `iter().filter().cloned()` pass deep-copied every plain entry right
/// before the originals were consumed and discarded).
///
/// Group composition and relative order match the previous construction
/// exactly: plains keep their source-list order, and gates collect as
/// v6-list gates first, then v4-list gates (the previous
/// `all_v6.into_iter().chain(all_v4)` gate order). Still O(N).
pub(super) fn partition_proxy_groups<P: GateSplit>(
    all_v6: Vec<P>,
    all_v4: Vec<P>,
) -> (Vec<P>, Vec<P>, Vec<P>) {
    let mut v6 = Vec::with_capacity(all_v6.len());
    let mut gates = Vec::new();
    for proxy in all_v6 {
        if proxy.is_gate() {
            gates.push(proxy);
        } else {
            v6.push(proxy);
        }
    }
    let mut v4 = Vec::with_capacity(all_v4.len());
    for proxy in all_v4 {
        if proxy.is_gate() {
            gates.push(proxy);
        } else {
            v4.push(proxy);
        }
    }
    (v6, v4, gates)
}

/// `cb_*` key names found in the raw main-config text, in file order.
/// Pure so the detection is unit-testable; matching is deliberately
/// textual (ktav drops unknown keys during deserialize without
/// reporting them): a key line starts (after indentation) with `cb_`
/// and contains `:`. Quoted values such as banned patterns never match.
pub(super) fn obsolete_cb_keys(text: &str) -> Vec<String> {
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

/// Previous `#[tokio::main]` body, unchanged apart from the name: all
/// runtime-dependent work stays here so `run_server` alone owns
/// runtime creation and the bounded teardown.
pub(super) async fn run_server_inner() -> Result<()> {
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

    let (v6_proxies, v4_proxies, gate_proxies) = partition_proxy_groups(all_v6, all_v4);

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
