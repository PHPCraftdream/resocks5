use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use regex::RegexSet;
use tokio::sync::mpsc;

use crate::auth;
use crate::config::{self, AllowedClients};
use crate::logger::{self, ELog};
use crate::server;
use resocks5_net::chain::GateLevels;
use resocks5_net::connect::parse_proxy_str;
use resocks5_net::rotator::ProxyRotator;
use resocks5_net::types::{ProxyConfig, ProxyProtocol};

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
///
/// Entries keep their parsed `user`/`password`. A SOCKS5 entry upgrades
/// automatically (method 0x80 offered first, 0x02 after it, the upstream
/// picks); an HTTP/HTTPS entry sends Basic in its first request, as 0.4.x
/// did. `;secure_only` on an entry — or the global
/// `upstream_auth.secure_only` switch — forces our-method-only for it.
fn parse_proxy_list(
    list_name: &str,
    list: &[String],
    proto: ProxyProtocol,
    upstream_secure_only: bool,
) -> Vec<ProxyConfig> {
    let (parsed, failed) = parse_proxy_list_checked(list, proto, upstream_secure_only);
    for line_no in &failed {
        // A malformed `;secure_only` flag gets its own message; everything
        // else is the generic parse failure. Both redact the entry.
        if let Some(line) = list.get(line_no - 1) {
            if split_secure_only_option(line).is_err() {
                println!(
                    "warning: {list_name}[{line_no}]: malformed `;secure_only` option — \
                     line skipped (entry redacted)"
                );
                continue;
            }
        }
        println!("{}", skipped_line_message(list_name, *line_no));
    }
    parsed
}

/// Pure part of [`parse_proxy_list`]: parsed configs plus the 1-based
/// numbers of dropped lines. `#` comment lines are skipped silently (the
/// parser rejects them by design).
///
/// A parsed entry keeps its `user`/`password`. A SOCKS5 entry upgrades
/// automatically (0x80 offered first, 0x02 after it); an HTTP/HTTPS entry
/// sends Basic in its first request, as 0.4.x did. The per-entry
/// `;secure_only` flag or the global `upstream_secure_only` switch forces
/// our-method-only (`ProxyConfig::secure_only()`): the dial then fails
/// before any password byte when the upstream offers nothing but clear
/// text. A 0.4.x `;gssapi=` entry is dropped with a warning (GSSAPI was
/// removed in 0.5.0).
pub(super) fn parse_proxy_list_checked(
    list: &[String],
    proto: ProxyProtocol,
    upstream_secure_only: bool,
) -> (Vec<ProxyConfig>, Vec<usize>) {
    let mut parsed = Vec::with_capacity(list.len());
    let mut failed = Vec::new();
    for (idx, line) in list.iter().enumerate() {
        if line.starts_with('#') {
            continue;
        }
        // 0.4.x GSSAPI entries cannot be honored any more (GSSAPI was
        // removed in 0.5.0): drop them with a clear warning. The old
        // `;gssapi=` guard applies: non-empty right side without `:`.
        if let Some((entry, service)) = line.rsplit_once(";gssapi=") {
            if !service.is_empty() && !service.contains(':') {
                match parse_proxy_str(entry, proto) {
                    Ok(config) => {
                        println!(
                            "warning: upstream {}:{}: `;gssapi=` is no longer supported \
                             (GSSAPI was removed in 0.5.0) — entry dropped",
                            config.host, config.port
                        );
                        failed.push(idx + 1);
                    }
                    // The generic skipped-line message covers it.
                    Err(_) => failed.push(idx + 1),
                }
                continue;
            }
        }
        let (entry, secure_only) = match split_secure_only_option(line) {
            Ok(split) => split,
            // Fail-closed: an entry whose auth policy we cannot parse
            // must not be dialed.
            Err(()) => {
                failed.push(idx + 1);
                continue;
            }
        };
        match parse_proxy_str(entry, proto) {
            Ok(config) => parsed.push(apply_upstream_auth(
                config,
                secure_only,
                upstream_secure_only,
            )),
            Err(_) => failed.push(idx + 1),
        }
    }
    (parsed, failed)
}

/// Split the trailing `;secure_only` flag off a proxy-list line. Anything
/// following the flag is malformed (`;secure_only=yes`): the auth policy
/// cannot be parsed, so the entry must be dropped.
pub(super) fn split_secure_only_option(line: &str) -> Result<(&str, bool), ()> {
    match line.rsplit_once(";secure_only") {
        Some((entry, "")) => Ok((entry, true)),
        Some(_) => Err(()),
        None => Ok((line, false)),
    }
}

/// Resolve the outbound auth policy: the per-entry `;secure_only` flag and
/// the global `upstream_auth.secure_only` switch both force
/// our-method-only; otherwise the entry keeps its parsed credentials and
/// the SDK upgrades it automatically.
pub(super) fn apply_upstream_auth(
    config: ProxyConfig,
    entry_secure_only: bool,
    global_secure_only: bool,
) -> ProxyConfig {
    if entry_secure_only || global_secure_only {
        config.secure_only()
    } else {
        config
    }
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
/// direct `ProxyConfig` field read, so the clone-free partitioning and
/// gate-rank grouping helpers can be tested with a clone-counting stand-in.
pub(super) trait GateSplit {
    fn is_gate(&self) -> bool;
    fn gate_level(&self) -> u8;
}

impl GateSplit for ProxyConfig {
    fn is_gate(&self) -> bool {
        self.is_gate
    }
    fn gate_level(&self) -> u8 {
        self.gate_level
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

/// Ordered map keys make gaps explicit and rotator construction deterministic.
pub(super) fn group_gate_levels<P: GateSplit>(
    gates: Vec<P>,
) -> std::collections::BTreeMap<u8, Vec<P>> {
    let mut levels = std::collections::BTreeMap::new();
    for gate in gates {
        levels
            .entry(gate.gate_level())
            .or_insert_with(Vec::new)
            .push(gate);
    }
    levels
}
/// Every rotator: all gate levels, then v6 and v4 exits.
///
/// Test-only since health saving needs each rotator's group name.
#[cfg(test)]
pub(super) fn all_rotators(
    gates: &GateLevels,
    exits: &[Option<Arc<ProxyRotator>>],
) -> Vec<Arc<ProxyRotator>> {
    gates
        .iter()
        .map(|(_, rotator)| Arc::clone(rotator))
        .chain(exits.iter().filter_map(Option::as_ref).map(Arc::clone))
        .collect()
}

/// Rotators dialed directly by the pool path: outermost gate, then exits.
pub(super) fn directly_dialed_rotators(
    gates: &GateLevels,
    exits: &[Option<Arc<ProxyRotator>>],
) -> Vec<Arc<ProxyRotator>> {
    gates
        .iter()
        .take(1)
        .map(|(_, rotator)| Arc::clone(rotator))
        .chain(exits.iter().filter_map(Option::as_ref).map(Arc::clone))
        .collect()
}

/// `cb_*` key names found in the raw main-config text, in file order.
/// Pure so the detection is unit-testable; matching is deliberately textual
/// (ktav drops unknown keys during deserialize without reporting them): a key
/// line starts (after indentation) with `cb_` and contains `:`. Quoted values
/// such as banned patterns never match.
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

/// `gssapi_*` key names found in the raw main-config text, in file order.
/// Pure so the detection is unit-testable; matching is deliberately textual
/// (ktav drops unknown keys during deserialize without reporting them): a
/// key line starts (after indentation) with `gssapi_service:` or
/// `gssapi_protection:` and contains `:`.
pub(super) fn obsolete_gssapi_keys(text: &str) -> Vec<String> {
    const PREFIXES: [&str; 2] = ["gssapi_service", "gssapi_protection"];
    text.lines()
        .filter_map(|line| {
            let trimmed = line.trim_start();
            PREFIXES.iter().find_map(|prefix| {
                trimmed
                    .strip_prefix(prefix)?
                    .starts_with(':')
                    .then(|| (*prefix).to_string())
            })
        })
        .collect()
}

/// Startup warning for settings this binary no longer understands.
fn warn_obsolete_gssapi_keys() {
    let Ok(text) = std::fs::read_to_string(crate::config::MAIN_PATH) else {
        return;
    };
    let ignored = obsolete_gssapi_keys(&text);
    if !ignored.is_empty() {
        println!(
            "warning: {} contains settings this version ignores: {}\n\
             GSSAPI support was removed in 0.5.0; remove these keys from the `auth:` section.",
            crate::config::MAIN_PATH,
            ignored.join(", ")
        );
    }
}

/// Single validation point for allowed_clients at startup: compiling
/// the global rule and AuthState::build (including each user's rules).
/// Called in `run_server_inner` BEFORE the route-bailout and
/// spawn_log_drain, so an invalid string yields a contextual
/// allowed_clients error even with no upstreams and is not masked by
/// the "no upstream proxies" message. Made pub(crate) as a seam for
/// a focused test of the validation path.
pub(crate) fn validate_allowed_clients(
    cfg_main: &crate::config::MainConfig,
    users: &crate::config::UsersConfig,
) -> anyhow::Result<(Arc<AllowedClients>, Arc<auth::AuthState>)> {
    let allowed_clients = Arc::new(
        crate::config::compile_allowed_clients(&cfg_main.allowed_clients)
            .map_err(|e| anyhow::anyhow!("{}: allowed_clients: {e}", crate::config::MAIN_PATH))?,
    );
    let auth = Arc::new(auth::AuthState::build(
        &cfg_main.auth,
        users,
        crate::config::USERS_PATH,
    )?);
    Ok((allowed_clients, auth))
}

/// Admission sanity at startup: refuse to serve a configuration that no
/// client could ever enter — no users configured AND anonymous access off
/// (either because `allow_anonymous` is false or because `secure_only`
/// silences it).
pub(crate) fn validate_admission(auth: &crate::auth::AuthState) -> anyhow::Result<()> {
    let admits_anonymous = auth.allow_anonymous && !auth.secure_only;
    if !admits_anonymous && auth.is_empty() {
        anyhow::bail!(
            "no users are configured and anonymous access is off, so no client could ever \
             connect (auth.allow_anonymous: {}{}).\n\
             \n\
             Create a user with `resocks5 users add <name>` (or `resocks5 users add-init <name>`),\n\
             or set `auth.allow_anonymous: true` in `{}` (and unset `auth.secure_only`\
             if you need anonymous access).",
            auth.allow_anonymous,
            if auth.secure_only {
                ", auth.secure_only: true"
            } else {
                ""
            },
            crate::config::MAIN_PATH
        );
    }
    Ok(())
}

/// `auth.secure_only` silences anonymous access: the combination is legal
/// but the anonymous setting has no effect, so warn.
pub(super) fn secure_only_conflict(auth: &crate::auth::AuthState) -> bool {
    auth.secure_only && auth.allow_anonymous
}

/// Previous `#[tokio::main]` body, unchanged apart from the name: all
/// runtime-dependent work stays here so `run_server` alone owns
/// runtime creation and the bounded teardown.
pub(super) async fn run_server_inner() -> Result<()> {
    let configs = config::load_or_init()?;
    let cfg_main = &configs.main;

    // Global rule + user rules — ONE validation point at startup,
    // before the route-bailout and before spawn_log_drain (all
    // `?`-returns above the spawns).
    let (allowed_clients, auth) = validate_allowed_clients(cfg_main, &configs.users)?;

    warn_obsolete_cb_keys();
    warn_obsolete_gssapi_keys();

    // Admission + auth-policy sanity: bail before any listener exists if
    // no client could ever connect. The secure_only conflict is printed
    // first so it is not masked by the bail.
    if secure_only_conflict(&auth) {
        println!(
            "warning: auth.secure_only is true — auth.allow_anonymous is ignored \
             (no anonymous access is served)"
        );
    }
    validate_admission(&auth)?;

    // Compile all banned patterns into one DFA — single-pass match per
    // connection regardless of how many patterns are configured.
    let banned = Arc::new(
        RegexSet::new(&cfg_main.banned_patterns).expect("Invalid regex pattern in banned_patterns"),
    );

    // Log banned patterns for debugging
    for pattern in &cfg_main.banned_patterns {
        println!("Banned pattern: {}", pattern);
    }

    let upstream_secure_only = cfg_main.upstream_auth.secure_only;
    let pl = &configs.proxy_list;
    let mut all_v6: Vec<ProxyConfig> = parse_proxy_list(
        "socks5_v6",
        &pl.socks5_v6,
        ProxyProtocol::Socks5,
        upstream_secure_only,
    );
    all_v6.extend(parse_proxy_list(
        "http_v6",
        &pl.http_v6,
        ProxyProtocol::Http,
        upstream_secure_only,
    ));
    all_v6.extend(parse_proxy_list(
        "https_v6",
        &pl.https_v6,
        ProxyProtocol::Https,
        upstream_secure_only,
    ));

    let mut all_v4: Vec<ProxyConfig> = parse_proxy_list(
        "socks5_v4",
        &pl.socks5_v4,
        ProxyProtocol::Socks5,
        upstream_secure_only,
    );
    all_v4.extend(parse_proxy_list(
        "http_v4",
        &pl.http_v4,
        ProxyProtocol::Http,
        upstream_secure_only,
    ));
    all_v4.extend(parse_proxy_list(
        "https_v4",
        &pl.https_v4,
        ProxyProtocol::Https,
        upstream_secure_only,
    ));

    let (v6_proxies, v4_proxies, gate_proxies) = partition_proxy_groups(all_v6, all_v4);
    let gate_groups = group_gate_levels(gate_proxies);

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
    for (rank, proxies) in gate_groups.iter().rev() {
        println!("gates level {rank}:");
        for proxy in proxies {
            println!(
                "{:?}://{}:{} - {}",
                proxy.protocol,
                proxy.host,
                proxy.port,
                crate::server::connect::print_cfg::family_label(&proxy.host)
            );
        }
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
    // A probe owns its slot long enough to finish one full upstream
    // attempt: one TCP connect plus one handshake per gate level plus the
    // final handshake to the tested node — the worst-case
    // `probe_deadline` budget the probe itself runs under, plus the
    // shared margin before the probe is re-issued, so a probe can never
    // outlive its lease (audit V08). The probe settlement side fences on
    // the same helper, so the two budgets cannot diverge (review P2 №4).
    let probe_lease = crate::server::connect::establish_connection::probe_lease(
        std::time::Duration::from_secs(cfg_main.network.connect_timeout_sec),
        std::time::Duration::from_secs(cfg_main.network.handshake_timeout_sec),
        gate_groups.len(),
    );
    let quarantine_policy = resocks5_net::rating::QuarantinePolicy::default()
        .with_threshold(cfg_main.network.quarantine_threshold)
        .with_initial(std::time::Duration::from_secs(
            cfg_main.network.quarantine_initial_sec,
        ))
        .with_max(std::time::Duration::from_secs(
            cfg_main.network.quarantine_max_sec,
        ))
        .with_probe_lease(probe_lease);
    let new_rotator = |proxies| {
        ProxyRotator::try_with_quarantine(
            proxies,
            rating_policy,
            quarantine_policy,
            resocks5_net::rotator::DEFAULT_STICKY_CACHE_MAX_ENTRIES,
            resocks5_net::rotator::DEFAULT_STICKY_CACHE_TTL,
        )
    };
    // The rotator constructor validates the rating and quarantine
    // policies itself; an invalid `network` section surfaces here.
    let map_cfg_err = |e: resocks5_net::rotator::RotatorError| {
        anyhow::anyhow!(
            "invalid sand rating or quarantine configuration in `{}` (network section): {e}",
            crate::config::MAIN_PATH
        )
    };

    let v6_rotator = if !v6_proxies.is_empty() {
        Some(Arc::new(new_rotator(v6_proxies).map_err(map_cfg_err)?))
    } else {
        None
    };

    // Ranks come from a map (unique by construction); `try_new` enforces the
    // invariant in release builds too.
    let gate_levels = Arc::new(
        GateLevels::try_new(
            gate_groups
                .into_iter()
                .map(|(rank, proxies)| {
                    Ok((rank, Arc::new(new_rotator(proxies).map_err(map_cfg_err)?)))
                })
                .collect::<Result<Vec<_>>>()?,
        )
        .map_err(|e| anyhow::anyhow!("invalid gate levels: {e}"))?,
    );

    let v4_rotator = if !v4_proxies.is_empty() {
        Some(Arc::new(new_rotator(v4_proxies).map_err(map_cfg_err)?))
    } else {
        None
    };

    let no_usable_route = !has_usable_route(v4_rotator.is_some(), v6_rotator.is_some());
    if should_bail_no_upstreams(no_usable_route, &configs.users) {
        anyhow::bail!(
            "no upstream proxies configured.\n\
             \n\
             Add SOCKS5 entries to `{}` under `socks5_v4: [...]` or\n\
             `socks5_v6: [...]`. Proxy lines may start with `*` repeated N times to set\n\
             gate level N; highest levels are outermost and dialed first.\n\
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

    // Pre-connect TCP pool for the outermost gate and each plain exit rotator;
    // inner gates are dialed only after the outer hop has completed.
    let pool = Arc::new(resocks5_net::pool::ProxyPool::new(
        cfg_main.pool.clone(),
        Duration::from_secs(cfg_main.network.connect_timeout_sec),
        cfg_main.network.max_per_upstream,
    ));
    if pool.enabled() {
        let mut count = 0usize;
        for r in directly_dialed_rotators(&gate_levels, &[v6_rotator.clone(), v4_rotator.clone()]) {
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

    // Dead upstreams of the previous run go straight to quarantine/probation.
    // Every rotator is saved and restored, each under its routing group's
    // name, so one endpoint in two groups keeps two health cells. Only the
    // directly dialed rotators (outermost gate + exits) get the post-restore
    // probes: an inner gate is reachable only through its prefix, and a
    // direct probe would falsely re-quarantine it.
    let mut health_rotators: Vec<server::health::HealthGroup> = gate_levels
        .iter()
        .map(|(rank, rotator)| server::health::HealthGroup {
            name: format!("gate{rank}"),
            rotator: Arc::clone(rotator),
        })
        .collect();
    for (name, rotator) in [("v6", &v6_rotator), ("v4", &v4_rotator)] {
        if let Some(rotator) = rotator {
            health_rotators.push(server::health::HealthGroup {
                name: name.to_owned(),
                rotator: Arc::clone(rotator),
            });
        }
    }
    let health_path = std::path::PathBuf::from(crate::config::HEALTH_PATH);
    let health = (cfg_main.network.health_save_sec > 0
        && cfg_main.network.quarantine_threshold > 0)
        .then(|| {
            server::health::start(
                health_rotators.clone(),
                directly_dialed_rotators(&gate_levels, &[v6_rotator.clone(), v4_rotator.clone()]),
                pool.clone(),
                health_path.clone(),
                Duration::from_secs(cfg_main.network.health_save_sec),
                Duration::from_secs(cfg_main.network.connect_timeout_sec.clamp(1, 3)),
                logger.clone(),
            )
        });

    let (health_saver, health_found) = match health {
        Some((saver, found)) => (Some(saver), found),
        None => (None, false),
    };

    // In the background: the listener must bind at once, a refused
    // connection makes browsers mark the proxy failed for a long time.
    // A saved health picture already says who was dead, and one connect at the
    // very first instant after a restart can fail for reasons of the host
    // (network not settled yet), so with a picture the check is skipped.
    if cfg_main.network.quarantine_threshold > 0 && !health_found {
        let rotators =
            directly_dialed_rotators(&gate_levels, &[v6_rotator.clone(), v4_rotator.clone()]);
        tokio::spawn(quarantine_unreachable_at_start(
            rotators,
            pool.clone(),
            logger.clone(),
            Duration::from_secs(cfg_main.network.connect_timeout_sec.clamp(1, 3)),
        ));
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
        gate_levels,
        v6_rotator,
        v4_rotator,
        &local_addr,
        &logger,
        banned,
        pool,
        frag,
        network,
        tls_connector,
        Some(allowed_clients),
    )
    .await;

    if let Some(saver) = health_saver {
        saver.finish(&health_rotators, &health_path).await;
    }

    // Flush whatever is still queued — run_server's own shutdown lines
    // included — before the runtime tears down: drop the last
    // `Arc<Logger>` (closing the channel) and join the drain task with
    // a bounded wait.
    shutdown_log_drain(logger, log_drain).await;
    result
}

/// Right after startup: one TCP connect to every upstream, all at once,
/// bounded by `timeout`. Unreachable ones get quarantined, so clients after
/// a restart soon stop drawing a dead upstream; background probes bring
/// them back once they answer.
async fn quarantine_unreachable_at_start(
    rotators: Vec<Arc<ProxyRotator>>,
    pool: Arc<resocks5_net::pool::ProxyPool>,
    logger: Arc<logger::Logger>,
    timeout: Duration,
) {
    let mut checks = tokio::task::JoinSet::new();
    for rotator in rotators {
        let pool = pool.clone();
        let logger = logger.clone();
        checks.spawn(async move {
            // At capacity (our own load) the start-up check defers: the
            // upstream is neither probed nor quarantined (review P2 №5).
            for event in rotator
                .probe_all_with(timeout, move |proxy| pool.reserve_permit(proxy).ok())
                .await
            {
                if let resocks5_net::rotator::ProbeEvent::QuarantinedAtStart {
                    proxy,
                    quarantined_for,
                    reason,
                } = event
                {
                    logger.proxy_failure(|| {
                        format!(
                            "Upstream {} is unreachable at startup ({}) - quarantined for {}s",
                            crate::server::print_cfg(&proxy),
                            reason,
                            quarantined_for.as_secs()
                        )
                    });
                }
            }
        });
    }
    while checks.join_next().await.is_some() {}
}
