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

/// Decide whether an empty upstream pool should abort startup.
///
/// Returns `true` (bail) when there are zero upstream proxies AND no
/// enabled direct user — i.e. no client could possibly route traffic.
/// Returns `false` when at least one enabled direct user exists, which
/// means the server can still be useful even without upstreams.
pub(crate) fn should_bail_no_upstreams(
    all_rotators_empty: bool,
    users: &crate::config::UsersConfig,
) -> bool {
    if !all_rotators_empty {
        return false;
    }
    let has_active_direct = users.users.iter().any(|u| u.is_enabled && u.direct);
    !has_active_direct
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

    // Compile all banned patterns into one DFA — single-pass match per
    // connection regardless of how many patterns are configured.
    let banned = Arc::new(
        RegexSet::new(&cfg_main.banned_patterns).expect("Invalid regex pattern in banned_patterns"),
    );

    // Log banned patterns for debugging
    for pattern in &cfg_main.banned_patterns {
        println!("Banned pattern: {}", pattern);
    }

    let parse_list = |list: &[String], proto, ip| -> Vec<ProxyConfig> {
        list.iter()
            .filter_map(|x| parse_proxy_str(x, proto, ip))
            .collect()
    };

    let pl = &configs.proxy_list;
    let mut all_v6: Vec<ProxyConfig> = parse_list(&pl.socks5_v6, ProxyProtocol::Socks5, IP::V6);
    all_v6.extend(parse_list(&pl.http_v6, ProxyProtocol::Http, IP::V6));
    all_v6.extend(parse_list(&pl.https_v6, ProxyProtocol::Https, IP::V6));

    let mut all_v4: Vec<ProxyConfig> = parse_list(&pl.socks5_v4, ProxyProtocol::Socks5, IP::V4);
    all_v4.extend(parse_list(&pl.http_v4, ProxyProtocol::Http, IP::V4));
    all_v4.extend(parse_list(&pl.https_v4, ProxyProtocol::Https, IP::V4));

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
    let (log_sender, mut log_receiver) = mpsc::channel::<ELog>(2048);
    let logger: Arc<logger::Logger> =
        Arc::new(logger::Logger::new(log_sender, cfg_main.log.clone()));

    let rating_policy = resocks5_net::rating::RatingPolicy {
        half_life_sec: cfg_main.network.sand_half_life_sec,
        fail_penalty: cfg_main.network.sand_fail_penalty,
        sand_max: cfg_main.network.sand_max,
        min_weight: cfg_main.network.sand_min_weight,
        success_factor: cfg_main.network.sand_success_factor,
    };

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

    let all_rotators_empty = v4_rotator.is_none() && v6_rotator.is_none() && gate_rotator.is_none();
    if should_bail_no_upstreams(all_rotators_empty, &configs.users) {
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
    if all_rotators_empty {
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

            if let Some(ref mut f) = file {
                if let Ok(()) = f.write_all(line.as_bytes()).await {
                    let _ = f.flush().await;
                }
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
    });
    let local_addr = format!("{}:{}", cfg_main.listen_host, cfg_main.port);

    println!();
    println!("port:{}", cfg_main.port);
    println!();

    let auth = Arc::new(auth::AuthState::build(
        &cfg_main.auth,
        &configs.users,
        crate::config::USERS_PATH,
    )?);

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

    server::run_server(
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
    .await
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
}
