use std::path::Path;

use anyhow::{Context, Result};
use serde::Deserialize;

use crate::config::{
    AuthConfig, Configs, FileLogConfig, MainConfig, NetworkConfig, ProxyListConfig,
    TlsFragmentConfig, UsersConfig, MAIN_PATH, PROXY_LIST_PATH, USERS_PATH,
};
use crate::logger::LogConfig;
use resocks5_net::pool::PoolConfig;

const OLD_MAIN_PATH: &str = "resocks5.conf";
const OLD_SOCKS5_V4_PATH: &str = "socks5_ipv4_list.txt";
const OLD_SOCKS5_V6_PATH: &str = "socks5_ipv6_list.txt";

/// Load all three configs, creating any that don't yet exist with
/// sensible defaults. Migrates the old `resocks5.conf` /
/// `socks5_*_list.txt` layout once if found.
pub fn load_or_init() -> Result<Configs> {
    let main = load_or_init_main()?;
    let proxy_list = load_or_init_proxy_list()?;
    let users = load_or_init_users()?;
    Ok(Configs {
        main,
        proxy_list,
        users,
    })
}

fn load_or_init_main() -> Result<MainConfig> {
    if Path::new(MAIN_PATH).exists() {
        return ktav::from_file(MAIN_PATH).with_context(|| format!("read {}", MAIN_PATH));
    }

    let cfg = if Path::new(OLD_MAIN_PATH).exists() {
        eprintln!("Migrating {} → {}", OLD_MAIN_PATH, MAIN_PATH);
        #[derive(Deserialize)]
        struct OldMain {
            port: u16,
            #[serde(default)]
            banned_patterns: Vec<String>,
        }
        let old: OldMain =
            ktav::from_file(OLD_MAIN_PATH).with_context(|| format!("migrate {}", OLD_MAIN_PATH))?;
        default_main(old.port, old.banned_patterns)
    } else {
        eprintln!("Creating default {}", MAIN_PATH);
        default_main(20082, Vec::new())
    };

    ktav::to_file(&cfg, MAIN_PATH).with_context(|| format!("write {}", MAIN_PATH))?;
    Ok(cfg)
}

fn load_or_init_proxy_list() -> Result<ProxyListConfig> {
    if Path::new(PROXY_LIST_PATH).exists() {
        return ktav::from_file(PROXY_LIST_PATH)
            .with_context(|| format!("read {}", PROXY_LIST_PATH));
    }

    let mut cfg = ProxyListConfig::default();
    let mut migrated = false;
    if Path::new(OLD_SOCKS5_V4_PATH).exists() {
        cfg.socks5_v4 = read_proxy_lines(OLD_SOCKS5_V4_PATH)?;
        migrated = true;
    }
    if Path::new(OLD_SOCKS5_V6_PATH).exists() {
        cfg.socks5_v6 = read_proxy_lines(OLD_SOCKS5_V6_PATH)?;
        migrated = true;
    }

    if migrated {
        eprintln!(
            "Migrated {} entries (v4) + {} entries (v6) from .txt → {}",
            cfg.socks5_v4.len(),
            cfg.socks5_v6.len(),
            PROXY_LIST_PATH
        );
    } else {
        eprintln!("Creating empty {}", PROXY_LIST_PATH);
    }

    ktav::to_file(&cfg, PROXY_LIST_PATH).with_context(|| format!("write {}", PROXY_LIST_PATH))?;
    Ok(cfg)
}

fn load_or_init_users() -> Result<UsersConfig> {
    if Path::new(USERS_PATH).exists() {
        return ktav::from_file(USERS_PATH).with_context(|| format!("read {}", USERS_PATH));
    }

    eprintln!("Creating empty {}", USERS_PATH);
    let cfg = UsersConfig::default();
    ktav::to_file(&cfg, USERS_PATH).with_context(|| format!("write {}", USERS_PATH))?;
    Ok(cfg)
}

/// Build a fully-populated default `MainConfig`. Centralises the
/// "fresh install" defaults so both branches above stay in sync, and
/// so the `default_main_serializes_every_field` test below has one
/// canonical instance to inspect.
fn default_main(port: u16, banned_patterns: Vec<String>) -> MainConfig {
    MainConfig {
        port,
        listen_host: "127.0.0.1".to_string(),
        banned_patterns,
        auth: AuthConfig {
            allow_anonymous: true,
        },
        log: LogConfig::default(),
        pool: PoolConfig::default(),
        tls_fragment: TlsFragmentConfig::default(),
        network: NetworkConfig::default(),
        file_log: FileLogConfig::default(),
    }
}

/// Read `.txt` proxy list — one entry per line, ignoring blank lines and
/// comments (`#…`). Used only by the one-time migration path.
fn read_proxy_lines(path: &str) -> Result<Vec<String>> {
    let text = std::fs::read_to_string(path).with_context(|| format!("read {}", path))?;
    Ok(text
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(String::from)
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The serializer must not emit ktav type-tags (`:i` for integers,
    /// `:b` for booleans, etc.) on field names. ktav ≥ 0.6 dropped
    /// support for them; if our deps drift back to a version that emits
    /// them, fresh `resocks5.main.ktav` files become unparseable.
    #[test]
    fn default_main_has_no_type_tags() {
        let serialized = ktav::to_string(&default_main(20082, Vec::new()))
            .expect("ktav serialization of default MainConfig");
        let re = regex::Regex::new(r"(?m)^\s*[A-Za-z_]\w*:[a-z]\s").unwrap();
        assert!(
            !re.is_match(&serialized),
            "serialized default MainConfig contains a ktav type-tag \
             (e.g. `port:i 20082` instead of `port: 20082`):\n{}",
            serialized
        );
    }

    /// The default config must round-trip through ktav. If
    /// serialization emits anything the deserializer cannot read back
    /// (a stray type-tag, an unsupported escape, a renamed field), the
    /// fresh file we wrote at first launch will fail to load on the
    /// second launch and the user is bricked. We catch that here.
    #[test]
    fn default_main_round_trips_through_ktav() {
        let cfg = default_main(20082, vec!["^bad\\.test$".to_string()]);
        let serialized = ktav::to_string(&cfg).expect("ktav serialization of default MainConfig");
        let parsed: MainConfig = ktav::from_str(&serialized)
            .unwrap_or_else(|e| panic!("ktav cannot read back its own output: {e}\n{serialized}"));
        let re_serialized =
            ktav::to_string(&parsed).expect("ktav serialization of round-tripped MainConfig");
        assert_eq!(
            serialized, re_serialized,
            "MainConfig is not stable under write → read → write"
        );
    }

    /// A fresh `resocks5.main.ktav` must literally contain every tunable —
    /// nothing should be hidden behind `#[serde(default)]` such that the
    /// user has to read source code to discover it. If you add a new
    /// option to `MainConfig` / `AuthConfig` / `LogConfig` / `PoolConfig`,
    /// add its serialised key here too — the test will fail loudly if
    /// the serializer drops it (e.g. someone added
    /// `#[serde(skip_serializing_if = "...")]`).
    #[test]
    fn default_main_serializes_every_field() {
        let serialized = ktav::to_string(&default_main(20082, Vec::new()))
            .expect("ktav serialization of default MainConfig");

        for key in [
            // MainConfig
            "port:",
            "listen_host:",
            "banned_patterns:",
            "auth:",
            "log:",
            "pool:",
            "tls_fragment:",
            "network:",
            "file_log:",
            // AuthConfig
            "allow_anonymous:",
            // LogConfig (every flag)
            "lifecycle:",
            "cache_attempts:",
            "cache_hits:",
            "cache_writes:",
            "proxy_failures:",
            "banned_targets:",
            "connection_errors:",
            // PoolConfig
            "enabled:",
            "spare_per_proxy:",
            "max_session_age_sec:",
            // TlsFragmentConfig
            "fragment_size:",
            "delay_ms:",
            // NetworkConfig
            "connect_timeout_sec:",
            "handshake_timeout_sec:",
            "tunnel_max_lifetime_sec:",
            "tcp_keepalive_sec:",
            "client_protocol_timeout_sec:",
            "max_concurrent_clients:",
            "max_upstream_attempts:",
            "max_per_upstream:",
            "tunnel_idle_timeout_sec:",
            "max_concurrent_direct:",
            "sand_half_life_sec:",
            "sand_fail_penalty:",
            "sand_max:",
            "sand_min_weight:",
            "sand_success_factor:",
            "recover_host_from_payload:",
            // FileLogConfig
            "enabled:",
            "path:",
            "also_console:",
        ] {
            assert!(
                serialized.contains(key),
                "default MainConfig serialization is missing key {:?}.\n\
                 Full output:\n{}",
                key,
                serialized
            );
        }
    }
}
