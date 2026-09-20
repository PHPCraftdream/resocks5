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
    load_or_init_main_at(Path::new(""))
}

fn load_or_init_main_at(dir: &Path) -> Result<MainConfig> {
    let path = dir.join(MAIN_PATH);
    if path.exists() {
        return ktav::from_file(&path).with_context(|| format!("read {}", path.display()));
    }

    let _lock = crate::config::users_file::UsersFileLock::acquire(&path)?;
    if path.exists() {
        return ktav::from_file(&path).with_context(|| format!("read {}", path.display()));
    }

    let cfg = if dir.join(OLD_MAIN_PATH).exists() {
        eprintln!("Migrating {} → {}", OLD_MAIN_PATH, MAIN_PATH);
        #[derive(Deserialize)]
        struct OldMain {
            port: u16,
            #[serde(default)]
            banned_patterns: Vec<String>,
        }
        let old: OldMain = ktav::from_file(dir.join(OLD_MAIN_PATH))
            .with_context(|| format!("migrate {}", OLD_MAIN_PATH))?;
        default_main(old.port, old.banned_patterns)
    } else {
        eprintln!("Creating default {}", MAIN_PATH);
        default_main(20082, Vec::new())
    };

    crate::config::users_file::write_atomic(&path, &cfg)
        .with_context(|| format!("write {}", path.display()))?;
    Ok(cfg)
}

fn load_or_init_proxy_list() -> Result<ProxyListConfig> {
    load_or_init_proxy_list_at(Path::new(""))
}

fn load_or_init_proxy_list_at(dir: &Path) -> Result<ProxyListConfig> {
    let path = dir.join(PROXY_LIST_PATH);
    if path.exists() {
        return ktav::from_file(&path).with_context(|| format!("read {}", path.display()));
    }

    let _lock = crate::config::users_file::UsersFileLock::acquire(&path)?;
    if path.exists() {
        return ktav::from_file(&path).with_context(|| format!("read {}", path.display()));
    }

    let mut cfg = ProxyListConfig::default();
    let mut migrated = false;
    let v4_path = dir.join(OLD_SOCKS5_V4_PATH);
    let v6_path = dir.join(OLD_SOCKS5_V6_PATH);
    if v4_path.exists() {
        cfg.socks5_v4 = read_proxy_lines(&v4_path)?;
        migrated = true;
    }
    if v6_path.exists() {
        cfg.socks5_v6 = read_proxy_lines(&v6_path)?;
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

    crate::config::users_file::write_atomic(&path, &cfg)
        .with_context(|| format!("write {}", path.display()))?;
    Ok(cfg)
}

fn load_or_init_users() -> Result<UsersConfig> {
    load_or_init_users_at(Path::new(USERS_PATH))
}

fn load_or_init_users_at(path: &Path) -> Result<UsersConfig> {
    if path.exists() {
        return ktav::from_file(path).with_context(|| format!("read {}", path.display()));
    }

    let _lock = crate::config::users_file::UsersFileLock::acquire(path)?;
    if path.exists() {
        return ktav::from_file(path).with_context(|| format!("read {}", path.display()));
    }
    eprintln!("Creating empty {}", path.display());
    let cfg = UsersConfig::default();
    crate::config::users_file::write_atomic(path, &cfg)?;
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
fn read_proxy_lines(path: &Path) -> Result<Vec<String>> {
    let text = std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
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
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn unique_users_path(tag: &str) -> std::path::PathBuf {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "resocks5_init_{}_{}_{}.ktav",
            std::process::id(),
            tag,
            nonce
        ))
    }

    #[test]
    fn initialization_cannot_write_while_another_writer_holds_the_lock() {
        let path = unique_users_path("locked");
        let lock = crate::config::users_file::UsersFileLock::acquire(&path).unwrap();
        let result = load_or_init_users_at(&path);
        let created = path.exists();
        if created {
            std::fs::remove_file(&path).unwrap();
        }
        drop(lock);
        assert!(
            result.is_err(),
            "initializer bypassed the existing writer lock"
        );
        assert!(!created);
    }

    #[test]
    fn existing_users_load_without_waiting_for_the_writer_lock() {
        let path = unique_users_path("existing");
        let users = UsersConfig {
            users: vec![crate::config::User {
                name: "existing".into(),
                hash: "init".into(),
                is_enabled: true,
                direct: false,
            }],
        };
        crate::config::users_file::write_atomic(&path, &users).unwrap();
        let lock = crate::config::users_file::UsersFileLock::acquire(&path).unwrap();
        let result = load_or_init_users_at(&path);
        drop(lock);
        std::fs::remove_file(&path).unwrap();
        let loaded = result.unwrap();
        assert_eq!(loaded.users.len(), 1);
        assert_eq!(loaded.users[0].name, "existing");
    }

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

    fn unique_dir(tag: &str) -> PathBuf {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let i = COUNTER.fetch_add(1, Ordering::Relaxed);
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "resocks5_init_dir_{}_{}_{}_{}",
            std::process::id(),
            tag,
            nonce,
            i
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn cleanup_dir(dir: &Path) {
        let _ = std::fs::remove_dir_all(dir);
    }

    #[cfg(windows)]
    #[test]
    fn migrated_proxy_list_is_owner_only_on_windows() {
        let dir = unique_dir("proxyowner");
        std::fs::write(
            dir.join("socks5_ipv4_list.txt"),
            "alice:secret@10.0.0.1:1080\n",
        )
        .unwrap();

        let cfg = load_or_init_proxy_list_at(&dir).unwrap();
        assert_eq!(
            cfg.socks5_v4,
            vec!["alice:secret@10.0.0.1:1080".to_string()]
        );

        let file = dir.join(PROXY_LIST_PATH);
        crate::config::users_file::test_support::assert_owner_only_dacl(&file);
        assert!(
            !dir.join(format!("{PROXY_LIST_PATH}.tmp")).exists(),
            "no temp file may survive the migration"
        );
        cleanup_dir(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn migrated_proxy_list_is_owner_only_on_unix() {
        use std::os::unix::fs::PermissionsExt;

        let dir = unique_dir("proxyowner");
        std::fs::write(
            dir.join("socks5_ipv6_list.txt"),
            "bob:hunter2@[2001:db8::1]:1080\n",
        )
        .unwrap();

        let cfg = load_or_init_proxy_list_at(&dir).unwrap();
        assert_eq!(cfg.socks5_v6.len(), 1);

        let file = dir.join(PROXY_LIST_PATH);
        let mode = std::fs::metadata(&file).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "migrated proxy list must be owner-only regardless of umask"
        );
        assert!(
            !dir.join(format!("{PROXY_LIST_PATH}.tmp")).exists(),
            "no temp file may survive the migration"
        );
        cleanup_dir(&dir);
    }

    #[test]
    fn concurrent_first_runs_read_a_complete_proxy_list() {
        let dir = unique_dir("concurrent_proxy");
        std::fs::write(
            dir.join("socks5_ipv4_list.txt"),
            "u1:p1@10.0.0.1:1080\nu2:p2@10.0.0.2:1080\n",
        )
        .unwrap();

        let barrier = std::sync::Barrier::new(6);
        let results: Vec<anyhow::Result<ProxyListConfig>> = std::thread::scope(|s| {
            let dir = &dir;
            let barrier = &barrier;
            let handles: Vec<_> = (0..6)
                .map(|_| {
                    s.spawn(move || {
                        barrier.wait();
                        load_or_init_proxy_list_at(dir)
                    })
                })
                .collect();
            handles
                .into_iter()
                .map(|h| h.join().expect("init thread panicked"))
                .collect()
        });

        assert_eq!(results.len(), 6);
        for result in &results {
            let cfg = result
                .as_ref()
                .unwrap_or_else(|e| panic!("concurrent first run failed: {e:#}"));
            assert_eq!(
                cfg.socks5_v4.len(),
                2,
                "every thread must see the complete migrated list"
            );
        }
        let on_disk: ProxyListConfig = ktav::from_file(dir.join(PROXY_LIST_PATH)).unwrap();
        assert_eq!(on_disk.socks5_v4.len(), 2);
        cleanup_dir(&dir);
    }

    #[test]
    fn concurrent_first_runs_read_a_complete_main_config() {
        let dir = unique_dir("concurrent_main");

        let barrier = std::sync::Barrier::new(6);
        let results: Vec<anyhow::Result<MainConfig>> = std::thread::scope(|s| {
            let dir = &dir;
            let barrier = &barrier;
            let handles: Vec<_> = (0..6)
                .map(|_| {
                    s.spawn(move || {
                        barrier.wait();
                        load_or_init_main_at(dir)
                    })
                })
                .collect();
            handles
                .into_iter()
                .map(|h| h.join().expect("init thread panicked"))
                .collect()
        });

        assert_eq!(results.len(), 6);
        for result in &results {
            let cfg = result
                .as_ref()
                .unwrap_or_else(|e| panic!("concurrent first run failed: {e:#}"));
            assert_eq!(
                cfg.port, 20082,
                "every thread must see the complete default config"
            );
        }
        let on_disk: MainConfig = ktav::from_file(dir.join(MAIN_PATH)).unwrap();
        assert_eq!(on_disk.port, 20082);
        cleanup_dir(&dir);
    }

    #[test]
    fn failed_init_write_leaves_no_partial_file_under_the_final_name() {
        // Sabotage `<final>.tmp` with a directory so the private-create in
        // write_atomic fails before anything is published under the final name.
        let dir = unique_dir("fail_main");
        let main_path = dir.join(MAIN_PATH);
        std::fs::create_dir(dir.join(format!("{MAIN_PATH}.tmp"))).unwrap();

        let main_result = load_or_init_main_at(&dir);
        let main_final_exists = main_path.exists();
        cleanup_dir(&dir);
        assert!(main_result.is_err(), "sabotaged main init must fail");
        assert!(
            !main_final_exists,
            "failed main init must not leave a file under the final name"
        );

        // Same sabotage while a legacy list is being migrated.
        let dir = unique_dir("fail_proxy");
        let proxy_path = dir.join(PROXY_LIST_PATH);
        std::fs::write(dir.join("socks5_ipv4_list.txt"), "u:p@10.0.0.3:1080\n").unwrap();
        std::fs::create_dir(dir.join(format!("{PROXY_LIST_PATH}.tmp"))).unwrap();

        let proxy_result = load_or_init_proxy_list_at(&dir);
        let proxy_final_exists = proxy_path.exists();
        cleanup_dir(&dir);
        assert!(proxy_result.is_err(), "sabotaged proxy-list init must fail");
        assert!(
            !proxy_final_exists,
            "failed proxy-list init must not leave a file under the final name"
        );
    }

    #[test]
    fn existing_configs_are_read_not_reinitialized() {
        let dir = unique_dir("existing");
        crate::config::users_file::write_atomic(
            &dir.join(MAIN_PATH),
            &default_main(12345, vec!["^blocked\\.example$".to_string()]),
        )
        .unwrap();
        crate::config::users_file::write_atomic(
            &dir.join(PROXY_LIST_PATH),
            &ProxyListConfig {
                socks5_v4: vec!["user:pass@10.9.9.9:1080".to_string()],
                ..ProxyListConfig::default()
            },
        )
        .unwrap();

        let main = load_or_init_main_at(&dir).unwrap();
        assert_eq!(main.port, 12345);
        assert_eq!(
            main.banned_patterns,
            vec!["^blocked\\.example$".to_string()]
        );

        let proxy = load_or_init_proxy_list_at(&dir).unwrap();
        assert_eq!(proxy.socks5_v4, vec!["user:pass@10.9.9.9:1080".to_string()]);

        // The on-disk files still carry the custom content — nothing was
        // overwritten with defaults.
        let main_on_disk: MainConfig = ktav::from_file(dir.join(MAIN_PATH)).unwrap();
        assert_eq!(main_on_disk.port, 12345);
        let proxy_on_disk: ProxyListConfig = ktav::from_file(dir.join(PROXY_LIST_PATH)).unwrap();
        assert_eq!(proxy_on_disk.socks5_v4.len(), 1);
        cleanup_dir(&dir);
    }
}
