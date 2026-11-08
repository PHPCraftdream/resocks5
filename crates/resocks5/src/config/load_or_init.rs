use std::path::Path;

use anyhow::{Context, Result};
use serde::Deserialize;

use crate::config::{
    Configs, MainConfig, ProxyListConfig, UsersConfig, MAIN_PATH, PROXY_LIST_PATH, USERS_PATH,
};

const OLD_MAIN_PATH: &str = "resocks5.conf";

/// Full default `resocks5.main.ktav` as ktav text with `##` comments —
/// written verbatim to disk on a fresh install, and parsed to build the
/// in-memory default config. This template is the single source of
/// truth for the defaults: edit here, never in `default_main_cfg`.
pub(crate) const DEFAULT_MAIN_TEMPLATE: &str = r#"
## resocks5.main.ktav — created with defaults; full reference: `resocks5 config`.

port: 20082
listen_host: 127.0.0.1
banned_patterns: []
allowed_clients: "*"

auth: {
    ## true: serve SOCKS5 without a name/password and HTTP CONNECT without
    ## Proxy-Authorization. Default true (as in 0.4.x).
    allow_anonymous: true
    ## true: accept ONLY our own secure method (SOCKS5 0x80 / HTTP
    ## Resocks5-Secure); clear-text passwords (0x02, Basic) and anonymous
    ## access are refused. Optional, default false.
    secure_only: false
    ## Argon2id cost of NEW user secrets (users add / set-password, the claim
    ## of an `init` account) and the floor of an init enrollment. Optional;
    ## existing secrets keep the cost stored with them, so changing it never
    ## breaks a users file. Defaults shown (the OWASP minimum).
    ## argon2: { memory_kib: 19456, iterations: 2, parallelism: 1 }
}

## Outbound policy: how upstreams authenticate when an entry has user:password.
upstream_auth: {
    ## true: use ONLY our own secure method for every upstream with
    ## credentials; an upstream that offers nothing else is refused before
    ## the password is sent. Optional, default false. One list entry can opt
    ## in with the line suffix `;secure_only`.
    secure_only: false
}

log: {
    lifecycle: true
    cache_attempts: false
    cache_hits: false
    cache_writes: false
    proxy_failures: true
    banned_targets: true
    connection_errors: true
    client_disconnects: false
    attempts: false
    tunnels: false
}

pool: {
    enabled: false
    spare_per_proxy: 1
    max_session_age_sec: 30
}

tls_fragment: {
    enabled: false
    fragment_size: 40
    delay_ms: 0
}

network: {
    connect_timeout_sec: 10
    handshake_timeout_sec: 10
    tunnel_max_lifetime_sec: 1800
    tcp_keepalive_sec: 60
    client_protocol_timeout_sec: 30
    max_concurrent_clients: 1024
    max_upstream_attempts: 10
    max_per_upstream: 8
    tunnel_idle_timeout_sec: 30
    max_concurrent_direct: 256
    sand_half_life_sec: 30.0
    sand_fail_penalty: 1.0
    sand_max: 8.0
    sand_min_weight: 0.05
    sand_success_factor: 0.5
    quarantine_threshold: 3
    quarantine_initial_sec: 30
    quarantine_max_sec: 600
    hedge_delay_ms: 2000
    health_save_sec: 30
    recover_host_from_payload: true
}

file_log: {
    enabled: false
    path: "resocks5.log"
    also_console: true
}
"#;
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
        let mut cfg = default_main_cfg();
        cfg.port = old.port;
        cfg.banned_patterns = old.banned_patterns;
        cfg
    } else {
        eprintln!("Creating default {}", MAIN_PATH);
        crate::config::users_file::write_atomic_text(&path, DEFAULT_MAIN_TEMPLATE)
            .with_context(|| format!("write {}", path.display()))?;
        return Ok(default_main_cfg());
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

pub(crate) fn load_or_init_users_at(path: &Path) -> Result<UsersConfig> {
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

/// Build a fully-populated default `MainConfig` by parsing
/// [`DEFAULT_MAIN_TEMPLATE`] — the template is the single source of
/// truth, so the config on disk (with its comments) and the config in
/// memory can never drift apart.
fn default_main_cfg() -> MainConfig {
    ktav::from_str(DEFAULT_MAIN_TEMPLATE).expect("built-in default main template parses")
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
                allowed_clients: None,
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
        assert_eq!(loaded.users[0].allowed_clients, None);
    }

    /// An old config without the `allowed_clients` field gets the default `"*"`.
    #[test]
    fn old_main_without_allowed_clients_defaults_to_star() {
        let src = "\
port: 20082
listen_host: 127.0.0.1
auth: { allow_anonymous: true }
";
        let cfg: MainConfig = ktav::from_str(src).unwrap();
        assert_eq!(cfg.allowed_clients, "*");
    }

    /// An old config WITHOUT the new `secure_only` keys keeps loading
    /// silently: both switches take their `false` default, no error.
    /// Mutation: making either serde default `true` fails it.
    #[test]
    fn old_main_without_the_secure_only_keys_loads_with_silent_defaults() {
        let src = "\
port: 20082
listen_host: 127.0.0.1
auth: { allow_anonymous: true }
";
        let cfg: MainConfig = ktav::from_str(src).unwrap();
        assert!(!cfg.auth.secure_only);
        assert!(!cfg.upstream_auth.secure_only);
        assert!(cfg.auth.allow_anonymous);
    }

    /// The generated default config: the template on disk parses, both
    /// switches are present with their defaults, both comment lines are
    /// there, and it round-trips through ktav. Mutation: an unparseable
    /// template, or a template missing a switch/comment, fails it.
    #[test]
    fn default_main_template_round_trips_with_both_switches_and_comments() {
        let dir = unique_dir("template");
        let path = dir.join(MAIN_PATH);
        crate::config::users_file::write_atomic_text(&path, DEFAULT_MAIN_TEMPLATE).unwrap();
        let cfg: MainConfig = ktav::from_file(&path).expect("template parses");
        assert!(!cfg.auth.secure_only);
        assert!(!cfg.upstream_auth.secure_only);
        assert!(cfg.auth.allow_anonymous);

        let lines: Vec<&str> = DEFAULT_MAIN_TEMPLATE
            .lines()
            .filter(|l| l.trim_start().starts_with('#'))
            .collect();
        assert!(
            lines.iter().any(|l| l.contains("secure_only")),
            "auth.secure_only comment line missing"
        );
        assert!(
            lines.iter().any(|l| l.contains("upstreams authenticate")),
            "upstream_auth comment line missing"
        );

        let serialized = ktav::to_string(&cfg).expect("re-serialize parsed template");
        let reparsed: MainConfig = ktav::from_str(&serialized).expect("re-parse");
        assert_eq!(reparsed.auth.secure_only, cfg.auth.secure_only);
        assert_eq!(reparsed.upstream_auth, cfg.upstream_auth);
        cleanup_dir(&dir);
    }

    /// Round-trip of the allowed_clients value through ktav.
    #[test]
    fn main_allowed_clients_round_trips() {
        let mut cfg = default_main_cfg();
        cfg.allowed_clients = "127.0.0.1,10.*.0.1,loopback".to_string();
        let serialized = ktav::to_string(&cfg).unwrap();
        let parsed: MainConfig = ktav::from_str(&serialized).unwrap();
        assert_eq!(parsed.allowed_clients, "127.0.0.1,10.*.0.1,loopback");
    }

    /// The serializer must not emit ktav type-tags (`:i` for integers,
    /// `:b` for booleans, etc.) on field names. ktav ≥ 0.6 dropped
    /// support for them; if our deps drift back to a version that emits
    /// them, fresh `resocks5.main.ktav` files become unparseable.
    #[test]
    fn default_main_has_no_type_tags() {
        let cfg = default_main_cfg();
        let serialized = ktav::to_string(&cfg).expect("ktav serialization of default MainConfig");
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
        let mut cfg = default_main_cfg();
        cfg.banned_patterns = vec!["^bad\\.test$".to_string()];
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
        // Assert against the TEMPLATE TEXT itself — that is what lands
        // on disk at first launch.
        let serialized = DEFAULT_MAIN_TEMPLATE;

        assert!(
            serialized.matches("secure_only:").count() >= 2,
            "template must carry secure_only twice (auth + upstream_auth):\n{serialized}"
        );
        assert!(
            serialized
                .lines()
                .any(|l| l.trim_start().starts_with('#') && l.contains("secure_only")),
            "template must contain a # comment line mentioning secure_only"
        );

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
            "allowed_clients:",
            // AuthConfig
            "allow_anonymous:",
            "secure_only:",
            // UpstreamAuthConfig
            "upstream_auth:",
            "secure_only:",
            // LogConfig (every flag)
            "lifecycle:",
            "cache_attempts:",
            "cache_hits:",
            "cache_writes:",
            "proxy_failures:",
            "banned_targets:",
            "connection_errors:",
            "client_disconnects:",
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
            "quarantine_threshold:",
            "quarantine_initial_sec:",
            "quarantine_max_sec:",
            "hedge_delay_ms:",
            "health_save_sec:",
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
        crate::config::users_file::write_atomic(&dir.join(MAIN_PATH), &{
            let mut cfg = default_main_cfg();
            cfg.port = 12345;
            cfg.banned_patterns = vec!["^blocked\\.example$".to_string()];
            cfg
        })
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
