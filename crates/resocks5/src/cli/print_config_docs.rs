/// Полный справочник, общий для бинарника и документации репозитория.
pub(crate) const DOCS: &str = include_str!("../../../../docs/REFERENCE.md");

pub fn print_config_docs() {
    print!("{DOCS}");
}

#[cfg(test)]
mod tests {
    use super::DOCS;
    use crate::cli::Cli;
    use clap::CommandFactory;
    use regex::Regex;

    #[test]
    fn reference_covers_every_configuration_field() {
        let fields = Regex::new(r"(?m)^\s*pub\s+(\w+)\s*:").unwrap();
        for (prefix, source) in [
            ("", include_str!("../config/main/main_config.rs")),
            ("auth.", include_str!("../config/main/auth_config.rs")),
            ("log.", include_str!("../logger/log_config.rs")),
            (
                "file_log.",
                include_str!("../config/main/file_log_config.rs"),
            ),
            ("network.", include_str!("../config/main/network_config.rs")),
            (
                "tls_fragment.",
                include_str!("../config/main/tls_fragment_config.rs"),
            ),
            (
                "pool.",
                include_str!("../../../resocks5-net/src/session/pool/pool_config.rs"),
            ),
            (
                "",
                include_str!("../config/proxy_list/proxy_list_config.rs"),
            ),
            ("", include_str!("../config/users/users_config.rs")),
            ("users[].", include_str!("../config/users/user.rs")),
        ] {
            let mut count = 0;
            for capture in fields.captures_iter(source) {
                let field = format!("| `{prefix}{}` |", &capture[1]);
                assert!(DOCS.contains(&field), "поле не описано: {field}");
                count += 1;
            }
            assert!(count > 0, "не найдены поля конфигурации: {prefix}");
        }
    }

    fn check_default(field: &str, actual: impl std::fmt::Debug) {
        let prefix = format!("| `{field}` |");
        let row = DOCS.lines().find(|line| line.starts_with(&prefix)).unwrap();
        let documented = row.split('|').nth(3).unwrap().trim().trim_matches('`');
        assert_eq!(format!("{actual:?}"), documented, "default поля {field}");
    }

    #[test]
    fn documented_defaults_match_runtime_defaults() {
        let main: crate::config::MainConfig = ktav::from_str("port: 1\nauth: {}\n").unwrap();
        macro_rules! check {
            ($config:expr, $prefix:literal, $($field:ident),+ $(,)?) => {
                $(check_default(concat!($prefix, stringify!($field)), &$config.$field);)+
            };
        }
        check!(main, "", listen_host, banned_patterns, allowed_clients);
        check!(main.auth, "auth.", allow_anonymous);
        check!(
            main.network,
            "network.",
            connect_timeout_sec,
            handshake_timeout_sec,
            tunnel_max_lifetime_sec,
            tcp_keepalive_sec,
            client_protocol_timeout_sec,
            max_concurrent_clients,
            max_upstream_attempts,
            max_per_upstream,
            tunnel_idle_timeout_sec,
            max_concurrent_direct,
            sand_half_life_sec,
            sand_fail_penalty,
            sand_max,
            sand_min_weight,
            sand_success_factor,
            quarantine_threshold,
            quarantine_initial_sec,
            quarantine_max_sec,
            hedge_delay_ms,
            recover_host_from_payload
        );
        check!(
            main.pool,
            "pool.",
            enabled,
            spare_per_proxy,
            max_session_age_sec
        );
        check!(
            main.tls_fragment,
            "tls_fragment.",
            enabled,
            fragment_size,
            delay_ms
        );
        check!(
            main.log,
            "log.",
            lifecycle,
            cache_attempts,
            cache_hits,
            cache_writes,
            proxy_failures,
            banned_targets,
            connection_errors,
            client_disconnects,
            attempts
        );
        check!(main.file_log, "file_log.", enabled, path, also_console);
        let proxies = crate::config::ProxyListConfig::default();
        check!(proxies, "", socks5_v4, socks5_v6, http_v4, http_v6, https_v4, https_v6);
        check!(crate::config::UsersConfig::default(), "", users);
        let user: crate::config::User = ktav::from_str("name: alice\nhash: init\n").unwrap();
        check!(user, "users[].", is_enabled, direct);
    }

    fn check_commands(command: &clap::Command, parent: &str) {
        for subcommand in command.get_subcommands() {
            let name = format!("{parent} {}", subcommand.get_name());
            assert!(
                DOCS.contains(&format!("`{name}`")) || DOCS.contains(&format!("`{name} ")),
                "команда не описана: {name}"
            );
            check_commands(subcommand, &name);
        }
    }

    #[test]
    fn reference_covers_all_cli_subcommands() {
        check_commands(&Cli::command(), "resocks5");
    }

    #[test]
    fn long_help_contains_the_full_reference_but_short_help_is_compact() {
        let long = Cli::command().term_width(0).render_long_help().to_string();
        assert!(long.contains(DOCS.trim_end()));
        let short = Cli::command().render_help().to_string();
        assert!(!short.contains("## 3. Каталог настроек"));
        assert!(short.contains("config"));
    }

    #[test]
    fn documented_configuration_examples_parse() {
        let examples: Vec<_> = DOCS
            .split("```text\n")
            .skip(1)
            .map(|block| block.split("```").next().unwrap())
            .collect();
        assert_eq!(examples.len(), 2);
        let main: crate::config::MainConfig = ktav::from_str(examples[0]).unwrap();
        assert!(!main.auth.allow_anonymous);
        assert_eq!(main.listen_host, "127.0.0.1");
        assert_eq!(main.allowed_clients, "loopback");
        let allowed = crate::config::compile_allowed_clients(&main.allowed_clients).unwrap();
        assert!(allowed.matches("127.0.0.1".parse().unwrap()));
        assert!(!allowed.matches("203.0.113.1".parse().unwrap()));
        let proxies: crate::config::ProxyListConfig = ktav::from_str(examples[1]).unwrap();
        assert_eq!(proxies.socks5_v4.len(), 2);
        assert_eq!(proxies.https_v4.len(), 1);
        use resocks5_net::types::ProxyProtocol::{Http, Https, Socks5};
        for (list, protocol) in [
            (&proxies.socks5_v4, Socks5),
            (&proxies.socks5_v6, Socks5),
            (&proxies.http_v4, Http),
            (&proxies.http_v6, Http),
            (&proxies.https_v4, Https),
            (&proxies.https_v6, Https),
        ] {
            for entry in list {
                resocks5_net::connect::parse_proxy_str(entry, protocol).unwrap();
            }
        }
    }

    #[test]
    fn readme_ip_rules_are_valid_native_ktav_values() {
        let mut count = 0;
        for line in include_str!("../../../../README.md")
            .lines()
            .filter(|line| line.starts_with("allowed_clients: "))
        {
            let source = format!("port: 1\nauth: {{}}\n{line}\n");
            let main: crate::config::MainConfig = ktav::from_str(&source).unwrap();
            crate::config::compile_allowed_clients(&main.allowed_clients).unwrap();
            count += 1;
        }
        assert!(count >= 5);
    }

    #[test]
    fn readme_and_architecture_link_to_the_reference() {
        assert!(include_str!("../../../../README.md").contains("docs/REFERENCE.md"));
        assert!(include_str!("../../../../docs/ARCHITECTURE.md").contains("REFERENCE.md"));
    }
}
