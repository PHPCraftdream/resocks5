//! Three-file configuration: server settings, proxy lists, users.
//!
//! Files are auto-created with sensible defaults on first launch.
//!
//! ```text
//! resocks5.main.ktav        — port, banned_patterns, auth, log, pool, tls_fragment
//! resocks5.proxy_list.ktav  — upstream proxies grouped by transport
//! resocks5.users.ktav       — users (managed by CLI; do not edit by hand)
//! ```
//!
//! Old layouts (`resocks5.conf` + `socks5_ipv4_list.txt` /
//! `socks5_ipv6_list.txt`) are migrated automatically on first launch
//! when the new files don't exist yet.

pub mod auth_config;
pub mod configs;
pub mod file_log_config;
pub mod load_or_init;
pub mod main_config;
pub mod main_path;
pub mod network_config;
pub mod proxy_list_config;
pub mod proxy_list_path;
pub mod tls_fragment_config;
pub mod user;
pub mod users_config;
pub(crate) mod users_file;
pub mod users_path;

pub use auth_config::AuthConfig;
pub use configs::Configs;
pub use file_log_config::FileLogConfig;
pub use load_or_init::load_or_init;
pub use main_config::MainConfig;
pub use main_path::MAIN_PATH;
pub use network_config::NetworkConfig;
pub use proxy_list_config::ProxyListConfig;
pub use proxy_list_path::PROXY_LIST_PATH;
pub use tls_fragment_config::TlsFragmentConfig;
pub use user::User;
pub use users_config::UsersConfig;
pub use users_path::USERS_PATH;
