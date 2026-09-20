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

mod configs;
pub mod load_or_init;
mod main;
mod proxy_list;
mod users;

pub use configs::Configs;
pub use load_or_init::load_or_init;
pub use main::AuthConfig;
pub use main::FileLogConfig;
pub use main::MainConfig;
pub use main::NetworkConfig;
pub use main::TlsFragmentConfig;
pub use main::MAIN_PATH;
pub use proxy_list::ProxyListConfig;
pub use proxy_list::PROXY_LIST_PATH;
pub(crate) use users::users_file;
pub use users::User;
pub use users::UsersConfig;
pub use users::USERS_PATH;
