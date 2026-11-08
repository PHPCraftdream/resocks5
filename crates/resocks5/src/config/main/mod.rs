mod auth_config;
mod file_log_config;
mod main_config;
mod network_config;
mod tls_fragment_config;
mod upstream_auth_config;

pub use auth_config::AuthConfig;
pub use file_log_config::FileLogConfig;
pub use main_config::MainConfig;
pub use network_config::NetworkConfig;
pub use tls_fragment_config::TlsFragmentConfig;
pub use upstream_auth_config::UpstreamAuthConfig;

pub const MAIN_PATH: &str = "resocks5.main.ktav";
/// Saved upstream health, written by the server itself.
pub const HEALTH_PATH: &str = "resocks5.health.ktav";
