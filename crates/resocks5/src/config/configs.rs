use crate::config::{MainConfig, ProxyListConfig, UsersConfig};

/// Bundle of all three configs as loaded at startup.
pub struct Configs {
    pub main: MainConfig,
    pub proxy_list: ProxyListConfig,
    pub users: UsersConfig,
}
