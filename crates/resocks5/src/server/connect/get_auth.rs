use resocks5_net::types::ProxyConfig;

#[inline]
pub fn get_auth(config: &ProxyConfig) -> Option<(&str, &str)> {
    config
        .user
        .as_ref()
        .map(|u| (u.as_str(), config.password.as_deref().unwrap_or("")))
}
