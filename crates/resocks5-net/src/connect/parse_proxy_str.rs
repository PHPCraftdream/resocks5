use crate::types::{ProxyConfig, ProxyProtocol, IP};

pub fn parse_proxy_str(conn_str: &str, protocol: ProxyProtocol, ip: IP) -> Option<ProxyConfig> {
    if conn_str.starts_with('#') {
        return None;
    }

    let (is_gate, conn_str) = if let Some(rest) = conn_str.strip_prefix('*') {
        (true, rest)
    } else {
        (false, conn_str)
    };

    let parts: Vec<&str> = conn_str.split('@').collect();

    if parts.len() == 2 {
        let user_pass_parts: Vec<&str> = parts[0].split(':').collect();
        if user_pass_parts.len() != 2 {
            return None;
        }
        let user = Some(user_pass_parts[0].to_string());
        let password = Some(user_pass_parts[1].to_string());

        let ip_port_parts: Vec<&str> = parts[1].split(':').collect();
        if ip_port_parts.len() != 2 {
            return None;
        }
        let host = ip_port_parts[0].to_string();
        let port = ip_port_parts[1].parse::<u16>().ok()?;

        Some(ProxyConfig {
            protocol,
            ip,
            user,
            password,
            host,
            port,
            is_gate,
            gate: None,
        })
    } else if parts.len() == 1 {
        let ip_port_parts: Vec<&str> = parts[0].split(':').collect();
        if ip_port_parts.len() != 2 {
            return None;
        }
        let host = ip_port_parts[0].to_string();
        let port = ip_port_parts[1].parse::<u16>().ok()?;

        Some(ProxyConfig {
            protocol,
            ip,
            user: None,
            password: None,
            host,
            port,
            is_gate,
            gate: None,
        })
    } else {
        None
    }
}
