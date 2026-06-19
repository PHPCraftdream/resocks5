use std::time::Duration;

use tokio_rustls::TlsConnector;

use crate::connect::upstream_tls::connect_https_proxy;
use crate::connect::{connect_http_proxy, connect_socks5_proxy};
use crate::pool::{AnyUpstream, ProxyPool};
use crate::types::{ProxyConfig, ProxyProtocol};

pub async fn connect_proxy(
    target_addr: &str,
    proxy: &ProxyConfig,
    pool: &ProxyPool,
    handshake_timeout: Duration,
    tls_connector: Option<&TlsConnector>,
) -> anyhow::Result<AnyUpstream> {
    match proxy.protocol {
        ProxyProtocol::Socks5 => {
            let s = connect_socks5_proxy(target_addr, proxy, pool, handshake_timeout).await?;
            Ok(AnyUpstream::Plain(s))
        }
        ProxyProtocol::Http => {
            let s = connect_http_proxy(target_addr, proxy, pool, handshake_timeout).await?;
            Ok(AnyUpstream::Plain(s))
        }
        ProxyProtocol::Https => {
            let connector = tls_connector
                .ok_or_else(|| anyhow::anyhow!("HTTPS upstream requires TLS connector"))?;
            let s =
                connect_https_proxy(target_addr, proxy, pool, handshake_timeout, connector).await?;
            Ok(AnyUpstream::Tls(Box::new(s)))
        }
    }
}
