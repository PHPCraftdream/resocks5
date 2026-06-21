//! HTTPS (TLS-wrapped CONNECT) upstream connector, plus a default
//! [`TlsConnector`] rooted at the Mozilla `webpki-roots` trust store.

use std::sync::Arc;
use std::time::Duration;

use anyhow::anyhow;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;
use tokio_rustls::client::TlsStream;
use tokio_rustls::TlsConnector;

use crate::pool::proxy_pool::upstream_endpoint;
use crate::pool::{ProxyPool, UpstreamStream};
use crate::types::ProxyConfig;

/// Establish a tunnel to `target_addr` through an HTTPS proxy.
///
/// Performs the TLS handshake to the proxy itself (using `proxy.host` as the
/// server name), then runs an HTTP `CONNECT` over the encrypted stream.
/// `handshake_timeout` bounds the whole TLS + CONNECT exchange.
pub async fn connect_https_proxy(
    target_addr: &str,
    proxy: &ProxyConfig,
    pool: &ProxyPool,
    handshake_timeout: Duration,
    tls_connector: &TlsConnector,
) -> anyhow::Result<TlsStream<UpstreamStream>> {
    let stream = pool.acquire(proxy).await?;
    let endpoint = upstream_endpoint(proxy);

    let server_name = rustls::pki_types::ServerName::try_from(proxy.host.clone())
        .map_err(|_| anyhow!("[HTTPS] invalid server name: {}", proxy.host))?;

    let tls_stream = match timeout(
        handshake_timeout,
        tls_connector.connect(server_name, stream),
    )
    .await
    {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            return Err(anyhow!("[HTTPS] TLS handshake to {}: {}", endpoint, e));
        }
        Err(_) => {
            return Err(anyhow!(
                "[HTTPS] TLS handshake timeout ({}s) to {}",
                handshake_timeout.as_secs(),
                endpoint
            ));
        }
    };

    let result = timeout(
        handshake_timeout,
        http_connect_over_tls(tls_stream, target_addr, proxy),
    )
    .await;

    match result {
        Ok(Ok(s)) => Ok(s),
        Ok(Err(e)) => Err(e),
        Err(_) => Err(anyhow!(
            "[HTTPS] CONNECT handshake timeout ({}s) to {}",
            handshake_timeout.as_secs(),
            endpoint
        )),
    }
}

async fn http_connect_over_tls<S>(
    mut stream: S,
    target_addr: &str,
    proxy: &ProxyConfig,
) -> anyhow::Result<S>
where
    S: AsyncReadExt + AsyncWriteExt + Unpin,
{
    use base64::{engine::general_purpose, Engine as _};

    let mut req = format!(
        "CONNECT {} HTTP/1.1\r\nHost: {}\r\n",
        target_addr, target_addr
    );

    if let (Some(user), Some(pass)) = (&proxy.user, &proxy.password) {
        let creds = general_purpose::STANDARD.encode(format!("{}:{}", user, pass));
        req.push_str(&format!("Proxy-Authorization: Basic {}\r\n", creds));
    }

    req.push_str("\r\n");
    stream.write_all(req.as_bytes()).await?;

    let mut buf = vec![0u8; 4096];
    let mut filled = 0usize;

    loop {
        if filled >= buf.len() {
            return Err(anyhow!("[HTTPS] upstream proxy response too large"));
        }
        let n = stream.read(&mut buf[filled..]).await?;
        if n == 0 {
            return Err(anyhow!(
                "[HTTPS] upstream proxy closed before completing response"
            ));
        }
        filled += n;

        if let Some(pos) = buf[..filled].windows(4).position(|w| w == b"\r\n\r\n") {
            let status_str = String::from_utf8_lossy(&buf[..pos]);
            if status_str.starts_with("HTTP/1.1 200") || status_str.starts_with("HTTP/1.0 200") {
                return Ok(stream);
            }
            let first_line = status_str.lines().next().unwrap_or("");
            return Err(anyhow!(
                "[HTTPS] upstream proxy rejected CONNECT: {}",
                first_line
            ));
        }
    }
}

/// Build a [`TlsConnector`] rooted at the Mozilla `webpki-roots` trust store.
///
/// Convenience for callers without their own rustls config — both the
/// library example and the binary's HTTPS-upstream path use this.
pub fn make_tls_connector() -> TlsConnector {
    let root_store =
        rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    TlsConnector::from(Arc::new(config))
}
