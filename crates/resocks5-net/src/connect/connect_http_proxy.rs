//! HTTP `CONNECT` upstream connector.

use std::time::Duration;

use anyhow::anyhow;
use base64::{engine::general_purpose, Engine as _};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;

use crate::pool::proxy_pool::upstream_endpoint;
use crate::pool::{ProxyPool, UpstreamStream};
use crate::types::ProxyConfig;

/// Establish a tunnel to `target_addr` through an HTTP CONNECT proxy.
///
/// `handshake_timeout` bounds the wait for the proxy's `200` response; a
/// proxy that accepts the TCP but never answers CONNECT is treated as dead.
pub async fn connect_http_proxy(
    target_addr: &str,
    proxy: &ProxyConfig,
    pool: &ProxyPool,
    handshake_timeout: Duration,
) -> anyhow::Result<UpstreamStream> {
    let mut stream = pool.acquire(proxy).await?;

    let endpoint = upstream_endpoint(proxy);
    let result = timeout(
        handshake_timeout,
        http_connect_handshake(&mut stream, target_addr, proxy),
    )
    .await;

    match result {
        Ok(Ok(())) => Ok(stream),
        Ok(Err(e)) => Err(e),
        Err(_) => Err(anyhow!(
            "[HTTP] handshake timeout ({}s) to {}",
            handshake_timeout.as_secs(),
            endpoint
        )),
    }
}

async fn http_connect_handshake<S>(
    stream: &mut S,
    target_addr: &str,
    proxy: &ProxyConfig,
) -> anyhow::Result<()>
where
    S: AsyncReadExt + AsyncWriteExt + Unpin,
{
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
            return Err(anyhow!("[HTTP] upstream proxy response too large"));
        }
        let n = stream.read(&mut buf[filled..]).await?;
        if n == 0 {
            return Err(anyhow!(
                "[HTTP] upstream proxy closed before completing response"
            ));
        }
        filled += n;

        if let Some(header_end) = find_header_end(&buf[..filled]) {
            let status_line = &buf[..header_end];
            let status_str = String::from_utf8_lossy(status_line);

            if status_str.starts_with("HTTP/1.1 200") || status_str.starts_with("HTTP/1.0 200") {
                return Ok(());
            }

            let first_line = status_str.lines().next().unwrap_or("");
            return Err(anyhow!(
                "[HTTP] upstream proxy rejected CONNECT: {}",
                first_line
            ));
        }
    }
}

fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}
