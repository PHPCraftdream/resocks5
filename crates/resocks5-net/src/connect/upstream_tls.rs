//! HTTPS (TLS-wrapped CONNECT) upstream connector, plus a default
//! [`TlsConnector`] rooted at the Mozilla `webpki-roots` trust store.

use std::sync::Arc;
use std::time::Duration;

use anyhow::anyhow;
use tokio::time::{timeout_at, Instant};
use tokio_rustls::client::TlsStream;
use tokio_rustls::TlsConnector;

use crate::connect::connect_http_proxy::http_connect_handshake;
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

    let deadline = Instant::now() + handshake_timeout;
    let mut tls_stream =
        match timeout_at(deadline, tls_connector.connect(server_name, stream)).await {
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

    let result = timeout_at(
        deadline,
        http_connect_handshake(&mut tls_stream, target_addr, proxy),
    )
    .await;

    match result {
        Ok(Ok(())) => Ok(tls_stream),
        Ok(Err(e)) => Err(e),
        Err(_) => Err(anyhow!(
            "[HTTPS] CONNECT handshake timeout ({}s) to {}",
            handshake_timeout.as_secs(),
            endpoint
        )),
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
