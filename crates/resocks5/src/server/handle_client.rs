use std::sync::Arc;
use std::time::Duration;

use anyhow::anyhow;
use regex::RegexSet;
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use tokio::time::timeout;

use tokio_rustls::TlsConnector;

use crate::auth::AuthState;
use crate::config::{NetworkConfig, TlsFragmentConfig};
use crate::http_proxy::handle_http_client;
use crate::logger::Logger;
use crate::server::handle_socks5_client;
use resocks5_net::pool::ProxyPool;
use resocks5_net::rotator::ProxyRotator;

/// Single accept-loop dispatcher: peeks the first byte without
/// consuming it and routes the client to the SOCKS5 or HTTP CONNECT
/// handler. This is what lets one listening port serve both protocols
/// transparently — SOCKS5 always opens with `0x05` (greeting version),
/// HTTP always opens with an ASCII method letter, so a single byte is
/// enough to tell them apart with zero ambiguity.
#[allow(clippy::too_many_arguments)]
pub async fn handle_client(
    client_stream: TcpStream,
    auth: &Arc<AuthState>,
    gate_rotator: &Option<Arc<ProxyRotator>>,
    v6_rotator: &Option<Arc<ProxyRotator>>,
    v4_rotator: &Option<Arc<ProxyRotator>>,
    logger: &Arc<Logger>,
    banned: &Arc<RegexSet>,
    pool: &Arc<ProxyPool>,
    frag: &Arc<TlsFragmentConfig>,
    network: &Arc<NetworkConfig>,
    tls_connector: Option<&TlsConnector>,
    direct_limiter: &Arc<Semaphore>,
) -> anyhow::Result<()> {
    // Slowloris guard on protocol-detection: a client that completes
    // TCP connect but never sends the first byte would otherwise
    // freeze this task indefinitely (until TCP keepalive eventually
    // kills the socket, ~60-90 s). We bound it explicitly so the
    // global `max_concurrent_clients` slot is freed promptly.
    let protocol_dur = Duration::from_secs(network.client_protocol_timeout_sec);
    let mut peek_buf = [0u8; 1];
    let n = match timeout(protocol_dur, client_stream.peek(&mut peek_buf)).await {
        Ok(res) => res?,
        Err(_) => {
            return Err(anyhow!(
                "client did not send any byte within {}s — protocol-detect timeout",
                protocol_dur.as_secs()
            ));
        }
    };
    if n == 0 {
        return Err(anyhow!("client closed before sending any data"));
    }
    match peek_buf[0] {
        0x05 => {
            handle_socks5_client(
                client_stream,
                auth,
                gate_rotator,
                v6_rotator,
                v4_rotator,
                logger,
                banned,
                pool,
                frag,
                network,
                tls_connector,
                direct_limiter,
            )
            .await
        }
        b if b.is_ascii_alphabetic() => {
            handle_http_client(
                client_stream,
                auth,
                gate_rotator,
                v6_rotator,
                v4_rotator,
                logger,
                banned,
                pool,
                frag,
                network,
                tls_connector,
                direct_limiter,
            )
            .await
        }
        other => Err(anyhow!(
            "unrecognised first byte {:#04x} — neither SOCKS5 (0x05) nor an HTTP method",
            other
        )),
    }
}
