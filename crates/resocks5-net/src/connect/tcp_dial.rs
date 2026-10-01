use std::time::Duration;

use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::error::{ConnectError, Stage, TimeoutKind};
use crate::types::ProxyConfig;

/// `host:port` for log messages — upstream credentials (both user
/// and password) are intentionally NOT included, since the username
/// half of a SOCKS5 cred is itself sensitive enough to keep out of
/// log files, shell scrollback, and shipped diagnostics.
#[cfg(any(feature = "pool", feature = "tls"))]
pub(crate) fn upstream_endpoint(proxy: &ProxyConfig) -> String {
    format!("{}:{}", proxy.host, proxy.port)
}

/// Plain TCP dial to the proxy under `connect_timeout`.
///
/// The address is passed as `(host, port)`: `ProxyConfig.host` has no
/// IPv6 brackets, so formatting `host:port` would mangle `::1` and fall
/// into the blocking system resolver.
pub(crate) async fn tcp_dial(
    proxy: &ProxyConfig,
    connect_timeout: Duration,
) -> Result<TcpStream, ConnectError> {
    let endpoint = || format!("{}:{}", proxy.host, proxy.port);
    match timeout(
        connect_timeout,
        TcpStream::connect((proxy.host.as_str(), proxy.port)),
    )
    .await
    {
        Ok(Ok(s)) => Ok(s),
        Ok(Err(e)) => Err(ConnectError::Io {
            stage: Stage::Connect,
            endpoint: Some(endpoint()),
            source: e,
        }),
        Err(_) => Err(ConnectError::Timeout {
            stage: Stage::Connect,
            kind: TimeoutKind::TcpConnect,
            endpoint: endpoint(),
            after: connect_timeout,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::IP as IPV;

    fn proxy(host: &str, port: u16) -> ProxyConfig {
        ProxyConfig::socks5(host, port).with_family(IPV::V4)
    }

    #[tokio::test]
    async fn dial_succeeds_against_listener() {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        let s = tcp_dial(&proxy("127.0.0.1", port), Duration::from_secs(2))
            .await
            .expect("dial");
        assert_eq!(s.peer_addr().unwrap().port(), port);
    }

    #[tokio::test]
    async fn refused_is_io_connect_with_endpoint() {
        // Port 0 fails immediately everywhere (a closed port retries ~2s on Windows).
        let port = 0;
        let err = tcp_dial(&proxy("127.0.0.1", port), Duration::from_secs(5))
            .await
            .expect_err("port 0");
        assert!(
            matches!(
                &err,
                ConnectError::Io { stage: Stage::Connect, endpoint: Some(e), .. }
                    if *e == format!("127.0.0.1:{port}")
            ),
            "got: {err:?}"
        );
        assert!(
            err.to_string()
                .contains(&format!("connect to 127.0.0.1:{port}: ")),
            "got: {err}"
        );
    }

    #[tokio::test]
    async fn unroutable_ends_in_connect_stage_error() {
        // TEST-NET-1 (RFC 5737): Timeout, or Io where the network is unreachable.
        let err = tcp_dial(&proxy("203.0.113.1", 1080), Duration::from_millis(300))
            .await
            .expect_err("must not connect");
        match &err {
            ConnectError::Timeout {
                stage: Stage::Connect,
                kind: TimeoutKind::TcpConnect,
                endpoint,
                after,
            } => {
                assert_eq!(endpoint, "203.0.113.1:1080");
                assert_eq!(*after, Duration::from_millis(300));
                assert_eq!(err.to_string(), "connect timeout (0s) to 203.0.113.1:1080");
            }
            ConnectError::Io {
                stage: Stage::Connect,
                ..
            } => assert!(err.to_string().contains("203.0.113.1:1080")),
            other => panic!("unexpected: {other:?}"),
        }
    }
}
