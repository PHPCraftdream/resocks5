//! HTTP `CONNECT` upstream connector.

use std::fmt::Write as _;
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
    let result = timeout(handshake_timeout, async {
        write_connect_request(&mut stream, target_addr, proxy).await?;
        read_connect_response_tcp(&mut stream).await
    })
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

/// cancel-safe: NO — a cancelled handshake must close the stream.
pub(crate) async fn http_connect_handshake<S>(
    stream: &mut S,
    target_addr: &str,
    proxy: &ProxyConfig,
) -> anyhow::Result<()>
where
    S: AsyncReadExt + AsyncWriteExt + Unpin,
{
    write_connect_request(stream, target_addr, proxy).await?;
    let mut head = ResponseHead::new();
    loop {
        let filled = head.filled;
        let suffix = &head.buf[..filled];
        let remaining = if suffix.ends_with(b"\r\n\r") {
            1
        } else if suffix.ends_with(b"\r\n") {
            2
        } else if suffix.ends_with(b"\r") {
            3
        } else {
            4
        };
        let limit = remaining.min(head.remaining()?);
        // TLS buffers decrypted records internally. Stop exactly at the header.
        let n = stream.read(&mut head.buf[filled..filled + limit]).await?;
        if head.advance(n)? {
            return Ok(());
        }
    }
}

async fn write_connect_request<S>(
    stream: &mut S,
    target_addr: &str,
    proxy: &ProxyConfig,
) -> anyhow::Result<()>
where
    S: AsyncWriteExt + Unpin,
{
    if target_addr
        .bytes()
        .any(|b| b.is_ascii_control() || b.is_ascii_whitespace())
    {
        return Err(anyhow!("[HTTP] invalid CONNECT target"));
    }
    let mut req = format!(
        "CONNECT {} HTTP/1.1\r\nHost: {}\r\n",
        target_addr, target_addr
    );

    if let (Some(user), Some(pass)) = (&proxy.user, &proxy.password) {
        let creds = general_purpose::STANDARD.encode(format!("{}:{}", user, pass));
        write!(req, "Proxy-Authorization: Basic {}\r\n", creds)?;
    }

    req.push_str("\r\n");
    stream.write_all(req.as_bytes()).await?;
    stream.flush().await?;
    Ok(())
}

/// cancel-safe: NO — cancellation must discard the partially read stream.
async fn read_connect_response_tcp(stream: &mut UpstreamStream) -> anyhow::Result<()> {
    let mut head = ResponseHead::new();
    loop {
        let filled = head.filled;
        let remaining = head.remaining()?;
        let n = stream
            .as_tcp()
            .peek(&mut head.buf[filled..filled + remaining])
            .await?;
        let scan_from = filled.saturating_sub(3);
        let consume_to = find_header_end(&head.buf[scan_from..filled + n])
            .map_or(filled + n, |pos| scan_from + pos + 4);
        stream.read_exact(&mut head.buf[filled..consume_to]).await?;
        if head.advance(consume_to - filled)? {
            return Ok(());
        }
    }
}

struct ResponseHead {
    buf: Vec<u8>,
    filled: usize,
    total: usize,
}

impl ResponseHead {
    fn new() -> Self {
        Self {
            buf: vec![0; 4096],
            filled: 0,
            total: 0,
        }
    }

    fn remaining(&self) -> anyhow::Result<usize> {
        let remaining = self.buf.len() - self.total;
        if remaining == 0 {
            return Err(anyhow!("[HTTP] upstream proxy response too large"));
        }
        Ok(remaining)
    }

    fn advance(&mut self, n: usize) -> anyhow::Result<bool> {
        if n == 0 {
            return Err(anyhow!(
                "[HTTP] upstream proxy closed before completing response"
            ));
        }
        self.filled += n;
        self.total += n;
        if !self.buf[..self.filled].ends_with(b"\r\n\r\n") {
            return Ok(false);
        }
        let first_line = self.buf[..self.filled]
            .split(|&b| b == b'\r')
            .next()
            .unwrap_or_default();
        let valid = first_line.len() >= 13
            && (first_line.starts_with(b"HTTP/1.1 ") || first_line.starts_with(b"HTTP/1.0 "))
            && first_line[9..12].iter().all(u8::is_ascii_digit)
            && first_line[12] == b' ';
        if valid && first_line[9] == b'2' {
            return Ok(true);
        }
        if valid && first_line[9] == b'1' && &first_line[9..12] != b"101" {
            self.filled = 0;
            return Ok(false);
        }
        Err(anyhow!(
            "[HTTP] upstream proxy rejected CONNECT: {}",
            String::from_utf8_lossy(first_line)
        ))
    }
}

fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{ProxyProtocol, IP};
    use tokio::io::duplex;

    fn proxy() -> ProxyConfig {
        ProxyConfig {
            protocol: ProxyProtocol::Http,
            ip: IP::V4,
            host: "localhost".into(),
            port: 8080,
            user: None,
            password: None,
            is_gate: false,
            gate: None,
        }
    }

    #[tokio::test(start_paused = true)]
    async fn preserves_payload_coalesced_with_connect_response() {
        let (mut client, mut upstream) = duplex(4096);
        upstream
            .write_all(b"HTTP/1.1 200 OK\r\n\r\nSSH-2.0-test\r\n")
            .await
            .unwrap();
        upstream.shutdown().await.unwrap();
        http_connect_handshake(&mut client, "example.com:22", &proxy())
            .await
            .unwrap();
        let mut payload = Vec::new();
        client.read_to_end(&mut payload).await.unwrap();
        assert_eq!(payload, b"SSH-2.0-test\r\n");
    }

    #[tokio::test]
    async fn accepts_other_success_statuses() {
        let (mut client, mut upstream) = duplex(4096);
        upstream
            .write_all(b"HTTP/1.1 201 Created\r\n\r\n")
            .await
            .unwrap();
        http_connect_handshake(&mut client, "example.com:22", &proxy())
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn rejects_invalid_status_code_prefix() {
        let (mut client, mut upstream) = duplex(4096);
        upstream
            .write_all(b"HTTP/1.1 2000 Invalid\r\n\r\n")
            .await
            .unwrap();
        assert!(
            http_connect_handshake(&mut client, "example.com:22", &proxy())
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn tcp_connector_preserves_coalesced_payload() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let mut config = proxy();
        config.host = address.ip().to_string();
        config.port = address.port();
        let server = async {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            while !request.ends_with(b"\r\n\r\n") {
                request.push(stream.read_u8().await.unwrap());
            }
            assert!(request.starts_with(b"CONNECT example.com:22 HTTP/1.1\r\n"));
            stream
                .write_all(b"HTTP/1.1 200 OK\r\n\r\nSSH-2.0-test\r\n")
                .await
                .unwrap();
            stream.shutdown().await.unwrap();
        };
        let client = async {
            let pool = ProxyPool::new(Default::default(), Duration::from_secs(2), 1);
            let mut stream =
                connect_http_proxy("example.com:22", &config, &pool, Duration::from_secs(2))
                    .await
                    .unwrap();
            let mut bytes = Vec::new();
            stream.read_to_end(&mut bytes).await.unwrap();
            assert_eq!(bytes, b"SSH-2.0-test\r\n");
        };
        tokio::time::timeout(Duration::from_secs(5), async {
            tokio::join!(server, client);
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn handles_bytewise_informational_and_final_headers() {
        let (mut client, mut upstream) = duplex(1);
        let server = async {
            let mut request = Vec::new();
            while !request.ends_with(b"\r\n\r\n") {
                request.push(upstream.read_u8().await.unwrap());
            }
            for byte in b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.0 200 OK\r\n\r\npayload" {
                upstream.write_all(&[*byte]).await.unwrap();
            }
            upstream.shutdown().await.unwrap();
        };
        let client = async {
            http_connect_handshake(&mut client, "example.com:22", &proxy())
                .await
                .unwrap();
            let mut bytes = Vec::new();
            client.read_to_end(&mut bytes).await.unwrap();
            assert_eq!(bytes, b"payload");
        };
        tokio::time::timeout(Duration::from_secs(5), async {
            tokio::join!(server, client);
        })
        .await
        .unwrap();
    }
}
