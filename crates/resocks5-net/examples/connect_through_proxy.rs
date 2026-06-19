//! Connect to a target through a SOCKS5 upstream proxy and drive a plain
//! HTTP request over the returned stream. Mirrors the "Use as a library"
//! example in the repository README — kept as a real example so CI fails
//! if the public API drifts away from what the README shows.
//!
//! Run with a reachable upstream:  cargo run --example connect_through_proxy

use std::time::Duration;

use resocks5_net::connect::{connect_proxy, parse_proxy_str};
use resocks5_net::pool::{PoolConfig, ProxyPool};
use resocks5_net::rotator::ProxyRotator;
use resocks5_net::types::{ProxyProtocol, IP};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Parse upstream lines: "[*]user:pass@host:port" (credentials optional).
    let proxies = ["user:pass@198.51.100.7:1080"]
        .into_iter()
        .filter_map(|s| parse_proxy_str(s, ProxyProtocol::Socks5, IP::V4))
        .collect::<Vec<_>>();

    // Round-robin rotator + a pre-connect TCP pool (left disabled here).
    let rotator = ProxyRotator::new(proxies);
    let pool = ProxyPool::new(
        PoolConfig::default(),
        Duration::from_secs(10), // upstream connect timeout
        8,                       // max concurrent connections per upstream
    );

    // Pick an upstream and tunnel to the target through it. The returned
    // stream is AsyncRead + AsyncWrite.
    let upstream = rotator.get_next();
    let mut stream = connect_proxy(
        "example.com:80",
        &upstream,
        &pool,
        Duration::from_secs(10), // handshake timeout
        None,                    // TLS connector — Some(..) only for HTTPS upstreams
    )
    .await?;

    stream
        .write_all(b"GET / HTTP/1.0\r\nHost: example.com\r\n\r\n")
        .await?;
    let mut body = Vec::new();
    stream.read_to_end(&mut body).await?;
    println!("received {} bytes", body.len());
    Ok(())
}
