//! Run a two-hop proxy chain over a stream that is already open. The stream
//! here is a plain TCP connection to the outermost node; any owned
//! `AsyncRead + AsyncWrite` (for example a Tor stream) works the same way.
//! Mirrors the "Over an existing stream" example in the `resocks5-net` README.
//!
//! Run with reachable proxies:  cargo run --example dial_chain_over

use std::time::Duration;

use resocks5_net::connect::{dial_chain_over, DialOptions};
use resocks5_net::types::ProxyConfig;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Outermost node first: the stream is connected to `198.51.100.7`, which
    // tunnels to `exit.example`, which tunnels to the target.
    let proxy = ProxyConfig::socks5("exit.example", 1080)
        .with_gate(ProxyConfig::socks5("198.51.100.7", 1080));

    let outer = proxy.outermost();
    let base = TcpStream::connect((outer.host.as_str(), outer.port)).await?;

    // `total_timeout` is the remaining budget of your own deadline.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    let opts = DialOptions::new()
        .with_handshake_timeout(Duration::from_secs(10))
        .with_total_timeout(deadline.saturating_duration_since(tokio::time::Instant::now()));

    let mut stream = dial_chain_over(base, &proxy, "example.com", 80, &opts, None).await?;

    stream
        .write_all(b"GET / HTTP/1.0\r\nHost: example.com\r\n\r\n")
        .await?;
    let mut body = Vec::new();
    let n = tokio::time::timeout(Duration::from_secs(5), async {
        stream.take(64 * 1024).read_to_end(&mut body).await
    })
    .await
    .map_err(|_| anyhow::anyhow!("peer kept sending for over 5 s"))??;
    println!("received {n} bytes");
    Ok(())
}
