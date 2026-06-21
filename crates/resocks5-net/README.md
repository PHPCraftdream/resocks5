# resocks5-net

Reusable proxy networking toolkit in Rust: the engine the
[`resocks5`](https://github.com/PHPCraftdream/resocks5) proxy server is
built on, factored out as a self-contained library.

What's inside:

- **Upstream connectors** for SOCKS5, HTTP CONNECT, and HTTPS (TLS-wrapped
  CONNECT) proxies.
- **Pre-connect TCP pool** that keeps warm sockets to each upstream, plus a
  per-upstream concurrency cap that respects provider-side per-account
  connection quotas.
- **Sand-rating model** — each upstream has a failure accumulator that
  decays exponentially over time. Upstream selection is weighted-random
  with weight `exp(-k · sand)`: failing upstreams are picked less often
  but never excluded, and recover automatically as their sand drains.
  When every upstream is bad the weights equalise, so a full outage
  degrades to uniform round-robin instead of locking out.
- **TLS ClientHello fragmentation** for SNI-based DPI evasion.

No application concerns leak in: no config-file format, no logger,
no authentication.

## Usage

```toml
[dependencies]
resocks5-net = { git = "https://github.com/PHPCraftdream/resocks5" }
tokio = { version = "1", features = ["full"] }
anyhow = "1"
```

```rust
use std::time::Duration;

use resocks5_net::connect::{connect_proxy, parse_proxy_str};
use resocks5_net::pool::{PoolConfig, ProxyPool};
use resocks5_net::rotator::ProxyRotator;
use resocks5_net::types::{ProxyProtocol, IP};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let proxies = ["user:pass@198.51.100.7:1080"]
        .into_iter()
        .filter_map(|s| parse_proxy_str(s, ProxyProtocol::Socks5, IP::V4))
        .collect::<Vec<_>>();

    let rotator = ProxyRotator::new(proxies);
    let pool = ProxyPool::new(
        PoolConfig::default(),
        Duration::from_secs(10),
        8,
    );

    let upstream = rotator.get_next();
    let mut stream = connect_proxy(
        "example.com:80",
        &upstream,
        &pool,
        Duration::from_secs(10),
        None,
    )
    .await?;

    stream.write_all(b"GET / HTTP/1.0\r\nHost: example.com\r\n\r\n").await?;
    let mut body = Vec::new();
    stream.read_to_end(&mut body).await?;
    println!("received {} bytes", body.len());
    Ok(())
}
```

Top-level modules: `connect`, `pool`, `rating`, `rotator`, `types`.

A working version of this example lives at
[`examples/connect_through_proxy.rs`](examples/connect_through_proxy.rs)
and is built by CI, so the README never drifts from the API.

## Status

Pre-1.0. The API may still change before a 1.0 release. For project
context, full architecture, and the consuming binary see the main
[`resocks5`](https://github.com/PHPCraftdream/resocks5) repository.

## License

Dual-licensed under MIT OR Apache-2.0, at your option.
