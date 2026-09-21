//! Compile-time fixture, half A: a downstream crate that depends on
//! resocks5-net with `default-features = false` and calls the universal
//! entry points. This source must compile unchanged whether or not some
//! other crate in the same build graph turns resocks5-net's `tls` on —
//! that is the feature-unification guarantee under test.

use std::time::Duration;

use resocks5_net::connect::{connect_proxy, connect_proxy_once, parse_proxy_str};
use resocks5_net::pool::{PoolConfig, ProxyPool};
use resocks5_net::types::{IP, ProxyProtocol};

fn main() {
    let proxy = parse_proxy_str("user:pass@198.51.100.7:1080", ProxyProtocol::Socks5, IP::V4)
        .expect("valid proxy line");
    let pool = ProxyPool::new(PoolConfig::default(), Duration::from_secs(1), 1);

    // The trailing `None` slot exists under every feature combination;
    // arity must never depend on what cargo unified into this build.
    let once = connect_proxy_once(
        "example.com:443",
        &proxy,
        Duration::from_secs(1),
        Duration::from_secs(1),
        None,
    );
    let pooled = connect_proxy("example.com:443", &proxy, &pool, Duration::from_secs(1), None);

    // Never polled: this fixture proves compilation, not connectivity.
    drop(once);
    drop(pooled);
    println!("lean-consumer: compiled OK (lean dependency, no tls of its own)");
}
