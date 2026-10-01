//! Compile-time fixture, half B: same build graph, resocks5-net with its
//! default features (`tls` and `pool` on). When cargo unifies features across this
//! workspace, half A's lean source must compile against this same
//! tls-enabled resocks5-net unchanged — that pairing is the whole point
//! of the fixture.

use std::time::Duration;

use resocks5_net::connect::{
    connect_proxy, connect_proxy_once, make_tls_connector, parse_proxy_str,
};
use resocks5_net::pool::{PoolConfig, ProxyPool};
use resocks5_net::types::{IP, ProxyProtocol};

fn main() {
    let proxy = parse_proxy_str("user:pass@198.51.100.7:1080", ProxyProtocol::Https, IP::V4)
        .expect("valid proxy line");
    let connector = make_tls_connector();

    let once = connect_proxy_once(
        "example.com:443",
        &proxy,
        Duration::from_secs(1),
        Duration::from_secs(1),
        Some(&connector),
    );
    // Pool-taking dispatcher (default `pool` feature on).
    let pool = ProxyPool::new(PoolConfig::default(), Duration::from_secs(1), 1);
    let pooled = connect_proxy(
        "example.com:443",
        &proxy,
        &pool,
        Duration::from_secs(1),
        Some(&connector),
    );
    // Never polled: this fixture proves compilation, not connectivity.
    drop(once);
    drop(pooled);
    println!("tls-consumer: compiled OK (resocks5-net defaults: tls + pool on)");
}
