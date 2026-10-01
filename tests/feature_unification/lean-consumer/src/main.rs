//! Compile-time fixture, half A: a downstream crate that depends on
//! resocks5-net with `default-features = false` and calls the pool-free
//! entry points (`dial`, `connect_proxy_once`). This source must compile unchanged whether or not some
//! other crate in the same build graph turns resocks5-net's `tls` on —
//! that is the feature-unification guarantee under test.

use std::time::Duration;

use resocks5_net::connect::connect_proxy::TlsConnector;
use resocks5_net::connect::{connect_proxy_once, dial, parse_proxy_str, AnyUpstream, DialOptions};
use resocks5_net::types::{IP, ProxyProtocol};

/// A real lean consumer may NAME the parameter type, not just pass an
/// untyped `None` — the named path `connect::connect_proxy::TlsConnector`
/// must stay public and resolve to the same type under every feature
/// combination (review R2-P2-01).
fn named_connector_slot() -> Option<&'static TlsConnector> {
    None
}

fn main() {
    let proxy = parse_proxy_str("user:pass@198.51.100.7:1080", ProxyProtocol::Socks5, IP::V4)
        .expect("valid proxy line");

    // The trailing `None` slot exists under every feature combination;
    // arity must never depend on what cargo unified into this build.
    let once = connect_proxy_once(
        "example.com:443",
        &proxy,
        Duration::from_secs(1),
        Duration::from_secs(1),
        None,
    );

    // Pool-free: no `ProxyPool`/`PoolConfig` is named, so this source builds
    // without the `pool` feature and must still build when unification
    // turns it on.
    let opts = DialOptions::new();
    let dialed = dial(&proxy, "example.com", 443, &opts, None);
    let _: Option<AnyUpstream> = None;

    // Never polled: this fixture proves compilation, not connectivity.
    drop(once);
    drop(dialed);
    let _ = named_connector_slot();
    println!("lean-consumer: compiled OK (lean dependency, no tls/pool of its own)");
}
