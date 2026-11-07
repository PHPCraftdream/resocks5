//! Compile-time guard: the public connect API stays usable from
//! `tokio::spawn`ed tasks.
//!
//! A consumer calls `dial` inside a spawned task. If a future or stream
//! here silently stops being `Send` (a `Rc`, a `MutexGuard` held across an
//! `.await`, a non-`Send` field), the consumer's build breaks, not ours —
//! so the bounds are pinned in this crate. Nothing here runs: the futures
//! are only built and type-checked.

use std::future::Future;
use std::time::Duration;

use resocks5_net::connect::tunnel::tunnel_with_timeouts;
use resocks5_net::connect::{
    connect_proxy_once, dial, dial_chain, dial_plain, handshake_over_stream, socks5_handshake,
    AnyUpstream, ChainError, DialOptions, UpstreamStream,
};
use resocks5_net::server::{accept, IncomingRequest, Prefixed, ServerOptions};
use resocks5_net::types::{ChainConfigError, ProxyConfig, ProxyConfigError};
use resocks5_net::ConnectError;
use tokio::io::DuplexStream;

fn assert_send<T: Send>() {}
fn assert_send_sync<T: Send + Sync>() {}
fn assert_unpin<T: Unpin>() {}
fn assert_send_static<T: Send + 'static>() {}

/// Takes a future by value and demands `Send` of it.
fn future_is_send<F: Future + Send>(_: F) {}

#[test]
fn streams_are_send_and_unpin() {
    assert_send::<AnyUpstream>();
    assert_unpin::<AnyUpstream>();
    assert_send::<UpstreamStream>();
    assert_unpin::<UpstreamStream>();
}

#[test]
fn errors_cross_threads_and_tasks() {
    assert_send_sync::<ConnectError>();
    assert_send_static::<ConnectError>();
    assert_send_static::<Result<AnyUpstream, ConnectError>>();
    assert_send_sync::<ChainError>();
    assert_send_static::<Result<AnyUpstream, ChainError>>();
}

#[test]
fn config_types_are_shareable() {
    assert_send_sync::<ProxyConfig>();
    assert_send_sync::<DialOptions>();
}

#[test]
fn validation_errors_are_shareable() {
    assert_send_sync::<ProxyConfigError>();
    assert_send_sync::<ChainConfigError>();
    assert_send_static::<ProxyConfigError>();
    assert_send_static::<ChainConfigError>();
}

/// `GateLevels::try_new`'s error crosses threads and spawned tasks.
#[cfg(feature = "rotator")]
#[test]
fn gate_levels_error_is_shareable() {
    use resocks5_net::chain::GateLevelsError;
    assert_send_sync::<GateLevelsError>();
    assert_send_static::<GateLevelsError>();
}

#[allow(dead_code)]
fn dial_futures_are_send() {
    let proxy = ProxyConfig::socks5("127.0.0.1", 1080);
    let opts = DialOptions::new();
    future_is_send(dial(&proxy, "example.com", 80, &opts, None));
    future_is_send(dial_plain(&proxy, "example.com", 80, &opts));
    future_is_send(dial_chain(&proxy, "example.com", 80, &opts, None));
    future_is_send(connect_proxy_once(
        "example.com:80",
        &proxy,
        Duration::from_secs(1),
        Duration::from_secs(1),
        None,
    ));
}

#[allow(dead_code)]
fn chain_over_tcp_future_is_send(tcp: tokio::net::TcpStream) {
    let proxy = ProxyConfig::socks5("127.0.0.1", 1080);
    let opts = DialOptions::new();
    future_is_send(resocks5_net::connect::dial_chain_over(
        tcp,
        &proxy,
        "example.com",
        80,
        &opts,
        None,
    ));
}

#[allow(dead_code)]
fn chain_over_duplex_future_is_send() {
    let proxy = ProxyConfig::socks5("127.0.0.1", 1080);
    let opts = DialOptions::new();
    let (duplex, _) = tokio::io::duplex(64);
    future_is_send(resocks5_net::connect::dial_chain_over(
        duplex,
        &proxy,
        "example.com",
        80,
        &opts,
        None,
    ));
}
/// The way a consumer really uses it: an owning `async move` block handed
/// to `tokio::spawn`, which needs `Send + 'static`.
#[allow(dead_code)]
fn dial_inside_spawned_task_is_spawnable() {
    fn spawnable<F: Future + Send + 'static>(_: F)
    where
        F::Output: Send + 'static,
    {
    }

    let proxy = ProxyConfig::socks5("127.0.0.1", 1080);
    spawnable(async move {
        let opts = DialOptions::new();
        dial_plain(&proxy, "example.com", 80, &opts).await
    });
}

#[allow(dead_code)]
fn handshake_and_tunnel_futures_are_send() {
    // SOCKS5 over a caller-provided stream (by value, as `Send` streams).
    let (a, b): (DuplexStream, DuplexStream) = tokio::io::duplex(64);
    future_is_send(socks5_handshake(a, "example.com", 80));
    let (c, d) = tokio::io::duplex(64);
    future_is_send(handshake_over_stream(c, "example.com:80"));
    future_is_send(tunnel_with_timeouts(
        b,
        d,
        Duration::from_secs(1),
        Duration::from_secs(1),
    ));
}

#[cfg(feature = "pool")]
#[allow(dead_code)]
fn pool_api_is_send() {
    use resocks5_net::connect::{connect_chain, connect_proxy};
    use resocks5_net::pool::{PoolConfig, ProxyPool};

    assert_send_sync::<ProxyPool>();
    let pool = ProxyPool::new(PoolConfig::default(), Duration::from_secs(1), 1);
    let proxy = ProxyConfig::socks5("127.0.0.1", 1080);
    future_is_send(connect_proxy(
        "example.com:80",
        &proxy,
        &pool,
        Duration::from_secs(1),
        None,
    ));
    future_is_send(connect_chain(
        &proxy,
        "example.com:80",
        &pool,
        Duration::from_secs(1),
        None,
    ));
    let candidates = vec![std::sync::Arc::new(proxy.clone())];
    future_is_send(resocks5_net::connect::connect_hedged(
        &candidates,
        "example.com:80",
        &std::sync::Arc::new(pool),
        None,
        &resocks5_net::connect::HedgeOptions::default(),
        |_| {},
    ));
}

#[test]
fn prefixed_wrappers_are_send_and_unpin() {
    assert_send::<Prefixed<tokio::net::TcpStream>>();
    assert_unpin::<Prefixed<tokio::net::TcpStream>>();
    assert_send::<Prefixed<DuplexStream>>();
    assert_unpin::<Prefixed<DuplexStream>>();
}

/// `into_prefixed` is usable from a spawned `Send + 'static` task.
#[allow(dead_code)]
fn into_prefixed_inside_spawned_task_is_spawnable() {
    fn spawnable<F: Future + Send + 'static>(_: F)
    where
        F::Output: Send + 'static,
    {
    }

    spawnable(async move {
        let (client, mut server) = tokio::io::duplex(1024);
        let opts = ServerOptions::new(
            tokio::time::Instant::now() + Duration::from_secs(1),
            true,
            false,
        );
        let request = accept(&mut server, &opts).await;
        if let Ok(req) = request {
            let mut prefixed = req.into_prefixed(server);
            use tokio::io::AsyncWriteExt;
            prefixed.write_all(b"ok").await.ok();
        }
        drop(client);
    });
}

#[test]
fn requests_stay_send() {
    assert_send::<IncomingRequest>();
}

/// The `accept` future with `strict_http(true)` stays `Send`.
#[allow(dead_code)]
fn strict_http_accept_future_is_send() {
    let (mut duplex, _) = tokio::io::duplex(1024);
    let opts = ServerOptions::new(
        tokio::time::Instant::now() + Duration::from_secs(1),
        false,
        true,
    )
    .strict_http(true);
    future_is_send(resocks5_net::server::accept(&mut duplex, &opts));
}
