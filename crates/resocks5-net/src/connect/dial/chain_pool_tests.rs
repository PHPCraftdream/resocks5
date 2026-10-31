use std::future::poll_fn;
use std::sync::Arc;
use std::task::Poll;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;
use tokio::time::timeout;

use crate::connect::dial::{connect_chain, ChainStage};
use crate::connect::proxy_connect::connect_proxy::{connect_proxy, TlsConnector};
use crate::connect::AnyUpstream;
use crate::error::ConnectError;
use crate::pool::{PoolConfig, ProxyPool};
use crate::types::ProxyConfig;

const GUARD: Duration = Duration::from_secs(10);

#[derive(Clone, Copy)]
enum Layer {
    Http(bool),
    Socks5(u8),
}

async fn bind() -> (TcpListener, ProxyConfig) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    (listener, ProxyConfig::http("127.0.0.1", port))
}

fn chain(nodes: Vec<ProxyConfig>) -> ProxyConfig {
    ProxyConfig::chain(nodes.into_iter().map(Arc::new)).unwrap()
}

fn unwrap_error<T>(
    result: Result<T, crate::connect::dial::ChainError>,
) -> crate::connect::dial::ChainError {
    match result {
        Ok(_) => panic!("expected chain dial error"),
        Err(error) => error,
    }
}

async fn http_step(stream: &mut TcpStream, accepted: bool) -> Vec<u8> {
    let mut request = Vec::new();
    while !request.ends_with(b"\r\n\r\n") {
        request.push(stream.read_u8().await.unwrap());
    }
    let response: &[u8] = if accepted {
        b"HTTP/1.1 200 OK\r\n\r\n"
    } else {
        b"HTTP/1.1 403 Forbidden\r\n\r\n"
    };
    stream.write_all(response).await.unwrap();
    request
}

async fn socks_step(stream: &mut TcpStream, rep: u8) -> Vec<u8> {
    let mut greeting = [0; 3];
    stream.read_exact(&mut greeting).await.unwrap();
    assert_eq!(greeting, [5, 1, 0]);
    stream.write_all(&[5, 0]).await.unwrap();
    let mut request = vec![0; 4];
    stream.read_exact(&mut request).await.unwrap();
    let rest = match request[3] {
        1 => 6,
        4 => 18,
        3 => {
            let len = stream.read_u8().await.unwrap();
            request.push(len);
            usize::from(len) + 2
        }
        atyp => panic!("unexpected ATYP {atyp}"),
    };
    let mut tail = vec![0; rest];
    stream.read_exact(&mut tail).await.unwrap();
    request.extend_from_slice(&tail);
    stream
        .write_all(&[5, rep, 0, 1, 0, 0, 0, 0, 0, 0])
        .await
        .unwrap();
    request
}

fn serve_layers(
    listener: TcpListener,
    layers: Vec<Layer>,
    payload: bool,
) -> JoinHandle<(Vec<Vec<u8>>, Vec<u8>)> {
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut requests = Vec::new();
        let mut eof_bytes = Vec::new();
        for layer in layers {
            let ok = match layer {
                Layer::Http(ok) => {
                    requests.push(http_step(&mut stream, ok).await);
                    ok
                }
                Layer::Socks5(rep) => {
                    requests.push(socks_step(&mut stream, rep).await);
                    rep == 0
                }
            };
            if !ok {
                return (requests, eof_bytes);
            }
        }
        if payload {
            stream.write_all(b"payload").await.unwrap();
        }
        stream.read_to_end(&mut eof_bytes).await.unwrap();
        (requests, eof_bytes)
    })
}

fn eof_server(listener: TcpListener) -> JoinHandle<Vec<u8>> {
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut bytes = Vec::new();
        stream.read_to_end(&mut bytes).await.unwrap();
        bytes
    })
}

fn pool(cap: usize) -> ProxyPool {
    ProxyPool::new(PoolConfig::default(), GUARD, cap)
}

async fn dial(
    config: &ProxyConfig,
    target: &str,
    pool: &ProxyPool,
) -> Result<AnyUpstream, crate::connect::dial::ChainError> {
    timeout(
        GUARD,
        connect_chain(config, target, pool, GUARD, None::<&TlsConnector>),
    )
    .await
    .expect("bounded chain dial")
}

async fn payload(upstream: &mut AnyUpstream) {
    let mut bytes = [0; 7];
    timeout(GUARD, upstream.read_exact(&mut bytes))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&bytes, b"payload");
}

fn targets(requests: &[Vec<u8>]) -> Vec<String> {
    requests
        .iter()
        .map(|request| {
            if request.starts_with(b"CONNECT ") {
                let line_end = request.windows(2).position(|w| w == b"\r\n").unwrap();
                return String::from_utf8(request[..line_end].to_vec()).unwrap();
            }
            assert_eq!(&request[..3], &[5, 1, 0]);
            assert_eq!(request[3], 3);
            let len = usize::from(request[4]);
            let host = std::str::from_utf8(&request[5..5 + len]).unwrap();
            let port = u16::from_be_bytes([request[5 + len], request[6 + len]]);
            format!("SOCKS {host}:{port}")
        })
        .collect()
}

async fn no_pending_accept(listener: &TcpListener) -> bool {
    poll_fn(|cx| match listener.poll_accept(cx) {
        Poll::Ready(Ok(_)) => Poll::Ready(true),
        Poll::Ready(Err(error)) => panic!("accept failed: {error}"),
        Poll::Pending => Poll::Ready(false),
    })
    .await
}

#[tokio::test]
async fn one_node_http_chain_connects_and_targets_exactly() {
    let (listener, node) = bind().await;
    let mut server = serve_layers(listener, vec![Layer::Http(true)], true);
    let config = chain(vec![node]);
    let mut upstream = dial(&config, "example.test:8080", &pool(1)).await.unwrap();
    assert!(matches!(&upstream, AnyUpstream::Plain(_)));
    payload(&mut upstream).await;
    drop(upstream);
    let (requests, _) = timeout(GUARD, &mut server).await.unwrap().unwrap();
    assert_eq!(targets(&requests), ["CONNECT example.test:8080 HTTP/1.1"]);
}

#[tokio::test]
async fn two_and_three_node_mixed_chains_send_exact_next_targets() {
    let (listener, outer) = bind().await;
    let config = chain(vec![outer, ProxyConfig::socks5("exit.test", 1082)]);
    let mut server = serve_layers(listener, vec![Layer::Http(true), Layer::Socks5(0)], true);
    let mut upstream = dial(&config, "destination.test:443", &pool(1))
        .await
        .unwrap();
    assert!(matches!(&upstream, AnyUpstream::Gate(_)));
    payload(&mut upstream).await;
    drop(upstream);
    let (requests, _) = timeout(GUARD, &mut server).await.unwrap().unwrap();
    assert_eq!(
        targets(&requests),
        [
            "CONNECT exit.test:1082 HTTP/1.1",
            "SOCKS destination.test:443"
        ]
    );

    let (listener, outer) = bind().await;
    let config = chain(vec![
        outer,
        ProxyConfig::http("middle.test", 8081),
        ProxyConfig::socks5("exit.test", 1082),
    ]);
    let mut server = serve_layers(
        listener,
        vec![Layer::Http(true), Layer::Http(true), Layer::Socks5(0)],
        true,
    );
    let mut upstream = dial(&config, "destination.test:443", &pool(1))
        .await
        .unwrap();
    payload(&mut upstream).await;
    drop(upstream);
    let (requests, _) = timeout(GUARD, &mut server).await.unwrap().unwrap();
    assert_eq!(
        targets(&requests),
        [
            "CONNECT middle.test:8081 HTTP/1.1",
            "CONNECT exit.test:1082 HTTP/1.1",
            "SOCKS destination.test:443",
        ]
    );
}

#[tokio::test]
async fn refusal_reports_intermediate_hop_zero_and_final_target() {
    let (listener, outer) = bind().await;
    let inner = ProxyConfig::http("inner.test", 8081);
    let config = chain(vec![outer.clone(), inner.clone()]);
    let mut server = serve_layers(listener, vec![Layer::Http(false)], false);
    let pool = pool(1);
    let error = unwrap_error(dial(&config, "destination.test:80", &pool).await);
    assert_eq!(error.stage(), ChainStage::Hop(0));
    assert!(matches!(error.error(), ConnectError::ProxyRejected { .. }));
    drop(pool.reserve_permit(&outer).unwrap());
    drop(pool.reserve_permit(&inner).unwrap());
    timeout(GUARD, &mut server).await.unwrap().unwrap();

    let (listener, outer) = bind().await;
    let inner = ProxyConfig::socks5("inner.test", 1081);
    let config = chain(vec![outer.clone(), inner.clone()]);
    let mut server = serve_layers(listener, vec![Layer::Http(true), Layer::Socks5(5)], false);
    let second_pool = ProxyPool::new(PoolConfig::default(), GUARD, 1);
    let error = unwrap_error(dial(&config, "destination.test:80", &second_pool).await);
    assert_eq!(error.stage(), ChainStage::Target);
    assert!(matches!(error.error(), ConnectError::ProxyRejected { .. }));
    drop(second_pool.reserve_permit(&outer).unwrap());
    drop(second_pool.reserve_permit(&inner).unwrap());
    timeout(GUARD, &mut server).await.unwrap().unwrap();
}

#[tokio::test]
async fn outer_socket_failure_is_connect_stage() {
    let (listener, outer) = bind().await;
    drop(listener);
    let error = unwrap_error(dial(&chain(vec![outer]), "destination.test:80", &pool(1)).await);
    assert_eq!(error.stage(), ChainStage::Connect);
    assert!(matches!(
        error.error(),
        ConnectError::Io { .. } | ConnectError::Timeout { .. }
    ));
}

#[tokio::test]
async fn last_node_capacity_failure_precedes_all_hops_and_releases_prior_reservations() {
    let (listener, outer) = bind().await;
    let middle = ProxyConfig::http("middle.test", 8081);
    let inner = ProxyConfig::socks5("shared-inner.test", 1081);
    let config = chain(vec![outer.clone(), middle.clone(), inner.clone()]);
    let mut server = eof_server(listener);
    let pool = pool(1);
    let occupied = pool.reserve_permit(&inner).unwrap();
    let error = unwrap_error(dial(&config, "destination.test:80", &pool).await);
    assert_eq!(error.stage(), ChainStage::Hop(1));
    assert!(matches!(error.error(), ConnectError::AtCapacity(_)));
    let outer_permit = pool.reserve_permit(&outer).unwrap();
    let middle_permit = pool.reserve_permit(&middle).unwrap();
    assert!(matches!(
        pool.reserve_permit(&inner),
        Err(ConnectError::AtCapacity(_))
    ));
    drop(outer_permit);
    drop(middle_permit);
    drop(occupied);
    drop(pool.reserve_permit(&inner).unwrap());
    assert!(timeout(GUARD, &mut server)
        .await
        .unwrap()
        .unwrap()
        .is_empty());
}

#[tokio::test]
async fn live_chain_holds_each_endpoint_permit_until_stream_drop() {
    let (listener, outer) = bind().await;
    let inner = ProxyConfig::socks5("inner.test", 1081);
    let config = chain(vec![outer.clone(), inner.clone()]);
    let mut server = serve_layers(listener, vec![Layer::Http(true), Layer::Socks5(0)], true);
    let pool = pool(1);
    let mut upstream = dial(&config, "destination.test:80", &pool).await.unwrap();
    assert!(matches!(
        pool.reserve_permit(&outer),
        Err(ConnectError::AtCapacity(_))
    ));
    assert!(matches!(
        pool.reserve_permit(&inner),
        Err(ConnectError::AtCapacity(_))
    ));
    payload(&mut upstream).await;
    drop(upstream);
    drop(pool.reserve_permit(&outer).unwrap());
    drop(pool.reserve_permit(&inner).unwrap());
    timeout(GUARD, &mut server).await.unwrap().unwrap();
}

#[tokio::test]
async fn invalid_target_is_rejected_without_socket_checkout() {
    let (listener, outer) = bind().await;
    let pool = pool(1);
    let error = unwrap_error(dial(&chain(vec![outer.clone()]), "invalid", &pool).await);
    assert_eq!(error.stage(), ChainStage::Target);
    assert!(matches!(error.error(), ConnectError::InvalidTarget(_)));
    drop(pool.reserve_permit(&outer).unwrap());
    assert!(!no_pending_accept(&listener).await);
}

#[tokio::test]
async fn shared_inner_cap_across_distinct_outer_sockets_rolls_back_second_outer() {
    let (l1, outer1) = bind().await;
    let (l2, outer2) = bind().await;
    let shared = ProxyConfig::socks5("shared.test", 1080);
    let chain1 = chain(vec![outer1.clone(), shared.clone()]);
    let chain2 = chain(vec![outer2.clone(), shared.clone()]);
    let mut first_server = serve_layers(l1, vec![Layer::Http(true), Layer::Socks5(0)], true);
    let second_server = eof_server(l2);
    let pool = pool(1);
    let mut live = dial(&chain1, "destination.test:80", &pool).await.unwrap();
    let error = unwrap_error(dial(&chain2, "destination.test:80", &pool).await);
    assert_eq!(error.stage(), ChainStage::Hop(0));
    assert!(matches!(error.error(), ConnectError::AtCapacity(_)));
    drop(pool.reserve_permit(&outer2).unwrap());
    payload(&mut live).await;
    drop(live);
    drop(pool.reserve_permit(&outer1).unwrap());
    drop(pool.reserve_permit(&shared).unwrap());
    timeout(GUARD, &mut first_server).await.unwrap().unwrap();
    assert!(timeout(GUARD, second_server)
        .await
        .unwrap()
        .unwrap()
        .is_empty());
}

fn assert_missing_tls(error: &ConnectError) {
    #[cfg(feature = "tls")]
    assert!(matches!(error, ConnectError::Tls { .. }), "{error:?}");
    #[cfg(not(feature = "tls"))]
    assert!(
        matches!(error, ConnectError::TlsFeatureMissing { .. }),
        "{error:?}"
    );
}
#[tokio::test]
async fn https_without_connector_rejects_single_and_inner_nodes_before_socket_open() {
    let (listener, outer) = bind().await;
    let https = ProxyConfig::https("127.0.0.1", outer.port);
    let pool = pool(1);
    let error = unwrap_error(dial(&chain(vec![https.clone()]), "destination.test:80", &pool).await);
    assert_eq!(error.stage(), ChainStage::Connect);
    assert_missing_tls(error.error());
    drop(pool.reserve_permit(&https).unwrap());
    assert!(!no_pending_accept(&listener).await);

    let (listener, outer) = bind().await;
    let inner_https = ProxyConfig::https("inner.test", 443);
    let config = chain(vec![outer.clone(), inner_https.clone()]);
    let error = unwrap_error(dial(&config, "destination.test:80", &pool).await);
    assert_eq!(error.stage(), ChainStage::Connect);
    assert_missing_tls(error.error());
    drop(pool.reserve_permit(&outer).unwrap());
    drop(pool.reserve_permit(&inner_https).unwrap());
    assert!(!no_pending_accept(&listener).await);
}

#[tokio::test]
async fn single_node_connect_proxy_http_and_socks5_match_chain_behavior_and_cap() {
    let (listener, http) = bind().await;
    let mut http_server = serve_layers(listener, vec![Layer::Http(true)], true);
    let pool = pool(1);
    let mut upstream = timeout(
        GUARD,
        connect_proxy(
            "http-target.test:81",
            &http,
            &pool,
            GUARD,
            None::<&TlsConnector>,
        ),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(matches!(&upstream, AnyUpstream::Plain(_)));
    assert!(matches!(
        pool.reserve_permit(&http),
        Err(ConnectError::AtCapacity(_))
    ));
    payload(&mut upstream).await;
    drop(upstream);
    drop(pool.reserve_permit(&http).unwrap());
    let (requests, _) = timeout(GUARD, &mut http_server).await.unwrap().unwrap();
    assert_eq!(targets(&requests), ["CONNECT http-target.test:81 HTTP/1.1"]);

    let (listener, socks) = bind().await;
    let socks = ProxyConfig::socks5("127.0.0.1", socks.port);
    let mut socks_server = serve_layers(listener, vec![Layer::Socks5(0)], true);
    let mut upstream = timeout(
        GUARD,
        connect_proxy(
            "socks-target.test:82",
            &socks,
            &pool,
            GUARD,
            None::<&TlsConnector>,
        ),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(matches!(&upstream, AnyUpstream::Plain(_)));
    assert!(matches!(
        pool.reserve_permit(&socks),
        Err(ConnectError::AtCapacity(_))
    ));
    payload(&mut upstream).await;
    drop(upstream);
    drop(pool.reserve_permit(&socks).unwrap());
    let (requests, _) = timeout(GUARD, &mut socks_server).await.unwrap().unwrap();
    assert_eq!(targets(&requests), ["SOCKS socks-target.test:82"]);
}

#[tokio::test]
async fn outer_capacity_fails_connect_before_socket_open() {
    let (listener, outer) = bind().await;
    let pool = pool(1);
    let held = pool.reserve_permit(&outer).unwrap();
    let error = unwrap_error(dial(&chain(vec![outer.clone()]), "target.test:80", &pool).await);
    assert_eq!(error.stage(), ChainStage::Connect);
    assert!(matches!(error.error(), ConnectError::AtCapacity(_)));
    drop(held);
    drop(pool.reserve_permit(&outer).unwrap());
    assert!(!no_pending_accept(&listener).await);
}

#[tokio::test]
async fn connect_chain_single_node_matches_connect_proxy_for_http_and_socks5() {
    let (listener, http) = bind().await;
    let mut http_server = serve_layers(listener, vec![Layer::Http(true)], true);
    let pool = pool(1);
    let mut upstream = dial(&chain(vec![http.clone()]), "http-target.test:81", &pool)
        .await
        .unwrap();
    assert!(matches!(&upstream, AnyUpstream::Plain(_)));
    assert!(matches!(
        pool.reserve_permit(&http),
        Err(ConnectError::AtCapacity(_))
    ));
    payload(&mut upstream).await;
    drop(upstream);
    drop(pool.reserve_permit(&http).unwrap());
    let (requests, _) = timeout(GUARD, &mut http_server).await.unwrap().unwrap();
    assert_eq!(targets(&requests), ["CONNECT http-target.test:81 HTTP/1.1"]);

    let (listener, bound) = bind().await;
    let socks = ProxyConfig::socks5("127.0.0.1", bound.port);
    let mut socks_server = serve_layers(listener, vec![Layer::Socks5(0)], true);
    let mut upstream = dial(&chain(vec![socks.clone()]), "socks-target.test:82", &pool)
        .await
        .unwrap();
    assert!(matches!(&upstream, AnyUpstream::Plain(_)));
    assert!(matches!(
        pool.reserve_permit(&socks),
        Err(ConnectError::AtCapacity(_))
    ));
    payload(&mut upstream).await;
    drop(upstream);
    drop(pool.reserve_permit(&socks).unwrap());
    let (requests, _) = timeout(GUARD, &mut socks_server).await.unwrap().unwrap();
    assert_eq!(targets(&requests), ["SOCKS socks-target.test:82"]);
}

#[tokio::test]
async fn connect_chain_single_node_refusals_are_target_errors_and_release_caps() {
    let (listener, http) = bind().await;
    let mut http_server = serve_layers(listener, vec![Layer::Http(false)], false);
    let pool = pool(1);
    let error = unwrap_error(dial(&chain(vec![http.clone()]), "target.test:80", &pool).await);
    assert_eq!(error.stage(), ChainStage::Target);
    assert!(matches!(error.error(), ConnectError::ProxyRejected { .. }));
    drop(pool.reserve_permit(&http).unwrap());
    timeout(GUARD, &mut http_server).await.unwrap().unwrap();

    let (listener, bound) = bind().await;
    let socks = ProxyConfig::socks5("127.0.0.1", bound.port);
    let mut socks_server = serve_layers(listener, vec![Layer::Socks5(5)], false);
    let error = unwrap_error(dial(&chain(vec![socks.clone()]), "target.test:80", &pool).await);
    assert_eq!(error.stage(), ChainStage::Target);
    assert!(matches!(error.error(), ConnectError::ProxyRejected { .. }));
    drop(pool.reserve_permit(&socks).unwrap());
    timeout(GUARD, &mut socks_server).await.unwrap().unwrap();
}
