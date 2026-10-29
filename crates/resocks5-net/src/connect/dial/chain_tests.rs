use std::error::Error as _;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;

use super::*;

const GUARD: Duration = Duration::from_secs(10);
const OK_200: &[u8] = b"HTTP/1.1 200 OK\r\n\r\n";
const FORBIDDEN_403: &[u8] = b"HTTP/1.1 403 Forbidden\r\n\r\n";

/// One protocol layer served by [`layered_stub`] on the same TCP socket.
enum Layer {
    Http(&'static [u8]),
    Socks5(u8),
}

async fn bind() -> (TcpListener, u16) {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    (l, port)
}

/// Reads one HTTP request head, answers `response`; `(head, accepted)`.
async fn serve_http(s: &mut TcpStream, response: &[u8]) -> (Vec<u8>, bool) {
    let mut req = Vec::new();
    while !req.ends_with(b"\r\n\r\n") {
        req.push(s.read_u8().await.unwrap());
    }
    s.write_all(response).await.unwrap();
    (req, response.starts_with(b"HTTP/1.1 200"))
}

/// No-auth SOCKS5 server step; `(greeting + request, accepted)`.
async fn serve_socks5(s: &mut TcpStream, rep: u8) -> (Vec<u8>, bool) {
    let mut greeting = [0u8; 3];
    s.read_exact(&mut greeting).await.unwrap();
    assert_eq!(greeting, [0x05, 0x01, 0x00]);
    s.write_all(&[0x05, 0x00]).await.unwrap();
    let mut req = vec![0u8; 4];
    s.read_exact(&mut req).await.unwrap();
    let rest = match req[3] {
        0x01 => 6,
        0x04 => 18,
        0x03 => {
            let len = s.read_u8().await.unwrap();
            req.push(len);
            len as usize + 2
        }
        other => panic!("ATYP {other}"),
    };
    let mut tail = vec![0u8; rest];
    s.read_exact(&mut tail).await.unwrap();
    req.extend_from_slice(&tail);
    s.write_all(&[0x05, rep, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await
        .unwrap();
    (req, rep == 0)
}

/// Accepts one connection and serves `layers` back to back on it, the way
/// a chain of tunnels shares one socket. Stops at the first refusal; after
/// the last accepted layer it writes `ok`. Returns each layer's request.
fn layered_stub(l: TcpListener, layers: Vec<Layer>) -> JoinHandle<Vec<Vec<u8>>> {
    tokio::spawn(async move {
        let (mut s, _) = l.accept().await.unwrap();
        let mut seen = Vec::new();
        let mut all_ok = true;
        for layer in layers {
            let (req, ok) = match layer {
                Layer::Http(resp) => serve_http(&mut s, resp).await,
                Layer::Socks5(rep) => serve_socks5(&mut s, rep).await,
            };
            seen.push(req);
            if !ok {
                all_ok = false;
                break;
            }
        }
        if all_ok {
            s.write_all(b"ok").await.unwrap();
        }
        let _ = s.read(&mut [0u8; 1]).await;
        seen
    })
}

/// Accepts and never replies.
fn silent_stub(l: TcpListener) -> JoinHandle<()> {
    tokio::spawn(async move {
        let (_s, _) = l.accept().await.unwrap();
        std::future::pending::<()>().await;
    })
}

fn opts() -> DialOptions {
    DialOptions::new()
        .with_connect_timeout(Duration::from_secs(5))
        .with_handshake_timeout(Duration::from_secs(5))
}

async fn chain(
    proxy: &ProxyConfig,
    host: &str,
    port: u16,
    opts: &DialOptions,
) -> Result<AnyUpstream, ChainError> {
    timeout(GUARD, dial_chain(proxy, host, port, opts, None))
        .await
        .expect("test guard")
}

async fn chain_err(proxy: &ProxyConfig, host: &str, port: u16, opts: &DialOptions) -> ChainError {
    match chain(proxy, host, port, opts).await {
        Ok(_) => panic!("dial_chain must fail"),
        Err(e) => e,
    }
}

async fn expect_ok_payload(mut up: AnyUpstream) {
    let mut buf = [0u8; 2];
    up.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"ok");
}

#[test]
fn stage_encoding_round_trips() {
    for stage in [
        ChainStage::Connect,
        ChainStage::Hop(0),
        ChainStage::Hop(7),
        ChainStage::Target,
    ] {
        assert_eq!(ChainStage::decode(stage.encode()), stage);
    }
}

#[tokio::test]
async fn gate_and_proxy_reach_target() {
    let (l, port) = bind().await;
    let stub = layered_stub(l, vec![Layer::Http(OK_200), Layer::Socks5(0)]);
    let proxy =
        ProxyConfig::socks5("inner.test", 1080).with_gate(ProxyConfig::http("127.0.0.1", port));
    let up = chain(&proxy, "example.com", 80, &opts()).await.unwrap();
    assert!(matches!(up, AnyUpstream::Gate(_)));
    expect_ok_payload(up).await;
    let seen = stub.await.unwrap();
    assert!(seen[0].starts_with(b"CONNECT inner.test:1080 HTTP/1.1\r\n"));
    assert_eq!(&seen[1][3..5], &[0x03, 11]);
    assert_eq!(&seen[1][5..16], b"example.com");
    assert_eq!(&seen[1][16..], &[0, 80]);
}

#[tokio::test]
async fn three_nodes_reach_target() {
    let (l, port) = bind().await;
    let stub = layered_stub(
        l,
        vec![Layer::Http(OK_200), Layer::Http(OK_200), Layer::Socks5(0)],
    );
    let proxy = ProxyConfig::socks5("c.test", 3)
        .with_gate(ProxyConfig::http("b.test", 2).with_gate(ProxyConfig::http("127.0.0.1", port)));
    let up = chain(&proxy, "example.com", 80, &opts()).await.unwrap();
    expect_ok_payload(up).await;
    let seen = stub.await.unwrap();
    assert!(seen[0].starts_with(b"CONNECT b.test:2 HTTP/1.1\r\n"));
    assert!(seen[1].starts_with(b"CONNECT c.test:3 HTTP/1.1\r\n"));
    assert_eq!(seen.len(), 3);
}

#[tokio::test]
async fn bracketed_ipv6_target_is_sent_as_ipv6() {
    let (l, port) = bind().await;
    let stub = layered_stub(l, vec![Layer::Http(OK_200), Layer::Socks5(0)]);
    let proxy =
        ProxyConfig::socks5("inner.test", 1080).with_gate(ProxyConfig::http("127.0.0.1", port));
    let up = chain(&proxy, "[::1]", 443, &opts()).await.unwrap();
    expect_ok_payload(up).await;
    let seen = stub.await.unwrap();
    assert_eq!(seen[1][3], 0x04);
}

#[tokio::test]
async fn gate_refusal_is_hop_zero() {
    let (l, port) = bind().await;
    let _stub = layered_stub(l, vec![Layer::Http(FORBIDDEN_403)]);
    let proxy =
        ProxyConfig::socks5("inner.test", 1080).with_gate(ProxyConfig::http("127.0.0.1", port));
    let err = chain_err(&proxy, "example.com", 80, &opts()).await;
    assert_eq!(err.stage(), ChainStage::Hop(0));
    assert!(
        matches!(
            err.error(),
            ConnectError::ProxyRejected {
                protocol: ProxyProtocol::Http,
                code: Some(403),
                ..
            }
        ),
        "{err:?}"
    );
}

#[tokio::test]
async fn proxy_refusal_is_target_stage() {
    let (l, port) = bind().await;
    let _stub = layered_stub(l, vec![Layer::Http(OK_200), Layer::Socks5(5)]);
    let proxy =
        ProxyConfig::socks5("inner.test", 1080).with_gate(ProxyConfig::http("127.0.0.1", port));
    let err = chain_err(&proxy, "example.com", 80, &opts()).await;
    assert_eq!(err.stage(), ChainStage::Target);
    assert!(
        matches!(
            err.error(),
            ConnectError::ProxyRejected {
                protocol: ProxyProtocol::Socks5,
                code: Some(5),
                ..
            }
        ),
        "{err:?}"
    );
}

#[tokio::test]
async fn middle_node_refusal_is_hop_one() {
    let (l, port) = bind().await;
    let _stub = layered_stub(l, vec![Layer::Http(OK_200), Layer::Http(FORBIDDEN_403)]);
    let proxy = ProxyConfig::socks5("c.test", 3)
        .with_gate(ProxyConfig::http("b.test", 2).with_gate(ProxyConfig::http("127.0.0.1", port)));
    let err = chain_err(&proxy, "example.com", 80, &opts()).await;
    assert_eq!(err.stage(), ChainStage::Hop(1));
}

#[tokio::test]
async fn unreachable_gate_is_connect_stage() {
    let (l, port) = bind().await;
    drop(l);
    let proxy =
        ProxyConfig::socks5("inner.test", 1080).with_gate(ProxyConfig::http("127.0.0.1", port));
    let err = chain_err(&proxy, "example.com", 80, &opts()).await;
    assert_eq!(err.stage(), ChainStage::Connect);
    assert!(matches!(
        err.error(),
        ConnectError::Io {
            stage: Stage::Connect,
            ..
        } | ConnectError::Timeout {
            stage: Stage::Connect,
            ..
        }
    ));
}

#[tokio::test]
async fn stalled_gate_times_out_in_hop_zero() {
    let (l, port) = bind().await;
    let _stub = silent_stub(l);
    let proxy =
        ProxyConfig::socks5("inner.test", 1080).with_gate(ProxyConfig::http("127.0.0.1", port));
    let o = opts().with_handshake_timeout(Duration::from_millis(200));
    let err = chain_err(&proxy, "example.com", 80, &o).await;
    assert_eq!(err.stage(), ChainStage::Hop(0));
    assert!(
        matches!(
            err.error(),
            ConnectError::Timeout {
                stage: Stage::Handshake,
                kind: TimeoutKind::HttpHandshake,
                ..
            }
        ),
        "{err:?}"
    );
}

#[tokio::test]
async fn total_timeout_reports_the_step_in_progress() {
    let (l, port) = bind().await;
    let _stub = silent_stub(l);
    let proxy =
        ProxyConfig::socks5("inner.test", 1080).with_gate(ProxyConfig::http("127.0.0.1", port));
    let o = opts().with_total_timeout(Duration::from_millis(200));
    let err = chain_err(&proxy, "example.com", 80, &o).await;
    assert_eq!(err.stage(), ChainStage::Hop(0));
    assert!(
        matches!(
            err.error(),
            ConnectError::Timeout {
                stage: Stage::Total,
                kind: TimeoutKind::Total,
                ..
            }
        ),
        "{err:?}"
    );
}

#[tokio::test]
async fn without_gate_returns_plain_like_dial() {
    let (l, port) = bind().await;
    let stub = layered_stub(l, vec![Layer::Socks5(0)]);
    let up = chain(
        &ProxyConfig::socks5("127.0.0.1", port),
        "example.com",
        80,
        &opts(),
    )
    .await
    .unwrap();
    assert!(matches!(up, AnyUpstream::Plain(_)));
    expect_ok_payload(up).await;
    stub.await.unwrap();
}

#[tokio::test]
async fn without_gate_refusal_is_target_stage() {
    let (l, port) = bind().await;
    let _stub = layered_stub(l, vec![Layer::Socks5(5)]);
    let err = chain_err(
        &ProxyConfig::socks5("127.0.0.1", port),
        "example.com",
        80,
        &opts(),
    )
    .await;
    assert_eq!(err.stage(), ChainStage::Target);
}

#[tokio::test]
async fn without_gate_unreachable_is_connect_stage() {
    let (l, port) = bind().await;
    drop(l);
    let err = chain_err(
        &ProxyConfig::socks5("127.0.0.1", port),
        "example.com",
        80,
        &opts(),
    )
    .await;
    assert_eq!(err.stage(), ChainStage::Connect);
}

#[tokio::test]
async fn error_display_names_stage_and_exposes_source() {
    let (l, port) = bind().await;
    let _stub = layered_stub(l, vec![Layer::Http(FORBIDDEN_403)]);
    let proxy =
        ProxyConfig::socks5("inner.test", 1080).with_gate(ProxyConfig::http("127.0.0.1", port));
    let err = chain_err(&proxy, "example.com", 80, &opts()).await;
    let text = err.to_string();
    assert!(text.starts_with("chain hop 0: "), "{text}");
    assert!(err.source().is_some());
    assert!(matches!(
        err.into_error(),
        ConnectError::ProxyRejected { .. }
    ));
}

#[cfg(not(feature = "tls"))]
#[tokio::test]
async fn https_node_in_lean_build_fails_before_connecting() {
    let proxy =
        ProxyConfig::socks5("inner.test", 1080).with_gate(ProxyConfig::https("gate.test", 1));
    let err = chain_err(&proxy, "example.com", 80, &opts()).await;
    assert_eq!(err.stage(), ChainStage::Connect);
    assert!(
        matches!(err.error(), ConnectError::TlsFeatureMissing { host } if host == "gate.test"),
        "{err:?}"
    );
}

#[cfg(feature = "tls")]
#[tokio::test]
async fn https_node_without_connector_fails_before_connecting() {
    let proxy =
        ProxyConfig::socks5("inner.test", 1080).with_gate(ProxyConfig::https("gate.test", 1));
    let err = chain_err(&proxy, "example.com", 80, &opts()).await;
    assert_eq!(err.stage(), ChainStage::Connect);
    assert!(matches!(err.error(), ConnectError::Tls { .. }), "{err:?}");
}
