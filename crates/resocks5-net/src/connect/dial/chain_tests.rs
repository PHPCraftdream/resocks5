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

// Captures a complete SOCKS5 CONNECT request, including its address and port.
async fn read_socks_request<R: tokio::io::AsyncRead + Unpin>(reader: &mut R) -> Vec<u8> {
    let mut request = vec![0; 4];
    reader.read_exact(&mut request).await.unwrap();
    match request[3] {
        1 => request.resize(10, 0),
        4 => request.resize(22, 0),
        3 => {
            let len = reader.read_u8().await.unwrap();
            request.push(len);
            request.resize(5 + len as usize + 2, 0);
        }
        atyp => panic!("unexpected ATYP {atyp}"),
    }
    let already_read = if request[3] == 3 { 5 } else { 4 };
    reader
        .read_exact(&mut request[already_read..])
        .await
        .unwrap();
    request
}

#[tokio::test]
async fn over_socks5_preserves_domain_ipv4_and_bracketed_ipv6_bytes() {
    for (host, port, expected) in [
        (
            "target.invalid",
            80,
            [
                vec![5, 1, 0, 3, 14],
                b"target.invalid".to_vec(),
                vec![0, 80],
            ]
            .concat(),
        ),
        ("192.0.2.9", 443, vec![5, 1, 0, 1, 192, 0, 2, 9, 1, 187]),
        (
            "[::1]",
            53,
            [
                vec![5, 1, 0, 4],
                std::net::Ipv6Addr::LOCALHOST.octets().to_vec(),
                vec![0, 53],
            ]
            .concat(),
        ),
    ] {
        let (client, mut peer) = tokio::io::duplex(1024);
        let server = tokio::spawn(async move {
            let mut greeting = [0; 3];
            peer.read_exact(&mut greeting).await.unwrap();
            assert_eq!(greeting, [5, 1, 0]);
            peer.write_all(&[5, 0]).await.unwrap();
            let request = read_socks_request(&mut peer).await;
            peer.write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0x12, 0x34])
                .await
                .unwrap();
            request
        });
        let proxy = ProxyConfig::socks5("supplied", 1);
        let result = timeout(
            GUARD,
            dial_chain_over(client, &proxy, host, port, &opts(), None),
        )
        .await
        .unwrap();
        assert!(result.is_ok());
        let request = timeout(GUARD, server).await.unwrap().unwrap();
        assert_eq!(request, expected);
    }
}

#[tokio::test]
async fn over_socks5_then_http_sends_exact_ordered_requests() {
    let (client, mut peer) = tokio::io::duplex(4096);
    let server = tokio::spawn(async move {
        let mut greeting = [0; 3];
        peer.read_exact(&mut greeting).await.unwrap();
        assert_eq!(greeting, [5, 1, 0]);
        peer.write_all(&[5, 0]).await.unwrap();
        let socks = read_socks_request(&mut peer).await;
        assert_eq!(socks, [5, 1, 0, 3, 5, b'i', b'n', b'n', b'e', b'r', 0, 80]);
        peer.write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 80])
            .await
            .unwrap();
        let mut req = Vec::new();
        while !req.ends_with(b"\r\n\r\n") {
            req.push(peer.read_u8().await.unwrap());
        }
        assert_eq!(
            req,
            b"CONNECT final.test:443 HTTP/1.1\r\nHost: final.test:443\r\n\r\n"
        );
        peer.write_all(OK_200).await.unwrap();
        let mut payload = [0; 4];
        peer.read_exact(&mut payload).await.unwrap();
        assert_eq!(&payload, b"ping");
        peer.write_all(&payload).await.unwrap();
        (socks, req)
    });
    let proxy = ProxyConfig::http("inner", 80).with_gate(ProxyConfig::socks5("outer.test", 1080));
    let mut up = timeout(
        GUARD,
        dial_chain_over(client, &proxy, "final.test", 443, &opts(), None),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(matches!(up, AnyUpstream::Gate(_)));
    let mut payload = [0; 4];
    timeout(GUARD, up.write_all(b"ping"))
        .await
        .unwrap()
        .unwrap();
    timeout(GUARD, up.read_exact(&mut payload))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&payload, b"ping");
    let _ = timeout(GUARD, server).await.unwrap().unwrap();
}

#[tokio::test]
async fn over_first_and_last_refusals_have_typed_stages() {
    for first in [true, false] {
        let (client, mut peer) = tokio::io::duplex(2048);
        let server = tokio::spawn(async move {
            let mut req = Vec::new();
            if first {
                while !req.ends_with(b"\r\n\r\n") {
                    req.push(peer.read_u8().await.unwrap());
                }
                peer.write_all(FORBIDDEN_403).await.unwrap();
            } else {
                while !req.ends_with(b"\r\n\r\n") {
                    req.push(peer.read_u8().await.unwrap());
                }
                peer.write_all(OK_200).await.unwrap();
                let mut greeting = [0; 3];
                peer.read_exact(&mut greeting).await.unwrap();
                assert_eq!(greeting, [5, 1, 0]);
                peer.write_all(&[5, 0]).await.unwrap();
                let _ = read_socks_request(&mut peer).await;
                peer.write_all(&[5, 5, 0, 1, 0, 0, 0, 0, 0, 0])
                    .await
                    .unwrap();
            }
            req
        });
        let proxy =
            ProxyConfig::socks5("exit.test", 1080).with_gate(ProxyConfig::http("outer.test", 8080));
        let err = timeout(
            GUARD,
            dial_chain_over(client, &proxy, "final.test", 443, &opts(), None),
        )
        .await
        .unwrap()
        .err()
        .expect("expected proxy refusal");
        assert_eq!(
            err.stage(),
            if first {
                ChainStage::Hop(0)
            } else {
                ChainStage::Target
            }
        );
        assert!(
            matches!(err.error(), ConnectError::ProxyRejected { code: Some(code), .. } if *code == if first { 403 } else { 5 })
        );
        timeout(GUARD, server).await.unwrap().unwrap();
    }
}

#[tokio::test]
async fn over_stalled_middle_node_times_out_at_hop_one_handshake() {
    let (client, mut peer) = tokio::io::duplex(2048);
    let server = tokio::spawn(async move {
        for target in [
            b"CONNECT middle.test:2 HTTP/1.1\r\nHost: middle.test:2\r\n\r\n".as_slice(),
            b"CONNECT exit.test:3 HTTP/1.1\r\nHost: exit.test:3\r\n\r\n",
        ] {
            let mut req = Vec::new();
            while !req.ends_with(b"\r\n\r\n") {
                req.push(peer.read_u8().await.unwrap());
            }
            assert_eq!(req, target);
            if target.starts_with(b"CONNECT middle") {
                peer.write_all(OK_200).await.unwrap();
            } else {
                let mut unexpected = Vec::new();
                peer.read_to_end(&mut unexpected).await.unwrap();
                assert!(unexpected.is_empty());
                return;
            }
        }
    });
    let proxy = ProxyConfig::http("exit.test", 3).with_gate(
        ProxyConfig::http("middle.test", 2).with_gate(ProxyConfig::http("outer.test", 1)),
    );
    let o = opts().with_handshake_timeout(Duration::from_millis(150));
    let err = timeout(
        GUARD,
        dial_chain_over(client, &proxy, "target.test", 80, &o, None),
    )
    .await
    .unwrap()
    .err()
    .expect("expected timeout");
    assert_eq!(err.stage(), ChainStage::Hop(1));
    assert!(matches!(
        err.error(),
        ConnectError::Timeout {
            stage: Stage::Handshake,
            ..
        }
    ));
    timeout(GUARD, server).await.unwrap().unwrap();
}

#[tokio::test]
async fn over_total_timeout_reports_active_handshake_and_zero_sends_no_bytes() {
    let (client, mut peer) = tokio::io::duplex(1024);
    let server = tokio::spawn(async move {
        let mut greeting = [0; 3];
        peer.read_exact(&mut greeting).await.unwrap();
        std::future::pending::<()>().await;
    });
    let proxy = ProxyConfig::socks5("outer.test", 1);
    let o = opts()
        .with_handshake_timeout(Duration::from_secs(5))
        .with_total_timeout(Duration::from_millis(150));
    let err = timeout(GUARD, dial_chain_over(client, &proxy, "x", 80, &o, None))
        .await
        .unwrap()
        .err()
        .expect("expected timeout");
    assert_eq!(err.stage(), ChainStage::Target);
    assert!(matches!(
        err.error(),
        ConnectError::Timeout {
            stage: Stage::Total,
            kind: TimeoutKind::Total,
            ..
        }
    ));
    server.abort();
    let join = server.await.unwrap_err();
    assert!(join.is_cancelled());

    let (client, mut peer) = tokio::io::duplex(1024);
    let o = opts().with_total_timeout(Duration::ZERO);
    let err = timeout(GUARD, dial_chain_over(client, &proxy, "x", 80, &o, None))
        .await
        .unwrap()
        .err()
        .expect("expected timeout");
    assert_eq!(err.stage(), ChainStage::Connect);
    assert!(matches!(
        err.error(),
        ConnectError::Timeout {
            stage: Stage::Total,
            kind: TimeoutKind::Total,
            ..
        }
    ));
    let mut rest = Vec::new();
    timeout(GUARD, peer.read_to_end(&mut rest))
        .await
        .unwrap()
        .unwrap();
    assert!(rest.is_empty());
}

#[cfg(feature = "tls")]
#[tokio::test]
async fn over_https_tls_handshake_failure_is_typed() {
    let (client, mut peer) = tokio::io::duplex(4096);
    let server = tokio::spawn(async move {
        let mut record = [0; 5];
        peer.read_exact(&mut record).await.unwrap();
        assert_eq!(record[0], 0x16);
        let mut hello = vec![0; u16::from_be_bytes([record[3], record[4]]) as usize];
        peer.read_exact(&mut hello).await.unwrap();
        peer.write_all(b"not TLS").await.unwrap();
    });
    let proxy = ProxyConfig::https("localhost", 443);
    let connector = crate::connect::make_tls_connector();
    let err = timeout(
        GUARD,
        dial_chain_over(client, &proxy, "target.test", 80, &opts(), Some(&connector)),
    )
    .await
    .unwrap()
    .err()
    .expect("expected TLS error");
    assert_eq!(err.stage(), ChainStage::Target);
    assert!(matches!(err.error(), ConnectError::Tls { .. }));
    timeout(GUARD, server).await.unwrap().unwrap();
}

#[tokio::test]
async fn over_auth_error_chain_never_discloses_any_node_credentials() {
    let (client, mut peer) = tokio::io::duplex(4096);
    let server = tokio::spawn(async move {
        for response in [OK_200, FORBIDDEN_403] {
            let mut req = Vec::new();
            while !req.ends_with(b"\r\n\r\n") {
                req.push(peer.read_u8().await.unwrap());
            }
            assert!(req.starts_with(b"CONNECT "));
            assert!(req
                .windows(b"Authorization: Basic ".len())
                .any(|w| w == b"Authorization: Basic "));
            peer.write_all(response).await.unwrap();
        }
    });
    let proxy = ProxyConfig::http("exit.test", 2)
        .with_auth("cred-user-7", "secret-pass")
        .with_gate(ProxyConfig::http("outer.test", 1).with_auth("cred-user-7", "secret-pass"));
    let err = timeout(
        GUARD,
        dial_chain_over(client, &proxy, "target.test", 80, &opts(), None),
    )
    .await
    .unwrap()
    .err()
    .expect("expected proxy refusal");
    assert_eq!(err.stage(), ChainStage::Target);
    assert!(matches!(
        err.error(),
        ConnectError::ProxyRejected {
            code: Some(403),
            ..
        }
    ));
    timeout(GUARD, server).await.unwrap().unwrap();
    for text in [err.to_string(), format!("{err:?}")] {
        assert!(!text.contains("cred-user-7"));
        assert!(!text.contains("secret-pass"));
    }
    let mut source = err.source();
    while let Some(error) = source {
        let display = error.to_string();
        let debug = format!("{error:?}");
        assert!(!display.contains("cred-user-7"));
        assert!(!display.contains("secret-pass"));
        assert!(!debug.contains("cred-user-7"));
        assert!(!debug.contains("secret-pass"));
        source = error.source();
    }
}

#[tokio::test]
async fn over_cancellation_closes_peer_and_returns_eof() {
    let (client, mut peer) = tokio::io::duplex(1024);
    let proxy = ProxyConfig::socks5("outer.test", 1);
    let task = tokio::spawn(async move {
        dial_chain_over(client, &proxy, "target.test", 80, &opts(), None).await
    });
    let mut greeting = [0; 3];
    timeout(GUARD, peer.read_exact(&mut greeting))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(greeting, [5, 1, 0]);
    task.abort();
    let join = match task.await {
        Ok(_) => panic!("cancelled dial unexpectedly completed"),
        Err(join) => join,
    };
    assert!(join.is_cancelled());
    let mut rest = Vec::new();
    timeout(GUARD, peer.read_to_end(&mut rest))
        .await
        .unwrap()
        .unwrap();
    assert!(rest.is_empty());
}

#[cfg(not(feature = "tls"))]
#[tokio::test]
async fn over_https_preflight_fails_without_writing_bytes() {
    let (client, mut peer) = tokio::io::duplex(1024);
    let proxy = ProxyConfig::https("gate.test", 443);
    let err = timeout(
        GUARD,
        dial_chain_over(client, &proxy, "x", 80, &opts(), None),
    )
    .await
    .unwrap()
    .err()
    .expect("expected preflight error");
    assert_eq!(err.stage(), ChainStage::Connect);
    assert!(matches!(
        err.error(),
        ConnectError::TlsFeatureMissing { .. }
    ));
    let mut b = [0];
    assert_eq!(timeout(GUARD, peer.read(&mut b)).await.unwrap().unwrap(), 0);
}

#[cfg(feature = "tls")]
#[tokio::test]
async fn over_https_without_connector_fails_before_writing_bytes() {
    let (client, mut peer) = tokio::io::duplex(1024);
    let proxy = ProxyConfig::https("gate.test", 443);
    let err = timeout(
        GUARD,
        dial_chain_over(client, &proxy, "x", 80, &opts(), None),
    )
    .await
    .unwrap()
    .err()
    .expect("expected preflight error");
    assert_eq!(err.stage(), ChainStage::Connect);
    assert!(matches!(err.error(), ConnectError::Tls { .. }));
    let mut b = [0];
    assert_eq!(timeout(GUARD, peer.read(&mut b)).await.unwrap().unwrap(), 0);
}
