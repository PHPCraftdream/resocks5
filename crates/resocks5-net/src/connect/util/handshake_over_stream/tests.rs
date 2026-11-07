use std::net::Ipv6Addr;
use std::time::Duration;

use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt};

use super::{deadline_after, handshake_over_stream};

/// Mutation: the plain `Instant::now() + budget` panics on `Duration::MAX`;
/// a clamp to `now` would fail the far-future floor.
#[test]
fn deadline_after_survives_unrepresentable_budgets() {
    let now = tokio::time::Instant::now();
    let far = deadline_after(Duration::MAX);
    assert!(far.saturating_duration_since(now) >= Duration::from_secs(365 * 24 * 3600));
    let soon = deadline_after(Duration::from_secs(5));
    let ahead = soon.saturating_duration_since(tokio::time::Instant::now());
    assert!(ahead >= Duration::from_secs(4) && ahead <= Duration::from_secs(5));
}

/// Minimal SOCKS5 server stub over a duplex half: completes the greeting
/// (plus username/password sub-negotiation when `auth` is set, asserting
/// the credentials), captures the CONNECT request (head + address + port),
/// then replies with success and the payload `ok`.
async fn stub_server(mut upstream: tokio::io::DuplexStream, auth: bool) -> ([u8; 4], Vec<u8>) {
    let mut greeting = [0u8; 3];
    upstream.read_exact(&mut greeting).await.unwrap();
    if auth {
        assert_eq!(greeting, [0x05, 0x01, 0x02]);
        upstream.write_all(&[0x05, 0x02]).await.unwrap();
        let mut ver = [0u8; 1];
        upstream.read_exact(&mut ver).await.unwrap();
        assert_eq!(ver[0], 0x01);
        let mut ulen = [0u8; 1];
        upstream.read_exact(&mut ulen).await.unwrap();
        let mut uname = vec![0u8; ulen[0] as usize];
        upstream.read_exact(&mut uname).await.unwrap();
        let mut plen = [0u8; 1];
        upstream.read_exact(&mut plen).await.unwrap();
        let mut passwd = vec![0u8; plen[0] as usize];
        upstream.read_exact(&mut passwd).await.unwrap();
        assert_eq!(uname, b"user");
        assert_eq!(passwd, b"pass");
        upstream.write_all(&[0x01, 0x00]).await.unwrap();
    } else {
        assert_eq!(greeting, [0x05, 0x01, 0x00]);
        upstream.write_all(&[0x05, 0x00]).await.unwrap();
    }

    let mut head = [0u8; 4];
    upstream.read_exact(&mut head).await.unwrap();
    let mut addr = match head[3] {
        0x01 => {
            let mut b = [0u8; 6];
            upstream.read_exact(&mut b).await.unwrap();
            b.to_vec()
        }
        0x03 => {
            let mut len = [0u8; 1];
            upstream.read_exact(&mut len).await.unwrap();
            let mut b = vec![0u8; len[0] as usize + 2];
            upstream.read_exact(&mut b).await.unwrap();
            b
        }
        0x04 => {
            let mut b = [0u8; 18];
            upstream.read_exact(&mut b).await.unwrap();
            b.to_vec()
        }
        other => panic!("unexpected ATYP {other:02x}"),
    };
    addr.insert(0, head[3]);
    upstream
        .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await
        .unwrap();
    upstream.write_all(b"ok").await.unwrap();
    (head, addr)
}

/// Drive the client side and return the captured request head and
/// ATYP-prefixed address bytes, asserting the returned stream still
/// carries the stub's `ok` payload.
async fn exchange(target: &str) -> anyhow::Result<([u8; 4], Vec<u8>)> {
    let (mut client, upstream) = duplex(4096);
    let server = tokio::spawn(stub_server(upstream, false));
    let stream = handshake_over_stream(&mut client, target, None).await?;
    let mut payload = Vec::new();
    tokio::pin!(stream);
    stream.read_to_end(&mut payload).await?;
    assert_eq!(payload, b"ok");
    Ok(server.await.unwrap())
}

#[tokio::test]
async fn bracketed_ipv6_uses_atyp4() {
    let (head, addr) = tokio::time::timeout(Duration::from_secs(5), exchange("[::1]:443"))
        .await
        .expect("timed out")
        .unwrap();
    assert_eq!(head, [0x05, 0x01, 0x00, 0x04]);
    assert_eq!(addr[0], 0x04);
    assert_eq!(&addr[1..17], &Ipv6Addr::LOCALHOST.octets());
    assert_eq!(&addr[17..], &[0x01, 0xBB]);
}

#[tokio::test]
async fn bare_ipv6_uses_atyp4() {
    let (head, addr) = tokio::time::timeout(Duration::from_secs(5), exchange("::1:443"))
        .await
        .expect("timed out")
        .unwrap();
    assert_eq!(head, [0x05, 0x01, 0x00, 0x04]);
    assert_eq!(&addr[1..17], &Ipv6Addr::LOCALHOST.octets());
    assert_eq!(&addr[17..], &[0x01, 0xBB]);
}

#[tokio::test]
async fn ipv4_uses_atyp1() {
    let (head, addr) = tokio::time::timeout(Duration::from_secs(5), exchange("1.2.3.4:443"))
        .await
        .expect("timed out")
        .unwrap();
    assert_eq!(head, [0x05, 0x01, 0x00, 0x01]);
    assert_eq!(addr, vec![0x01, 1, 2, 3, 4, 0x01, 0xBB]);
}

#[tokio::test]
async fn domain_uses_atyp3() {
    let (head, addr) = tokio::time::timeout(Duration::from_secs(5), exchange("example.com:443"))
        .await
        .expect("timed out")
        .unwrap();
    assert_eq!(head, [0x05, 0x01, 0x00, 0x03]);
    assert_eq!(addr[0], 0x03);
    assert_eq!(&addr[1..12], b"example.com");
    assert_eq!(&addr[12..], &[0x01, 0xBB]);
}

#[tokio::test]
async fn missing_port_is_rejected() {
    let result = tokio::time::timeout(Duration::from_secs(5), exchange("no-port-target"))
        .await
        .expect("timed out");
    assert!(result.is_err());
}

#[tokio::test]
async fn full_ipv6_bracketed() {
    let (head, addr) = tokio::time::timeout(Duration::from_secs(5), exchange("[2001:db8::1]:443"))
        .await
        .expect("timed out")
        .unwrap();
    assert_eq!(head, [0x05, 0x01, 0x00, 0x04]);
    let expected: [u8; 16] = "2001:db8::1".parse::<Ipv6Addr>().unwrap().octets();
    assert_eq!(&addr[1..17], &expected);
    assert_eq!(&addr[17..], &[0x01, 0xBB]);
}

/// Same as [`exchange`], but the client half is wrapped in a real
/// buffering layer: `BufStream::write_all` only reaches its own internal
/// buffer until an explicit `flush`, so this times out unless every
/// handshake message is flushed to the peer before the matching read.
async fn exchange_buffered(
    target: &str,
    auth: Option<(&str, &str)>,
) -> anyhow::Result<([u8; 4], Vec<u8>)> {
    let (client, upstream) = duplex(4096);
    let mut buffered = tokio::io::BufStream::new(client);
    let server = tokio::spawn(stub_server(upstream, auth.is_some()));
    let stream = handshake_over_stream(&mut buffered, target, auth).await?;
    tokio::pin!(stream);
    let mut payload = Vec::new();
    stream.read_to_end(&mut payload).await?;
    assert_eq!(payload, b"ok");
    Ok(server.await.unwrap())
}

#[tokio::test]
async fn no_auth_completes_through_buffered_client() {
    let (head, addr) = tokio::time::timeout(
        Duration::from_secs(5),
        exchange_buffered("1.2.3.4:443", None),
    )
    .await
    .expect("handshake stalled: greeting/CONNECT never flushed to the peer")
    .unwrap();
    assert_eq!(head, [0x05, 0x01, 0x00, 0x01]);
    assert_eq!(addr, vec![0x01, 1, 2, 3, 4, 0x01, 0xBB]);
}

#[tokio::test]
async fn auth_completes_through_buffered_client() {
    let (head, addr) = tokio::time::timeout(
        Duration::from_secs(5),
        exchange_buffered("1.2.3.4:443", Some(("user", "pass"))),
    )
    .await
    .expect("handshake stalled: greeting/auth/CONNECT never flushed to the peer")
    .unwrap();
    assert_eq!(head, [0x05, 0x01, 0x00, 0x01]);
    assert_eq!(addr, vec![0x01, 1, 2, 3, 4, 0x01, 0xBB]);
}

#[tokio::test]
async fn strict_reply_errors_are_typed_and_classified() {
    use crate::error::{ConnectError, ProtocolViolation};
    tokio::time::timeout(Duration::from_secs(5), async {
        for (reply, expected) in [([0x05, 0x00, 0x01, 0x01], 1), ([0x05, 0x05, 0x01, 0x01], 2)] {
            let (client, mut server) = duplex(128);
            let peer = tokio::spawn(async move {
                let mut greeting = [0; 3];
                server.read_exact(&mut greeting).await.unwrap();
                server.write_all(&[0x05, 0x00]).await.unwrap();
                let mut request = [0; 4];
                server.read_exact(&mut request).await.unwrap();
                let mut address = [0; 6];
                server.read_exact(&mut address).await.unwrap();
                server.write_all(&reply).await.unwrap();
            });
            let error = super::socks5_handshake(client, "1.2.3.4", 80, None)
                .await
                .unwrap_err();
            match expected {
                1 => assert!(matches!(
                    error,
                    ConnectError::Protocol(ProtocolViolation::Socks5BadReserved { got: 1 })
                )),
                _ => assert!(matches!(
                    error,
                    ConnectError::ProxyRejected { code: Some(5), .. }
                )),
            }
            assert!(!error.is_upstream_down());
            assert!(error.counts_against_upstream());
            peer.await.unwrap();
        }
    })
    .await
    .expect("strict reply exchange timed out");
}

#[tokio::test]
async fn empty_bound_domain_rejected_without_waiting_for_address() {
    use crate::error::{ConnectError, ProtocolViolation};
    let (client, mut server) = duplex(128);
    let (release_tx, release_rx) = tokio::sync::oneshot::channel::<()>();
    let peer = tokio::spawn(async move {
        let mut greeting = [0; 3];
        server.read_exact(&mut greeting).await.unwrap();
        server.write_all(&[0x05, 0x00]).await.unwrap();
        let mut request = [0; 4];
        server.read_exact(&mut request).await.unwrap();
        let mut address = [0; 6];
        server.read_exact(&mut address).await.unwrap();
        server.write_all(&[0x05, 0, 0, 3, 0]).await.unwrap();
        let _ = release_rx.await;
        let mut bytes = Vec::new();
        server.read_to_end(&mut bytes).await.unwrap();
        bytes
    });
    let error = tokio::time::timeout(
        Duration::from_secs(5),
        super::socks5_handshake(client, "1.2.3.4", 80, None),
    )
    .await
    .expect("handshake waited for missing address")
    .unwrap_err();
    assert!(matches!(
        error,
        ConnectError::Protocol(ProtocolViolation::Socks5EmptyBoundDomain)
    ));
    assert!(!error.is_upstream_down());
    assert!(error.counts_against_upstream());
    let _ = release_tx.send(());
    assert!(tokio::time::timeout(Duration::from_secs(5), peer)
        .await
        .expect("peer timeout")
        .unwrap()
        .is_empty());
}

#[tokio::test]
async fn invalid_targets_write_no_bytes() {
    use crate::error::ConnectError;
    for (host, port) in [("", 80), ("valid.invalid", 0)] {
        tokio::time::timeout(Duration::from_secs(5), async {
            let (client, mut server) = duplex(128);
            let peer = tokio::spawn(async move {
                let mut bytes = Vec::new();
                server.read_to_end(&mut bytes).await.unwrap();
                bytes
            });
            let error = super::socks5_handshake(client, host, port, None)
                .await
                .unwrap_err();
            assert!(matches!(error, ConnectError::InvalidTarget(_)));
            assert!(peer.await.unwrap().is_empty());
        })
        .await
        .expect("invalid target EOF check timed out");
    }
}

#[tokio::test]
async fn success_reply_shapes_preserve_payload() {
    tokio::time::timeout(Duration::from_secs(5), async {
        for (atyp, bound) in [
            (1, vec![0; 6]),
            (3, vec![3, b'f', b'o', b'o', 0, 80]),
            (4, vec![0; 18]),
        ] {
            let (client, mut server) = duplex(128);
            let peer = tokio::spawn(async move {
                let mut greeting = [0; 3];
                server.read_exact(&mut greeting).await.unwrap();
                server.write_all(&[0x05, 0x00]).await.unwrap();
                let mut request = [0; 4];
                server.read_exact(&mut request).await.unwrap();
                let mut address = [0; 6];
                server.read_exact(&mut address).await.unwrap();
                server.write_all(&[0x05, 0, 0, atyp]).await.unwrap();
                server.write_all(&bound).await.unwrap();
                server.write_all(b"payload").await.unwrap();
            });
            let mut stream = super::socks5_handshake(client, "1.2.3.4", 80, None)
                .await
                .unwrap();
            let mut payload = [0; 7];
            stream.read_exact(&mut payload).await.unwrap();
            assert_eq!(&payload, b"payload");
            peer.await.unwrap();
        }
    })
    .await
    .expect("successful reply exchange timed out");
}
