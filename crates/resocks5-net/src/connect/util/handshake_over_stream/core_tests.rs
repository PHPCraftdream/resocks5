use tokio::io::duplex;

use super::{handshake_over_stream, socks5_handshake};

async fn wire(use_core: bool, auth: Option<(&str, &str)>) -> Vec<u8> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let has_auth = auth.is_some();
    let (mut client, mut server) = duplex(4096);
    let peer = tokio::spawn(async move {
        let mut seen = Vec::new();
        let mut buf = [0u8; 3];
        server.read_exact(&mut buf).await.unwrap();
        seen.extend_from_slice(&buf);
        if has_auth {
            server.write_all(&[0x05, 0x02]).await.unwrap();
            let mut a = [0u8; 3 + 4 + 4];
            server.read_exact(&mut a).await.unwrap();
            seen.extend_from_slice(&a);
            server.write_all(&[0x01, 0x00]).await.unwrap();
        } else {
            server.write_all(&[0x05, 0x00]).await.unwrap();
        }
        // 4 head + 1 len + 11 domain + 2 port
        let mut req = [0u8; 18];
        server.read_exact(&mut req).await.unwrap();
        seen.extend_from_slice(&req);
        server
            .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .await
            .unwrap();
        seen
    });
    if use_core {
        socks5_handshake(&mut client, "example.com", 443, auth)
            .await
            .unwrap();
    } else {
        handshake_over_stream(&mut client, "example.com:443", auth)
            .await
            .unwrap();
    }
    peer.await.unwrap()
}

#[tokio::test]
async fn core_and_wrapper_emit_identical_bytes() {
    assert_eq!(wire(true, None).await, wire(false, None).await);
    let auth = Some(("user", "pass"));
    assert_eq!(wire(true, auth).await, wire(false, auth).await);
}
