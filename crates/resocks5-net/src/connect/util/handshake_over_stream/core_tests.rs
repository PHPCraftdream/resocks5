use tokio::io::duplex;

use super::{handshake_over_stream, socks5_handshake};

async fn wire(use_core: bool) -> Vec<u8> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let (mut client, mut server) = duplex(4096);
    let peer = tokio::spawn(async move {
        let mut seen = Vec::new();
        let mut buf = [0u8; 3];
        server.read_exact(&mut buf).await.unwrap();
        seen.extend_from_slice(&buf);
        server.write_all(&[0x05, 0x00]).await.unwrap();
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
        socks5_handshake(&mut client, "example.com", 443)
            .await
            .unwrap();
    } else {
        handshake_over_stream(&mut client, "example.com:443")
            .await
            .unwrap();
    }
    peer.await.unwrap()
}

#[tokio::test]
async fn core_and_wrapper_emit_identical_bytes() {
    let core = wire(true).await;
    // The greeting offers only "no authentication" (method 0x00).
    assert_eq!(core[..3], [0x05, 0x01, 0x00]);
    assert_eq!(core, wire(false).await);
}
