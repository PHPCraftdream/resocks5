//! Downstream witness: public API, host authentication, and real separate TCP egress.
use resocks5_net::server::{accept, Protocol, Reply, ServerOptions};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{timeout, Instant};

struct Verifier {
    calls: AtomicUsize,
}
impl Verifier {
    async fn verify(&self, user: &str, password: &str) -> bool {
        self.calls.fetch_add(1, Ordering::SeqCst);
        user == "user" && password == "pass"
    }
}

#[tokio::test]
async fn public_closure_and_real_egress_share_one_port_losslessly() {
    timeout(Duration::from_secs(15), async {
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let destination = target.local_addr().unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy = listener.local_addr().unwrap();
        let verifier = Arc::new(Verifier { calls: AtomicUsize::new(0) });
        let payload: Vec<u8> = [vec![0x16, 3, 1, 0, 255], (0..=255).cycle().take(4096).collect()].concat();
        let expected_payload = payload.clone();
        let (dial_tx, mut dial_rx) = tokio::sync::mpsc::channel(1);
        let (ready_tx, mut ready_rx) = tokio::sync::mpsc::channel(1);
        let (permit_tx, mut permit_rx) = tokio::sync::mpsc::channel(1);
        let egress = async {
            for _ in 0..2 {
                let (mut socket, _) = target.accept().await.unwrap();
                let mut received = Vec::new();
                socket.read_to_end(&mut received).await.unwrap();
                assert_eq!(received, expected_payload);
                // Distinct target-produced result, not an implicit parser echo.
                let mut response = b"TARGET:".to_vec();
                response.extend(received.iter().map(|byte| byte ^ 0xa5));
                socket.write_all(&response).await.unwrap();
                socket.shutdown().await.unwrap();
            }
        };
        let server = async {
            for protocol in [Protocol::Socks5, Protocol::Http] {
                let (mut client, _) = listener.accept().await.unwrap();
                let deadline = Instant::now() + Duration::from_secs(5);
                let owned_verifier = verifier.clone();
                let mut req = accept(&mut client, &ServerOptions::new(deadline, false, true), move |credentials| async move {
                    owned_verifier.verify(credentials.username(), credentials.password()).await
                }).await.unwrap();
                assert_eq!(req.protocol(), protocol);
                assert_eq!(req.username(), Some("user"));
                assert_eq!(req.target(), destination.to_string());
                dial_tx.send(()).await.unwrap();
                // Caller proves no success response precedes real egress readiness.
                permit_rx.recv().await.unwrap();
                let mut upstream = TcpStream::connect(req.target()).await.unwrap();
                ready_tx.send(()).await.unwrap();
                req.reply(&mut client, Reply::Established).await.unwrap();
                let prefix = req.take_pipeline();
                assert!(req.take_pipeline().is_empty());
                upstream.write_all(&prefix).await.unwrap();
                resocks5_net::connect::tunnel::tunnel_with_timeouts(client, upstream, Duration::from_secs(5), Duration::from_secs(10)).await.unwrap();
            }
        };
        let clients = async {
            for socks in [true, false] {
                let mut socket = TcpStream::connect(proxy).await.unwrap();
                if socks {
                    socket.write_all(&[5, 1, 2]).await.unwrap();
                    let mut method = [0; 2]; socket.read_exact(&mut method).await.unwrap();
                    assert_eq!(method, [5, 2]);
                    socket.write_all(b"\x01\x04user\x04pass").await.unwrap();
                    socket.read_exact(&mut method).await.unwrap(); assert_eq!(method, [1, 0]);
                    let mut request = vec![5, 1, 0, 1, 127, 0, 0, 1];
                    request.extend_from_slice(&destination.port().to_be_bytes());
                    request.extend_from_slice(&payload); socket.write_all(&request).await.unwrap();
                } else {
                    let mut request = format!("CONNECT {destination} HTTP/1.1\r\nProxy-Authorization: Basic dXNlcjpwYXNz\r\nX-Opaque: ").into_bytes();
                    request.extend_from_slice(b"\xff\r\n\r\n"); request.extend_from_slice(&payload);
                    socket.write_all(&request).await.unwrap();
                }
                dial_rx.recv().await.unwrap();
                let mut probe = [0];
                assert!(matches!(socket.try_read(&mut probe), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock));
                permit_tx.send(()).await.unwrap(); ready_rx.recv().await.unwrap();
                if socks {
                    let mut reply = [0; 10]; socket.read_exact(&mut reply).await.unwrap();
                    assert_eq!(reply, [5, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
                } else {
                    let expected = b"HTTP/1.1 200 Connection Established\r\n\r\n";
                    let mut reply = vec![0; expected.len()]; socket.read_exact(&mut reply).await.unwrap();
                    assert_eq!(reply, expected);
                }
                socket.shutdown().await.unwrap();
                let mut response = Vec::new(); socket.read_to_end(&mut response).await.unwrap();
                let mut expected = b"TARGET:".to_vec(); expected.extend(payload.iter().map(|byte| byte ^ 0xa5));
                assert_eq!(response, expected);
            }
        };
        tokio::join!(egress, server, clients);
        assert_eq!(verifier.calls.load(Ordering::SeqCst), 2);
    }).await.expect("finite downstream roundtrip");
}
