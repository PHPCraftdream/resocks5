use super::*;
use std::pin::Pin;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt, BufWriter, DuplexStream, ReadBuf};

// Independent boundary oracle: changing the production limit must fail these tests.
const EXPECT_HEADER_LIMIT: usize = 16_384;

// Independent wire oracles: never derive expected replies from production encoders.
const EXPECT_HTTP_400: &[u8] =
    b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";
const EXPECT_HTTP_403: &[u8] =
    b"HTTP/1.1 403 Forbidden\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";
const EXPECT_HTTP_407: &[u8] = b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"resocks5\", charset=\"UTF-8\"\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";
const EXPECT_HTTP_431: &[u8] = b"HTTP/1.1 431 Request Header Fields Too Large\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";
const EXPECT_HTTP_501: &[u8] =
    b"HTTP/1.1 501 Not Implemented\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";
const EXPECT_HTTP_502: &[u8] =
    b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";
const EXPECT_HTTP_503: &[u8] =
    b"HTTP/1.1 503 Service Unavailable\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";

fn options(anonymous: bool, password: bool) -> ServerOptions {
    ServerOptions::new(Instant::now() + Duration::from_secs(5), anonymous, password)
}

fn socks_request(domain: &[u8]) -> Vec<u8> {
    let mut bytes = vec![5, 1, 0, 5, 1, 0, 3];
    bytes.push(u8::try_from(domain.len()).unwrap());
    bytes.extend_from_slice(domain);
    bytes.extend_from_slice(&443u16.to_be_bytes());
    bytes
}

async fn parse(
    bytes: &[u8],
    anonymous: bool,
    password: bool,
    verified: bool,
) -> (Result<IncomingRequest, ServerError>, Vec<u8>, usize) {
    let (mut peer, mut server) = duplex(64 * 1024);
    peer.write_all(bytes).await.unwrap();
    peer.shutdown().await.unwrap();
    let calls = Arc::new(AtomicUsize::new(0));
    let count = calls.clone();
    let result = accept(
        &mut server,
        &options(anonymous, password),
        move |_| async move {
            count.fetch_add(1, Ordering::SeqCst);
            verified
        },
    )
    .await;
    drop(server);
    let mut response = Vec::new();
    peer.read_to_end(&mut response).await.unwrap();
    (result, response, calls.load(Ordering::SeqCst))
}

/// Framing, authentication, and header-handling tests (protocol-level).
mod framing;

/// Buffered-reply visibility, flush-fault, and cancellation tests (I/O-level).
mod io_failures;
