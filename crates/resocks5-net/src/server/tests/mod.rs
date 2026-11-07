use super::*;
use std::pin::Pin;
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
// The only 407 challenge: no clear-text scheme is ever advertised.
const EXPECT_HTTP_407: &[u8] = b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Resocks5-Secure\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";
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
    users: bool,
) -> (Result<IncomingRequest, ServerError>, Vec<u8>) {
    let (mut peer, mut server) = duplex(64 * 1024);
    peer.write_all(bytes).await.unwrap();
    peer.shutdown().await.unwrap();
    let result = accept(&mut server, &options(anonymous, users)).await;
    drop(server);
    let mut response = Vec::new();
    peer.read_to_end(&mut response).await.unwrap();
    (result, response)
}

/// Framing, authentication, and header-handling tests (protocol-level).
mod framing;

/// Buffered-reply visibility, flush-fault, and cancellation tests (I/O-level).
mod io_failures;

/// Prefix-then-stream wrapper tests (library-level).
mod prefixed;

/// Opt-in strict RFC 9112 HTTP CONNECT ingress tests.
mod strict_http;
