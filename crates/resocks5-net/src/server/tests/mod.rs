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
// Wire oracles for the feature-less `accept`, which has no authentication
// scheme enabled: every refusal is the bare closing 407 (independent bytes,
// never derived from production encoders).
const EXPECT_HTTP_407_BARE_CLOSE: &[u8] =
    b"HTTP/1.1 407 Proxy Authentication Required\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";
// Keep-alive challenge with secure auth AND clear text enabled (`accept_with`).
#[cfg(feature = "secure-auth")]
const EXPECT_HTTP_407_CHALLENGE: &[u8] = b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Resocks5-Secure\r\nProxy-Authenticate: Basic realm=\"resocks5\"\r\nContent-Length: 0\r\n\r\n";
// Keep-alive challenge with secure auth only.
#[cfg(feature = "secure-auth")]
const EXPECT_HTTP_407_SECURE_ONLY: &[u8] = b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Resocks5-Secure\r\nContent-Length: 0\r\n\r\n";
const EXPECT_HTTP_431: &[u8] = b"HTTP/1.1 431 Request Header Fields Too Large\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";
const EXPECT_HTTP_501: &[u8] =
    b"HTTP/1.1 501 Not Implemented\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";
const EXPECT_HTTP_502: &[u8] =
    b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";
const EXPECT_HTTP_503: &[u8] =
    b"HTTP/1.1 503 Service Unavailable\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";

/// A comfortably future deadline for the bounded tests.
pub(super) fn soon() -> Instant {
    Instant::now() + Duration::from_secs(5)
}

/// Admission policy from the three knobs the production builder exposes.
fn options(deadline: Instant, anonymous: bool, cleartext: bool) -> ServerOptions {
    ServerOptions::new(deadline)
        .allow_anonymous(anonymous)
        .allow_cleartext(cleartext)
}

/// Default-deadline policy for the feature-less `accept` tests, which only
/// consume the anonymous knob (clear text needs `accept_with`).
fn anon_options(anonymous: bool) -> ServerOptions {
    options(soon(), anonymous, false)
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
    cleartext: bool,
) -> (Result<IncomingRequest, ServerError>, Vec<u8>) {
    let (mut peer, mut server) = duplex(64 * 1024);
    peer.write_all(bytes).await.unwrap();
    peer.shutdown().await.unwrap();
    let result = accept(&mut server, &options(soon(), anonymous, cleartext)).await;
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

/// The full SOCKS5/HTTP negotiation matrix over `accept_with` (feature
/// `secure-auth`).
#[cfg(feature = "secure-auth")]
mod negotiation;

/// RFC 1929 / HTTP Basic wire-level strictness tests (feature `secure-auth`).
#[cfg(feature = "secure-auth")]
mod cleartext;
