//! HTTP `CONNECT` upstream connector: one credential-less CONNECT first, then
//! the authentication the proxy's `407` names (`Resocks5-Secure` beats
//! `Basic`; `Basic` inside TLS is always allowed, on plain HTTP only while
//! `allow_cleartext` is on).

use std::fmt::Write as _;
#[cfg(feature = "pool")]
use std::time::Duration;

use base64::{engine::general_purpose, Engine as _};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
#[cfg(feature = "pool")]
use tokio::time::timeout;

#[cfg(feature = "pool")]
use crate::connect::tcp_dial::upstream_endpoint;
use crate::connect::UpstreamStream;
use crate::error::{ConnectError, ProtocolViolation};
#[cfg(feature = "pool")]
use crate::error::{Stage, TimeoutKind};
#[cfg(feature = "pool")]
use crate::pool::ProxyPool;
use crate::types::{ProxyConfig, ProxyProtocol};

/// Establish a tunnel to `target_addr` through an HTTP CONNECT proxy.
///
/// `handshake_timeout` bounds the wait for the proxy's `200` response; a
/// proxy that accepts the TCP but never answers CONNECT is treated as dead.
///
/// # Errors
///
/// Returns [`ConnectError`] when acquiring a socket from the pool, writing
/// the CONNECT request, or reading the proxy's response fails, or when the
/// handshake budget expires (`TimeoutKind::HttpHandshake`).
#[cfg(feature = "pool")]
pub async fn connect_http_proxy(
    target_addr: &str,
    proxy: &ProxyConfig,
    pool: &ProxyPool,
    handshake_timeout: Duration,
) -> Result<UpstreamStream, ConnectError> {
    let stream = pool.acquire(proxy).await?;
    http_on_acquired(stream, target_addr, proxy, handshake_timeout).await
}

/// The HTTP CONNECT half of [`connect_http_proxy`] on a socket already
/// taken from the pool, bounded by `handshake_timeout`. All HTTP rounds
/// (the credential-less probe and any authentication rounds) count toward
/// the same deadline.
#[cfg(feature = "pool")]
pub(crate) async fn http_on_acquired(
    mut stream: UpstreamStream,
    target_addr: &str,
    proxy: &ProxyConfig,
    handshake_timeout: Duration,
) -> Result<UpstreamStream, ConnectError> {
    let endpoint = upstream_endpoint(proxy);
    let result = timeout(
        handshake_timeout,
        http_connect_on_tcp(&mut stream, target_addr, proxy),
    )
    .await;

    match result {
        Ok(Ok(())) => Ok(stream),
        Ok(Err(e)) => Err(e),
        Err(_) => Err(ConnectError::Timeout {
            stage: Stage::Handshake,
            kind: TimeoutKind::HttpHandshake,
            endpoint,
            after: handshake_timeout,
        }),
    }
}

/// HTTP CONNECT core for a plain upstream socket: no deadline, no pool.
/// One credential-less CONNECT first; on a 407 the offered schemes pick the
/// authentication (`Resocks5-Secure` beats `Basic`); the exchange completes
/// on this connection. See [`http_connect_handshake`] for the full contract.
///
/// cancel-safe: NO — a cancelled handshake must close the stream.
pub(crate) async fn http_connect_on_tcp(
    stream: &mut UpstreamStream,
    target_addr: &str,
    proxy: &ProxyConfig,
) -> Result<(), ConnectError> {
    http_connect_dance(stream, target_addr, proxy).await
}

/// The authentication dance shared by the plain-TCP and generic paths.
///
/// A user/password entry sends `Basic` in the FIRST request, exactly as
/// 0.4.x did: proxies such as 3proxy answer an unauthenticated CONNECT with
/// `407` and close the connection, so a probe-then-retry could never reach
/// them. The probe (a credential-less CONNECT, then the scheme its `407`
/// names) runs only when Basic cannot or must not be sent first:
/// `secure_only` entries, plain-HTTP entries with clear text disallowed, and
/// entries with secure credentials but no user/password pair.
///
/// cancel-safe: NO.
async fn http_connect_dance<S>(
    stream: &mut S,
    target_addr: &str,
    proxy: &ProxyConfig,
) -> Result<(), ConnectError>
where
    S: AsyncReadExt + AsyncWriteExt + Unpin,
{
    proxy.preflight_auth()?;
    if let Some((user, password)) = proxy.usable_pair() {
        let https = proxy.protocol == ProxyProtocol::Https;
        if !proxy.secure_only && (proxy.allow_cleartext || https) {
            let head = send_connect(
                stream,
                target_addr,
                Some(basic_authorization(user, password)),
            )
            .await?;
            return if head.status() / 100 == 2 {
                Ok(())
            } else {
                Err(rejected(&head))
            };
        }
    }
    let head = send_connect(stream, target_addr, None).await?;
    if head.status() / 100 == 2 {
        return Ok(());
    }
    if head.status() != 407 {
        return Err(rejected(&head));
    }
    #[cfg(feature = "secure-auth")]
    if head.has_scheme(crate::http_auth::SECURE) && proxy.secure_auth.is_some() {
        let credentials = proxy.secure_auth.as_deref().expect("checked above");
        return secure_http_rounds(stream, target_addr, credentials).await;
    }
    if proxy.secure_only {
        // Only our method is acceptable; the upstream offered none.
        return Err(ConnectError::SecureAuthUnsupported);
    }
    if proxy.usable_pair().is_some() && head.has_scheme(crate::http_auth::BASIC) {
        // Clear text is the only method on offer and it is disallowed here;
        // refuse before the password is sent.
        return Err(ConnectError::CleartextCredentialsRefused);
    }
    Err(rejected(&head))
}

/// Perform the HTTP `CONNECT` handshake for one tunnel hop on an
/// already-connected stream, leaving the stream usable for payload.
///
/// Public so that gate-tunnel callers in dependent crates can run the
/// HTTP hop over any stream (plain, TLS, or TLS-in-TLS), not just
/// [`UpstreamStream`].
///
/// The dance: one CONNECT without credentials first. A `2xx` finishes the
/// hop (an upstream that does not require authentication tunnels this entry
/// anonymously). A `407` names the accepted schemes in `Proxy-Authenticate`;
/// the strongest one this entry can speak is then used ON THE SAME
/// CONNECTION: `Resocks5-Secure` (feature `secure-auth`) runs the
/// `secure_auth` exchange one message per round, base64 in
/// `Proxy-Authorization`, and the tunnel's `200` carries the server's last
/// token in `Proxy-Authenticate`, which is verified before the hop is
/// accepted; `Basic` is sent once the upstream asked for it — plain HTTP
/// only while `allow_cleartext` is on (`CleartextCredentialsRefused`
/// otherwise, before the password is sent), inside TLS always. In
/// `secure_only` mode ONLY `Resocks5-Secure` is acceptable: a `407` without
/// it fails with `ConnectError::SecureAuthUnsupported` before any password
/// byte. Without usable credentials a `407` is a plain `ProxyRejected` —
/// unless secure credentials are present, in which case the secure exchange
/// runs regardless of any pair.
/// Any other well-formed status is `ProxyRejected` as before.
///
/// # Errors
///
/// Returns [`ConnectError`] when the request cannot be written, the
/// response cannot be read/parsed, the proxy rejects the CONNECT, or the
/// negotiated authentication fails (`SecureAuth` variants).
///
/// cancel-safe: NO — a cancelled handshake must close the stream.
pub async fn http_connect_handshake<S>(
    stream: &mut S,
    target_addr: &str,
    proxy: &ProxyConfig,
) -> Result<(), ConnectError>
where
    S: AsyncReadExt + AsyncWriteExt + Unpin,
{
    http_connect_dance(stream, target_addr, proxy).await
}

/// [`http_connect_handshake`] bounded by an ABSOLUTE `deadline`, with a typed
/// timeout: [`ConnectError::Timeout`] (stage [`Stage::Handshake`](crate::error::Stage::Handshake), kind
/// [`TimeoutKind::HttpHandshake`](crate::error::TimeoutKind::HttpHandshake), or [`TimeoutKind::HttpsConnectHandshake`](crate::error::TimeoutKind::HttpsConnectHandshake)
/// when `proxy` is an HTTPS upstream), the `host:port` of `proxy` as the
/// endpoint and the time left at the call as `after`. HTTP has no separate
/// greeting phase; every round of the authentication dance counts toward
/// the same deadline, so there is no finer kind than "the CONNECT reply did
/// not arrive".
///
/// On error or timeout the stream is in an unspecified state: drop it.
///
/// # Errors
///
/// As [`http_connect_handshake`], plus the timeout above.
///
/// cancel-safe: NO — a cancelled handshake must close the stream.
pub async fn http_connect_handshake_until<S>(
    stream: &mut S,
    target_addr: &str,
    proxy: &ProxyConfig,
    deadline: tokio::time::Instant,
) -> Result<(), ConnectError>
where
    S: AsyncReadExt + AsyncWriteExt + Unpin,
{
    let after = deadline.saturating_duration_since(tokio::time::Instant::now());
    match tokio::time::timeout_at(deadline, http_connect_handshake(stream, target_addr, proxy))
        .await
    {
        Ok(result) => result,
        Err(_) => Err(ConnectError::Timeout {
            stage: crate::error::Stage::Handshake,
            kind: if proxy.protocol == ProxyProtocol::Https {
                crate::error::TimeoutKind::HttpsConnectHandshake
            } else {
                crate::error::TimeoutKind::HttpHandshake
            },
            endpoint: format!("{}:{}", proxy.host, proxy.port),
            after,
        }),
    }
}

/// Write one CONNECT round and read the complete response head.
///
/// cancel-safe: NO.
async fn send_connect<S>(
    stream: &mut S,
    target_addr: &str,
    authorization: Option<String>,
) -> Result<ResponseHead, ConnectError>
where
    S: AsyncReadExt + AsyncWriteExt + Unpin,
{
    write_connect_request(stream, target_addr, authorization).await?;
    read_response_head(stream).await
}

/// `Basic` header value for a `user:password` pair (RFC 7617; the pair was
/// screened non-empty by `usable_pair`).
fn basic_authorization(user: &str, password: &str) -> String {
    format!(
        "Basic {}",
        general_purpose::STANDARD.encode(format!("{user}:{password}"))
    )
}

/// The typed rejection for a completed non-2xx head.
fn rejected(head: &ResponseHead) -> ConnectError {
    ConnectError::ProxyRejected {
        protocol: ProxyProtocol::Http,
        code: Some(head.status()),
        response: head.status_line(),
    }
}

async fn write_connect_request<S>(
    stream: &mut S,
    target_addr: &str,
    authorization: Option<String>,
) -> Result<(), ConnectError>
where
    S: AsyncWriteExt + Unpin,
{
    if target_addr
        .bytes()
        .any(|b| b.is_ascii_control() || b.is_ascii_whitespace())
    {
        return Err(ConnectError::Protocol(
            ProtocolViolation::HttpInvalidConnectTarget,
        ));
    }
    let mut req = format!(
        "CONNECT {} HTTP/1.1\r\nHost: {}\r\n",
        target_addr, target_addr
    );

    if let Some(value) = authorization {
        write!(req, "Proxy-Authorization: {}\r\n", value).expect("String write cannot fail");
    }

    req.push_str("\r\n");
    stream.write_all(req.as_bytes()).await?;
    stream.flush().await?;
    Ok(())
}

/// The generic capped-read loop: read until the head is complete, preserving
/// any coalesced payload past it (TCP and TLS alike).
///
/// cancel-safe: NO — cancellation must discard the partially read stream.
async fn read_response_head<S>(stream: &mut S) -> Result<ResponseHead, ConnectError>
where
    S: AsyncReadExt + Unpin,
{
    let mut head = ResponseHead::new();
    loop {
        let filled = head.filled;
        let suffix = &head.buf[..filled];
        let remaining = if suffix.ends_with(b"\r\n\r") {
            1
        } else if suffix.ends_with(b"\r\n") {
            2
        } else if suffix.ends_with(b"\r") {
            3
        } else {
            4
        };
        let limit = remaining.min(head.remaining()?);
        // TLS buffers decrypted records internally. Stop exactly at the header.
        let n = stream.read(&mut head.buf[filled..filled + limit]).await?;
        if head.advance(n)? {
            return Ok(head);
        }
    }
}

struct ResponseHead {
    buf: Vec<u8>,
    filled: usize,
    total: usize,
}

impl ResponseHead {
    fn new() -> Self {
        Self {
            buf: vec![0; 4096],
            filled: 0,
            total: 0,
        }
    }

    fn remaining(&self) -> Result<usize, ConnectError> {
        let remaining = self.buf.len() - self.total;
        if remaining == 0 {
            return Err(ConnectError::Protocol(
                ProtocolViolation::HttpResponseTooLarge,
            ));
        }
        Ok(remaining)
    }

    /// Feed `n` freshly read bytes; `Ok(true)` once a final head is complete.
    /// A well-formed non-2xx status (a `407` included) completes too — the
    /// caller interprets it. Informational `1xx` heads reset the buffer.
    fn advance(&mut self, n: usize) -> Result<bool, ConnectError> {
        if n == 0 {
            return Err(ConnectError::Protocol(ProtocolViolation::HttpClosedEarly));
        }
        self.filled += n;
        self.total += n;
        if !self.buf[..self.filled].ends_with(b"\r\n\r\n") {
            return Ok(false);
        }
        let first_line = self.buf[..self.filled]
            .split(|&b| b == b'\r')
            .next()
            .unwrap_or_default();
        let valid = first_line.len() >= 13
            && (first_line.starts_with(b"HTTP/1.1 ") || first_line.starts_with(b"HTTP/1.0 "))
            && first_line[9..12].iter().all(u8::is_ascii_digit)
            && first_line[12] == b' ';
        if valid && first_line[9] != b'1' {
            return Ok(true);
        }
        if valid && first_line[9] == b'1' && &first_line[9..12] != b"101" {
            self.filled = 0;
            return Ok(false);
        }
        Err(ConnectError::ProxyRejected {
            protocol: ProxyProtocol::Http,
            code: None,
            response: String::from_utf8_lossy(first_line).into_owned(),
        })
    }

    /// The status code of the completed head (valid per `advance`).
    fn status(&self) -> u16 {
        self.first_line()[9..12]
            .iter()
            .fold(0u16, |acc, &d| acc * 10 + u16::from(d - b'0'))
    }

    /// The raw status line of the completed head.
    fn status_line(&self) -> String {
        String::from_utf8_lossy(self.first_line()).into_owned()
    }

    /// The bytes up to the first `\r` of the completed head.
    fn first_line(&self) -> &[u8] {
        self.buf[..self.filled]
            .split(|&b| b == b'\r')
            .next()
            .unwrap_or_default()
    }

    /// Every `Proxy-Authenticate` header value of the completed head, with
    /// the name matched case-insensitively. Non-UTF-8 headers (or a non-UTF-8
    /// head) yield nothing: they can never match a scheme.
    fn authenticate_headers(&self) -> Vec<String> {
        let text = String::from_utf8_lossy(&self.buf[..self.filled]);
        text.lines()
            .filter_map(|line| {
                let (header, value) = line.split_once(':')?;
                header
                    .trim()
                    .eq_ignore_ascii_case("proxy-authenticate")
                    .then(|| value.trim().to_owned())
            })
            .collect()
    }

    /// Every `(scheme, rest)` of every `Proxy-Authenticate` header,
    /// comma-separated parts included.
    fn schemes(&self) -> Vec<(String, String)> {
        self.authenticate_headers()
            .iter()
            .flat_map(|value| value.split(','))
            .map(|part| {
                let (scheme, rest) = crate::http_auth::split_credentials(part);
                (scheme.to_owned(), rest.to_owned())
            })
            .collect()
    }

    /// Whether `scheme` was offered (case-insensitive).
    fn has_scheme(&self, scheme: &str) -> bool {
        self.schemes()
            .iter()
            .any(|(offered, _)| offered.eq_ignore_ascii_case(scheme))
    }

    /// The decoded token of `scheme` in the challenge, if any.
    #[cfg(feature = "secure-auth")]
    fn token(&self, scheme: &str) -> Option<Vec<u8>> {
        self.authenticate_headers()
            .iter()
            .flat_map(|value| value.split(','))
            .find_map(|part| crate::http_auth::decode_token(part, scheme))
    }
}

/// `Resocks5-Secure` over HTTP rounds: the exchange runs over an in-memory
/// pipe (see `crate::http_auth`), every flushed message becomes one CONNECT
/// round's `Proxy-Authorization` token, every challenge's token is fed back,
/// and the `200`'s final token is verified by the exchange itself — a
/// token-less answer is an EOF for the exchange (`close_input`), never a
/// silently accepted hop.
///
/// cancel-safe: NO.
#[cfg(feature = "secure-auth")]
async fn secure_http_rounds<S>(
    stream: &mut S,
    target_addr: &str,
    credentials: &crate::secure_auth::SecureCredentials,
) -> Result<(), ConnectError>
where
    S: AsyncReadExt + AsyncWriteExt + Unpin,
{
    use crate::http_auth::Pipe;
    let pipe = Pipe::new();
    let mut end = pipe.end();
    let exchange = crate::secure_auth::client_authenticate(&mut end, credentials);
    tokio::pin!(exchange);
    let mut rounds = 0usize;
    let result = loop {
        tokio::select! {
            biased;
            result = &mut exchange => break result,
            message = pipe.next_message() => {
                if rounds >= crate::http_auth::MAX_ROUNDS {
                    return Err(ConnectError::SecureAuth(
                        crate::SecureAuthError::Refused,
                    ));
                }
                let value = crate::http_auth::encode_token(crate::http_auth::SECURE, &message);
                let head = send_connect(stream, target_addr, Some(value)).await?;
                rounds += 1;
                let status = head.status();
                if status != 407 && status / 100 != 2 {
                    // A rejection mid-exchange: surface it, not an I/O error.
                    return Err(rejected(&head));
                }
                match head.token(crate::http_auth::SECURE) {
                    Some(token) => pipe.push(&token),
                    // A token-less close ends the exchange with an EOF, so a
                    // silent proxy cannot fake acceptance.
                    None => pipe.close_input(),
                }
            }
        }
    };
    result.map_err(|error| match error {
        crate::SecureAuthError::Io(kind) => ConnectError::Io {
            stage: Stage::Handshake,
            endpoint: None,
            source: std::io::Error::from(kind),
        },
        other => ConnectError::SecureAuth(other),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(not(feature = "pool"))]
    use std::time::Duration;
    use tokio::io::duplex;

    fn proxy() -> ProxyConfig {
        ProxyConfig::http("localhost", 8080)
    }

    #[tokio::test(start_paused = true)]
    async fn preserves_payload_coalesced_with_connect_response() {
        let (mut client, mut upstream) = duplex(4096);
        upstream
            .write_all(b"HTTP/1.1 200 OK\r\n\r\nSSH-2.0-test\r\n")
            .await
            .unwrap();
        upstream.shutdown().await.unwrap();
        http_connect_handshake(&mut client, "example.com:22", &proxy())
            .await
            .unwrap();
        let mut payload = Vec::new();
        client.read_to_end(&mut payload).await.unwrap();
        assert_eq!(payload, b"SSH-2.0-test\r\n");
    }

    #[tokio::test]
    async fn accepts_other_success_statuses() {
        let (mut client, mut upstream) = duplex(4096);
        upstream
            .write_all(b"HTTP/1.1 201 Created\r\n\r\n")
            .await
            .unwrap();
        http_connect_handshake(&mut client, "example.com:22", &proxy())
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn rejects_invalid_status_code_prefix() {
        let (mut client, mut upstream) = duplex(4096);
        upstream
            .write_all(b"HTTP/1.1 2000 Invalid\r\n\r\n")
            .await
            .unwrap();
        assert!(
            http_connect_handshake(&mut client, "example.com:22", &proxy())
                .await
                .is_err()
        );
    }

    #[cfg(feature = "pool")]
    #[tokio::test]
    async fn tcp_connector_preserves_coalesced_payload() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let mut config = proxy();
        config.host = address.ip().to_string();
        config.port = address.port();
        let server = async {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            while !request.ends_with(b"\r\n\r\n") {
                request.push(stream.read_u8().await.unwrap());
            }
            assert!(request.starts_with(b"CONNECT example.com:22 HTTP/1.1\r\n"));
            stream
                .write_all(b"HTTP/1.1 200 OK\r\n\r\nSSH-2.0-test\r\n")
                .await
                .unwrap();
            stream.shutdown().await.unwrap();
        };
        let client = async {
            let pool = ProxyPool::new(Default::default(), Duration::from_secs(2), 1);
            let mut stream =
                connect_http_proxy("example.com:22", &config, &pool, Duration::from_secs(2))
                    .await
                    .unwrap();
            let mut bytes = Vec::new();
            stream.read_to_end(&mut bytes).await.unwrap();
            assert_eq!(bytes, b"SSH-2.0-test\r\n");
        };
        tokio::time::timeout(Duration::from_secs(5), async {
            tokio::join!(server, client);
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn handles_bytewise_informational_and_final_headers() {
        let (mut client, mut upstream) = duplex(1);
        let server = async {
            let mut request = Vec::new();
            while !request.ends_with(b"\r\n\r\n") {
                request.push(upstream.read_u8().await.unwrap());
            }
            for byte in b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.0 200 OK\r\n\r\npayload" {
                upstream.write_all(&[*byte]).await.unwrap();
            }
            upstream.shutdown().await.unwrap();
        };
        let client = async {
            http_connect_handshake(&mut client, "example.com:22", &proxy())
                .await
                .unwrap();
            let mut bytes = Vec::new();
            client.read_to_end(&mut bytes).await.unwrap();
            assert_eq!(bytes, b"payload");
        };
        tokio::time::timeout(Duration::from_secs(5), async {
            tokio::join!(server, client);
        })
        .await
        .unwrap();
    }
}

#[cfg(test)]
mod first_request_tests {
    use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt, DuplexStream};

    use super::http_connect_handshake;
    use crate::error::ConnectError;
    use crate::types::ProxyConfig;

    /// One request head (up to the blank line) as text.
    async fn read_head(upstream: &mut DuplexStream) -> String {
        let mut head = Vec::new();
        let mut byte = [0u8; 1];
        while !head.ends_with(b"\r\n\r\n") {
            upstream.read_exact(&mut byte).await.unwrap();
            head.push(byte[0]);
        }
        String::from_utf8(head).unwrap()
    }

    const CLOSING_BASIC_407: &[u8] = b"HTTP/1.0 407 Proxy Authentication Required\r\n\
        Proxy-Authenticate: Basic realm=\"proxy\"\r\nConnection: close\r\n\r\n";

    /// 0.4.x compatibility: a user/password entry puts Basic in the FIRST
    /// CONNECT, so an upstream that answers an unauthenticated request with
    /// `407` + `Connection: close` (3proxy does) is still reachable.
    /// Mutation: probing first makes the first request carry no
    /// `Proxy-Authorization`, and the closing `407` strands the client.
    #[tokio::test]
    async fn a_credentialed_entry_sends_basic_in_the_first_request() {
        let (mut client, mut upstream) = duplex(4096);
        let proxy = ProxyConfig::http("localhost", 8080).with_auth("u", "p");
        let server = async {
            let head = read_head(&mut upstream).await;
            assert!(
                head.contains("Proxy-Authorization: Basic dTpw\r\n"),
                "{head}"
            );
            upstream
                .write_all(b"HTTP/1.1 200 OK\r\n\r\n")
                .await
                .unwrap();
        };
        let (_, result) = tokio::join!(
            server,
            http_connect_handshake(&mut client, "example.com:443", &proxy)
        );
        result.unwrap();
    }

    /// A `secure_only` entry never sends Basic: its first request is the
    /// credential-less probe, and a Basic-only `407` ends in
    /// `SecureAuthUnsupported`. Mutation: sending Basic first would hand the
    /// password to a clear-text-only upstream.
    #[tokio::test]
    async fn a_secure_only_entry_probes_without_credentials() {
        let (mut client, mut upstream) = duplex(4096);
        let proxy = ProxyConfig::http("localhost", 8080)
            .with_auth("u", "p")
            .secure_only();
        let server = async {
            let head = read_head(&mut upstream).await;
            assert!(!head.contains("Proxy-Authorization"), "{head}");
            upstream.write_all(CLOSING_BASIC_407).await.unwrap();
        };
        let (_, result) = tokio::join!(
            server,
            http_connect_handshake(&mut client, "example.com:443", &proxy)
        );
        assert!(
            matches!(result, Err(ConnectError::SecureAuthUnsupported)),
            "{result:?}"
        );
    }

    /// With clear text disallowed on plain HTTP the entry probes and refuses a
    /// Basic-only `407` BEFORE any password byte. Mutation: sending Basic
    /// anyway puts `Proxy-Authorization` in the first request.
    #[cfg(feature = "secure-auth")]
    #[tokio::test]
    async fn disallowed_clear_text_refuses_before_sending_the_password() {
        let (mut client, mut upstream) = duplex(4096);
        let proxy = ProxyConfig::http("localhost", 8080)
            .with_auth("u", "p")
            .allow_cleartext(false);
        let server = async {
            let head = read_head(&mut upstream).await;
            assert!(!head.contains("Proxy-Authorization"), "{head}");
            upstream.write_all(CLOSING_BASIC_407).await.unwrap();
        };
        let (_, result) = tokio::join!(
            server,
            http_connect_handshake(&mut client, "example.com:443", &proxy)
        );
        assert!(
            matches!(result, Err(ConnectError::CleartextCredentialsRefused)),
            "{result:?}"
        );
    }
}

#[cfg(test)]
mod deadline_tests {
    use std::time::Duration;

    use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt};
    use tokio::time::Instant;

    use super::http_connect_handshake_until;
    use crate::error::{ConnectError, Stage, TimeoutKind};
    use crate::types::ProxyConfig;

    fn soon() -> Instant {
        Instant::now() + Duration::from_millis(200)
    }

    /// A silent HTTP upstream is a typed handshake timeout carrying the
    /// upstream endpoint; an HTTPS upstream gets its own kind. Mutation:
    /// dropping the deadline (the call hangs) or reusing one kind for both
    /// fails the matches.
    #[tokio::test]
    async fn a_silent_upstream_is_a_typed_timeout() {
        for (proxy, expected) in [
            (ProxyConfig::http("up", 8080), TimeoutKind::HttpHandshake),
            (
                ProxyConfig::https("up", 8443),
                TimeoutKind::HttpsConnectHandshake,
            ),
        ] {
            let (mut client, _server) = duplex(1024);
            let error = http_connect_handshake_until(&mut client, "h.test:443", &proxy, soon())
                .await
                .unwrap_err();
            match &error {
                ConnectError::Timeout {
                    stage: Stage::Handshake,
                    kind,
                    endpoint,
                    ..
                } => {
                    assert_eq!(*kind, expected);
                    assert_eq!(endpoint, &format!("up:{}", proxy.port));
                }
                other => panic!("unexpected: {other:?}"),
            }
        }
    }

    /// A 200 inside the deadline completes the handshake.
    #[tokio::test]
    async fn a_reply_inside_the_deadline_succeeds() {
        let (mut client, mut server) = duplex(1024);
        let stub = tokio::spawn(async move {
            let mut head = [0u8; 64];
            let _ = server.read(&mut head).await.unwrap();
            server
                .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                .await
                .unwrap();
        });
        http_connect_handshake_until(
            &mut client,
            "h.test:443",
            &ProxyConfig::http("up", 8080),
            Instant::now() + Duration::from_secs(10),
        )
        .await
        .unwrap();
        stub.await.unwrap();
    }
}
