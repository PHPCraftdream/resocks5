//! Inbound SOCKS5 and HTTP CONNECT framing, independent of application policy storage.
//!
//! Available without default features. Destinations remain unresolved: this module
//! never dials, resolves DNS, selects a route, or grants a direct-routing privilege.
//! [`accept`] authenticates and parses only; the host sends [`Reply::Established`]
//! after egress is ready (or deliberately before a host-owned recovery phase).
//! Credentials are plaintext on these protocols; transport protection is the host's concern.

use std::fmt;
use std::future::Future;
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr};

use base64::{engine::general_purpose, Engine as _};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::{timeout, Instant};

use crate::connect::HostPort;

const MAX_HEADER_BYTES: usize = 16 * 1024;
const AUTH_FAILURE: &[u8] = &[1, 1];
const RESP_407: &[u8] = b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"resocks5\", charset=\"UTF-8\"\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";

/// Independent authentication capabilities and the host-supplied absolute deadline.
///
/// Password capability means configured users exist, not that any particular user
/// is enabled. The closure remains responsible for verification and persistence.
#[derive(Debug, Clone, Copy)]
pub struct ServerOptions {
    deadline: Instant,
    anonymous: bool,
    password: bool,
}

impl ServerOptions {
    /// Use one absolute deadline for detection, framing, and authentication.
    /// A past deadline refuses to poll the stream or authentication closure.
    pub fn new(deadline: Instant, allow_anonymous: bool, allow_password: bool) -> Self {
        Self {
            deadline,
            anonymous: allow_anonymous,
            password: allow_password,
        }
    }
}

/// Owned UTF-8 credentials supplied at most once per handshake.
/// Debug deliberately reveals neither username nor password.
pub struct Credentials {
    username: String,
    password: String,
}

impl Credentials {
    /// Submitted username, without normalization.
    pub fn username(&self) -> &str {
        &self.username
    }
    /// Submitted password, without normalization.
    pub fn password(&self) -> &str {
        &self.password
    }
}

impl fmt::Debug for Credentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Credentials { username: [REDACTED], password: [REDACTED] }")
    }
}

/// Detected inbound protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Protocol {
    /// SOCKS version 5.
    Socks5,
    /// HTTP CONNECT.
    Http,
}

/// Host-selected final tunnel response; parsing itself never sends success.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Reply {
    /// Egress is ready, or the host deliberately begins early-success recovery.
    Established,
    /// Target policy rejected the request (SOCKS REP 2 / HTTP 403).
    Forbidden,
    /// Egress failed (SOCKS REP 4 / HTTP 502).
    UpstreamUnavailable,
    /// Egress failed without a more specific cause (SOCKS REP 1 / HTTP 502).
    GeneralFailure,
    /// Host admission cap reached (SOCKS REP 1 / HTTP 503).
    Overloaded,
}

/// An authenticated, unresolved request and the exact payload already consumed.
#[derive(Debug)]
pub struct IncomingRequest {
    protocol: Protocol,
    target: String,
    username: Option<String>,
    pipeline: Vec<u8>,
}

impl IncomingRequest {
    /// Detected protocol, used to encode host replies.
    pub fn protocol(&self) -> Protocol {
        self.protocol
    }
    /// Unresolved authority. HTTP spelling is preserved; SOCKS IPs are canonical.
    pub fn target(&self) -> &str {
        &self.target
    }
    /// Verified username, including an empty HTTP username if the closure accepts it.
    /// Anonymous acceptance is always `None`, never a synthetic empty identity.
    pub fn username(&self) -> Option<&str> {
        self.username.as_deref()
    }
    /// Exact HTTP over-read bytes; SOCKS payload remains unread on the stream.
    pub fn pipeline(&self) -> &[u8] {
        &self.pipeline
    }
    /// Transfer ownership of over-read bytes for forwarding exactly once.
    /// Subsequent calls return an empty vector. Unread stream bytes follow this prefix.
    pub fn take_pipeline(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.pipeline)
    }
    /// Write the host's tunnel outcome. Call once, before forwarding payload.
    /// Never send another protocol reply after early success.
    ///
    /// cancel-safe: NO — a partial reply is terminal; discard the stream on
    /// cancellation or error. This operation has no implicit timeout: the host
    /// supplies the ordinary egress or early-recovery response budget.
    pub async fn reply<S: AsyncWrite + Unpin>(
        &self,
        stream: &mut S,
        reply: Reply,
    ) -> Result<(), ServerError> {
        let bytes: &[u8] = match (self.protocol, reply) {
            (Protocol::Socks5, Reply::Established) => &[5, 0, 0, 1, 0, 0, 0, 0, 0, 0],
            (Protocol::Socks5, Reply::Forbidden) => &[5, 2, 0, 1, 0, 0, 0, 0, 0, 0],
            (Protocol::Socks5, Reply::UpstreamUnavailable) => &[5, 4, 0, 1, 0, 0, 0, 0, 0, 0],
            (Protocol::Socks5, Reply::GeneralFailure) => &[5, 1, 0, 1, 0, 0, 0, 0, 0, 0],
            (Protocol::Socks5, Reply::Overloaded) => &[5, 1, 0, 1, 0, 0, 0, 0, 0, 0],
            (Protocol::Http, Reply::Established) => b"HTTP/1.1 200 Connection Established\r\n\r\n",
            (Protocol::Http, Reply::Forbidden) => http_error(403),
            (Protocol::Http, Reply::UpstreamUnavailable) => http_error(502),
            (Protocol::Http, Reply::GeneralFailure) => http_error(502),
            (Protocol::Http, Reply::Overloaded) => http_error(503),
        };
        stream.write_all(bytes).await.map_err(ServerError::Io)
    }
}

/// Typed inbound failure. Diagnostic text never contains submitted passwords or tokens.
/// On any failure the host must discard the stream; some failures already wrote a reply.
#[derive(Debug)]
#[non_exhaustive]
pub enum ServerError {
    /// Transport failure, including truncated SOCKS frames.
    Io(io::Error),
    /// Invalid protocol framing or destination.
    Protocol(String),
    /// Invalid or rejected authentication.
    Authentication(String),
    /// HTTP request line and headers exceeded 16KiB, including their delimiter.
    HeaderTooLarge,
    /// Absolute client deadline exhausted.
    Deadline,
    /// Peer closed before detection or HTTP header completion.
    Closed,
}

impl fmt::Display for ServerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "{e}"),
            Self::Protocol(s) | Self::Authentication(s) => f.write_str(s),
            Self::HeaderTooLarge => write!(f, "HTTP headers exceeded {MAX_HEADER_BYTES} bytes"),
            Self::Deadline => f.write_str("client protocol deadline exhausted"),
            Self::Closed => f.write_str("client closed before completing protocol framing"),
        }
    }
}
impl std::error::Error for ServerError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            _ => None,
        }
    }
}
impl From<io::Error> for ServerError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

/// Detect and parse one inbound request, authenticating through an owned-credentials closure.
///
/// `0x05` selects SOCKS5; an ASCII letter selects HTTP; other bytes fail.
/// SOCKS prefers password authentication when both methods are available.
/// HTTP verifies supplied credentials even when anonymous access is allowed;
/// supplied credentials fail when password capability is disabled.
/// No DNS, egress, final success reply, or application routing occurs here.
///
/// cancel-safe: NO — partial reads/writes and owned prefixes cannot be resumed.
/// On timeout, error, or cancellation the host MUST discard the stream, including
/// any buffered wrapper. An expired deadline is checked before polling any phase.
/// Live deadlines use Tokio timeout semantics, not synchronous preemption. Dropping
/// the authentication future does not roll back its side effects: admitted blocking
/// verification/persistence can finish after cancellation and must retain its own
/// admission permits. The closure must not perform blocking work on the executor.
/// Futures are `Send` when the stream, closure, and authentication future are `Send`.
pub async fn accept<S, A, F>(
    stream: &mut S,
    options: &ServerOptions,
    authenticate: A,
) -> Result<IncomingRequest, ServerError>
where
    S: AsyncRead + AsyncWrite + Unpin,
    A: FnOnce(Credentials) -> F,
    F: Future<Output = bool>,
{
    let first = phase(options.deadline, async {
        let mut byte = [0];
        if stream.read(&mut byte).await? == 0 {
            return Err(ServerError::Closed);
        }
        Ok(byte[0])
    })
    .await?;
    match first {
        5 => phase(options.deadline, socks(stream, options, authenticate)).await,
        b if b.is_ascii_alphabetic() => {
            phase(options.deadline, http(stream, b, options, authenticate)).await
        }
        other => Err(ServerError::Protocol(format!(
            "unrecognised first byte {other:#04x} — neither SOCKS5 (0x05) nor an HTTP method"
        ))),
    }
}

/// cancel-safe: NO — drops a partially polled operation on live timeout; the
/// caller discards the stream. Expired entry never polls the operation.
async fn phase<T>(
    deadline: Instant,
    operation: impl Future<Output = Result<T, ServerError>>,
) -> Result<T, ServerError> {
    let budget = deadline.saturating_duration_since(Instant::now());
    if budget.is_zero() {
        return Err(ServerError::Deadline);
    }
    timeout(budget, operation)
        .await
        .map_err(|_| ServerError::Deadline)?
}

/// cancel-safe: NO — exact reads and replies may be partial; authentication
/// side effects may survive cancellation. The host discards the stream.
async fn socks<S, A, F>(
    stream: &mut S,
    options: &ServerOptions,
    authenticate: A,
) -> Result<IncomingRequest, ServerError>
where
    S: AsyncRead + AsyncWrite + Unpin,
    A: FnOnce(Credentials) -> F,
    F: Future<Output = bool>,
{
    let nmethods = stream.read_u8().await?;
    let mut methods = vec![0; usize::from(nmethods)];
    stream.read_exact(&mut methods).await?;
    let chosen = if options.password && methods.contains(&2) {
        2
    } else if options.anonymous && methods.contains(&0) {
        0
    } else {
        stream.write_all(&[5, 255]).await?;
        return Err(ServerError::Authentication(format!("No mutually supported SOCKS5 auth method (server: anonymous={}, user/pass={}; client offered {} method(s))", options.anonymous, options.password, methods.len())));
    };
    stream.write_all(&[5, chosen]).await?;
    let username = if chosen == 2 {
        let mut header = [0; 2];
        stream.read_exact(&mut header).await?;
        if header[0] != 1 {
            return Err(ServerError::Authentication(format!(
                "Invalid auth subnegotiation version: {:02x}",
                header[0]
            )));
        }
        if header[1] == 0 {
            return auth_fail(
                stream,
                "Zero-length username in auth subnegotiation (RFC 1929 requires 1-255 bytes)",
            )
            .await;
        }
        let mut user = vec![0; usize::from(header[1])];
        stream.read_exact(&mut user).await?;
        let plen = stream.read_u8().await?;
        if plen == 0 {
            return auth_fail(
                stream,
                "Zero-length password in auth subnegotiation (RFC 1929 requires 1-255 bytes)",
            )
            .await;
        }
        let mut password = vec![0; usize::from(plen)];
        stream.read_exact(&mut password).await?;
        let user = match String::from_utf8(user) {
            Ok(s) => s,
            Err(_) => return auth_fail(stream, "Invalid UTF-8 in username").await,
        };
        let password = match String::from_utf8(password) {
            Ok(s) => s,
            Err(_) => return auth_fail(stream, "Invalid UTF-8 in password").await,
        };
        let identity = user.clone();
        if !authenticate(Credentials {
            username: user,
            password,
        })
        .await
        {
            let _ = stream.write_all(AUTH_FAILURE).await;
            return Err(ServerError::Authentication(format!(
                "Auth failed for user '{identity}'"
            )));
        }
        stream.write_all(&[1, 0]).await?;
        Some(identity)
    } else {
        None
    };
    let mut header = [0; 4];
    stream.read_exact(&mut header).await?;
    if header[0] != 5 {
        return Err(ServerError::Protocol(
            "Invalid version in CONNECT request".into(),
        ));
    }
    if header[1] != 1 {
        return Err(ServerError::Protocol(
            "Only CONNECT commands are supported".into(),
        ));
    }
    // Preserve current behavior: RSV is ignored; only domain targets need grammar validation.
    let target = match header[3] {
        1 => {
            let mut ip = [0; 4];
            stream.read_exact(&mut ip).await?;
            let port = stream.read_u16().await?;
            format!("{}:{port}", Ipv4Addr::from(ip))
        }
        4 => {
            let mut ip = [0; 16];
            stream.read_exact(&mut ip).await?;
            let port = stream.read_u16().await?;
            format!("[{}]:{port}", Ipv6Addr::from(ip))
        }
        3 => {
            let len = stream.read_u8().await?;
            let mut domain = vec![0; usize::from(len)];
            stream.read_exact(&mut domain).await?;
            let port = stream.read_u16().await?;
            let domain =
                String::from_utf8(domain).map_err(|e| ServerError::Protocol(e.to_string()))?;
            let target = format!("{domain}:{port}");
            if domain.is_empty()
                || domain
                    .bytes()
                    .any(|b| b.is_ascii_control() || b.is_ascii_whitespace())
                || HostPort::parse(&target).is_none()
            {
                let _ = stream.write_all(&[5, 4, 0, 1, 0, 0, 0, 0, 0, 0]).await;
                return Err(ServerError::Protocol(format!(
                    "Invalid DOMAINNAME in CONNECT request: {domain:?}"
                )));
            }
            target
        }
        atyp => return Err(ServerError::Protocol(format!("Unknown ATYP: {atyp:02x}"))),
    };
    Ok(IncomingRequest {
        protocol: Protocol::Socks5,
        target,
        username,
        pipeline: Vec::new(),
    })
}

async fn auth_fail<T, S: AsyncWrite + Unpin>(
    stream: &mut S,
    message: &str,
) -> Result<T, ServerError> {
    let _ = stream.write_all(AUTH_FAILURE).await;
    Err(ServerError::Authentication(message.into()))
}

fn http_error(status: u16) -> &'static [u8] {
    match status {
        400 => b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",
        403 => b"HTTP/1.1 403 Forbidden\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",
        407 => RESP_407,
        431 => b"HTTP/1.1 431 Request Header Fields Too Large\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",
        501 => b"HTTP/1.1 501 Not Implemented\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",
        502 => b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",
        503 => b"HTTP/1.1 503 Service Unavailable\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",
        _ => unreachable!("private HTTP response status"),
    }
}

async fn http_fail<T, S: AsyncWrite + Unpin>(
    stream: &mut S,
    status: u16,
    error: ServerError,
) -> Result<T, ServerError> {
    let _ = stream.write_all(http_error(status)).await;
    Err(error)
}

struct ByteLines<'a> {
    rest: &'a [u8],
}
impl<'a> Iterator for ByteLines<'a> {
    type Item = &'a [u8];
    fn next(&mut self) -> Option<Self::Item> {
        if self.rest.is_empty() {
            return None;
        }
        match self.rest.windows(2).position(|w| w == b"\r\n") {
            Some(pos) => {
                let line = &self.rest[..pos];
                self.rest = &self.rest[pos + 2..];
                Some(line)
            }
            None => {
                let line = self.rest;
                self.rest = &[];
                Some(line)
            }
        }
    }
}

/// cancel-safe: NO — consumed header/pipeline bytes are future-owned and replies
/// may be partial; authentication side effects may survive stream disposal.
async fn http<S, A, F>(
    stream: &mut S,
    first: u8,
    options: &ServerOptions,
    authenticate: A,
) -> Result<IncomingRequest, ServerError>
where
    S: AsyncRead + AsyncWrite + Unpin,
    A: FnOnce(Credentials) -> F,
    F: Future<Output = bool>,
{
    let mut buf = Vec::with_capacity(2048);
    buf.push(first);
    let mut tmp = [0; 1024];
    let header_end = loop {
        let n = stream.read(&mut tmp).await?;
        if n == 0 {
            return Err(ServerError::Closed);
        }
        let scan_from = buf.len().saturating_sub(3);
        buf.extend_from_slice(&tmp[..n]);
        if let Some(pos) = buf[scan_from..].windows(4).position(|w| w == b"\r\n\r\n") {
            let end = scan_from + pos + 4;
            if end > MAX_HEADER_BYTES {
                return http_fail(stream, 431, ServerError::HeaderTooLarge).await;
            }
            break end;
        }
        if buf.len() > MAX_HEADER_BYTES {
            return http_fail(stream, 431, ServerError::HeaderTooLarge).await;
        }
    };
    let pipeline = buf.split_off(header_end);
    let mut lines = ByteLines {
        rest: &buf[..header_end - 4],
    };
    let request_line = match lines.next() {
        None => "",
        Some(line) => match std::str::from_utf8(line) {
            Ok(s) => s,
            Err(_) => {
                return http_fail(
                    stream,
                    400,
                    ServerError::Protocol("non-UTF-8 bytes in HTTP request line".into()),
                )
                .await
            }
        },
    };
    let mut parts = request_line.splitn(3, ' ');
    let method = parts.next().unwrap_or("");
    let target = parts.next().unwrap_or("");
    let version = parts.next().unwrap_or("");
    if method.is_empty() || target.is_empty() || !version.starts_with("HTTP/") {
        return http_fail(
            stream,
            400,
            ServerError::Protocol(format!("malformed HTTP request line: {request_line:?}")),
        )
        .await;
    }
    if method != "CONNECT" {
        return http_fail(
            stream,
            501,
            ServerError::Protocol(format!("only CONNECT is supported, client sent {method:?}")),
        )
        .await;
    }
    if target
        .bytes()
        .any(|b| b.is_ascii_control() || b.is_ascii_whitespace())
    {
        return http_fail(
            stream,
            400,
            ServerError::Protocol(format!(
                "CONNECT target contains control or whitespace bytes — {target:?}"
            )),
        )
        .await;
    }
    if HostPort::parse(target).is_none() {
        return http_fail(
            stream,
            400,
            ServerError::Protocol(format!(
                "CONNECT target is not a valid host:port authority — {target:?}"
            )),
        )
        .await;
    }
    let mut auth_value = None;
    for line in lines {
        if line.is_empty() {
            continue;
        }
        let Some(colon) = line.iter().position(|&b| b == b':') else {
            continue;
        };
        let (name, value) = (&line[..colon], &line[colon + 1..]);
        if !name
            .trim_ascii()
            .eq_ignore_ascii_case(b"proxy-authorization")
        {
            continue;
        }
        let Ok(value) = std::str::from_utf8(value.trim_ascii()) else {
            return http_fail(
                stream,
                407,
                ServerError::Authentication("Proxy-Authorization header is not valid UTF-8".into()),
            )
            .await;
        };
        auth_value = Some(value);
        break;
    }
    let username = match auth_value {
        Some(value) => {
            let mut parts = value.splitn(2, ' ');
            let scheme = parts.next().unwrap_or("");
            let token = parts.next().map(str::trim);
            let Some(token) = token.filter(|_| scheme.eq_ignore_ascii_case("Basic")) else {
                return http_fail(
                    stream,
                    407,
                    ServerError::Authentication("unsupported Proxy-Authorization scheme".into()),
                )
                .await;
            };
            let decoded = match general_purpose::STANDARD.decode(token) {
                Ok(b) => b,
                Err(_) => {
                    return http_fail(
                        stream,
                        407,
                        ServerError::Authentication(
                            "Proxy-Authorization base64 decode failed".into(),
                        ),
                    )
                    .await
                }
            };
            let text = match std::str::from_utf8(&decoded) {
                Ok(s) => s,
                Err(_) => {
                    return http_fail(
                        stream,
                        407,
                        ServerError::Authentication("Proxy-Authorization not valid UTF-8".into()),
                    )
                    .await
                }
            };
            let Some((user, password)) = text.split_once(':') else {
                return http_fail(
                    stream,
                    407,
                    ServerError::Authentication("Proxy-Authorization missing ':'".into()),
                )
                .await;
            };
            if !options.password {
                return http_fail(
                    stream,
                    407,
                    ServerError::Authentication(
                        "client sent Proxy-Authorization but server has no users configured".into(),
                    ),
                )
                .await;
            }
            let identity = user.to_owned();
            if !authenticate(Credentials {
                username: identity.clone(),
                password: password.to_owned(),
            })
            .await
            {
                return http_fail(
                    stream,
                    407,
                    ServerError::Authentication(format!("HTTP auth failed for user {identity:?}")),
                )
                .await;
            }
            Some(identity)
        }
        None => {
            if !options.anonymous {
                return http_fail(
                    stream,
                    407,
                    ServerError::Authentication(
                        "anonymous HTTP CONNECT not allowed (allow_anonymous=false)".into(),
                    ),
                )
                .await;
            }
            None
        }
    };
    Ok(IncomingRequest {
        protocol: Protocol::Http,
        target: target.to_owned(),
        username,
        pipeline,
    })
}

#[cfg(test)]
#[path = "server_tests.rs"]
mod tests;
