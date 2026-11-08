//! Inbound SOCKS5 and HTTP CONNECT framing on one dual port, independent of
//! application policy storage.
//!
//! Available without default features; full negotiation needs feature
//! `secure-auth`. The server always picks the strongest method the client
//! supports, in this order: secure auth (SOCKS5 method 0x80 / HTTP
//! `Resocks5-Secure`), clear text (SOCKS5 method 0x02 / HTTP `Basic`, subject
//! to `ServerOptions::allow_cleartext`, verified against the same
//! `SecretStore` that secures the strong
//! method — one secret per user, any protocol, any method), and anonymous
//! (SOCKS5 0x00 / HTTP without credentials, only when
//! `ServerOptions::allow_anonymous`, default off). [`accept`] serves
//! anonymous-only hosts; `accept_with`/`accept_secure` (feature
//! `secure-auth`) run the full negotiation and parse only — the host sends
//! [`Reply::Established`] after egress is ready. Destinations remain
//! unresolved: this module never dials, resolves DNS, selects a route, or
//! grants a direct-routing privilege.

use std::fmt;
use std::future::Future;
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::{timeout, Instant};

use crate::connect::HostPort;

const MAX_HEADER_BYTES: usize = 16 * 1024;

mod reply;

pub use reply::Reply;

use reply::{http_error, reply_bytes};

mod prefixed;

pub use prefixed::Prefixed;

#[cfg(feature = "secure-auth")]
mod http_rounds;
#[cfg(feature = "secure-auth")]
mod secure;
mod strict_http;
#[cfg(feature = "secure-auth")]
pub use secure::{accept_secure, accept_with, AuthMethods, NoSecrets};

/// The host-supplied absolute deadline and the admission policy.
///
/// `allow_anonymous` is OFF by default and `allow_cleartext` is ON by
/// default; users exist exactly when an `AuthMethods`
/// is handed to `accept_with`/`accept_secure`.
#[derive(Debug, Clone, Copy)]
pub struct ServerOptions {
    deadline: Instant,
    anonymous: bool,
    #[cfg_attr(not(feature = "secure-auth"), allow(dead_code))]
    cleartext: bool,
    strict_http: bool,
}

impl ServerOptions {
    /// Use one absolute deadline for detection, framing, and authentication
    /// (all HTTP authentication rounds included). A past deadline refuses to
    /// poll the stream or the authentication exchange. Anonymous access and
    /// clear text start at their defaults (`allow_anonymous` off,
    /// `allow_cleartext` on).
    pub fn new(deadline: Instant) -> Self {
        Self {
            deadline,
            anonymous: false,
            cleartext: true,
            strict_http: false,
        }
    }

    /// Allow or refuse anonymous clients (SOCKS5 method 0x00, HTTP without
    /// credentials). Default off.
    #[must_use]
    pub fn allow_anonymous(mut self, allow: bool) -> Self {
        self.anonymous = allow;
        self
    }

    /// Allow or refuse clear-text authentication (SOCKS5 0x02, HTTP Basic).
    /// Default on; it only matters when users are configured (an
    /// `AuthMethods` was given) and is ignored otherwise.
    #[must_use]
    pub fn allow_cleartext(mut self, allow: bool) -> Self {
        self.cleartext = allow;
        self
    }

    /// Convenience for the strongest mode: refuse clear text AND anonymous
    /// access, so only secure auth (SOCKS5 method 0x80 / HTTP
    /// `Resocks5-Secure`) is ever accepted. With the feature-less [`accept`]
    /// (no users configured) a `secure_only` server accepts nobody.
    #[must_use]
    pub fn secure_only(mut self) -> Self {
        self.anonymous = false;
        self.cleartext = false;
        self
    }

    /// Default off. When on, the HTTP CONNECT request is validated against
    /// RFC 9112; violations are answered with the HTTP status below and
    /// `ServerError::Protocol`.
    #[must_use]
    pub fn strict_http(mut self, strict: bool) -> Self {
        self.strict_http = strict;
        self
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

/// How an inbound client authenticated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum AuthMethod {
    /// No authentication (SOCKS5 method 0x00, or HTTP without credentials).
    /// [`IncomingRequest::username`] is `None`.
    Anonymous,
    /// Clear-text password authentication (SOCKS5 0x02, HTTP Basic),
    /// verified against the user's stored secret.
    #[cfg(feature = "secure-auth")]
    Cleartext,
    /// Secure auth (SOCKS5 method 0x80, HTTP `Resocks5-Secure`).
    #[cfg(feature = "secure-auth")]
    Secure,
}

/// The authenticated identity of a request: how it authenticated and as whom.
pub(crate) enum Who {
    /// Anonymous admission (the host's `allow_anonymous` policy).
    Anonymous,
    /// Clear text (SOCKS5 0x02 / HTTP Basic), verified via
    /// `SecretStore::check_password`.
    #[cfg(feature = "secure-auth")]
    Cleartext(String),
    /// Secure auth (SOCKS5 0x80 / HTTP `Resocks5-Secure`).
    #[cfg(feature = "secure-auth")]
    Secure(String),
}

impl Who {
    fn method(&self) -> AuthMethod {
        match self {
            Who::Anonymous => AuthMethod::Anonymous,
            #[cfg(feature = "secure-auth")]
            Who::Cleartext(_) => AuthMethod::Cleartext,
            #[cfg(feature = "secure-auth")]
            Who::Secure(_) => AuthMethod::Secure,
        }
    }
    /// Moves the verified name out; anonymous is `None`.
    fn username(self) -> Option<String> {
        match self {
            Who::Anonymous => None,
            #[cfg(feature = "secure-auth")]
            Who::Cleartext(name) | Who::Secure(name) => Some(name),
        }
    }
}

/// An authenticated, unresolved request and the exact payload already consumed.
pub struct IncomingRequest {
    protocol: Protocol,
    target: String,
    auth: AuthMethod,
    username: Option<String>,
    auth_info: Option<String>,
    pipeline: Vec<u8>,
}

impl fmt::Debug for IncomingRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IncomingRequest")
            .field("protocol", &self.protocol)
            .field("target", &self.target)
            .field("auth", &self.auth)
            .field("has_username", &self.username.is_some())
            .field("pipeline_len", &self.pipeline.len())
            .finish_non_exhaustive()
    }
}

impl IncomingRequest {
    /// An authenticated/anonymous HTTP CONNECT request.
    #[cfg(feature = "secure-auth")]
    pub(crate) fn http(
        target: String,
        who: Who,
        auth_info: Option<String>,
        pipeline: Vec<u8>,
    ) -> Self {
        Self {
            protocol: Protocol::Http,
            target,
            auth: who.method(),
            username: who.username(),
            auth_info,
            pipeline,
        }
    }

    /// An anonymous HTTP CONNECT request (feature-less `accept`).
    pub(crate) fn http_anonymous(target: String, pipeline: Vec<u8>) -> Self {
        Self {
            protocol: Protocol::Http,
            target,
            auth: AuthMethod::Anonymous,
            username: None,
            auth_info: None,
            pipeline,
        }
    }

    /// Detected protocol, used to encode host replies.
    pub fn protocol(&self) -> Protocol {
        self.protocol
    }
    /// Unresolved authority. HTTP spelling is preserved; SOCKS IPs are canonical.
    pub fn target(&self) -> &str {
        &self.target
    }
    /// How the client authenticated.
    pub fn auth_method(&self) -> AuthMethod {
        self.auth
    }
    /// Verified username (`None` only for anonymous admission).
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
    /// Replace the authenticated identity with `name`, so that everything
    /// downstream sees the chosen account name. `auth_method()` is unchanged.
    pub fn set_identity(&mut self, name: String) {
        #[cfg(feature = "zeroize")]
        zeroize::Zeroize::zeroize(&mut self.username);
        self.username = Some(name);
    }
    /// Moves the verified username out; afterwards `username()` is `None`.
    /// Anonymous: `None`.
    pub fn take_username(&mut self) -> Option<String> {
        self.username.take()
    }
    /// Write and flush the host's tunnel outcome. Call once, before forwarding payload.
    /// Never send another protocol reply after early success.
    ///
    /// Over HTTP, when this request completed a `Resocks5-Secure` exchange,
    /// the `200` carries the server's last authentication token as
    /// `Proxy-Authenticate`, which a mutually authenticating client checks.
    ///
    /// cancel-safe: NO — a partial reply is terminal; discard the stream on
    /// cancellation or error. This operation has no implicit timeout: the host
    /// supplies the ordinary egress or early-recovery response budget.
    pub async fn reply<S: AsyncWrite + Unpin>(
        &self,
        stream: &mut S,
        reply: Reply,
    ) -> Result<(), ServerError> {
        if let (Protocol::Http, Reply::Established, Some(info)) =
            (self.protocol, reply, &self.auth_info)
        {
            let head = format!(
                "HTTP/1.1 200 Connection Established\r\nProxy-Authenticate: {info}\r\n\r\n"
            );
            stream.write_all(head.as_bytes()).await?;
            return stream.flush().await.map_err(ServerError::Io);
        }
        let bytes = reply_bytes(self.protocol, reply);
        stream.write_all(bytes).await?;
        stream.flush().await.map_err(ServerError::Io)
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

/// Detect and parse one inbound request from an anonymous client.
///
/// `0x05` selects SOCKS5; an ASCII letter selects HTTP; other bytes fail.
/// This entry point serves anonymous clients only, and only when `options`
/// allow them: the SOCKS5 greeting answers method 0x00 and nothing else, and
/// a request carrying `Proxy-Authorization` is answered with a bare `407`
/// (`Connection: close`) — no scheme is enabled here. Users authenticate
/// through `accept_with`/`accept_secure` (feature `secure-auth`), which run
/// the full negotiation. No DNS, egress, final success reply, or application
/// routing occurs here. Completed handshake and error replies are flushed
/// within the same absolute deadline before reading the next frame or
/// returning.
///
/// cancel-safe: NO — partial reads/writes and owned prefixes cannot be resumed.
/// On timeout, error, or cancellation the host MUST discard the stream, including
/// any buffered wrapper. An expired deadline is checked before polling any phase.
/// Live deadlines use Tokio timeout semantics, not synchronous preemption.
/// Futures are `Send` when the stream is `Send`.
pub async fn accept<S>(
    stream: &mut S,
    options: &ServerOptions,
) -> Result<IncomingRequest, ServerError>
where
    S: AsyncRead + AsyncWrite + Unpin,
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
        5 => phase(options.deadline, socks_anonymous(stream, options)).await,
        b if b.is_ascii_alphabetic() => {
            phase(options.deadline, http_anonymous(stream, b, options)).await
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

/// cancel-safe: NO — exact reads and replies may be partial. The host discards
/// the stream.
async fn socks_anonymous<S>(
    stream: &mut S,
    options: &ServerOptions,
) -> Result<IncomingRequest, ServerError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let nmethods = stream.read_u8().await?;
    let mut methods = vec![0; usize::from(nmethods)];
    stream.read_exact(&mut methods).await?;
    // Anonymous-only entry point: only "no authentication" is available.
    let chosen = options.anonymous && methods.contains(&0);
    if !chosen {
        stream.write_all(&[5, 255]).await?;
        stream.flush().await?;
        return Err(ServerError::Authentication(format!(
            "No mutually supported SOCKS5 auth method (server: anonymous={}; client offered {} method(s))",
            options.anonymous,
            methods.len()
        )));
    }
    stream.write_all(&[5, 0]).await?;
    stream.flush().await?;
    socks_request(stream, Who::Anonymous).await
}

/// cancel-safe: NO — exact reads and replies may be partial.
async fn http_anonymous<S>(
    stream: &mut S,
    first: u8,
    options: &ServerOptions,
) -> Result<IncomingRequest, ServerError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let request = read_http_request(stream, Some(first), options).await?;
    if request.authorization.is_some() {
        return http_fail(
            stream,
            407,
            ServerError::Authentication(
                "credentials are not accepted: no authentication scheme is enabled on this server"
                    .into(),
            ),
        )
        .await;
    }
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
    Ok(IncomingRequest::http_anonymous(
        request.target,
        request.pipeline,
    ))
}

/// The SOCKS5 request after authentication: `CONNECT` and its target.
///
/// cancel-safe: NO — exact reads and replies may be partial.
pub(super) async fn socks_request<S>(
    stream: &mut S,
    who: Who,
) -> Result<IncomingRequest, ServerError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut header = [0; 4];
    stream.read_exact(&mut header).await?;
    if header[0] != 5 {
        return Err(ServerError::Protocol(
            "Invalid version in CONNECT request".into(),
        ));
    }
    if header[1] != 1 {
        // RFC 1928 section 6: command not supported, unspecified IPv4 bind address.
        stream.write_all(&[5, 7, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
        stream.flush().await?;
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
            // Deliberately permissive: `@`, `/`, `%` pass; only control or
            // whitespace bytes and the host:port shape are rejected (strict
            // HTTP mode is the stricter grammar).
            if domain.is_empty()
                || domain
                    .bytes()
                    .any(|b| b.is_ascii_control() || b.is_ascii_whitespace())
                || HostPort::parse(&target).is_none()
            {
                stream.write_all(&[5, 4, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
                stream.flush().await?;
                return Err(ServerError::Protocol(format!(
                    "Invalid DOMAINNAME in CONNECT request: {domain:?}"
                )));
            }
            target
        }
        atyp => {
            // RFC 1928 section 6: address type not supported.
            stream.write_all(&[5, 8, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
            stream.flush().await?;
            return Err(ServerError::Protocol(format!("Unknown ATYP: {atyp:02x}")));
        }
    };
    Ok(IncomingRequest {
        protocol: Protocol::Socks5,
        target,
        auth: who.method(),
        username: who.username(),
        auth_info: None,
        pipeline: Vec::new(),
    })
}

async fn http_fail<T, S: AsyncWrite + Unpin>(
    stream: &mut S,
    status: u16,
    error: ServerError,
) -> Result<T, ServerError> {
    stream.write_all(http_error(status)).await?;
    stream.flush().await?;
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

/// One parsed HTTP CONNECT request: its target, its `Proxy-Authorization`
/// value and the bytes read past its header block.
pub(super) struct HttpRequest {
    pub(super) target: String,
    pub(super) authorization: Option<String>,
    pub(super) pipeline: Vec<u8>,
}

/// Read and validate one CONNECT request head; `first` is its first byte
/// when detection already consumed it. Malformed requests are answered
/// (400, 431, 501, 505) and fail; authentication is the caller's.
///
/// cancel-safe: NO — consumed header/pipeline bytes are future-owned and
/// replies may be partial.
pub(super) async fn read_http_request<S>(
    stream: &mut S,
    first: Option<u8>,
    options: &ServerOptions,
) -> Result<HttpRequest, ServerError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut buf = Vec::with_capacity(2048);
    buf.extend(first);
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
    let header_lines: Vec<&[u8]> = lines.collect();
    if options.strict_http {
        if let Err(violation) = strict_http::validate(request_line, &header_lines) {
            let (status, reason) = match violation {
                strict_http::StrictViolation::Bad(reason) => (400u16, reason),
                strict_http::StrictViolation::Unsupported => {
                    (505u16, "strict HTTP: unsupported HTTP-version")
                }
            };
            return http_fail(stream, status, ServerError::Protocol(reason.into())).await;
        }
    }
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
    // Permissive target grammar: `HostPort::parse` accepts `@`, `/`, `%` in
    // the host; strict_http applies the stricter RFC grammar.
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
    let mut authorization = None;
    for line in header_lines {
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
        authorization = Some(value.to_owned());
        break;
    }
    Ok(HttpRequest {
        target: target.to_owned(),
        authorization,
        pipeline,
    })
}

#[cfg(feature = "zeroize")]
impl IncomingRequest {
    /// Overwrite the retained user name and authentication info in place; the
    /// pipeline is payload and stays.
    fn wipe(&mut self) {
        if let Some(username) = &mut self.username {
            zeroize::Zeroize::zeroize(username);
        }
        if let Some(auth_info) = &mut self.auth_info {
            zeroize::Zeroize::zeroize(auth_info);
        }
    }
}

#[cfg(feature = "zeroize")]
impl Drop for IncomingRequest {
    fn drop(&mut self) {
        self.wipe();
    }
}

#[cfg(test)]
mod tests;
