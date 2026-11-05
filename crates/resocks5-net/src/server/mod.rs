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

mod credentials;

pub use credentials::Credentials;

mod reply;

pub use reply::Reply;

use reply::{http_error, reply_bytes};

mod prefixed;

pub use prefixed::Prefixed;

#[cfg(feature = "secure-auth")]
mod secure;
mod strict_http;
#[cfg(feature = "secure-auth")]
pub use secure::{accept_secure, accept_with, AuthMethods, NoSecrets};

/// Independent authentication capabilities and the host-supplied absolute deadline.
///
/// Password capability means configured users exist, not that any particular user
/// is enabled. The closure remains responsible for verification and persistence.
#[derive(Debug, Clone, Copy)]
pub struct ServerOptions {
    deadline: Instant,
    anonymous: bool,
    password: bool,
    retain_credentials: bool,
    raw_credentials: bool,
    strict_http: bool,
}

impl ServerOptions {
    /// Use one absolute deadline for detection, framing, and authentication.
    /// A past deadline refuses to poll the stream or authentication closure.
    pub fn new(deadline: Instant, allow_anonymous: bool, allow_password: bool) -> Self {
        Self {
            deadline,
            anonymous: allow_anonymous,
            password: allow_password,
            retain_credentials: false,
            raw_credentials: false,
            strict_http: false,
        }
    }

    /// Default off. When on, `accept` keeps a copy of the verified credentials in the returned request.
    pub fn retain_credentials(mut self, retain: bool) -> Self {
        self.retain_credentials = retain;
        self
    }

    /// Default off. When on, SOCKS5 UNAME/PASSWD that are not valid UTF-8 are
    /// accepted and exposed as raw bytes (`Credentials::username_bytes`). The
    /// RFC 1929 1..255 length limits still apply. HTTP Basic is unchanged: a
    /// non-UTF-8 `Proxy-Authorization` payload is still a 407 regardless of
    /// this flag.
    pub fn raw_credentials(mut self, raw: bool) -> Self {
        self.raw_credentials = raw;
        self
    }

    /// Default off. When on, the HTTP CONNECT request is validated against
    /// RFC 9112; violations are answered with the HTTP status below and
    /// `ServerError::Protocol`.
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
    Anonymous,
    /// A clear-text password (SOCKS5 0x02, HTTP Basic); only with
    /// `cleartext-server`.
    ClearText,
    /// Secure auth (SOCKS5 method 0x80): `username()` is the user name.
    Secure,
    /// GSSAPI (SOCKS5 method 0x01): `username()` is the authenticated
    /// principal (for Kerberos, `name@REALM`).
    Gssapi,
}

/// An authenticated, unresolved request and the exact payload already consumed.
pub struct IncomingRequest {
    protocol: Protocol,
    target: String,
    auth: AuthMethod,
    /// The GSSAPI session whose protection the SOCKS reply travels under.
    #[cfg(feature = "gssapi")]
    gss: Option<std::sync::Mutex<crate::gssapi::GssSession>>,
    username: Option<String>,
    username_raw: Option<Vec<u8>>,
    credentials: Option<Credentials>,
    pipeline: Vec<u8>,
}

impl fmt::Debug for IncomingRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IncomingRequest")
            .field("protocol", &self.protocol)
            .field("target", &self.target)
            .field("auth", &self.auth)
            .field("has_username", &self.username.is_some())
            .field("has_credentials", &self.credentials.is_some())
            .field("pipeline_len", &self.pipeline.len())
            .finish()
    }
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
    /// How the client authenticated.
    pub fn auth_method(&self) -> AuthMethod {
        self.auth
    }

    /// Record how the client authenticated (and, for GSSAPI, the session the
    /// reply is protected under).
    #[cfg(feature = "secure-auth")]
    pub(crate) fn authenticated_with(
        mut self,
        auth: AuthMethod,
        #[cfg(feature = "gssapi")] gss: Option<crate::gssapi::GssSession>,
    ) -> Self {
        self.auth = auth;
        #[cfg(feature = "gssapi")]
        {
            self.gss = gss.map(std::sync::Mutex::new);
        }
        self
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

    /// Retained credentials, if `retain_credentials(true)` was set and password auth
    /// ran; hands ownership to the caller. Second call: `None`.
    pub fn take_credentials(&mut self) -> Option<Credentials> {
        self.credentials.take()
    }

    /// Moves the verified username out; afterwards `username()` is `None`. Independent
    /// of retained credentials (they keep their own copy until taken or dropped).
    /// Anonymous: `None`.
    pub fn take_username(&mut self) -> Option<String> {
        let taken = self.username.take();
        discard_wiped(&mut self.username_raw);
        taken
    }

    /// Exact verified identity bytes; `None` for anonymous or after
    /// [`Self::take_username`]. For a non-UTF-8 UNAME these are the raw
    /// submitted bytes (the `username()` text is then lossy).
    pub fn username_bytes(&self) -> Option<&[u8]> {
        self.username
            .as_ref()
            .map(|username| self.username_raw.as_deref().unwrap_or(username.as_bytes()))
    }
    /// Write and flush the host's tunnel outcome. Call once, before forwarding payload.
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
        let bytes = reply_bytes(self.protocol, reply);
        #[cfg(feature = "gssapi")]
        if let Some(gss) = &self.gss {
            let framed = gss
                .lock()
                .expect("gss session lock")
                .seal(bytes)
                .map_err(|error| ServerError::Protocol(error.to_string()))?;
            stream.write_all(&framed).await?;
            return stream.flush().await.map_err(ServerError::Io);
        }
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

/// Detect and parse one inbound request, authenticating through an owned-credentials closure.
///
/// `0x05` selects SOCKS5; an ASCII letter selects HTTP; other bytes fail.
/// SOCKS prefers password authentication when both methods are available.
/// HTTP verifies supplied credentials even when anonymous access is allowed;
/// supplied credentials fail when password capability is disabled.
/// No DNS, egress, final success reply, or application routing occurs here.
/// Completed handshake and error replies are flushed within the same absolute
/// deadline before reading the next frame or returning.
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

/// Raw-mode decode of one submitted credential field: the lossy text plus the
/// exact bytes when they were not valid UTF-8. Consumes the buffer — the
/// valid-UTF-8 path converts the allocation in place, the invalid path
/// recovers the bytes from the decode error instead of cloning.
fn decode_raw_field(raw: Vec<u8>) -> (String, Option<Vec<u8>>) {
    match String::from_utf8(raw) {
        Ok(text) => (text, None),
        Err(error) => {
            let bytes = error.into_bytes();
            let lossy = String::from_utf8_lossy(&bytes).into_owned();
            (lossy, Some(bytes))
        }
    }
}

/// Consume a rejected credential buffer; wiped before it is freed under
/// feature `zeroize`, a plain drop otherwise.
#[cfg(feature = "zeroize")]
fn drop_secret<T: zeroize::Zeroize>(secret: T) {
    let mut secret = secret;
    zeroize::Zeroize::zeroize(&mut secret);
}

#[cfg(not(feature = "zeroize"))]
fn drop_secret<T>(_: T) {}

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
    // Method 0x02 (RFC 1929) carries the password in clear text: offered only
    // by a build with `cleartext-server`.
    let password_offered = crate::CLEARTEXT_SERVER && options.password;
    let chosen = if password_offered && methods.contains(&2) {
        2
    } else if options.anonymous && methods.contains(&0) {
        0
    } else {
        stream.write_all(&[5, 255]).await?;
        stream.flush().await?;
        return Err(ServerError::Authentication(format!("No mutually supported SOCKS5 auth method (server: anonymous={}, user/pass={}; client offered {} method(s))", options.anonymous, password_offered, methods.len())));
    };
    stream.write_all(&[5, chosen]).await?;
    stream.flush().await?;
    let mut retained = None;
    let (username, username_raw) = if chosen == 2 {
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
        let (username, username_raw) = if options.raw_credentials {
            decode_raw_field(user)
        } else {
            match String::from_utf8(user) {
                Ok(text) => (text, None),
                Err(error) => {
                    drop_secret(error.into_bytes());
                    return auth_fail(stream, "Invalid UTF-8 in username").await;
                }
            }
        };
        let (password, password_raw) = if options.raw_credentials {
            decode_raw_field(password)
        } else {
            match String::from_utf8(password) {
                Ok(text) => (text, None),
                Err(error) => {
                    drop_secret(error.into_bytes());
                    return auth_fail(stream, "Invalid UTF-8 in password").await;
                }
            }
        };
        let credentials = Credentials::with_raw(
            username.clone(),
            password,
            username_raw.clone(),
            password_raw,
        );
        retained = options.retain_credentials.then(|| credentials.duplicate());
        if !authenticate(credentials).await {
            stream.write_all(AUTH_FAILURE).await?;
            stream.flush().await?;
            return Err(ServerError::Authentication(
                "SOCKS5 username/password authentication failed".into(),
            ));
        }
        stream.write_all(&[1, 0]).await?;
        stream.flush().await?;
        (Some(username), username_raw)
    } else {
        (None, None)
    };
    socks_request(stream, username, username_raw, retained).await
}

/// The SOCKS5 request after authentication: `CONNECT` and its target.
///
/// cancel-safe: NO — exact reads and replies may be partial.
pub(super) async fn socks_request<S>(
    stream: &mut S,
    username: Option<String>,
    username_raw: Option<Vec<u8>>,
    retained: Option<Credentials>,
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
        auth: if username.is_some() {
            AuthMethod::ClearText
        } else {
            AuthMethod::Anonymous
        },
        #[cfg(feature = "gssapi")]
        gss: None,
        username,
        username_raw,
        credentials: retained,
        pipeline: Vec::new(),
    })
}

async fn auth_fail<T, S: AsyncWrite + Unpin>(
    stream: &mut S,
    message: &str,
) -> Result<T, ServerError> {
    stream.write_all(AUTH_FAILURE).await?;
    stream.flush().await?;
    Err(ServerError::Authentication(message.into()))
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
    let mut retained = None;
    let mut auth_value = None;
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
        auth_value = Some(value);
        break;
    }
    let username = match auth_value {
        Some(value) => {
            // Only a single SP separates scheme and token (RFC 9110 section
            // 11): a TAB stays inside the scheme token, which then never
            // matches Basic — 407, intentionally.
            let mut parts = value.splitn(2, ' ');
            let scheme = parts.next().unwrap_or("");
            let token = parts.next().map(str::trim);
            if !crate::CLEARTEXT_SERVER && scheme.eq_ignore_ascii_case("Basic") {
                // HTTP Basic is the password in (base64) clear text.
                return http_fail(
                    stream,
                    407,
                    ServerError::Authentication(
                        "clear-text credentials (HTTP Basic) are not accepted".into(),
                    ),
                )
                .await;
            }
            let Some(token) = token.filter(|_| scheme.eq_ignore_ascii_case("Basic")) else {
                return http_fail(
                    stream,
                    407,
                    ServerError::Authentication("unsupported Proxy-Authorization scheme".into()),
                )
                .await;
            };
            // Canonical STANDARD base64 requires padding: an unpadded token
            // fails the decode and answers 407, intentionally.
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
            let credentials = Credentials::with_basic_payload(
                identity.clone(),
                password.to_owned(),
                text.to_owned(),
            );
            retained = options.retain_credentials.then(|| credentials.duplicate());
            if !authenticate(credentials).await {
                return http_fail(
                    stream,
                    407,
                    ServerError::Authentication("HTTP proxy authentication failed".into()),
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
        auth: if username.is_some() {
            AuthMethod::ClearText
        } else {
            AuthMethod::Anonymous
        },
        #[cfg(feature = "gssapi")]
        gss: None,
        username,
        username_raw: None,
        credentials: retained,
        pipeline,
    })
}

/// Drop the value held by `slot`, wiping it in place first: the struct's
/// `Drop`-based wipe never sees a value already taken out, so under
/// `zeroize` the buffer is overwritten BEFORE it is freed.
#[cfg(feature = "zeroize")]
fn discard_wiped<T: zeroize::Zeroize>(slot: &mut Option<T>) {
    if let Some(value) = slot.as_mut() {
        zeroize::Zeroize::zeroize(value);
    }
    slot.take();
}

/// Without `zeroize` this is a plain take-and-drop; behaviour is unchanged.
#[cfg(not(feature = "zeroize"))]
fn discard_wiped<T>(slot: &mut Option<T>) {
    slot.take();
}

#[cfg(feature = "zeroize")]
impl IncomingRequest {
    /// Overwrite retained secret material in place; the pipeline is payload and stays.
    pub(crate) fn wipe(&mut self) {
        if let Some(username) = &mut self.username {
            zeroize::Zeroize::zeroize(username);
        }
        if let Some(raw) = &mut self.username_raw {
            zeroize::Zeroize::zeroize(raw);
        }
        if let Some(credentials) = &mut self.credentials {
            credentials.wipe();
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
