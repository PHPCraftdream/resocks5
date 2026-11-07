//! Inbound SOCKS5 and HTTP CONNECT framing, independent of application policy storage.
//!
//! Available without default features. Destinations remain unresolved: this module
//! never dials, resolves DNS, selects a route, or grants a direct-routing privilege.
//! [`accept`] (anonymous clients only) and, with feature `secure-auth`,
//! `accept_secure`/`accept_with` (strong authentication) parse only; the host
//! sends [`Reply::Established`] after egress is ready (or deliberately before a
//! host-owned recovery phase). No clear-text password is ever accepted: SOCKS5
//! method 0x02 is never offered and any HTTP `Proxy-Authorization` is a 407.

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
mod secure;
mod strict_http;
#[cfg(feature = "secure-auth")]
pub use secure::{accept_secure, accept_with, AuthMethods, NoSecrets};

/// Which clients the host admits and the host-supplied absolute deadline.
///
/// "Users" means configured accounts exist (they authenticate with a strong
/// method, see `accept_with`), not that any particular user is enabled.
#[derive(Debug, Clone, Copy)]
pub struct ServerOptions {
    deadline: Instant,
    anonymous: bool,
    #[cfg_attr(not(feature = "secure-auth"), allow(dead_code))]
    users: bool,
    strict_http: bool,
}

impl ServerOptions {
    /// Use one absolute deadline for detection, framing, and authentication.
    /// A past deadline refuses to poll the stream or the authentication exchange.
    /// `has_users` says that configured accounts exist: only `accept_with` and
    /// `accept_secure` let them in, with a strong method.
    pub fn new(deadline: Instant, allow_anonymous: bool, has_users: bool) -> Self {
        Self {
            deadline,
            anonymous: allow_anonymous,
            users: has_users,
            strict_http: false,
        }
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

    /// Verified username (the secure-auth user or the GSSAPI principal).
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
    /// Replace the authenticated identity: for a host that maps an
    /// authenticated GSSAPI principal (`name@REALM`) to a local account name,
    /// so that everything downstream sees the account. `auth_method()` is
    /// unchanged.
    pub fn set_identity(&mut self, name: String) {
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

/// Detect and parse one inbound request from an anonymous client.
///
/// `0x05` selects SOCKS5; an ASCII letter selects HTTP; other bytes fail.
/// Only anonymous clients are served, and only when `options` allow them: no
/// clear-text password is ever accepted (SOCKS5 method 0x02 is never offered, a
/// request carrying `Proxy-Authorization` is answered 407). Users authenticate
/// with a strong method through `accept_with`/`accept_secure` (feature
/// `secure-auth`). No DNS, egress, final success reply, or application routing
/// occurs here. Completed handshake and error replies are flushed within the same
/// absolute deadline before reading the next frame or returning.
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
        5 => phase(options.deadline, socks(stream, options)).await,
        b if b.is_ascii_alphabetic() => phase(options.deadline, http(stream, b, options)).await,
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
async fn socks<S>(stream: &mut S, options: &ServerOptions) -> Result<IncomingRequest, ServerError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let nmethods = stream.read_u8().await?;
    let mut methods = vec![0; usize::from(nmethods)];
    stream.read_exact(&mut methods).await?;
    // Only "no authentication": method 0x02 (RFC 1929) would carry a password
    // in clear text and is never offered.
    if !(options.anonymous && methods.contains(&0)) {
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
    socks_request(stream, None).await
}

/// The SOCKS5 request after authentication: `CONNECT` and its target.
///
/// cancel-safe: NO — exact reads and replies may be partial.
pub(super) async fn socks_request<S>(
    stream: &mut S,
    username: Option<String>,
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
            AuthMethod::Secure
        } else {
            AuthMethod::Anonymous
        },
        #[cfg(feature = "gssapi")]
        gss: None,
        username,
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

/// cancel-safe: NO — consumed header/pipeline bytes are future-owned and replies
/// may be partial; authentication side effects may survive stream disposal.
async fn http<S>(
    stream: &mut S,
    first: u8,
    options: &ServerOptions,
) -> Result<IncomingRequest, ServerError>
where
    S: AsyncRead + AsyncWrite + Unpin,
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
    // Over HTTP the only way in is "no credentials": a Proxy-Authorization
    // header, whatever its scheme, is a 407. Basic would be a password in
    // (base64) clear text; strong methods exist for SOCKS5 only.
    if let Some(value) = auth_value {
        // Only a single SP separates scheme and token (RFC 9110 section 11).
        let scheme = value.split(' ').next().unwrap_or("");
        let message = if scheme.eq_ignore_ascii_case("Basic") {
            "clear-text credentials (HTTP Basic) are not accepted"
        } else {
            "unsupported Proxy-Authorization scheme"
        };
        return http_fail(stream, 407, ServerError::Authentication(message.into())).await;
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
    Ok(IncomingRequest {
        protocol: Protocol::Http,
        target: target.to_owned(),
        auth: AuthMethod::Anonymous,
        #[cfg(feature = "gssapi")]
        gss: None,
        username: None,
        pipeline,
    })
}

#[cfg(feature = "zeroize")]
impl IncomingRequest {
    /// Overwrite the retained user name in place; the pipeline is payload and stays.
    pub(crate) fn wipe(&mut self) {
        if let Some(username) = &mut self.username {
            zeroize::Zeroize::zeroize(username);
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
