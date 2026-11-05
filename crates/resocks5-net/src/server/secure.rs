//! Inbound SOCKS5/HTTP with strong authentication only: secure auth (SOCKS5
//! method 0x80) and GSSAPI (method 0x01, feature `gssapi`), never a clear-text
//! password (feature `secure-auth`).

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use super::{http, phase, socks_request, AuthMethod, IncomingRequest, ServerError, ServerOptions};
use crate::secure_auth::{server_authenticate, DecoyKey, SecretStore, StoredUser, UserSecret};
use crate::SecureAuthError;

/// The strong methods a server accepts. When a client offers several, the
/// server picks the strongest it has enabled: GSSAPI, then secure auth, then
/// (if `options` allow anonymous clients) no authentication.
pub struct AuthMethods<'a, T: SecretStore> {
    secure: Option<(&'a T, &'a DecoyKey)>,
    #[cfg(feature = "gssapi")]
    gssapi: Option<&'a crate::gssapi::GssAcceptor>,
}

/// A [`SecretStore`] with no users, for a server that only offers GSSAPI.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoSecrets;

impl SecretStore for NoSecrets {
    async fn lookup(&self, _user: &str) -> Option<StoredUser> {
        None
    }

    async fn claim(&self, _user: &str, _secret: UserSecret) -> bool {
        false
    }
}

impl<'a, T: SecretStore> AuthMethods<'a, T> {
    /// Secure auth only: users from `store`, `decoy` for unknown names.
    pub fn secure(store: &'a T, decoy: &'a DecoyKey) -> Self {
        Self {
            secure: Some((store, decoy)),
            #[cfg(feature = "gssapi")]
            gssapi: None,
        }
    }

    /// GSSAPI only (no secure auth); `T` is usually [`NoSecrets`].
    #[cfg(feature = "gssapi")]
    pub fn gssapi(acceptor: &'a crate::gssapi::GssAcceptor) -> Self {
        Self {
            secure: None,
            gssapi: Some(acceptor),
        }
    }

    /// Also accept GSSAPI; it is preferred over secure auth.
    #[cfg(feature = "gssapi")]
    #[must_use]
    pub fn with_gssapi(mut self, acceptor: &'a crate::gssapi::GssAcceptor) -> Self {
        self.gssapi = Some(acceptor);
        self
    }

    #[cfg(feature = "gssapi")]
    fn has_gssapi(&self) -> bool {
        self.gssapi.is_some()
    }

    #[cfg(not(feature = "gssapi"))]
    fn has_gssapi(&self) -> bool {
        false
    }
}

/// Like [`accept`](super::accept), but users authenticate with secure auth
/// (SOCKS5 method 0x80, see [`secure_auth`](crate::secure_auth)): the password
/// never crosses the wire and the server only holds the stored secret from
/// `store`. No clear-text password is ever offered or accepted, whatever the
/// build: SOCKS5 offers 0x80 (when `options` allow passwords) and 0x00 (when
/// they allow anonymous clients), never 0x02; an HTTP request carrying
/// `Proxy-Authorization` is answered 407, and one without it is served only to
/// an anonymous-capable host. `decoy` answers unknown user names.
///
/// The returned request carries the authenticated user name (`username()`);
/// no credentials are retained. For GSSAPI as well, see [`accept_with`].
///
/// # Errors
///
/// As [`accept`](super::accept); a failed secure-auth exchange is
/// `ServerError::Authentication` with a fixed text (no user name).
///
/// cancel-safe: NO — consumed bytes and partial replies are future-owned; the
/// host discards the stream.
pub async fn accept_secure<S, T>(
    stream: &mut S,
    options: &ServerOptions,
    store: &T,
    decoy: &DecoyKey,
) -> Result<IncomingRequest, ServerError>
where
    S: AsyncRead + AsyncWrite + Unpin,
    T: SecretStore,
{
    accept_with(stream, options, &AuthMethods::secure(store, decoy)).await
}

/// [`accept_secure`] over a chosen set of strong methods: the server adapts to
/// what the client offers and picks the strongest enabled one (GSSAPI >
/// secure auth > anonymous). `request.auth_method()` tells which one ran; with
/// GSSAPI `username()` is the authenticated principal and the SOCKS reply is
/// protected under the negotiated context (use [`IncomingRequest::reply`]).
///
/// # Errors
///
/// As [`accept_secure`].
///
/// cancel-safe: NO — consumed bytes and partial replies are future-owned; the
/// host discards the stream.
pub async fn accept_with<S, T>(
    stream: &mut S,
    options: &ServerOptions,
    methods: &AuthMethods<'_, T>,
) -> Result<IncomingRequest, ServerError>
where
    S: AsyncRead + AsyncWrite + Unpin,
    T: SecretStore,
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
        5 => phase(options.deadline, socks_strong(stream, options, methods)).await,
        b if b.is_ascii_alphabetic() => {
            // HTTP has no strong method here: a password-capable host must not
            // see Basic at all, so the HTTP side runs as "no users configured"
            // (any Proxy-Authorization is a 407, the callback never runs).
            let http_options = ServerOptions {
                password: false,
                retain_credentials: false,
                ..*options
            };
            phase(
                options.deadline,
                http(stream, b, &http_options, |_| async { false }),
            )
            .await
        }
        other => Err(ServerError::Protocol(format!(
            "unrecognised first byte {other:#04x} — neither SOCKS5 (0x05) nor an HTTP method"
        ))),
    }
}

fn auth_error(error: SecureAuthError) -> ServerError {
    match error {
        SecureAuthError::Io(kind) => ServerError::Io(std::io::Error::from(kind)),
        other => ServerError::Authentication(other.to_string()),
    }
}

/// The in-memory stand-in the protected SOCKS request is parsed from and its
/// error replies are collected into.
#[cfg(feature = "gssapi")]
struct Memory {
    input: std::io::Cursor<Vec<u8>>,
    output: Vec<u8>,
}

#[cfg(feature = "gssapi")]
impl AsyncRead for Memory {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.input).poll_read(cx, buf)
    }
}

#[cfg(feature = "gssapi")]
impl AsyncWrite for Memory {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        self.output.extend_from_slice(buf);
        std::task::Poll::Ready(Ok(buf.len()))
    }
    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }
    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }
}

/// cancel-safe: NO — exact reads and replies may be partial.
async fn socks_strong<S, T>(
    stream: &mut S,
    options: &ServerOptions,
    methods: &AuthMethods<'_, T>,
) -> Result<IncomingRequest, ServerError>
where
    S: AsyncRead + AsyncWrite + Unpin,
    T: SecretStore,
{
    let nmethods = stream.read_u8().await?;
    let mut offered = vec![0; usize::from(nmethods)];
    stream.read_exact(&mut offered).await?;
    let strong = options.password;
    // The strongest method both sides have, in the server's order.
    let chosen = if strong && methods.has_gssapi() && offered.contains(&0x01) {
        0x01
    } else if strong && methods.secure.is_some() && offered.contains(&crate::secure_auth::METHOD) {
        crate::secure_auth::METHOD
    } else if options.anonymous && offered.contains(&0) {
        0
    } else {
        stream.write_all(&[5, 255]).await?;
        stream.flush().await?;
        return Err(ServerError::Authentication(format!(
            "No mutually supported SOCKS5 auth method (server: anonymous={}, strong={}; client offered {} method(s))",
            options.anonymous,
            strong,
            offered.len()
        )));
    };
    stream.write_all(&[5, chosen]).await?;
    stream.flush().await?;
    #[cfg(feature = "gssapi")]
    if chosen == crate::gssapi::METHOD {
        let acceptor = methods.gssapi.expect("chosen only when enabled");
        return socks_gssapi(stream, acceptor).await;
    }
    if chosen == crate::secure_auth::METHOD {
        let (store, decoy) = methods.secure.expect("chosen only when enabled");
        let user = server_authenticate(stream, store, decoy)
            .await
            .map_err(auth_error)?;
        let request = socks_request(stream, Some(user), None, None).await?;
        return Ok(authenticated(request, AuthMethod::Secure));
    }
    socks_request(stream, None, None, None).await
}

#[cfg(feature = "gssapi")]
fn authenticated(request: IncomingRequest, method: AuthMethod) -> IncomingRequest {
    request.authenticated_with(method, None)
}

#[cfg(not(feature = "gssapi"))]
fn authenticated(request: IncomingRequest, method: AuthMethod) -> IncomingRequest {
    request.authenticated_with(method)
}

/// GSSAPI: establish the context, then take the SOCKS request from one
/// protected message; error replies and the final reply go back protected.
#[cfg(feature = "gssapi")]
async fn socks_gssapi<S>(
    stream: &mut S,
    acceptor: &crate::gssapi::GssAcceptor,
) -> Result<IncomingRequest, ServerError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let gss_error = |error: crate::GssapiError| match error {
        crate::GssapiError::Io(kind) => ServerError::Io(std::io::Error::from(kind)),
        other => ServerError::Authentication(other.to_string()),
    };
    let (mut session, principal) = crate::gssapi::server_gssapi(stream, acceptor)
        .await
        .map_err(gss_error)?;
    let request = session.read_message(stream).await.map_err(gss_error)?;
    let mut memory = Memory {
        input: std::io::Cursor::new(request),
        output: Vec::new(),
    };
    let parsed = socks_request(&mut memory, Some(principal), None, None).await;
    if !memory.output.is_empty() {
        // An error reply the request parser wrote: send it protected.
        let _ = session.write_message(stream, &memory.output).await;
    }
    Ok(parsed?.authenticated_with(AuthMethod::Gssapi, Some(session)))
}
