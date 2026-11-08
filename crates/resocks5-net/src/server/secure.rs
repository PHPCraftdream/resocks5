//! Inbound negotiation over the enabled methods: secure auth (SOCKS5 method
//! 0x80, HTTP `Resocks5-Secure`), clear text (SOCKS5 0x02, HTTP `Basic`,
//! verified against the same store via `check_password`), and anonymous —
//! the strongest enabled one wins (feature `secure-auth`).

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use super::{phase, socks_request, IncomingRequest, ServerError, ServerOptions, Who};
use crate::secure_auth::{
    server_authenticate, DecoyKey, PasswordCheck, SecretStore, StoredUser, UserSecret,
};
use crate::SecureAuthError;

/// RFC 1929 failure status: `ver=1, status=1`.
const AUTH_FAILURE: &[u8] = &[1, 1];

/// The methods a server accepts users with. `secure` enables the strong
/// method (SOCKS5 0x80 / HTTP `Resocks5-Secure`) AND clear text (SOCKS5 0x02
/// / HTTP `Basic`) against the same store: one stored `UserSecret` verifies
/// both, and clear text is additionally subject to
/// [`ServerOptions::allow_cleartext`]. When a client offers several methods
/// the server picks the strongest it has enabled, then anonymous access if
/// `options` allow it.
pub struct AuthMethods<'a, T: SecretStore> {
    pub(super) store: &'a T,
    /// `Some` enables the strong method; `None` leaves clear text only.
    pub(super) decoy: Option<&'a DecoyKey>,
}

/// A [`SecretStore`] with no users: every name is unknown, every login fails
/// like a wrong password while still costing one derivation. Implements
/// `check_password` through the default.
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
    /// Users from `store`, `decoy` answering unknown names; clear text is
    /// accepted against the same store while `options.allow_cleartext` is on.
    pub fn secure(store: &'a T, decoy: &'a DecoyKey) -> Self {
        Self {
            store,
            decoy: Some(decoy),
        }
    }

    /// Clear text only (SOCKS5 0x02 / HTTP Basic), checked by
    /// [`SecretStore::check_password`] of `store`; the strong method is not
    /// offered, so a client that lists 0x80 together with 0x02 is served with
    /// 0x02 and an HTTP `407` names only `Basic`. This is the mode for a host
    /// that verifies passwords itself (an overridden `check_password`) and
    /// keeps no `UserSecret` for [`SecretStore::lookup`] to return.
    /// [`ServerOptions::allow_cleartext`] still applies: with it off (and
    /// anonymous access off) nothing is acceptable.
    pub fn cleartext_only(store: &'a T) -> Self {
        Self { store, decoy: None }
    }
}

/// Like [`accept`](super::accept), but users authenticate with secure auth
/// AND clear text against `store` (see [`secure_auth`](crate::secure_auth)):
/// secure auth (SOCKS5 method 0x80, HTTP `Resocks5-Secure`) where the
/// password never crosses the wire, or RFC 1929 / HTTP Basic where it does
/// (while `options.allow_cleartext` is on); anonymous access per `options`.
/// `decoy` answers unknown user names.
///
/// The returned request carries the authenticated user name (`username()`);
/// no credentials are retained.
///
/// # Errors
///
/// As [`accept_with`].
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

/// Detect SOCKS5 or HTTP CONNECT on `stream` and authenticate the client
/// with the strongest method of `methods` it supports, subject to `options`:
///
/// - SOCKS5: secure auth (0x80) over clear text (0x02, only while
///   `allow_cleartext` is on) over anonymous (0x00, only while
///   `allow_anonymous` is on); a client offering none of them gets
///   `[5, 0xFF]`.
/// - HTTP CONNECT: a request without `Proxy-Authorization` is served when
///   `allow_anonymous` is on, else answered with a keep-alive `407` listing
///   the enabled schemes (`Resocks5-Secure`, then `Basic realm="resocks5"`
///   while `allow_cleartext` is on) so a standard client retries with
///   credentials on the same connection. The `Resocks5-Secure` exchange runs
///   one message per round over `407` rounds and its last token rides on the
///   `200`; `Basic` is verified against the same store. After `MAX_ROUNDS`,
///   an unsupported scheme or a failed check the answer is a `407` with
///   `Connection: close`.
///
/// `request.auth_method()` tells which method ran; `username()` is the user
/// (`None` only for anonymous admission). No DNS, egress or final success
/// reply happens here, and all of it runs under the absolute deadline of
/// `options`.
///
/// # Errors
///
/// `ServerError::Authentication` with a fixed text (no user name, no token,
/// no submitted password) for a refused or failed authentication; `Protocol`,
/// `HeaderTooLarge`, `Closed`, `Deadline` and `Io` as the framing goes.
///
/// cancel-safe: NO — consumed bytes and partial replies are future-owned; the
/// host discards the stream. Futures are `Send` when the stream is `Send`.
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
        5 => phase(options.deadline, socks_with(stream, options, methods)).await,
        b if b.is_ascii_alphabetic() => {
            phase(
                options.deadline,
                super::http_rounds::http_with(stream, b, options, methods),
            )
            .await
        }
        other => Err(ServerError::Protocol(format!(
            "unrecognised first byte {other:#04x} — neither SOCKS5 (0x05) nor an HTTP method"
        ))),
    }
}

pub(super) fn auth_error(error: SecureAuthError) -> ServerError {
    match error {
        SecureAuthError::Io(kind) => ServerError::Io(std::io::Error::from(kind)),
        other => ServerError::Authentication(other.to_string()),
    }
}

/// cancel-safe: NO — exact reads and replies may be partial.
async fn socks_with<S, T>(
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
    let strong = methods.decoy.is_some();
    // The strongest method both sides have, in the server's order.
    let chosen = if strong && offered.contains(&crate::secure_auth::METHOD) {
        crate::secure_auth::METHOD
    } else if options.cleartext && offered.contains(&2) {
        2
    } else if options.anonymous && offered.contains(&0) {
        0
    } else {
        stream.write_all(&[5, 255]).await?;
        stream.flush().await?;
        return Err(ServerError::Authentication(format!(
            "No mutually supported SOCKS5 auth method (server: secure={strong}, cleartext={}, anonymous={}; client offered {} method(s))",
            options.cleartext, options.anonymous, offered.len()
        )));
    };
    stream.write_all(&[5, chosen]).await?;
    stream.flush().await?;
    if chosen == crate::secure_auth::METHOD {
        let decoy = methods.decoy.expect("chosen only when enabled");
        let user = server_authenticate(stream, methods.store, decoy)
            .await
            .map_err(auth_error)?;
        return socks_request(stream, Who::Secure(user)).await;
    }
    if chosen == 2 {
        return socks_cleartext(stream, methods).await;
    }
    socks_request(stream, Who::Anonymous).await
}

/// The RFC 1929 username/password sub-negotiation, verified against the
/// store. A `hash: init` user is claimed by this login (`PasswordCheck::
/// Claimed`), exactly as by a first secure-auth enrollment.
///
/// cancel-safe: NO — exact reads and replies may be partial.
async fn socks_cleartext<S, T>(
    stream: &mut S,
    methods: &AuthMethods<'_, T>,
) -> Result<IncomingRequest, ServerError>
where
    S: AsyncRead + AsyncWrite + Unpin,
    T: SecretStore,
{
    let store = methods.store;
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
    let (user, password) = match (String::from_utf8(user), String::from_utf8(password)) {
        (Ok(user), Ok(password)) => (user, password),
        _ => return auth_fail(stream, "Invalid UTF-8 in username or password").await,
    };
    match store.check_password(&user, &password).await {
        PasswordCheck::Accepted | PasswordCheck::Claimed => {
            stream.write_all(&[1, 0]).await?;
            stream.flush().await?;
            socks_request(stream, Who::Cleartext(user)).await
        }
        PasswordCheck::Rejected => {
            stream.write_all(AUTH_FAILURE).await?;
            stream.flush().await?;
            Err(ServerError::Authentication(
                "SOCKS5 username/password authentication failed".into(),
            ))
        }
    }
}

/// Answer the RFC 1929 failure status and fail with `message`.
async fn auth_fail<T, S: AsyncWrite + Unpin>(
    stream: &mut S,
    message: &str,
) -> Result<T, ServerError> {
    stream.write_all(AUTH_FAILURE).await?;
    stream.flush().await?;
    Err(ServerError::Authentication(message.to_owned()))
}
