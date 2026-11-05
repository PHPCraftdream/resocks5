//! Inbound SOCKS5/HTTP with secure auth (SOCKS5 method 0x80) instead of any
//! clear-text password (feature `secure-auth`).

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use super::{http, phase, socks_request, IncomingRequest, ServerError, ServerOptions};
use crate::secure_auth::{server_authenticate, DecoyKey, SecretStore, METHOD};
use crate::SecureAuthError;

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
/// no credentials are retained.
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
    let first = phase(options.deadline, async {
        let mut byte = [0];
        if stream.read(&mut byte).await? == 0 {
            return Err(ServerError::Closed);
        }
        Ok(byte[0])
    })
    .await?;
    match first {
        5 => {
            phase(
                options.deadline,
                socks_secure(stream, options, store, decoy),
            )
            .await
        }
        b if b.is_ascii_alphabetic() => {
            // HTTP has no secure method here: a password-capable host must not
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

/// cancel-safe: NO — exact reads and replies may be partial.
async fn socks_secure<S, T>(
    stream: &mut S,
    options: &ServerOptions,
    store: &T,
    decoy: &DecoyKey,
) -> Result<IncomingRequest, ServerError>
where
    S: AsyncRead + AsyncWrite + Unpin,
    T: SecretStore,
{
    let nmethods = stream.read_u8().await?;
    let mut methods = vec![0; usize::from(nmethods)];
    stream.read_exact(&mut methods).await?;
    let chosen = if options.password && methods.contains(&METHOD) {
        METHOD
    } else if options.anonymous && methods.contains(&0) {
        0
    } else {
        stream.write_all(&[5, 255]).await?;
        stream.flush().await?;
        return Err(ServerError::Authentication(format!(
            "No mutually supported SOCKS5 auth method (server: anonymous={}, secure={}; client offered {} method(s))",
            options.anonymous,
            options.password,
            methods.len()
        )));
    };
    stream.write_all(&[5, chosen]).await?;
    stream.flush().await?;
    let username = if chosen == METHOD {
        Some(
            server_authenticate(stream, store, decoy)
                .await
                .map_err(auth_error)?,
        )
    } else {
        None
    };
    socks_request(stream, username, None, None).await
}
