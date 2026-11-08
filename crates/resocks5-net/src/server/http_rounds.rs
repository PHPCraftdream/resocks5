//! HTTP CONNECT with authentication over `407` rounds (RFC 9110 section 11).
//!
//! The credential-less probe is answered with a keep-alive challenge listing
//! the enabled schemes, so a standard client retries on the same connection.
//! `Resocks5-Secure` runs one `secure_auth` message per round (see
//! [`crate::http_auth`]); its last token rides on the `200`.
//! `Basic` is verified against the same store via `check_password`. A
//! refusal — unsupported scheme, failed check, or too many rounds — is a
//! `407` with `Connection: close`.

use base64::{engine::general_purpose, Engine as _};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

use super::secure::{auth_error, AuthMethods};
use super::{read_http_request, HttpRequest, IncomingRequest, ServerError, ServerOptions, Who};
use crate::http_auth::{
    decode_token, encode_token, split_credentials, Pipe, BASIC, MAX_ROUNDS, SECURE,
};
use crate::secure_auth::{server_authenticate, PasswordCheck, SecretStore};

/// A `407`: the server's token for `scheme` when given, else every enabled
/// scheme as a bare challenge (`Resocks5-Secure`, then `Basic`). `close` ends
/// the connection (a refusal); otherwise the client retries on it.
fn challenge<T: SecretStore>(
    methods: &AuthMethods<'_, T>,
    options: &ServerOptions,
    token: Option<(&str, &[u8])>,
    close: bool,
) -> Vec<u8> {
    let mut head = String::from("HTTP/1.1 407 Proxy Authentication Required\r\n");
    match token {
        Some((scheme, token)) => {
            head.push_str("Proxy-Authenticate: ");
            head.push_str(&encode_token(scheme, token));
            head.push_str("\r\n");
        }
        None => {
            if methods.secure.is_some() {
                head.push_str("Proxy-Authenticate: ");
                head.push_str(SECURE);
                head.push_str("\r\n");
            }
            if methods.secure.is_some() && options.cleartext {
                head.push_str("Proxy-Authenticate: Basic realm=\"resocks5\"\r\n");
            }
        }
    }
    if close {
        head.push_str("Connection: close\r\n");
    }
    head.push_str("Content-Length: 0\r\n\r\n");
    head.into_bytes()
}

async fn send<S: AsyncWrite + Unpin>(stream: &mut S, bytes: &[u8]) -> Result<(), ServerError> {
    stream.write_all(bytes).await?;
    stream.flush().await.map_err(ServerError::Io)
}

/// Answer a final `407` (closing) and fail with `message`.
async fn refuse<S, T, R>(
    stream: &mut S,
    methods: &AuthMethods<'_, T>,
    options: &ServerOptions,
    message: &str,
) -> Result<R, ServerError>
where
    S: AsyncWrite + Unpin,
    T: SecretStore,
{
    send(stream, &challenge(methods, options, None, true)).await?;
    Err(ServerError::Authentication(message.to_owned()))
}

/// The next request of a round; its `Proxy-Authorization` must carry a
/// `scheme` token.
async fn next_token<S, T>(
    stream: &mut S,
    options: &ServerOptions,
    methods: &AuthMethods<'_, T>,
    scheme: &str,
) -> Result<(HttpRequest, Vec<u8>), ServerError>
where
    S: AsyncRead + AsyncWrite + Unpin,
    T: SecretStore,
{
    let request = read_http_request(stream, None, options).await?;
    match request
        .authorization
        .as_deref()
        .and_then(|value| decode_token(value, scheme))
    {
        Some(token) => Ok((request, token)),
        None => {
            refuse(
                stream,
                methods,
                options,
                "authentication round without a token",
            )
            .await
        }
    }
}

/// Serve one HTTP CONNECT client: a credential-less probe is served (when
/// anonymous access is on) or challenged; credentials pick `Resocks5-Secure`
/// or `Basic`.
///
/// cancel-safe: NO — consumed bytes and partial replies are future-owned.
pub(super) async fn http_with<S, T>(
    stream: &mut S,
    first: u8,
    options: &ServerOptions,
    methods: &AuthMethods<'_, T>,
) -> Result<IncomingRequest, ServerError>
where
    S: AsyncRead + AsyncWrite + Unpin,
    T: SecretStore,
{
    let mut request = read_http_request(stream, Some(first), options).await?;
    let mut rounds = 1usize;
    loop {
        match request.authorization.as_deref() {
            None => {
                if options.anonymous {
                    return Ok(IncomingRequest::http(
                        request.target,
                        Who::Anonymous,
                        None,
                        request.pipeline,
                    ));
                }
                if rounds >= MAX_ROUNDS {
                    return refuse(
                        stream,
                        methods,
                        options,
                        "no credentials after repeated challenges",
                    )
                    .await;
                }
                // A standard client first asks without credentials and retries
                // on this connection with a scheme from the challenge.
                send(stream, &challenge(methods, options, None, false)).await?;
                request = read_http_request(stream, None, options).await?;
                rounds += 1;
            }
            Some(value) => {
                let value = value.to_owned();
                let (scheme, _) = split_credentials(&value);
                if scheme.eq_ignore_ascii_case(SECURE) && methods.secure.is_some() {
                    return secure_rounds(stream, request, options, methods).await;
                }
                if scheme.eq_ignore_ascii_case(BASIC)
                    && methods.secure.is_some()
                    && options.cleartext
                {
                    return basic(stream, request, &value, options, methods).await;
                }
                let message = if scheme.eq_ignore_ascii_case(BASIC) {
                    "clear-text credentials (HTTP Basic) are not accepted"
                } else {
                    "unsupported Proxy-Authorization scheme"
                };
                return refuse(stream, methods, options, message).await;
            }
        }
    }
}

/// `Resocks5-Secure`: the secure-auth exchange, one message per round.
async fn secure_rounds<S, T>(
    stream: &mut S,
    mut request: HttpRequest,
    options: &ServerOptions,
    methods: &AuthMethods<'_, T>,
) -> Result<IncomingRequest, ServerError>
where
    S: AsyncRead + AsyncWrite + Unpin,
    T: SecretStore,
{
    let (store, decoy) = methods.secure.expect("chosen only when enabled");
    let Some(token) = request
        .authorization
        .as_deref()
        .and_then(|value| decode_token(value, SECURE))
    else {
        return refuse(stream, methods, options, "malformed Resocks5-Secure token").await;
    };
    let pipe = Pipe::new();
    pipe.push(&token);
    let mut end = pipe.end();
    let exchange = server_authenticate(&mut end, store, decoy);
    tokio::pin!(exchange);
    let mut rounds = 1;
    let result = loop {
        tokio::select! {
            biased;
            result = &mut exchange => break result,
            message = pipe.next_message() => {
                if rounds >= MAX_ROUNDS {
                    return refuse(stream, methods, options, "too many authentication rounds").await;
                }
                send(stream, &challenge(methods, options, Some((SECURE, &message)), false)).await?;
                let (next, token) = next_token(stream, options, methods, SECURE).await?;
                request = next;
                pipe.push(&token);
                rounds += 1;
            }
        }
    };
    let last = pipe.take_message();
    match result {
        Ok(user) => Ok(IncomingRequest::http(
            request.target,
            Who::Secure(user),
            last.map(|message| encode_token(SECURE, &message)),
            request.pipeline,
        )),
        Err(error) => {
            // The exchange's own refusal (if it wrote one) closes the round.
            let token = last.as_deref().map(|message| (SECURE, message));
            send(stream, &challenge(methods, options, token, true)).await?;
            Err(auth_error(error))
        }
    }
}

/// HTTP `Basic`: verify the submitted password against the store.
async fn basic<S, T>(
    stream: &mut S,
    request: HttpRequest,
    value: &str,
    options: &ServerOptions,
    methods: &AuthMethods<'_, T>,
) -> Result<IncomingRequest, ServerError>
where
    S: AsyncRead + AsyncWrite + Unpin,
    T: SecretStore,
{
    let (store, _decoy) = methods.secure.expect("Basic chosen only when enabled");
    let (user, password) = match parse_basic(value) {
        Ok(pair) => pair,
        Err(message) => return refuse(stream, methods, options, message).await,
    };
    match store.check_password(&user, &password).await {
        PasswordCheck::Accepted | PasswordCheck::Claimed => Ok(IncomingRequest::http(
            request.target,
            Who::Cleartext(user),
            None,
            request.pipeline,
        )),
        PasswordCheck::Rejected => {
            refuse(stream, methods, options, "HTTP proxy authentication failed").await
        }
    }
}

/// Decode and split an HTTP Basic value: `user:pass` split at the FIRST ':',
/// strict base64 (padding required), no control characters and no empty parts.
fn parse_basic(value: &str) -> Result<(String, String), &'static str> {
    let (_, token) = split_credentials(value);
    if token.is_empty() {
        return Err("Proxy-Authorization base64 decode failed");
    }
    let Ok(decoded) = general_purpose::STANDARD.decode(token) else {
        return Err("Proxy-Authorization base64 decode failed");
    };
    let Ok(text) = String::from_utf8(decoded) else {
        return Err("Proxy-Authorization not valid UTF-8");
    };
    let Some((user, password)) = text.split_once(':') else {
        return Err("Proxy-Authorization missing ':'");
    };
    if user.is_empty() || password.is_empty() {
        return Err("Proxy-Authorization has empty credentials");
    }
    if user.bytes().any(|b| b.is_ascii_control()) || password.bytes().any(|b| b.is_ascii_control())
    {
        return Err("Proxy-Authorization contains control characters");
    }
    Ok((user.to_owned(), password.to_owned()))
}
