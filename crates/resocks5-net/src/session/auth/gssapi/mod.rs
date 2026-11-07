//! GSSAPI authentication for SOCKS5 (RFC 1961, method 0x01; feature `gssapi`).
//!
//! No password and no credential crosses the wire: the peers run a GSS-API
//! security-context exchange (Kerberos, normally) and agree on a per-message
//! protection level; the SOCKS request and reply then travel as protected
//! messages. This module is the protocol (framing, token exchange, abort,
//! protection negotiation, message protection) over the [`GssBackend`] trait;
//! the mechanism itself is the backend's business.
//!
//! * Client: [`client_gssapi`] with [`GssCredentials`]. It asks for no
//!   per-message protection ([`Protection::None`]) and accepts what the server
//!   answers, from its configured minimum up.
//! * Server: [`server_gssapi`] with a [`GssAcceptor`]; it returns the
//!   authenticated peer name (the Kerberos principal) and a [`GssSession`] for
//!   the protected request and reply.
//!
//! Scope: what is protected is the authentication — the context exchange is
//! mutual and the mechanism (Kerberos) proves both peers. By default the SOCKS
//! request and reply are not additionally protected ([`Protection::None`], the
//! level `curl --socks5-gssapi` and Dante's `clear` speak, so those clients
//! work); levels 1 and 2 (RFC 1961 §5: protected request and reply) are opt-in.
//! The tunnel data afterwards is always unprotected.
//!
//! ```text
//! let creds = GssCredentials::new(backend, "socks@proxy.example.com");
//! let session = client_gssapi(&mut stream, &creds).await?;
//! ```

use std::io;
use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::error::GssapiError;

#[cfg(any(test, feature = "test-instrumentation"))]
pub mod mock;
#[cfg(test)]
mod negotiation_tests;
#[cfg(feature = "gssapi-system")]
pub mod system;
#[cfg(test)]
mod tests;

/// SOCKS5 method number of GSSAPI authentication.
pub const METHOD: u8 = 0x01;
const VERSION: u8 = 1;
const MTYP_AUTH: u8 = 1;
const MTYP_PROTECTION: u8 = 2;
const MTYP_DATA: u8 = 3;
const MTYP_ABORT: u8 = 0xFF;

/// Per-message protection level: RFC 1961 §4 levels 1 and 2 (the "selective"
/// level 3 is not offered) and level 0, the de-facto "no per-message
/// protection" of curl and Dante's `clear`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Protection {
    /// Level 0, not in the RFC but spoken by common clients (`curl
    /// --socks5-gssapi`): the context still authenticates both peers
    /// (Kerberos mutual authentication), but the SOCKS request and reply are
    /// not protected and not encapsulated. Weaker; opt-in on both sides.
    None = 0,
    /// Level 1: every message carries an integrity check.
    Integrity = 1,
    /// Level 2: every message is integrity-protected and encrypted.
    Confidential = 2,
}

impl Protection {
    fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            0 => Some(Self::None),
            1 => Some(Self::Integrity),
            2 => Some(Self::Confidential),
            _ => None,
        }
    }
}

/// One step of the context exchange.
#[derive(Debug, Default)]
pub struct GssStep {
    /// The token to send to the peer, if any.
    pub token: Option<Vec<u8>>,
    /// The context is established on this side.
    pub done: bool,
}

/// A GSS-API security context as the protocol needs it.
pub trait GssContext: Send {
    /// Advance the exchange: `input` is `None` for a client's first step, the
    /// peer's token afterwards.
    ///
    /// # Errors
    ///
    /// [`GssapiError::Backend`] when the mechanism rejects the exchange.
    fn step(&mut self, input: Option<&[u8]>) -> Result<GssStep, GssapiError>;

    /// The peer's authenticated name (a server's view of the client), once
    /// established.
    fn peer_name(&self) -> Option<String>;

    /// Protect `data` (`gss_wrap`): integrity, plus confidentiality when
    /// `confidential`.
    ///
    /// # Errors
    ///
    /// [`GssapiError::NotEstablished`] before the context is done, or a
    /// backend failure.
    fn wrap(&mut self, data: &[u8], confidential: bool) -> Result<Vec<u8>, GssapiError>;

    /// Verify and open a token made by the peer's `wrap` (`gss_unwrap`).
    ///
    /// # Errors
    ///
    /// [`GssapiError::Integrity`] when it does not verify (tampered, replayed
    /// or out of sequence).
    fn unwrap(&mut self, token: &[u8]) -> Result<Vec<u8>, GssapiError>;
}

/// Creates contexts: the GSSAPI mechanism behind the protocol.
pub trait GssBackend: Send + Sync {
    /// A client context towards the service `target` (for Kerberos, a service
    /// principal such as `socks@proxy.example.com`).
    ///
    /// # Errors
    ///
    /// [`GssapiError::Backend`] when no credentials or no such service.
    fn initiate(&self, target: &str) -> Result<Box<dyn GssContext>, GssapiError>;

    /// A server (acceptor) context.
    ///
    /// # Errors
    ///
    /// [`GssapiError::Backend`] when the server has no acceptor credentials.
    fn accept(&self) -> Result<Box<dyn GssContext>, GssapiError>;
}

/// What a client needs to authenticate with GSSAPI.
#[derive(Clone)]
pub struct GssCredentials {
    backend: Arc<dyn GssBackend>,
    service: String,
    want: Protection,
    min: Protection,
}

impl GssCredentials {
    /// Authenticate to `service` through `backend`; asks for no per-message
    /// protection and accepts any answer (a server that wants protection gets
    /// it).
    pub fn new(backend: Arc<dyn GssBackend>, service: impl Into<String>) -> Self {
        Self {
            backend,
            service: service.into(),
            want: Protection::None,
            min: Protection::None,
        }
    }

    /// The level to ask the server for (default none).
    #[must_use]
    pub fn with_requested_protection(mut self, level: Protection) -> Self {
        self.want = level;
        self
    }

    /// The weakest level to accept from the server (default none): set it to
    /// require a protected request and reply.
    #[must_use]
    pub fn with_min_protection(mut self, level: Protection) -> Self {
        self.min = level;
        self
    }
}

impl std::fmt::Debug for GssCredentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GssCredentials")
            .field("service", &self.service)
            .finish_non_exhaustive()
    }
}

/// What a server needs to accept GSSAPI clients.
#[derive(Clone)]
pub struct GssAcceptor {
    backend: Arc<dyn GssBackend>,
    protection: Protection,
}

impl GssAcceptor {
    /// Accept through `backend`, with no per-message protection of the SOCKS
    /// request and reply (authentication is still mutual): the level common
    /// clients such as `curl --socks5-gssapi` speak. See
    /// [`with_protection`](Self::with_protection).
    pub fn new(backend: Arc<dyn GssBackend>) -> Self {
        Self {
            backend,
            protection: Protection::None,
        }
    }

    /// The per-message protection level the server answers, whatever the
    /// client asks (RFC 1961 lets the server decide; a client that finds it
    /// too weak closes the connection). Default [`Protection::None`].
    #[must_use]
    pub fn with_protection(mut self, level: Protection) -> Self {
        self.protection = level;
        self
    }
}

impl std::fmt::Debug for GssAcceptor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("GssAcceptor { .. }")
    }
}

/// An established context with its agreed protection: seals and opens the
/// SOCKS request and reply.
pub struct GssSession {
    ctx: Box<dyn GssContext>,
    protection: Protection,
}

impl GssSession {
    /// The agreed protection level.
    pub fn protection(&self) -> Protection {
        self.protection
    }

    /// Whether SOCKS messages are protected: false only for
    /// [`Protection::None`], where they travel plain and `seal`/`open` are not
    /// used.
    pub fn is_protected(&self) -> bool {
        self.protection != Protection::None
    }

    /// Protect `data` as one encapsulated message (RFC 1961 §5): the complete
    /// frame, ready to write.
    ///
    /// # Errors
    ///
    /// A backend failure, or [`GssapiError::BadFrame`] when the token does not
    /// fit a frame.
    pub fn seal(&mut self, data: &[u8]) -> Result<Vec<u8>, GssapiError> {
        if !self.is_protected() {
            return Err(GssapiError::NotEstablished);
        }
        let token = self
            .ctx
            .wrap(data, self.protection == Protection::Confidential)?;
        frame(MTYP_DATA, &token)
    }

    /// Open the token of one received encapsulated message.
    ///
    /// # Errors
    ///
    /// [`GssapiError::Integrity`] when it does not verify.
    pub fn open(&mut self, token: &[u8]) -> Result<Vec<u8>, GssapiError> {
        if !self.is_protected() {
            return Err(GssapiError::NotEstablished);
        }
        self.ctx.unwrap(token)
    }

    /// Read one encapsulated message from `stream` and open it.
    ///
    /// # Errors
    ///
    /// Framing, I/O and integrity errors; an abort frame is `Aborted`.
    pub async fn read_message<S>(&mut self, stream: &mut S) -> Result<Vec<u8>, GssapiError>
    where
        S: AsyncRead + Unpin,
    {
        let token = read_frame(stream, MTYP_DATA).await?;
        self.open(&token)
    }

    /// Seal `data` and write it as one message.
    ///
    /// # Errors
    ///
    /// Backend and I/O errors.
    pub async fn write_message<S>(&mut self, stream: &mut S, data: &[u8]) -> Result<(), GssapiError>
    where
        S: AsyncWrite + Unpin,
    {
        let bytes = self.seal(data)?;
        stream.write_all(&bytes).await.map_err(io)?;
        stream.flush().await.map_err(io)
    }
}

impl std::fmt::Debug for GssSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GssSession")
            .field("protection", &self.protection)
            .finish_non_exhaustive()
    }
}

fn io(error: io::Error) -> GssapiError {
    GssapiError::Io(error.kind())
}

fn frame(mtyp: u8, token: &[u8]) -> Result<Vec<u8>, GssapiError> {
    let len = u16::try_from(token.len()).map_err(|_| GssapiError::BadFrame)?;
    let mut out = Vec::with_capacity(4 + token.len());
    out.extend_from_slice(&[VERSION, mtyp]);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(token);
    Ok(out)
}

async fn write_frame<S: AsyncWrite + Unpin>(
    stream: &mut S,
    mtyp: u8,
    token: &[u8],
) -> Result<(), GssapiError> {
    stream.write_all(&frame(mtyp, token)?).await.map_err(io)?;
    stream.flush().await.map_err(io)
}

/// One frame of type `expect`; the abort frame is `Aborted`.
async fn read_frame<S: AsyncRead + Unpin>(
    stream: &mut S,
    expect: u8,
) -> Result<Vec<u8>, GssapiError> {
    let mut head = [0u8; 2];
    stream.read_exact(&mut head).await.map_err(io)?;
    if head[0] != VERSION {
        return Err(GssapiError::BadVersion);
    }
    if head[1] == MTYP_ABORT {
        return Err(GssapiError::Aborted);
    }
    if head[1] != expect {
        return Err(GssapiError::BadFrame);
    }
    let mut len = [0u8; 2];
    stream.read_exact(&mut len).await.map_err(io)?;
    let mut token = vec![0u8; usize::from(u16::from_be_bytes(len))];
    stream.read_exact(&mut token).await.map_err(io)?;
    Ok(token)
}

/// Run the client side on `stream`, which must already be past the SOCKS5
/// method selection that chose [`METHOD`]: establish the context, negotiate the
/// protection level, return the session.
///
/// # Errors
///
/// A [`GssapiError`]: `Aborted` when the server refuses, `Backend` for a
/// mechanism failure, `ProtectionTooWeak` when the server agrees to less than
/// the configured minimum (the caller must close the connection), and
/// `BadVersion`/`BadFrame`/`Io` for a broken exchange.
///
/// cancel-safe: NO — a cancelled exchange must close the stream.
pub async fn client_gssapi<S>(
    stream: &mut S,
    credentials: &GssCredentials,
) -> Result<GssSession, GssapiError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut ctx = credentials.backend.initiate(&credentials.service)?;
    let mut step = ctx.step(None)?;
    loop {
        if let Some(token) = step.token.take() {
            write_frame(stream, MTYP_AUTH, &token).await?;
        }
        // The server's answer: its token, or an empty one that only confirms.
        let reply = read_frame(stream, MTYP_AUTH).await?;
        if step.done {
            break;
        }
        step = ctx.step(Some(&reply))?;
        if step.done && step.token.is_none() {
            break;
        }
    }
    // Protection level: ask for the strongest, accept the minimum or better.
    let ask = ctx.wrap(&[credentials.want as u8], false)?;
    write_frame(stream, MTYP_PROTECTION, &ask).await?;
    let answer = read_frame(stream, MTYP_PROTECTION).await?;
    let agreed = match ctx.unwrap(&answer)?.as_slice() {
        [byte] => Protection::from_byte(*byte).ok_or(GssapiError::BadFrame)?,
        _ => return Err(GssapiError::BadFrame),
    };
    if agreed < credentials.min {
        return Err(GssapiError::ProtectionTooWeak);
    }
    Ok(GssSession {
        ctx,
        protection: agreed,
    })
}

/// Run the server side on `stream`, past the method selection that chose
/// [`METHOD`]. Returns the session and the authenticated peer name. On a
/// failed exchange the client is sent the abort message.
///
/// # Errors
///
/// As [`client_gssapi`], from the server's side.
///
/// cancel-safe: NO — a cancelled exchange must close the stream.
pub async fn server_gssapi<S>(
    stream: &mut S,
    acceptor: &GssAcceptor,
) -> Result<(GssSession, String), GssapiError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    match serve(stream, acceptor).await {
        Ok(done) => Ok(done),
        Err(error) => {
            if !matches!(error, GssapiError::Io(_) | GssapiError::Aborted) {
                let _ = stream.write_all(&[VERSION, MTYP_ABORT]).await;
                let _ = stream.flush().await;
            }
            Err(error)
        }
    }
}

async fn serve<S>(
    stream: &mut S,
    acceptor: &GssAcceptor,
) -> Result<(GssSession, String), GssapiError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut ctx = acceptor.backend.accept()?;
    loop {
        let token = read_frame(stream, MTYP_AUTH).await?;
        let step = ctx.step(Some(&token))?;
        match (step.token, step.done) {
            (Some(token), done) => {
                write_frame(stream, MTYP_AUTH, &token).await?;
                if done {
                    break;
                }
            }
            // Established with nothing to say: an empty token confirms it.
            (None, true) => {
                write_frame(stream, MTYP_AUTH, &[]).await?;
                break;
            }
            (None, false) => return Err(GssapiError::BadFrame),
        }
    }
    let peer = ctx
        .peer_name()
        .ok_or_else(|| GssapiError::Backend("no authenticated peer name".to_owned()))?;
    let ask = read_frame(stream, MTYP_PROTECTION).await?;
    let asked = match ctx.unwrap(&ask)?.as_slice() {
        [byte] => *byte,
        _ => return Err(GssapiError::BadFrame),
    };
    // The server's configured level; the client's request is only checked to be
    // a level byte (0, 1, 2 or the "selective" 3).
    if asked > 3 {
        return Err(GssapiError::BadFrame);
    }
    let agreed = acceptor.protection;
    let answer = ctx.wrap(&[agreed as u8], false)?;
    write_frame(stream, MTYP_PROTECTION, &answer).await?;
    Ok((
        GssSession {
            ctx,
            protection: agreed,
        },
        peer,
    ))
}
