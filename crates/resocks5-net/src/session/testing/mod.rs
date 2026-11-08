//! Scripted upstream proxies for tests (feature `test-instrumentation`).
//!
//! A [`MockUpstream`] listens on `127.0.0.1:0` and serves every connection as
//! a SOCKS5 or HTTP CONNECT proxy following a [`Script`]: complete the
//! handshake and echo the tunnel, refuse the CONNECT with a code, stay silent
//! at the greeting or at the CONNECT, or hang up. It checks the configured
//! [`MockAuth`] and records the CONNECT targets it saw. Dropping it stops
//! the listener and every open connection.
//!
//! ```text
//! let mock = MockUpstream::socks5().script(Script::Tunnel).spawn().await?;
//! let mut tunnel = dial_tcp(&mock.proxy(), "example.test", 443, &DialOptions::new()).await?;
//! tunnel.write_all(b"ping").await?;   // echoed back
//! assert_eq!(mock.targets(), ["example.test:443"]);
//! ```
//!
//! In-memory peers use the same protocol handler without using a socket for the
//! returned stream (the mock itself still binds its listener in `spawn`):
//!
//! ```text
//! let mock = MockUpstream::http().reply_delay(Duration::from_millis(25)).spawn().await?;
//! let mut stream = mock.connect_in_memory();
//! http_connect_handshake(&mut stream, "example.test:443", &mock.proxy()).await?;
//! ```
//!
//! - [`MockAuth::AuthStatus`]: secure auth is selected and the client's first
//!   authentication message is answered with the two bytes [`VERSION, byte]`
//!   (`0xFF` reads as a refusal, `0x01` as an enrollment offer, any other
//!   non-zero value as a bad version).
//!
//! Authentication modes (feature `secure-auth`):
//!
//! - [`MockAuth::Cleartext`] speaks clear text only (SOCKS5 method 0x02, HTTP
//!   `Basic`) against a single user whose password is stored with
//!   [`MOCK_KDF`].
//! - [`MockAuth::Secure`] stores one secret for one user; because that secret
//!   verifies every method, the mock picks the strongest method the client
//!   offered: secure auth (SOCKS5 method 0x80 / HTTP `Resocks5-Secure`) when
//!   offered, clear text otherwise.
//! - [`MockAuth::SecureDenied`] selects secure auth and always denies via the
//!   real exchange against an empty user store.
//!
//! The HTTP flow runs a bounded 407 dance: the mock answers with
//! `407 Proxy Authentication Required` listing the schemes it accepts, the
//! client retries with `Proxy-Authorization`, and on success the tunnel is
//! answered with `200 Connection established` — for the secure exchange,
//! carrying the final `Proxy-Authenticate` token.
//!
//! [`MockAuth::AuthStatus`] over HTTP answers the first `Resocks5-Secure`
//! round with `[VERSION, status]` on a closing 407.

use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream};
use tokio::net::TcpListener;
use tokio::task::{JoinHandle, JoinSet};

use crate::connect::HostPort;
use crate::types::{ProxyConfig, ProxyProtocol};

/// What the mock does with each connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Script {
    /// Complete the handshake, then echo every tunnel byte back.
    Tunnel,
    /// Refuse the CONNECT: the SOCKS5 REP (must fit a byte) or the HTTP
    /// status, then close.
    Refuse(u16),
    /// Accept TCP and never answer.
    SilentGreeting,
    /// Answer the greeting (and authentication), never the CONNECT.
    SilentConnect,
    /// Close right after accepting.
    Hangup,
}

/// How the mock authenticates clients.
#[derive(Clone)]
#[non_exhaustive]
pub enum MockAuth {
    /// No authentication (SOCKS5 method 0x00; HTTP tunnels immediately).
    None,
    /// Clear text only (SOCKS5 method 0x02, HTTP `Basic`) against this one
    /// user; the mock stores `UserSecret::from_password(password, MOCK_KDF)`.
    #[cfg(feature = "secure-auth")]
    Cleartext {
        /// The user name.
        user: String,
        /// The password.
        password: String,
    },
    /// Secure auth (SOCKS5 method 0x80 / HTTP `Resocks5-Secure`) against this
    /// one user — and, because one stored secret verifies every method, clear
    /// text (SOCKS5 0x02 / HTTP `Basic`) as well: the mock picks the strongest
    /// method the client offered.
    #[cfg(feature = "secure-auth")]
    Secure {
        /// The user name.
        user: String,
        /// Its stored secret.
        secret: crate::secure_auth::UserSecret,
    },
    /// Refuse SOCKS5 method negotiation with `[5, 255]`, regardless of offer;
    /// HTTP answers CONNECT with 407.
    NoAcceptableMethod,
    /// Select secure auth and deny using the real exchange against an empty
    /// user store (unknown users receive the normal decoy response); HTTP
    /// answers 407.
    #[cfg(feature = "secure-auth")]
    SecureDenied,
    /// Select secure auth and answer the client's first authentication message
    /// with `[VERSION, status]`, then close. The client maps `0xFF` to
    /// `SecureAuthError::Refused`, `0x01` to `EnrollmentNotAllowed` (unless it
    /// allows enrollment) and any other non-zero status to `BadVersion`; HTTP
    /// answers 407.
    #[cfg(feature = "secure-auth")]
    AuthStatus(u8),
}

impl std::fmt::Debug for MockAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::None => "MockAuth::None",
            #[cfg(feature = "secure-auth")]
            Self::Cleartext { .. } => "MockAuth::Cleartext { .. }",
            #[cfg(feature = "secure-auth")]
            Self::Secure { .. } => "MockAuth::Secure { .. }",
            Self::NoAcceptableMethod => "MockAuth::NoAcceptableMethod",
            #[cfg(feature = "secure-auth")]
            Self::AuthStatus(_) => "MockAuth::AuthStatus(..)",
            #[cfg(feature = "secure-auth")]
            Self::SecureDenied => "MockAuth::SecureDenied",
        })
    }
}

/// Builder for a [`MockUpstream`]: `MockUpstream::socks5()` or `::http()`.
#[derive(Debug, Clone)]
#[must_use]
pub struct MockUpstreamBuilder {
    protocol: ProxyProtocol,
    auth: MockAuth,
    script: Script,
    reply_delay: Duration,
    drip: bool,
}

impl MockUpstreamBuilder {
    /// Set the authentication (default [`MockAuth::None`]).
    pub fn auth(mut self, auth: MockAuth) -> Self {
        self.auth = auth;
        self
    }

    /// Set the script (default [`Script::Tunnel`]).
    pub fn script(mut self, script: Script) -> Self {
        self.script = script;
        self
    }

    /// Delay each mock-generated method selection or CONNECT response by
    /// `delay` (default zero). In-memory streams observe this delay; TCP
    /// clients get best-effort timing subject to kernel scheduling/coalescing.
    /// Secure-auth exchange messages are generated internally and are not
    /// delayed by this option.
    pub fn reply_delay(mut self, delay: Duration) -> Self {
        self.reply_delay = delay;
        self
    }

    /// Write mock-generated method selections and CONNECT responses one byte
    /// at a time, flushing and yielding between bytes. In-memory streams expose
    /// this fragmentation; TCP observation is best-effort and may be coalesced
    /// by the kernel. Secure-auth exchange messages are not dripped.
    pub fn drip(mut self, enabled: bool) -> Self {
        self.drip = enabled;
        self
    }

    /// Bind `127.0.0.1:0` and start serving.
    ///
    /// # Errors
    ///
    /// The bind error; for secure auth, a failing OS random source.
    pub async fn spawn(self) -> io::Result<MockUpstream> {
        let auth = self.auth;
        #[cfg(feature = "secure-auth")]
        let user = match &auth {
            MockAuth::Cleartext { user, password } => Some((
                user.clone(),
                crate::secure_auth::UserSecret::from_password(password, MOCK_KDF)
                    .map_err(|e| io::Error::other(e.to_string()))?,
            )),
            MockAuth::Secure { user, secret } => Some((user.clone(), secret.clone())),
            _ => None,
        };
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let state = Arc::new(Shared {
            auth,
            script: self.script,
            reply_delay: self.reply_delay,
            drip: self.drip,
            targets: Mutex::new(Vec::new()),
            connections: AtomicUsize::new(0),
            #[cfg(feature = "secure-auth")]
            user,
            #[cfg(feature = "secure-auth")]
            decoy: crate::secure_auth::DecoyKey::generate()
                .map_err(|e| io::Error::other(e.to_string()))?,
        });
        let protocol = self.protocol;
        let task = tokio::spawn({
            let state = Arc::clone(&state);
            async move {
                let mut connections = JoinSet::new();
                while let Ok((stream, _)) = listener.accept().await {
                    state.connections.fetch_add(1, Ordering::SeqCst);
                    let state = Arc::clone(&state);
                    connections.spawn(async move {
                        let _ = match protocol {
                            ProxyProtocol::Http => serve_http(stream, &state).await,
                            _ => serve_socks5(stream, &state).await,
                        };
                    });
                    while connections.try_join_next().is_some() {}
                }
            }
        });
        Ok(MockUpstream {
            addr,
            protocol,
            state,
            task,
            in_memory_tasks: Mutex::new(JoinSet::new()),
        })
    }
}

/// Cheap cost parameters for a mock's stored secret: a real derivation cost
/// would dominate the tests, and the mock is a fixture, not a policy.
#[cfg(feature = "secure-auth")]
const MOCK_KDF: crate::secure_auth::KdfParams = crate::secure_auth::KdfParams {
    memory_kib: 64,
    iterations: 1,
    parallelism: 1,
};

struct Shared {
    auth: MockAuth,
    script: Script,
    reply_delay: Duration,
    drip: bool,
    targets: Mutex<Vec<String>>,
    connections: AtomicUsize,
    /// The mock's single user (name + stored secret): `Some` for the
    /// `Secure` and `Cleartext` auth modes, derived at spawn with
    /// [`MOCK_KDF`] for `Cleartext`.
    #[cfg(feature = "secure-auth")]
    user: Option<(String, crate::secure_auth::UserSecret)>,
    #[cfg(feature = "secure-auth")]
    decoy: crate::secure_auth::DecoyKey,
}

impl Shared {
    fn record(&self, target: String) {
        self.targets.lock().expect("targets lock").push(target);
    }

    /// The SOCKS5 method the mock picks from the client's offer: the
    /// strongest it can speak. `None` = no acceptable method (`[5, 0xFF]`).
    fn socks_choice(&self, offered: &[u8]) -> Option<u8> {
        match &self.auth {
            MockAuth::None => offered.contains(&0x00).then_some(0x00),
            MockAuth::NoAcceptableMethod => None,
            #[cfg(feature = "secure-auth")]
            MockAuth::Cleartext { .. } => offered.contains(&0x02).then_some(0x02),
            #[cfg(feature = "secure-auth")]
            MockAuth::Secure { .. } => {
                // One secret, every method: strongest offered wins.
                if offered.contains(&crate::secure_auth::METHOD) {
                    Some(crate::secure_auth::METHOD)
                } else {
                    offered.contains(&0x02).then_some(0x02)
                }
            }
            #[cfg(feature = "secure-auth")]
            MockAuth::SecureDenied | MockAuth::AuthStatus(_) => offered
                .contains(&crate::secure_auth::METHOD)
                .then_some(crate::secure_auth::METHOD),
        }
    }
}

/// A running scripted upstream; see the module docs.
#[derive(Debug)]
pub struct MockUpstream {
    addr: SocketAddr,
    protocol: ProxyProtocol,
    state: Arc<Shared>,
    task: JoinHandle<()>,
    in_memory_tasks: Mutex<JoinSet<()>>,
}

impl std::fmt::Debug for Shared {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Shared")
            .field("script", &self.script)
            .finish_non_exhaustive()
    }
}

impl MockUpstream {
    /// A SOCKS5 mock.
    pub fn socks5() -> MockUpstreamBuilder {
        Self::builder(ProxyProtocol::Socks5)
    }

    /// An HTTP CONNECT mock.
    pub fn http() -> MockUpstreamBuilder {
        Self::builder(ProxyProtocol::Http)
    }

    fn builder(protocol: ProxyProtocol) -> MockUpstreamBuilder {
        MockUpstreamBuilder {
            protocol,
            auth: MockAuth::None,
            script: Script::Tunnel,
            reply_delay: Duration::ZERO,
            drip: false,
        }
    }

    /// Make an in-memory client stream served by this mock. It shares script,
    /// auth and observability state with TCP connections. The returned stream
    /// uses no socket (although this mock was created by `spawn`, which binds
    /// its TCP listener).
    pub fn connect_in_memory(&self) -> DuplexStream {
        let (client, server) = tokio::io::duplex(64 * 1024);
        let state = Arc::clone(&self.state);
        let protocol = self.protocol;
        state.connections.fetch_add(1, Ordering::SeqCst);
        let mut tasks = self.in_memory_tasks.lock().expect("in-memory tasks lock");
        while tasks.try_join_next().is_some() {}
        tasks.spawn(async move {
            let _ = match protocol {
                ProxyProtocol::Http => serve_http(server, &state).await,
                _ => serve_socks5(server, &state).await,
            };
        });
        client
    }

    /// The listening address.
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// A `ProxyConfig` for this mock, without credentials.
    pub fn proxy(&self) -> ProxyConfig {
        ProxyConfig::new(self.protocol, "127.0.0.1", self.addr.port())
    }

    /// The CONNECT targets seen so far (`host:port`, IPv6 in brackets), in
    /// arrival order; only requests that got past authentication.
    pub fn targets(&self) -> Vec<String> {
        self.state.targets.lock().expect("targets lock").clone()
    }

    /// The TCP connections accepted and in-memory streams created so far.
    pub fn connections(&self) -> usize {
        self.state.connections.load(Ordering::SeqCst)
    }
}

impl Drop for MockUpstream {
    fn drop(&mut self) {
        // Aborting the accept loop drops its JoinSet, which aborts every
        // connection task.
        self.task.abort();
        match self.in_memory_tasks.get_mut() {
            Ok(tasks) => tasks.abort_all(),
            Err(poisoned) => poisoned.into_inner().abort_all(),
        }
    }
}

async fn write_reply<S: AsyncWrite + Unpin>(
    stream: &mut S,
    state: &Shared,
    bytes: &[u8],
) -> io::Result<()> {
    if !state.reply_delay.is_zero() {
        tokio::time::sleep(state.reply_delay).await;
    }
    if state.drip {
        for byte in bytes {
            stream.write_all(std::slice::from_ref(byte)).await?;
            stream.flush().await?;
            tokio::task::yield_now().await;
        }
        Ok(())
    } else {
        stream.write_all(bytes).await
    }
}

async fn forever() -> io::Result<()> {
    std::future::pending().await
}

async fn echo<S: AsyncRead + AsyncWrite + Unpin>(stream: S) -> io::Result<()> {
    let (mut reader, mut writer) = tokio::io::split(stream);
    tokio::io::copy(&mut reader, &mut writer).await?;
    Ok(())
}

async fn serve_socks5<S: AsyncRead + AsyncWrite + Unpin + Send>(
    mut stream: S,
    state: &Shared,
) -> io::Result<()> {
    if state.script == Script::Hangup {
        return Ok(());
    }
    let mut head = [0u8; 2];
    stream.read_exact(&mut head).await?;
    let mut methods = vec![0u8; usize::from(head[1])];
    stream.read_exact(&mut methods).await?;
    if state.script == Script::SilentGreeting {
        return forever().await;
    }
    let Some(wanted) = state.socks_choice(&methods) else {
        return write_reply(&mut stream, state, &[0x05, 0xFF]).await;
    };
    write_reply(&mut stream, state, &[0x05, wanted]).await?;
    match wanted {
        0x00 => {}
        #[cfg(feature = "secure-auth")]
        m if m == crate::secure_auth::METHOD => match &state.auth {
            MockAuth::AuthStatus(status) => {
                let mut first_head = [0u8; 2];
                stream.read_exact(&mut first_head).await?;
                let user_len = usize::from(first_head[1]);
                let mut first_rest = vec![0u8; user_len + 32];
                stream.read_exact(&mut first_rest).await?;
                let reply = [crate::secure_auth::VERSION, *status];
                write_reply(&mut stream, state, &reply).await?;
                return Ok(());
            }
            MockAuth::SecureDenied => {
                if crate::secure_auth::server_authenticate(&mut stream, &EmptyUsers, &state.decoy)
                    .await
                    .is_err()
                {
                    return Ok(());
                }
            }
            _ => {
                let Some((user, secret)) = state.user.clone() else {
                    return Ok(());
                };
                let store = MockUsers { user, secret };
                if crate::secure_auth::server_authenticate(&mut stream, &store, &state.decoy)
                    .await
                    .is_err()
                {
                    return Ok(());
                }
            }
        },
        #[cfg(feature = "secure-auth")]
        0x02 => {
            if !socks5_cleartext_server(&mut stream, state).await? {
                return Ok(());
            }
        }
        _ => unreachable!("socks_choice returned a method with no handler"),
    }
    if state.script == Script::SilentConnect {
        return forever().await;
    }
    let mut request = [0u8; 4];
    stream.read_exact(&mut request).await?;
    let host = match request[3] {
        0x01 => {
            let mut ip = [0u8; 4];
            stream.read_exact(&mut ip).await?;
            std::net::Ipv4Addr::from(ip).to_string()
        }
        0x04 => {
            let mut ip = [0u8; 16];
            stream.read_exact(&mut ip).await?;
            std::net::Ipv6Addr::from(ip).to_string()
        }
        0x03 => {
            let mut name = vec![0u8; usize::from(stream.read_u8().await?)];
            stream.read_exact(&mut name).await?;
            String::from_utf8_lossy(&name).into_owned()
        }
        _ => {
            return write_reply(&mut stream, state, &[0x05, 0x08, 0, 1, 0, 0, 0, 0, 0, 0]).await;
        }
    };
    let port = stream.read_u16().await?;
    state.record(HostPort::format(&host, port));
    match state.script {
        Script::Refuse(code) => {
            let rep = u8::try_from(code).expect("a SOCKS5 REP fits a byte");
            write_reply(&mut stream, state, &[0x05, rep, 0, 1, 0, 0, 0, 0, 0, 0]).await
        }
        _ => {
            write_reply(&mut stream, state, &[0x05, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
            echo(stream).await
        }
    }
}

/// One CONNECT request head, read byte-wise up to 16 KiB.
async fn read_head<S>(stream: &mut S) -> io::Result<Vec<u8>>
where
    S: AsyncRead + Unpin,
{
    let mut head = Vec::new();
    while !head.ends_with(b"\r\n\r\n") {
        if head.len() >= 16 * 1024 {
            return Ok(head);
        }
        head.push(stream.read_u8().await?);
    }
    Ok(head)
}

/// The request line's target and the `Proxy-Authorization` value (lossy
/// UTF-8), if any.
fn parse_head(head: &[u8]) -> (String, Option<String>) {
    let text = String::from_utf8_lossy(head).into_owned();
    let mut lines = text.split("\r\n");
    let target = lines
        .next()
        .and_then(|line| line.strip_prefix("CONNECT "))
        .and_then(|rest| rest.split(' ').next())
        .unwrap_or_default()
        .to_owned();
    let authorization = text.split("\r\n").find_map(|line| {
        let (name, value) = line.split_once(':')?;
        name.eq_ignore_ascii_case("Proxy-Authorization")
            .then(|| value.trim().to_owned())
    });
    (target, authorization)
}

/// Strict `Basic` credential parse (mirrors the server rules): STANDARD
/// decoding, UTF-8, split at the first `:`, no empty or control characters.
#[cfg(feature = "secure-auth")]
fn parse_basic(value: &str) -> Option<(String, String)> {
    let raw = crate::http_auth::decode_token(value, crate::http_auth::BASIC)?;
    let text = String::from_utf8(raw).ok()?;
    let (user, password) = text.split_once(':')?;
    (!user.is_empty()
        && !password.is_empty()
        && !user.chars().any(char::is_control)
        && !password.chars().any(char::is_control))
    .then(|| (user.to_owned(), password.to_owned()))
}

/// Build a `407 Proxy Authentication Required` reply: one
/// `Proxy-Authenticate` header per entry, optionally `Connection: close`.
fn challenge_407(headers: &[String], close: bool) -> Vec<u8> {
    let mut reply = b"HTTP/1.1 407 Proxy Authentication Required\r\n".to_vec();
    for header in headers {
        reply.extend_from_slice(format!("Proxy-Authenticate: {header}\r\n").as_bytes());
    }
    if close {
        reply.extend_from_slice(b"Connection: close\r\n");
    }
    reply.extend_from_slice(b"Content-Length: 0\r\n\r\n");
    reply
}

/// The mock's script phase after an established HTTP tunnel: record the
/// target, then stay silent, refuse, or (writing the `200` when
/// `established` is false) echo.
async fn http_tunnel<S>(
    mut stream: S,
    state: &Shared,
    target: String,
    established: bool,
) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    state.record(target);
    match state.script {
        Script::SilentConnect => forever().await,
        Script::Refuse(code) => {
            let response = format!("HTTP/1.1 {code} Mock\r\nContent-Length: 0\r\n\r\n");
            write_reply(&mut stream, state, response.as_bytes()).await
        }
        _ => {
            if !established {
                write_reply(
                    &mut stream,
                    state,
                    b"HTTP/1.1 200 Connection established\r\n\r\n",
                )
                .await?;
            }
            echo(stream).await
        }
    }
}

/// The real secure-auth exchange over a [`crate::http_auth::Pipe`], fed by
/// successive 407 rounds. On success the tunnel `200` is written (carrying
/// the exchange's final `Proxy-Authenticate` token when present) and the
/// caller proceeds to the CONNECT phase; on failure a closing 407 with the
/// denial token (if any) is written.
#[cfg(feature = "secure-auth")]
async fn http_secure_exchange<S, U>(
    mut stream: S,
    state: &Shared,
    token: Vec<u8>,
    store: U,
) -> io::Result<bool>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
    U: crate::secure_auth::SecretStore,
{
    let pipe = crate::http_auth::Pipe::new();
    pipe.push(&token);
    let mut end = pipe.end();
    let exchange = crate::secure_auth::server_authenticate(&mut end, &store, &state.decoy);
    tokio::pin!(exchange);
    let mut rounds = 1;
    let result = loop {
        tokio::select! {
            biased;
            result = &mut exchange => break result,
            message = pipe.next_message() => {
                if rounds >= crate::http_auth::MAX_ROUNDS {
                    write_reply(&mut stream, state, &challenge_407(&[], true)).await?;
                    return Ok(false);
                }
                write_reply(
                    &mut stream,
                    state,
                    &challenge_407(
                        &[crate::http_auth::encode_token(crate::http_auth::SECURE, &message)],
                        false,
                    ),
                )
                .await?;
                let head = read_head(&mut stream).await?;
                let (_t, authz) = parse_head(&head);
                match authz
                    .as_deref()
                    .and_then(|v| crate::http_auth::decode_token(v, crate::http_auth::SECURE))
                {
                    Some(t) => pipe.push(&t),
                    None => pipe.close_input(),
                }
                rounds += 1;
            }
        }
    };
    match result {
        Ok(_) => {
            let mut reply = b"HTTP/1.1 200 Connection established\r\n".to_vec();
            if let Some(m) = pipe.take_message() {
                reply.extend_from_slice(
                    format!(
                        "Proxy-Authenticate: {}\r\n",
                        crate::http_auth::encode_token(crate::http_auth::SECURE, &m)
                    )
                    .as_bytes(),
                );
            }
            reply.extend_from_slice(b"\r\n");
            write_reply(&mut stream, state, &reply).await?;
            Ok(true)
        }
        Err(_) => {
            let headers = pipe
                .take_message()
                .map(|m| vec![crate::http_auth::encode_token(crate::http_auth::SECURE, &m)])
                .unwrap_or_default();
            write_reply(&mut stream, state, &challenge_407(&headers, true)).await?;
            Ok(false)
        }
    }
}

/// The mock's HTTP verdict for a request that carries no secure-auth token.
#[cfg_attr(not(feature = "secure-auth"), allow(dead_code))]
enum HttpVerdict {
    /// Authenticated (or auth-free): tunnel the CONNECT.
    Tunnel,
    /// Answer a keep-alive 407 listing these `Proxy-Authenticate` values
    /// (each a full header value, e.g. `Resocks5-Secure` or
    /// `Basic realm="mock"`).
    Challenge(Vec<String>),
    /// Answer a closing 407 listing these values.
    Refuse(Vec<String>),
}

/// The `Proxy-Authenticate` values the mock advertises for its auth mode.
#[cfg(feature = "secure-auth")]
fn http_challenges(auth: &MockAuth) -> Vec<String> {
    match auth {
        MockAuth::Secure { .. } | MockAuth::SecureDenied => vec![
            crate::http_auth::SECURE.to_owned(),
            "Basic realm=\"mock\"".to_owned(),
        ],
        MockAuth::Cleartext { .. } | MockAuth::AuthStatus(_) => {
            vec!["Basic realm=\"mock\"".to_owned()]
        }
        _ => Vec::new(),
    }
}

/// Clear-text HTTP verdict against `store`, verified through
/// `SecretStore::check_password`. A request with no `Proxy-Authorization`
/// header (the client's bare probe) is a keep-alive challenge so the client
/// can retry on the same connection; a present but malformed Basic token, or
/// a rejected credential, closes with a refusal.
#[cfg(feature = "secure-auth")]
async fn basic_verdict<U>(
    store: &U,
    authorization: Option<&str>,
    challenges: Vec<String>,
) -> HttpVerdict
where
    U: crate::secure_auth::SecretStore,
{
    let Some(value) = authorization else {
        return HttpVerdict::Challenge(challenges);
    };
    let Some((user, password)) = parse_basic(value) else {
        return HttpVerdict::Refuse(challenges);
    };
    match crate::secure_auth::SecretStore::check_password(store, &user, &password).await {
        crate::secure_auth::PasswordCheck::Accepted
        | crate::secure_auth::PasswordCheck::Claimed => HttpVerdict::Tunnel,
        crate::secure_auth::PasswordCheck::Rejected => HttpVerdict::Refuse(challenges),
    }
}

async fn serve_http<S: AsyncRead + AsyncWrite + Unpin + Send>(
    mut stream: S,
    state: &Shared,
) -> io::Result<()> {
    if state.script == Script::Hangup {
        return Ok(());
    }
    if state.script == Script::SilentGreeting {
        return forever().await;
    }
    for _ in 0..=crate::http_auth::MAX_ROUNDS {
        let head = read_head(&mut stream).await?;
        #[cfg_attr(not(feature = "secure-auth"), allow(unused_variables))]
        let (target, authorization) = parse_head(&head);
        #[cfg(feature = "secure-auth")]
        {
            // AuthStatus: answer the first secure round with [VERSION,
            // status] on a closing 407; otherwise challenge with `SECURE`.
            if let MockAuth::AuthStatus(status) = &state.auth {
                if authorization
                    .as_deref()
                    .and_then(|v| crate::http_auth::decode_token(v, crate::http_auth::SECURE))
                    .is_some()
                {
                    let token = crate::http_auth::encode_token(
                        crate::http_auth::SECURE,
                        &[crate::secure_auth::VERSION, *status],
                    );
                    return write_reply(&mut stream, state, &challenge_407(&[token], true)).await;
                }
                let challenges = [crate::http_auth::SECURE.to_owned()];
                write_reply(&mut stream, state, &challenge_407(&challenges, false)).await?;
                continue;
            }
            // Secure / SecureDenied with a secure token: run the real
            // exchange over a pipe (Secure: the mock's user; SecureDenied:
            // an empty store, so it always denies).
            if let Some(token) = authorization
                .as_deref()
                .and_then(|v| crate::http_auth::decode_token(v, crate::http_auth::SECURE))
            {
                if matches!(state.auth, MockAuth::Secure { .. } | MockAuth::SecureDenied) {
                    let tunneled = match (&state.auth, &state.user) {
                        (MockAuth::Secure { .. }, Some((user, secret))) => {
                            let store = MockUsers {
                                user: user.clone(),
                                secret: secret.clone(),
                            };
                            http_secure_exchange(&mut stream, state, token, store).await?
                        }
                        (MockAuth::SecureDenied, _) => {
                            http_secure_exchange(&mut stream, state, token, EmptyUsers).await?
                        }
                        _ => {
                            write_reply(&mut stream, state, &challenge_407(&[], true)).await?;
                            false
                        }
                    };
                    if tunneled {
                        http_tunnel(stream, state, target, true).await?;
                    }
                    return Ok(());
                }
            }
            // Clear-text path against the appropriate store.
            let verdict = match (&state.auth, &state.user) {
                (MockAuth::Secure { .. }, Some((name, secret))) => {
                    let store = MockUsers {
                        user: name.clone(),
                        secret: secret.clone(),
                    };
                    basic_verdict(
                        &store,
                        authorization.as_deref(),
                        http_challenges(&state.auth),
                    )
                    .await
                }
                (MockAuth::Secure { .. }, None) => {
                    HttpVerdict::Refuse(http_challenges(&state.auth))
                }
                (MockAuth::SecureDenied, _) => {
                    basic_verdict(
                        &EmptyUsers,
                        authorization.as_deref(),
                        http_challenges(&state.auth),
                    )
                    .await
                }
                (MockAuth::Cleartext { .. }, Some((name, secret))) => {
                    let store = MockUsers {
                        user: name.clone(),
                        secret: secret.clone(),
                    };
                    basic_verdict(
                        &store,
                        authorization.as_deref(),
                        http_challenges(&state.auth),
                    )
                    .await
                }
                // Impossible by construction: fail closed.
                (MockAuth::Cleartext { .. }, None) => {
                    HttpVerdict::Refuse(http_challenges(&state.auth))
                }
                (MockAuth::NoAcceptableMethod, _) => HttpVerdict::Refuse(Vec::new()),
                // AuthStatus answers only a secure token (handled above); any
                // other request is refused with the secure challenge.
                (MockAuth::AuthStatus(_), _) => HttpVerdict::Refuse(http_challenges(&state.auth)),
                (MockAuth::None, _) => HttpVerdict::Tunnel,
            };
            match verdict {
                HttpVerdict::Tunnel => {
                    http_tunnel(stream, state, target, false).await?;
                    return Ok(());
                }
                HttpVerdict::Challenge(headers) => {
                    write_reply(&mut stream, state, &challenge_407(&headers, false)).await?;
                }
                HttpVerdict::Refuse(headers) => {
                    return write_reply(&mut stream, state, &challenge_407(&headers, true)).await;
                }
            }
        }
        #[cfg(not(feature = "secure-auth"))]
        {
            match &state.auth {
                MockAuth::None => {
                    http_tunnel(stream, state, target, false).await?;
                    return Ok(());
                }
                MockAuth::NoAcceptableMethod => {
                    return write_reply(&mut stream, state, &challenge_407(&[], true)).await;
                }
            }
        }
    }
    // Too many rounds.
    write_reply(&mut stream, state, &challenge_407(&[], true)).await
}

/// The RFC 1929 server side against the mock's one user, verified through
/// `SecretStore::check_password` like a real server. `false` = denied (the
/// failure status was written).
#[cfg(feature = "secure-auth")]
async fn socks5_cleartext_server<S>(stream: &mut S, state: &Shared) -> io::Result<bool>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    const FAILURE: &[u8; 2] = &[1, 1];
    let Some((name, secret)) = state.user.clone() else {
        write_reply(stream, state, FAILURE).await?;
        return Ok(false);
    };
    let mut header = [0u8; 2];
    stream.read_exact(&mut header).await?;
    if header[0] != 1 || header[1] == 0 {
        write_reply(stream, state, FAILURE).await?;
        return Ok(false);
    }
    let mut user = vec![0u8; usize::from(header[1])];
    stream.read_exact(&mut user).await?;
    let mut plen = [0u8; 1];
    stream.read_exact(&mut plen).await?;
    if plen[0] == 0 {
        write_reply(stream, state, FAILURE).await?;
        return Ok(false);
    }
    let mut password = vec![0u8; usize::from(plen[0])];
    stream.read_exact(&mut password).await?;
    let (Ok(user), Ok(password)) = (String::from_utf8(user), String::from_utf8(password)) else {
        write_reply(stream, state, FAILURE).await?;
        return Ok(false);
    };
    let store = MockUsers { user: name, secret };
    match crate::secure_auth::SecretStore::check_password(&store, &user, &password).await {
        crate::secure_auth::PasswordCheck::Accepted
        | crate::secure_auth::PasswordCheck::Claimed => {
            write_reply(stream, state, &[1, 0]).await?;
            Ok(true)
        }
        crate::secure_auth::PasswordCheck::Rejected => {
            write_reply(stream, state, FAILURE).await?;
            Ok(false)
        }
    }
}

#[cfg(feature = "secure-auth")]
struct EmptyUsers;

#[cfg(feature = "secure-auth")]
impl crate::secure_auth::SecretStore for EmptyUsers {
    async fn lookup(&self, _user: &str) -> Option<crate::secure_auth::StoredUser> {
        None
    }

    async fn claim(&self, _user: &str, _secret: crate::secure_auth::UserSecret) -> bool {
        false
    }
}

/// The mock's single user as a [`SecretStore`]: `lookup` answers only this
/// name, `claim` never succeeds (the user is already enrolled).
#[cfg(feature = "secure-auth")]
struct MockUsers {
    user: String,
    secret: crate::secure_auth::UserSecret,
}

#[cfg(feature = "secure-auth")]
impl crate::secure_auth::SecretStore for MockUsers {
    async fn lookup(&self, user: &str) -> Option<crate::secure_auth::StoredUser> {
        (user == self.user).then(|| crate::secure_auth::StoredUser::Secret(self.secret.clone()))
    }

    async fn claim(&self, _user: &str, _secret: crate::secure_auth::UserSecret) -> bool {
        false
    }
}

#[cfg(test)]
mod tests;
