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

use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
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
    /// No authentication (SOCKS5 method 0x00; HTTP ignores credentials).
    None,
    /// Secure auth (SOCKS5 method 0x80) against this one user; HTTP answers
    /// every CONNECT with 407.
    #[cfg(feature = "secure-auth")]
    Secure {
        /// The user name.
        user: String,
        /// Its stored secret.
        secret: crate::secure_auth::UserSecret,
    },
}

impl std::fmt::Debug for MockAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::None => "MockAuth::None",
            #[cfg(feature = "secure-auth")]
            Self::Secure { .. } => "MockAuth::Secure { .. }",
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

    /// Bind `127.0.0.1:0` and start serving.
    ///
    /// # Errors
    ///
    /// The bind error; for secure auth, a failing OS random source.
    pub async fn spawn(self) -> io::Result<MockUpstream> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let state = Arc::new(Shared {
            auth: self.auth,
            script: self.script,
            targets: Mutex::new(Vec::new()),
            connections: AtomicUsize::new(0),
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
                }
            }
        });
        Ok(MockUpstream {
            addr,
            protocol,
            state,
            task,
        })
    }
}

struct Shared {
    auth: MockAuth,
    script: Script,
    targets: Mutex<Vec<String>>,
    connections: AtomicUsize,
    #[cfg(feature = "secure-auth")]
    decoy: crate::secure_auth::DecoyKey,
}

impl Shared {
    fn record(&self, target: String) {
        self.targets.lock().expect("targets lock").push(target);
    }
}

/// A running scripted upstream; see the module docs.
#[derive(Debug)]
pub struct MockUpstream {
    addr: SocketAddr,
    protocol: ProxyProtocol,
    state: Arc<Shared>,
    task: JoinHandle<()>,
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
        }
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

    /// The TCP connections accepted so far.
    pub fn connections(&self) -> usize {
        self.state.connections.load(Ordering::SeqCst)
    }
}

impl Drop for MockUpstream {
    fn drop(&mut self) {
        // Aborting the accept loop drops its JoinSet, which aborts every
        // connection task.
        self.task.abort();
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

async fn serve_socks5(mut stream: TcpStream, state: &Shared) -> io::Result<()> {
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
    let wanted = match &state.auth {
        MockAuth::None => 0x00,
        #[cfg(feature = "secure-auth")]
        MockAuth::Secure { .. } => crate::secure_auth::METHOD,
    };
    if !methods.contains(&wanted) {
        return stream.write_all(&[0x05, 0xFF]).await;
    }
    stream.write_all(&[0x05, wanted]).await?;
    match &state.auth {
        MockAuth::None => {}
        #[cfg(feature = "secure-auth")]
        MockAuth::Secure { user, secret } => {
            let store = OneUser { user, secret };
            if crate::secure_auth::server_authenticate(&mut stream, &store, &state.decoy)
                .await
                .is_err()
            {
                return Ok(());
            }
        }
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
            return stream
                .write_all(&[0x05, 0x08, 0, 1, 0, 0, 0, 0, 0, 0])
                .await
        }
    };
    let port = stream.read_u16().await?;
    state.record(HostPort::format(&host, port));
    match state.script {
        Script::Refuse(code) => {
            let rep = u8::try_from(code).expect("a SOCKS5 REP fits a byte");
            stream.write_all(&[0x05, rep, 0, 1, 0, 0, 0, 0, 0, 0]).await
        }
        _ => {
            stream
                .write_all(&[0x05, 0x00, 0, 1, 0, 0, 0, 0, 0, 0])
                .await?;
            echo(stream).await
        }
    }
}

async fn serve_http(mut stream: TcpStream, state: &Shared) -> io::Result<()> {
    if state.script == Script::Hangup {
        return Ok(());
    }
    if state.script == Script::SilentGreeting {
        return forever().await;
    }
    let mut head = Vec::new();
    while !head.ends_with(b"\r\n\r\n") {
        if head.len() >= 16 * 1024 {
            return Ok(());
        }
        head.push(stream.read_u8().await?);
    }
    let text = String::from_utf8_lossy(&head).into_owned();
    let mut lines = text.split("\r\n");
    let target = lines
        .next()
        .and_then(|line| line.strip_prefix("CONNECT "))
        .and_then(|rest| rest.split(' ').next())
        .unwrap_or_default()
        .to_owned();
    let authorized = match &state.auth {
        MockAuth::None => true,
        #[cfg(feature = "secure-auth")]
        MockAuth::Secure { .. } => false,
    };
    if !authorized {
        return stream
            .write_all(b"HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 0\r\n\r\n")
            .await;
    }
    state.record(target);
    match state.script {
        Script::SilentConnect => forever().await,
        Script::Refuse(code) => {
            stream
                .write_all(format!("HTTP/1.1 {code} Mock\r\nContent-Length: 0\r\n\r\n").as_bytes())
                .await
        }
        _ => {
            stream
                .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                .await?;
            echo(stream).await
        }
    }
}

#[cfg(feature = "secure-auth")]
struct OneUser<'a> {
    user: &'a str,
    secret: &'a crate::secure_auth::UserSecret,
}

#[cfg(feature = "secure-auth")]
impl crate::secure_auth::SecretStore for OneUser<'_> {
    async fn lookup(&self, user: &str) -> Option<crate::secure_auth::StoredUser> {
        (user == self.user).then(|| crate::secure_auth::StoredUser::Secret(self.secret.clone()))
    }

    async fn claim(&self, _user: &str, _secret: crate::secure_auth::UserSecret) -> bool {
        false
    }
}

#[cfg(test)]
mod tests;
