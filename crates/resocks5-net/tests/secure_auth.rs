//! Secure auth end to end through the public API: an SDK client dials an
//! `accept_secure` server; the password is never on the wire, a first login
//! enrolls an `init` user, and the policy switches refuse every weak method.

#![cfg(feature = "secure-auth")]

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use resocks5_net::connect::{dial, DialOptions};
use resocks5_net::secure_auth::{
    DecoyKey, KdfParams, SecretStore, SecureCredentials, StoredUser, UserSecret,
};
use resocks5_net::server::{accept_secure, Reply, ServerError, ServerOptions};
use resocks5_net::types::ProxyConfig;
use resocks5_net::ConnectError;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{timeout, Instant};

/// Cheap parameters: the default 19 MiB would dominate the test time.
const WEAK: KdfParams = KdfParams {
    memory_kib: 64,
    iterations: 1,
    parallelism: 1,
};

#[derive(Default)]
struct Store(Mutex<HashMap<String, StoredUser>>);

impl Store {
    fn enrolled(user: &str, password: &str) -> Arc<Self> {
        let store = Self::default();
        store.0.lock().unwrap().insert(
            user.to_owned(),
            StoredUser::Secret(UserSecret::from_password(password, WEAK).unwrap()),
        );
        Arc::new(store)
    }

    fn waiting(user: &str) -> Arc<Self> {
        let store = Self::default();
        store
            .0
            .lock()
            .unwrap()
            .insert(user.to_owned(), StoredUser::Init);
        Arc::new(store)
    }

    fn is_enrolled(&self, user: &str) -> bool {
        matches!(
            self.0.lock().unwrap().get(user),
            Some(StoredUser::Secret(_))
        )
    }
}

impl SecretStore for Store {
    async fn lookup(&self, user: &str) -> Option<StoredUser> {
        self.0.lock().unwrap().get(user).cloned()
    }

    async fn claim(&self, user: &str, secret: UserSecret) -> bool {
        let mut map = self.0.lock().unwrap();
        if matches!(map.get(user), Some(StoredUser::Init)) {
            map.insert(user.to_owned(), StoredUser::Secret(secret));
            true
        } else {
            false
        }
    }

    fn enrollment_floor(&self) -> KdfParams {
        WEAK
    }
}

/// A one-connection `accept_secure` server: authenticates, replies
/// Established and echoes `pong:` + what it reads. Every byte the client sends
/// is also recorded.
async fn serve_once(
    store: Arc<Store>,
) -> (u16, tokio::task::JoinHandle<(Option<String>, Vec<u8>)>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let task = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        let recorded = Arc::new(Mutex::new(Vec::new()));
        let mut socket = Recorder {
            inner: socket,
            log: Arc::clone(&recorded),
        };
        let decoy = DecoyKey::generate().unwrap();
        let options =
            ServerOptions::new(Instant::now() + Duration::from_secs(10)).allow_cleartext(false);
        let user = match accept_secure(&mut socket, &options, &*store, &decoy).await {
            Ok(request) => {
                request
                    .reply(&mut socket, Reply::Established)
                    .await
                    .unwrap();
                let mut ping = [0u8; 4];
                socket.read_exact(&mut ping).await.unwrap();
                socket.write_all(b"pong:").await.unwrap();
                socket.write_all(&ping).await.unwrap();
                request.username().map(str::to_owned)
            }
            Err(_) => None,
        };
        let log = recorded.lock().unwrap().clone();
        (user, log)
    });
    (port, task)
}

/// Records everything read from the client.
struct Recorder {
    inner: TcpStream,
    log: Arc<Mutex<Vec<u8>>>,
}

impl tokio::io::AsyncRead for Recorder {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        let poll = std::pin::Pin::new(&mut self.inner).poll_read(cx, buf);
        let new = buf.filled()[before..].to_vec();
        self.log.lock().unwrap().extend_from_slice(&new);
        poll
    }
}

impl tokio::io::AsyncWrite for Recorder {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.inner).poll_write(cx, buf)
    }
    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

async fn ping(proxy: &ProxyConfig) -> Result<Vec<u8>, ConnectError> {
    let mut stream = dial(proxy, "example.test", 443, &DialOptions::new(), None).await?;
    stream.write_all(b"ping").await.unwrap();
    let mut answer = [0u8; 9];
    stream.read_exact(&mut answer).await.unwrap();
    Ok(answer.to_vec())
}

/// A secure-auth upstream: the dial authenticates, the tunnel works, and the
/// password never reaches the server. Mutation: falling back to UNAME/PASSWD
/// puts the password into the recorded bytes.
#[tokio::test]
async fn dial_through_a_secure_upstream_never_sends_the_password() {
    timeout(Duration::from_secs(20), async {
        let password = "the-password-that-stays-home";
        let (port, server) = serve_once(Store::enrolled("alice", password)).await;
        let proxy = ProxyConfig::socks5("127.0.0.1", port)
            .with_secure_auth(SecureCredentials::new("alice", password).with_min_kdf(WEAK));
        assert_eq!(ping(&proxy).await.unwrap(), b"pong:ping");
        let (user, received) = server.await.unwrap();
        assert_eq!(user.as_deref(), Some("alice"));
        assert!(
            !contains(&received, password.as_bytes()),
            "password reached the server"
        );
        assert!(!contains(&received, &[5, 1, 2]), "no UNAME/PASSWD greeting");
    })
    .await
    .expect("bounded secure dial");
}

/// A wrong password fails the dial with a typed secure-auth error.
#[tokio::test]
async fn a_wrong_password_fails_the_dial() {
    timeout(Duration::from_secs(20), async {
        let (port, server) = serve_once(Store::enrolled("alice", "right")).await;
        let proxy = ProxyConfig::socks5("127.0.0.1", port)
            .with_secure_auth(SecureCredentials::new("alice", "wrong").with_min_kdf(WEAK));
        let error = ping(&proxy).await.unwrap_err();
        assert!(
            matches!(
                error,
                ConnectError::SecureAuth(resocks5_net::SecureAuthError::Denied)
            ),
            "{error:?}"
        );
        assert_eq!(server.await.unwrap().0, None);
    })
    .await
    .expect("bounded wrong-password dial");
}

/// The first dial of an `init` user enrolls it; the next dial (a fresh
/// client) logs in with the same password. Mutation: no claim, or a claim
/// the next login cannot verify, fails one of the two dials.
#[tokio::test]
async fn the_first_dial_enrolls_an_init_user() {
    timeout(Duration::from_secs(30), async {
        let store = Store::waiting("bob");
        let (port, server) = serve_once(Arc::clone(&store)).await;
        let proxy = ProxyConfig::socks5("127.0.0.1", port).with_secure_auth(
            SecureCredentials::new("bob", "bobs-pw")
                .with_min_kdf(WEAK)
                .allow_enrollment(true)
                .with_enrollment_kdf(WEAK),
        );
        assert_eq!(ping(&proxy).await.unwrap(), b"pong:ping");
        let (_, received) = server.await.unwrap();
        assert!(
            !contains(&received, b"bobs-pw"),
            "the password reached the server"
        );
        assert!(store.is_enrolled("bob"));

        let (port, server) = serve_once(Arc::clone(&store)).await;
        let proxy = ProxyConfig::socks5("127.0.0.1", port)
            .with_secure_auth(SecureCredentials::new("bob", "bobs-pw").with_min_kdf(WEAK));
        assert_eq!(ping(&proxy).await.unwrap(), b"pong:ping");
        assert_eq!(server.await.unwrap().0.as_deref(), Some("bob"));
    })
    .await
    .expect("bounded enrollment dial");
}

/// `accept_secure` with `secure_only` options never takes a clear-text
/// password: SOCKS5 method 0x02 is not offered and HTTP Basic is a 407.
/// Mutation: delegating to a clear-text path accepts them.
#[tokio::test]
async fn secure_only_options_refuse_cleartext_on_accept_secure() {
    timeout(Duration::from_secs(10), async {
        let store = Store::enrolled("alice", "pw");
        for request in [
            b"\x05\x01\x02".to_vec(),
            b"CONNECT example.test:443 HTTP/1.1\r\nProxy-Authorization: Basic YWxpY2U6cHc=\r\n\r\n"
                .to_vec(),
        ] {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let port = listener.local_addr().unwrap().port();
            let store = Arc::clone(&store);
            let server = tokio::spawn(async move {
                let (mut socket, _) = listener.accept().await.unwrap();
                let decoy = DecoyKey::generate().unwrap();
                let options =
                    ServerOptions::new(Instant::now() + Duration::from_secs(5)).secure_only();
                accept_secure(&mut socket, &options, &*store, &decoy).await
            });
            let mut client = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
            client.write_all(&request).await.unwrap();
            let mut answer = Vec::new();
            let _ = client.read_to_end(&mut answer).await;
            let error = server.await.unwrap().unwrap_err();
            assert!(matches!(error, ServerError::Authentication(_)), "{error:?}");
            if request[0] == 5 {
                assert_eq!(answer, [5, 255], "method 0x02 must not be chosen");
            } else {
                assert!(
                    answer.starts_with(b"HTTP/1.1 407 "),
                    "{:?}",
                    String::from_utf8_lossy(&answer)
                );
                assert!(
                    answer.windows(17).any(|w| w == b"Resocks5-Secure"),
                    "the strong scheme must still be offered"
                );
                assert!(
                    !answer.windows(5).any(|w| w == b"Basic"),
                    "no Basic challenge: {:?}",
                    String::from_utf8_lossy(&answer)
                );
            }
        }
    })
    .await
    .expect("bounded clear-text refusal");
}

/// With the defaults, `accept_secure` accepts Basic against the SAME store:
/// the correct password succeeds (identity `alice`, method Cleartext) and a
/// wrong one is a closing 407. Mutation: verifying Basic against a separate
/// secret store (or skipping the check) breaks one branch.
#[tokio::test]
async fn accept_secure_accepts_basic_against_the_same_store() {
    timeout(Duration::from_secs(10), async {
        let store = Store::enrolled("alice", "pw");
        let run = |password: &'static str| {
            let store = Arc::clone(&store);
            async move {
                let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
                let port = listener.local_addr().unwrap().port();
                let server = tokio::spawn(async move {
                    let (mut socket, _) = listener.accept().await.unwrap();
                    let decoy = DecoyKey::generate().unwrap();
                    let options = ServerOptions::new(Instant::now() + Duration::from_secs(5));
                    accept_secure(&mut socket, &options, &*store, &decoy).await
                });
                let header = format!(
                    "CONNECT example.test:443 HTTP/1.1\r\nProxy-Authorization: Basic {}\r\n\r\n",
                    base64_of(&format!("alice:{password}")),
                );
                let mut client = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
                client.write_all(header.as_bytes()).await.unwrap();
                let mut answer = Vec::new();
                let _ = client.read_to_end(&mut answer).await;
                (server.await.unwrap(), answer)
            }
        };

        let (request, answer) = run("pw").await;
        let request = request.unwrap();
        assert_eq!(request.username(), Some("alice"));
        assert_eq!(
            request.auth_method(),
            resocks5_net::server::AuthMethod::Cleartext
        );
        assert!(answer.is_empty(), "no reply before the host's: {answer:?}");

        let (result, answer) = run("wrong").await;
        assert!(matches!(result, Err(ServerError::Authentication(_))));
        assert!(
            answer.starts_with(b"HTTP/1.1 407 "),
            "{:?}",
            String::from_utf8_lossy(&answer)
        );
    })
    .await
    .expect("bounded Basic acceptance");
}

/// RFC 4648 base64 of `text`, padding included.
fn base64_of(text: &str) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let bytes = text.as_bytes();
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        out.push(TABLE[(n >> 18) as usize & 63] as char);
        out.push(TABLE[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 {
            TABLE[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            TABLE[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}
