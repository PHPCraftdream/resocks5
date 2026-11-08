//! Authentication policy at the inbound and dial edges: clear text is a
//! runtime policy (`allow_cleartext`), anonymous access is off by default,
//! `secure_only` refuses everything but method 0x80, and one stored secret
//! verifies every protocol and method (the successor of `no_cleartext.rs`).
//!
//! Integration tests link the library without `cfg(test)`, so these run
//! against the real build. Requires feature `secure-auth` (the mock-free
//! policy under test only exists with it).
#![cfg(feature = "secure-auth")]

mod server_side {
    use std::sync::Arc;
    use std::time::Duration;

    use resocks5_net::connect::{dial, DialOptions};
    use resocks5_net::secure_auth::{
        DecoyKey, KdfParams, SecretStore, SecureCredentials, StoredUser, UserSecret,
    };
    use resocks5_net::server::{
        accept, accept_with, AuthMethod, AuthMethods, IncomingRequest, Reply, ServerError,
        ServerOptions,
    };
    use resocks5_net::types::ProxyConfig;
    use resocks5_net::ConnectError;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};
    use tokio::time::{timeout, Instant};

    /// Cheap parameters: the default 19 MiB would be noticeable across
    /// many logins, and the fixture is not a policy.
    pub(super) const WEAK: KdfParams = KdfParams {
        memory_kib: 64,
        iterations: 1,
        parallelism: 1,
    };

    pub(super) fn deadline() -> Instant {
        Instant::now() + Duration::from_secs(10)
    }

    #[derive(Default)]
    pub(super) struct Store(std::sync::Mutex<std::collections::HashMap<String, StoredUser>>);

    impl Store {
        pub(super) fn enrolled_at(user: &str, password: &str, params: KdfParams) -> Arc<Self> {
            let store = Self::default();
            store.0.lock().unwrap().insert(
                user.to_owned(),
                StoredUser::Secret(UserSecret::from_password(password, params).unwrap()),
            );
            Arc::new(store)
        }

        fn enrolled(user: &str, password: &str) -> Arc<Self> {
            Self::enrolled_at(user, password, WEAK)
        }

        pub(super) fn waiting(user: &str) -> Arc<Self> {
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

    /// What one served connection ended up as (`auth: None` = refused).
    #[derive(Debug)]
    pub(super) struct Served {
        pub(super) username: Option<String>,
        pub(super) auth: Option<AuthMethod>,
        /// Why the connection was refused (`None` when it was admitted).
        pub(super) error: Option<ServerError>,
    }

    /// One-connection `accept_with` server on `127.0.0.1:0`: authenticates,
    /// replies Established, optionally echoes `pong:` + payload. `echo` is
    /// off for HTTP clients that never send a payload.
    pub(super) async fn serve_once(
        store: Arc<Store>,
        options: ServerOptions,
        echo: bool,
    ) -> (u16, tokio::task::JoinHandle<Served>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let task = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let decoy = DecoyKey::generate_with(WEAK).unwrap();
            match accept_with(&mut socket, &options, &AuthMethods::secure(&*store, &decoy)).await {
                Ok(request) => {
                    request
                        .reply(&mut socket, Reply::Established)
                        .await
                        .unwrap();
                    if echo {
                        let mut ping = [0u8; 4];
                        socket.read_exact(&mut ping).await.unwrap();
                        socket.write_all(b"pong:").await.unwrap();
                        socket.write_all(&ping).await.unwrap();
                    }
                    Served {
                        username: request.username().map(str::to_owned),
                        auth: Some(request.auth_method()),
                        error: None,
                    }
                }
                Err(error) => Served {
                    username: None,
                    auth: None,
                    error: Some(error),
                },
            }
        });
        (port, task)
    }

    /// SOCKS5 greeting offering `methods` alone. A refusal test sends only this:
    /// bytes the server never reads make its close a TCP reset, and Windows
    /// then drops the `[5, 255]` answer the client has not read yet.
    fn socks_greeting(methods: &[u8]) -> Vec<u8> {
        socks_connect(methods)[..2 + methods.len()].to_vec()
    }

    /// SOCKS5 greeting offering `methods`, then a CONNECT to `example.test:443`.
    fn socks_connect(methods: &[u8]) -> Vec<u8> {
        let mut bytes = vec![5, u8::try_from(methods.len()).unwrap()];
        bytes.extend_from_slice(methods);
        bytes.extend_from_slice(&[5, 1, 0, 3, 12]);
        bytes.extend_from_slice(b"example.test");
        bytes.extend_from_slice(&443u16.to_be_bytes());
        bytes
    }

    /// RFC 1929 username/password sub-negotiation.
    fn rfc1929(user: &str, password: &str) -> Vec<u8> {
        let mut bytes = vec![1u8, user.len() as u8];
        bytes.extend_from_slice(user.as_bytes());
        bytes.push(password.len() as u8);
        bytes.extend_from_slice(password.as_bytes());
        bytes
    }

    const ESTABLISHED: &[u8] = &[5, 0, 0, 1, 0, 0, 0, 0, 0, 0];

    /// The keep-alive challenge of a users-configured server with defaults
    /// (secure enabled, clear text allowed, anonymous off).
    const KEEPALIVE_407: &[u8] = b"HTTP/1.1 407 Proxy Authentication Required\r\n\
Proxy-Authenticate: Resocks5-Secure\r\n\
Proxy-Authenticate: Basic realm=\"resocks5\"\r\n\
Content-Length: 0\r\n\r\n";

    /// The closing refusal of a server that accepts only the strong method.
    const CLOSE_407_SECURE_ONLY: &[u8] = b"HTTP/1.1 407 Proxy Authentication Required\r\n\
Proxy-Authenticate: Resocks5-Secure\r\n\
Connection: close\r\n\
Content-Length: 0\r\n\r\n";

    fn is_authentication(error: &ServerError) -> bool {
        matches!(error, ServerError::Authentication(_))
    }

    async fn ping(proxy: &ProxyConfig) -> Result<Vec<u8>, ConnectError> {
        let mut stream = dial(proxy, "example.test", 443, &DialOptions::new(), None).await?;
        stream.write_all(b"ping").await.unwrap();
        let mut answer = [0u8; 9];
        stream.read_exact(&mut answer).await.unwrap();
        Ok(answer.to_vec())
    }

    /// Clear text is a runtime policy: with the defaults (anonymous off, clear
    /// text on) a raw client logs in with RFC 1929 and gets a tunnel.
    /// Mutation: flipping `allow_cleartext(false)` answers `[5, 255]`.
    #[tokio::test]
    async fn cleartext_is_runtime_policy() {
        timeout(Duration::from_secs(20), async {
            let store = Store::enrolled("alice", "pw");
            let (port, server) = serve_once(store, ServerOptions::new(deadline()), true).await;
            let mut client = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
            client.write_all(&[5, 1, 2]).await.unwrap();
            let mut pick = [0u8; 2];
            client.read_exact(&mut pick).await.unwrap();
            assert_eq!(pick, [5, 2]);
            client.write_all(&rfc1929("alice", "pw")).await.unwrap();
            let mut status = [0u8; 2];
            client.read_exact(&mut status).await.unwrap();
            assert_eq!(status, [1, 0]);
            client
                .write_all(&[
                    5,
                    1,
                    0,
                    3,
                    12,
                    b'e',
                    b'x',
                    b'a',
                    b'm',
                    b'p',
                    b'l',
                    b'e',
                    b'.',
                    b't',
                    b'e',
                    b's',
                    b't',
                    443u16.to_be_bytes()[0],
                    443u16.to_be_bytes()[1],
                ])
                .await
                .unwrap();
            let mut established = [0u8; 10];
            client.read_exact(&mut established).await.unwrap();
            assert_eq!(established, ESTABLISHED);
            client.write_all(b"ping").await.unwrap();
            let mut answer = [0u8; 9];
            client.read_exact(&mut answer).await.unwrap();
            assert_eq!(&answer, b"pong:ping");
            let served = server.await.unwrap();
            assert_eq!(served.username.as_deref(), Some("alice"));
            assert_eq!(served.auth, Some(AuthMethod::Cleartext));
        })
        .await
        .expect("bounded clear-text login");
    }

    /// With clear text disabled (and anonymous off, i.e. `secure_only`) every
    /// weak method is refused: the SOCKS5 greeting answers `[5, 255]` and an
    /// HTTP Basic request is a closing 407 that lists only the strong scheme.
    /// Mutation: allowing clear text answers `[5, 2]` / accepts Basic.
    #[tokio::test]
    async fn cleartext_disabled_refuses_every_weak_method() {
        timeout(Duration::from_secs(20), async {
            let store = Store::enrolled("alice", "pw");
            let options = ServerOptions::new(deadline()).allow_cleartext(false);

            let (port, server) = serve_once(Arc::clone(&store), options, false).await;
            let mut client = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
            client.write_all(&[5, 1, 2]).await.unwrap();
            let mut answer = Vec::new();
            let _ = client.read_to_end(&mut answer).await;
            assert_eq!(answer, [5, 255]);
            assert!(is_authentication(
                server
                    .await
                    .unwrap()
                    .error
                    .as_ref()
                    .expect("the server refused"),
            ));

            let (port, server) = serve_once(Arc::clone(&store), options, false).await;
            let mut client = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
            client
                .write_all(
                    b"CONNECT example.test:443 HTTP/1.1\r\n\
                      Proxy-Authorization: Basic dXNlcjpwYXNz\r\n\r\n",
                )
                .await
                .unwrap();
            let mut answer = Vec::new();
            let _ = client.read_to_end(&mut answer).await;
            assert_eq!(answer, CLOSE_407_SECURE_ONLY);
            assert!(is_authentication(
                server
                    .await
                    .unwrap()
                    .error
                    .as_ref()
                    .expect("the server refused"),
            ));
        })
        .await
        .expect("bounded clear-text refusal");
    }

    /// Anonymous access is a separate, off-by-default switch: enabled, a
    /// client offering only method 0x00 is served with no identity; disabled
    /// (the default), the same greeting is refused.
    /// Mutation: defaulting `allow_anonymous` to on hands out anonymous
    /// tunnels without a configuration step.
    #[tokio::test]
    async fn anonymous_only_when_enabled() {
        timeout(Duration::from_secs(20), async {
            let store = Store::enrolled("alice", "pw");
            let options = ServerOptions::new(deadline()).allow_anonymous(true);
            let (port, server) = serve_once(store, options, false).await;
            let mut client = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
            client.write_all(&socks_connect(&[0])).await.unwrap();
            let mut pick = [0u8; 2];
            client.read_exact(&mut pick).await.unwrap();
            assert_eq!(pick, [5, 0]);
            let mut established = [0u8; 10];
            client.read_exact(&mut established).await.unwrap();
            assert_eq!(established, ESTABLISHED);
            let served = server.await.unwrap();
            assert_eq!(served.username, None);
            assert_eq!(served.auth, Some(AuthMethod::Anonymous));

            let store = Store::enrolled("alice", "pw");
            let (port, server) = serve_once(store, ServerOptions::new(deadline()), false).await;
            let mut client = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
            client.write_all(&socks_greeting(&[0])).await.unwrap();
            let mut answer = Vec::new();
            let _ = client.read_to_end(&mut answer).await;
            assert_eq!(answer, [5, 255]);
            assert!(server.await.unwrap().auth.is_none());
        })
        .await
        .expect("bounded anonymous policy");
    }

    /// `secure_only` refuses method 0x02, method 0x00 and HTTP Basic (a
    /// closing 407 naming only Resocks5-Secure), while a real 0x80 client
    /// sails through. Mutation: leaving clear text enabled answers
    /// `[5, 2]` and tunnels a raw UNAME/PASSWD client.
    #[tokio::test]
    async fn secure_only_server_accepts_only_the_strong_method() {
        timeout(Duration::from_secs(20), async {
            let options = ServerOptions::new(deadline()).secure_only();

            for greeting in [&[2u8][..], &[0u8][..]] {
                let store = Store::enrolled("alice", "pw");
                let (port, server) = serve_once(store, options, false).await;
                let mut client = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
                client.write_all(&socks_greeting(greeting)).await.unwrap();
                let mut answer = Vec::new();
                let _ = client.read_to_end(&mut answer).await;
                assert_eq!(answer, [5, 255], "greeting {greeting:?}");
                assert!(server.await.unwrap().auth.is_none());
            }

            let store = Store::enrolled("alice", "pw");
            let (port, server) = serve_once(store, options, false).await;
            let mut client = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
            client
                .write_all(
                    b"CONNECT example.test:443 HTTP/1.1\r\n\
                      Proxy-Authorization: Basic YWxpY2U6cHc=\r\n\r\n",
                )
                .await
                .unwrap();
            let mut answer = Vec::new();
            let _ = client.read_to_end(&mut answer).await;
            assert_eq!(answer, CLOSE_407_SECURE_ONLY);
            assert!(is_authentication(
                server
                    .await
                    .unwrap()
                    .error
                    .as_ref()
                    .expect("the server refused"),
            ));

            let store = Store::enrolled("alice", "pw");
            let (port, server) = serve_once(store, options, true).await;
            let proxy = ProxyConfig::socks5("127.0.0.1", port)
                .with_secure_auth(SecureCredentials::new("alice", "pw").with_min_kdf(WEAK));
            assert_eq!(ping(&proxy).await.unwrap(), b"pong:ping");
            let served = server.await.unwrap();
            assert_eq!(served.username.as_deref(), Some("alice"));
            assert_eq!(served.auth, Some(AuthMethod::Secure));
        })
        .await
        .expect("bounded secure-only server");
    }

    /// A standard HTTP client is challenged with a keep-alive 407 listing
    /// every enabled scheme, and its Basic retry on the SAME connection
    /// tunnels. Mutation: answering the probe with `Connection: close`
    /// strands the retry (Io error).
    #[tokio::test]
    async fn a_standard_client_retries_on_the_challenge() {
        timeout(Duration::from_secs(20), async {
            let store = Store::enrolled("alice", "pw");
            let (port, server) = serve_once(store, ServerOptions::new(deadline()), false).await;
            let mut client = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
            client
                .write_all(b"CONNECT example.test:443 HTTP/1.1\r\n\r\n")
                .await
                .unwrap();
            let mut challenge = [0u8; KEEPALIVE_407.len()];
            client.read_exact(&mut challenge).await.unwrap();
            assert_eq!(&challenge, KEEPALIVE_407);
            client
                .write_all(
                    b"CONNECT example.test:443 HTTP/1.1\r\n\
                      Proxy-Authorization: Basic YWxpY2U6cHc=\r\n\r\n",
                )
                .await
                .unwrap();
            let mut ok = [0u8; b"HTTP/1.1 200 Connection Established\r\n\r\n".len()];
            client.read_exact(&mut ok).await.unwrap();
            assert_eq!(&ok, b"HTTP/1.1 200 Connection Established\r\n\r\n");
            let served = server.await.unwrap();
            assert_eq!(served.username.as_deref(), Some("alice"));
            assert_eq!(served.auth, Some(AuthMethod::Cleartext));
        })
        .await
        .expect("bounded 407 retry");
    }

    /// One enrolled secret, three logins: enroll "carol" over SOCKS5 0x80 on
    /// a secure-only server, then log in over HTTP Basic and over RFC 1929
    /// against fresh servers — the same stored secret verifies all of them.
    /// Mutation: if the store kept separate secrets per method, one of the
    /// three logins fails.
    #[tokio::test]
    async fn one_secret_works_over_every_protocol_and_method() {
        timeout(Duration::from_secs(30), async {
            let store = Store::waiting("carol");

            // 1: enroll over the strong method.
            let options = ServerOptions::new(deadline()).secure_only();
            let (port, server) = serve_once(Arc::clone(&store), options, true).await;
            let proxy = ProxyConfig::socks5("127.0.0.1", port).with_secure_auth(
                SecureCredentials::new("carol", "carols-pw")
                    .with_min_kdf(WEAK)
                    .allow_enrollment(true)
                    .with_enrollment_kdf(WEAK),
            );
            assert_eq!(ping(&proxy).await.unwrap(), b"pong:ping");
            assert_eq!(server.await.unwrap().auth, Some(AuthMethod::Secure));
            assert!(store.is_enrolled("carol"));

            // 2: HTTP Basic against the same store. The pair is set field-wise
            // (not with `with_auth`) so the client cannot fall back to the
            // strong scheme: Basic is the method under test here.
            let (port, server) =
                serve_once(Arc::clone(&store), ServerOptions::new(deadline()), false).await;
            let mut proxy = ProxyConfig::http("127.0.0.1", port);
            proxy.user = Some("carol".to_owned());
            proxy.password = Some("carols-pw".to_owned());
            let mut stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
            http_connect_handshake_ok(&mut stream, &proxy).await;
            let served = server.await.unwrap();
            assert_eq!(served.username.as_deref(), Some("carol"));
            assert_eq!(served.auth, Some(AuthMethod::Cleartext));

            // 3: RFC 1929 against the same store (no secure credentials in the
            // config, so the client offers only method 0x02).
            let (port, server) =
                serve_once(Arc::clone(&store), ServerOptions::new(deadline()), true).await;
            let mut proxy = ProxyConfig::socks5("127.0.0.1", port);
            proxy.user = Some("carol".to_owned());
            proxy.password = Some("carols-pw".to_owned());
            assert_eq!(ping(&proxy).await.unwrap(), b"pong:ping");
            let served = server.await.unwrap();
            assert_eq!(served.username.as_deref(), Some("carol"));
            assert_eq!(served.auth, Some(AuthMethod::Cleartext));
        })
        .await
        .expect("bounded cross-method secret");
    }

    async fn http_connect_handshake_ok(stream: &mut TcpStream, proxy: &ProxyConfig) {
        use resocks5_net::connect::http_connect_handshake;
        http_connect_handshake(stream, "example.test:443", proxy)
            .await
            .unwrap();
    }

    /// An `init` user claimed by an HTTP Basic login holds the real secret:
    /// a following strong-method dial with the same password succeeds WITHOUT
    /// enrolling (the stored secret already verifies it).
    /// Mutation: a claim that stores something other than the submitted
    /// password's derivation breaks the follow-up secure dial.
    #[tokio::test]
    async fn init_claim_works_over_http_basic_too() {
        timeout(Duration::from_secs(30), async {
            let store = Store::waiting("dave");
            let (port, server) =
                serve_once(Arc::clone(&store), ServerOptions::new(deadline()), false).await;
            let mut proxy = ProxyConfig::http("127.0.0.1", port);
            proxy.user = Some("dave".to_owned());
            proxy.password = Some("daves-pw".to_owned());
            let mut stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
            http_connect_handshake_ok(&mut stream, &proxy).await;
            let served = server.await.unwrap();
            assert_eq!(served.username.as_deref(), Some("dave"));
            assert_eq!(served.auth, Some(AuthMethod::Cleartext));
            assert!(store.is_enrolled("dave"));

            let (port, server) =
                serve_once(Arc::clone(&store), ServerOptions::new(deadline()), true).await;
            let proxy = ProxyConfig::socks5("127.0.0.1", port).with_secure_auth(
                SecureCredentials::new("dave", "daves-pw")
                    .with_min_kdf(WEAK)
                    .allow_enrollment(true)
                    .with_enrollment_kdf(WEAK),
            );
            assert_eq!(ping(&proxy).await.unwrap(), b"pong:ping");
            let served = server.await.unwrap();
            assert_eq!(served.username.as_deref(), Some("dave"));
            assert_eq!(served.auth, Some(AuthMethod::Secure));
        })
        .await
        .expect("bounded init claim over Basic");
    }

    /// A SOCKS5 0x02 login and an HTTP Basic login racing the SAME `init`
    /// user: exactly one gets past authentication, the other is refused
    /// (`[1, 1]` / closing 407), because `claim` is atomic.
    /// Mutation: letting both claims through (a check-then-set race) fails
    /// the count.
    #[tokio::test]
    async fn concurrent_first_logins_exactly_one_wins() {
        timeout(Duration::from_secs(30), async {
            let store = Store::waiting("eve");
            let options = ServerOptions::new(deadline());
            let (port_a, server_a) = serve_once(Arc::clone(&store), options, false).await;
            let (port_b, server_b) = serve_once(Arc::clone(&store), options, false).await;
            let barrier = Arc::new(tokio::sync::Barrier::new(2));

            let socks = tokio::spawn({
                let barrier = Arc::clone(&barrier);
                async move {
                    let mut client = TcpStream::connect(("127.0.0.1", port_a)).await.unwrap();
                    client.write_all(&[5, 1, 2]).await.unwrap();
                    let mut pick = [0u8; 2];
                    client.read_exact(&mut pick).await.unwrap();
                    assert_eq!(pick, [5, 2]);
                    barrier.wait().await;
                    client.write_all(&rfc1929("eve", "eves-pw")).await.unwrap();
                    let mut status = [0u8; 2];
                    if client.read_exact(&mut status).await.is_err() || status != [1, 0] {
                        return false;
                    }
                    // The winner's server still waits for the CONNECT request.
                    client.write_all(&socks_connect(&[2])[3..]).await.unwrap();
                    let mut rest = Vec::new();
                    let _ = client.read_to_end(&mut rest).await;
                    true
                }
            });
            let basic = tokio::spawn({
                let barrier = Arc::clone(&barrier);
                async move {
                    let mut client = TcpStream::connect(("127.0.0.1", port_b)).await.unwrap();
                    client
                        .write_all(
                            b"CONNECT example.test:443 HTTP/1.1\r\n\
                              Proxy-Authorization: Basic ZXZlOmV2ZXMtcHc=\r\n\r\n",
                        )
                        .await
                        .unwrap();
                    barrier.wait().await;
                    let mut answer = Vec::new();
                    let _ = client.read_to_end(&mut answer).await;
                    answer.starts_with(b"HTTP/1.1 200")
                }
            });

            let (socks_won, basic_won) = (socks.await.unwrap(), basic.await.unwrap());
            let served_a = server_a.await.unwrap();
            let served_b = server_b.await.unwrap();
            let successes =
                usize::from(served_a.auth.is_some()) + usize::from(served_b.auth.is_some());
            assert_eq!(successes, 1, "exactly one login claims the init user");
            assert_eq!(
                usize::from(socks_won) + usize::from(basic_won),
                1,
                "exactly one client saw success"
            );
            assert!(store.is_enrolled("eve"));
        })
        .await
        .expect("bounded claim race");
    }

    /// The feature-less `accept` entry point with the defaults leaves a
    /// standard client NO method: the greeting answers `[5, 255]` and a bare
    /// HTTP CONNECT gets a bare closing 407 (no scheme advertised).
    /// Mutation: advertising a scheme in that 407 would send clients into an
    /// authentication path this entry point cannot serve.
    #[tokio::test]
    async fn anonymous_disabled_server_leaves_a_standard_client_no_method() {
        use tokio::io::duplex;
        async fn serve_accept(bytes: &[u8]) -> (Result<IncomingRequest, ServerError>, Vec<u8>) {
            let options = ServerOptions::new(Instant::now() + Duration::from_secs(5));
            let (mut peer, mut server) = duplex(64 * 1024);
            peer.write_all(bytes).await.unwrap();
            peer.shutdown().await.unwrap();
            let result = accept(&mut server, &options).await;
            drop(server);
            let mut written = Vec::new();
            peer.read_to_end(&mut written).await.unwrap();
            (result, written)
        }

        timeout(Duration::from_secs(10), async {
            let (result, written) = serve_accept(&socks_connect(&[0])).await;
            assert!(is_authentication(&result.unwrap_err()));
            assert_eq!(written, [5, 255]);

            let (result, written) =
                serve_accept(b"CONNECT example.test:443 HTTP/1.1\r\n\r\n").await;
            assert!(is_authentication(&result.unwrap_err()));
            assert_eq!(
                written,
                &b"HTTP/1.1 407 Proxy Authentication Required\r\n\
                   Connection: close\r\n\
                   Content-Length: 0\r\n\r\n"[..]
            );
        })
        .await
        .expect("bounded anonymous-disabled refusals");
    }
}

mod client_side {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use resocks5_net::connect::{dial, DialOptions};
    use resocks5_net::server::ServerOptions;
    use resocks5_net::types::ProxyConfig;
    use resocks5_net::ConnectError;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};
    use tokio::time::timeout;

    /// What the stub saw so far.
    #[derive(Default)]
    struct Recorded {
        connections: AtomicUsize,
        /// Sent credential pairs / auth header values, in arrival order.
        seen: Mutex<Vec<String>>,
    }

    /// A raw SOCKS5 upstream that speaks ONLY clear text (method 0x02):
    /// offers `[5, 255]` unless the client offered 0x02, accepts any
    /// UNAME/PASSWD pair (recording it), answers CONNECT and echoes
    /// `pong:` + payload. Serves up to four connections.
    async fn socks02_stub() -> (u16, Arc<Recorded>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let recorded = Arc::new(Recorded::default());
        let state = Arc::clone(&recorded);
        tokio::spawn(async move {
            for _ in 0..4 {
                let Ok((mut stream, _)) = listener.accept().await else {
                    return;
                };
                state.connections.fetch_add(1, Ordering::SeqCst);
                let mut head = [0u8; 2];
                if stream.read_exact(&mut head).await.is_err() {
                    continue;
                }
                let mut methods = vec![0u8; usize::from(head[1])];
                stream.read_exact(&mut methods).await.unwrap();
                if !methods.contains(&0x02) {
                    stream.write_all(&[5, 255]).await.unwrap();
                    continue;
                }
                stream.write_all(&[5, 2]).await.unwrap();
                assert_eq!(stream.read_u8().await.unwrap(), 1, "RFC 1929 version");
                let ulen = stream.read_u8().await.unwrap();
                let mut user = vec![0u8; usize::from(ulen)];
                stream.read_exact(&mut user).await.unwrap();
                let plen = stream.read_u8().await.unwrap();
                let mut password = vec![0u8; usize::from(plen)];
                stream.read_exact(&mut password).await.unwrap();
                state.seen.lock().unwrap().push(format!(
                    "{}:{}",
                    String::from_utf8_lossy(&user),
                    String::from_utf8_lossy(&password)
                ));
                stream.write_all(&[1, 0]).await.unwrap();
                let mut request = [0u8; 4];
                stream.read_exact(&mut request).await.unwrap();
                let address = match request[3] {
                    1 => 4,
                    4 => 16,
                    _ => usize::from(stream.read_u8().await.unwrap()),
                };
                let mut rest = vec![0u8; address + 2];
                stream.read_exact(&mut rest).await.unwrap();
                stream
                    .write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0])
                    .await
                    .unwrap();
                tunnel(&mut stream).await;
            }
        });
        (port, recorded)
    }

    /// A raw HTTP CONNECT upstream that REQUIRES Basic and behaves like
    /// 3proxy: a request without a Basic `Proxy-Authorization` is answered
    /// `HTTP/1.0 407` + `Connection: close` and the connection is dropped; a
    /// request with one is answered 200 and echoes `pong:` + payload. Every
    /// request's `Proxy-Authorization` value is recorded (empty when absent).
    /// Serves up to four connections.
    async fn http_basic_stub() -> (u16, Arc<Recorded>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let recorded = Arc::new(Recorded::default());
        let state = Arc::clone(&recorded);
        tokio::spawn(async move {
            for _ in 0..4 {
                let Ok((mut stream, _)) = listener.accept().await else {
                    return;
                };
                state.connections.fetch_add(1, Ordering::SeqCst);
                let first = read_head(&mut stream).await.unwrap_or_default();
                state.seen.lock().unwrap().push(first.clone());
                if first.starts_with("Basic ") {
                    stream
                        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                        .await
                        .unwrap();
                    tunnel(&mut stream).await;
                } else {
                    stream
                        .write_all(
                            b"HTTP/1.0 407 Proxy Authentication Required\r\n\
                              Proxy-Authenticate: Basic realm=\"stub\"\r\n\
                              Connection: close\r\n\r\n",
                        )
                        .await
                        .unwrap();
                }
            }
        });
        (port, recorded)
    }

    async fn read_head(stream: &mut TcpStream) -> Option<String> {
        let mut head = Vec::new();
        loop {
            let mut byte = [0u8; 1];
            stream.read_exact(&mut byte).await.ok()?;
            head.push(byte[0]);
            if head.ends_with(b"\r\n\r\n") {
                return Some(
                    head.split(|b| *b == b'\n')
                        .find_map(|line| {
                            let line = String::from_utf8_lossy(line);
                            line.trim()
                                .strip_prefix("Proxy-Authorization:")
                                .map(str::trim)
                                .map(str::to_owned)
                        })
                        .unwrap_or_default(),
                );
            }
        }
    }

    /// After the handshake: one `ping` → `pong:ping` round trip.
    async fn tunnel(stream: &mut TcpStream) {
        let mut ping = [0u8; 4];
        if stream.read_exact(&mut ping).await.is_err() {
            return;
        }
        let _ = stream.write_all(b"pong:").await;
        let _ = stream.write_all(&ping).await;
    }

    async fn dial_fails(proxy: &ProxyConfig) -> ConnectError {
        dial(proxy, "example.test", 443, &DialOptions::new(), None)
            .await
            .map(|_| ())
            .unwrap_err()
    }

    async fn ping(proxy: &ProxyConfig) {
        let mut stream = dial(proxy, "example.test", 443, &DialOptions::new(), None)
            .await
            .unwrap();
        stream.write_all(b"ping").await.unwrap();
        let mut answer = [0u8; 9];
        stream.read_exact(&mut answer).await.unwrap();
        assert_eq!(&answer, b"pong:ping");
    }

    /// The dial offers every configured method strongest-first and the
    /// upstream's pick wins: with a user/password pair (which also derives
    /// secure credentials) against a strong-method server the exchange runs
    /// over 0x80; against a 0x02-only upstream the RFC 1929 pair is sent and
    /// accepted.
    /// Mutation: dropping the pair from the offer makes the first dial fall
    /// back to 0x02 (password on the wire) against a server that accepts it.
    #[tokio::test]
    async fn the_dial_offers_every_method_and_the_upstream_picks() {
        timeout(Duration::from_secs(30), async {
            // No client floor is imposed by default, so a cheap stored secret
            // is fine for the 0x80 exchange.
            let strong = server_side_like_strong_server().await;
            let (port, server) = strong;
            let proxy = ProxyConfig::socks5("127.0.0.1", port).with_auth("alice", "pw");
            ping(&proxy).await;
            let served = server.await.unwrap();
            assert_eq!(served.auth, Some(resocks5_net::server::AuthMethod::Secure));
            assert_eq!(served.username.as_deref(), Some("alice"));

            let (port, recorded) = socks02_stub().await;
            let proxy = ProxyConfig::socks5("127.0.0.1", port).with_auth("bob", "bpw");
            ping(&proxy).await;
            assert_eq!(recorded.connections.load(Ordering::SeqCst), 1);
            assert_eq!(recorded.seen.lock().unwrap().as_slice(), ["bob:bpw"]);
        })
        .await
        .expect("bounded method negotiation");
    }

    /// A `secure_only` dial (or one with clear text disabled) against a
    /// 0x02-only upstream fails with `MethodUnsupported { got: 0xFF }` after
    /// one connection — the upstream saw the greeting but no credentials;
    /// `secure_only` WITHOUT secure credentials fails at preflight with
    /// `SecureAuthUnsupported` before any connection.
    /// Mutation: falling back to the upstream's weak method (or skipping the
    /// preflight) tunnels through the 0x02-only upstream.
    #[tokio::test]
    async fn secure_only_dial_refuses_cleartext_upstreams() {
        timeout(Duration::from_secs(20), async {
            let (port, recorded) = socks02_stub().await;
            let secure_only = ProxyConfig::socks5("127.0.0.1", port)
                .with_auth("bob", "bpw")
                .secure_only();
            let error = dial_fails(&secure_only).await;
            assert!(
                matches!(
                    error,
                    ConnectError::MethodUnsupported {
                        got: 0xFF,
                        with_auth: true
                    }
                ),
                "{error:?}"
            );
            assert_eq!(recorded.connections.load(Ordering::SeqCst), 1);
            assert!(recorded.seen.lock().unwrap().is_empty());

            let no_cleartext = ProxyConfig::socks5("127.0.0.1", port)
                .with_auth("bob", "bpw")
                .allow_cleartext(false);
            let error = dial_fails(&no_cleartext).await;
            assert!(
                matches!(
                    error,
                    ConnectError::MethodUnsupported {
                        got: 0xFF,
                        with_auth: true
                    }
                ),
                "{error:?}"
            );
            assert_eq!(recorded.connections.load(Ordering::SeqCst), 2);

            let no_credentials = ProxyConfig::socks5("127.0.0.1", port).secure_only();
            let error = dial_fails(&no_credentials).await;
            assert!(
                matches!(error, ConnectError::SecureAuthUnsupported),
                "{error:?}"
            );
            tokio::time::sleep(Duration::from_millis(100)).await;
            assert_eq!(
                recorded.connections.load(Ordering::SeqCst),
                2,
                "the preflight must not even connect"
            );
        })
        .await
        .expect("bounded secure-only dial refusals");
    }

    /// The Basic decision at the HTTP layer: with the defaults the pair goes
    /// in the FIRST request (0.4.x behaviour — an upstream that closes after
    /// its 407, like 3proxy, stays reachable); with `allow_cleartext(false)`
    /// the entry probes first and the dial fails with
    /// `CleartextCredentialsRefused`, the password never leaving — the
    /// upstream sees only the bare probe.
    /// Mutation: probing before sending Basic strands the closing upstream
    /// (the allowed case fails); sending Basic when clear text is disallowed
    /// puts the credentials on the wire (the refused case fails).
    #[tokio::test]
    async fn basic_inside_tls_is_allowed_but_wire_basic_needs_allow_cleartext() {
        timeout(Duration::from_secs(20), async {
            // Plain HTTP with clear text allowed: Basic in the first request.
            let (port, recorded) = http_basic_stub().await;
            let allowed = ProxyConfig::http("127.0.0.1", port).with_auth("bob", "bpw");
            ping(&allowed).await;
            {
                let seen = recorded.seen.lock().unwrap();
                assert_eq!(seen.len(), 1, "one request: {seen:?}");
                assert!(seen[0].starts_with("Basic "), "first: {:?}", seen[0]);
            }

            // Clear text disallowed: refused BEFORE the password is sent.
            let (port, recorded) = http_basic_stub().await;
            let refused = ProxyConfig::http("127.0.0.1", port)
                .with_auth("bob", "bpw")
                .allow_cleartext(false);
            let error = dial_fails(&refused).await;
            assert!(
                matches!(error, ConnectError::CleartextCredentialsRefused),
                "{error:?}"
            );
            assert_eq!(recorded.connections.load(Ordering::SeqCst), 1);
            let seen = recorded.seen.lock().unwrap();
            assert!(!seen.is_empty(), "the bare probe reached the stub");
            assert!(
                seen.iter().all(|value| value.is_empty()),
                "no credentials ever reached the stub: {seen:?}"
            );
        })
        .await
        .expect("bounded clear-text decision");
    }

    /// A minimal strong-method-capable server (the real `accept_with`) used
    /// by `the_dial_offers_every_method_and_the_upstream_picks`.
    async fn server_side_like_strong_server(
    ) -> (u16, tokio::task::JoinHandle<super::server_side::Served>) {
        super::server_side::serve_once(
            super::server_side::Store::enrolled_at("alice", "pw", super::server_side::WEAK),
            ServerOptions::new(super::server_side::deadline()),
            true,
        )
        .await
    }
}
