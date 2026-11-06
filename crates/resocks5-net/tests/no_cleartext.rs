//! The default build never works with clear-text passwords.
//!
//! Integration tests link the library WITHOUT `cfg(test)`, so these run against
//! the real default build: no `cleartext-server` means the inbound side neither
//! offers nor accepts SOCKS5 method 0x02 or HTTP Basic, and no
//! `cleartext-client` means the dial side refuses, before the first byte, to
//! send a user name and password in clear text.
//! Refusal checks are feature-gated; HTTP challenges are tested in both builds.

mod http_407 {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::Duration;

    use resocks5_net::server::{accept, IncomingRequest, ServerError, ServerOptions};
    use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt};
    use tokio::time::Instant;

    fn options(anonymous: bool, password: bool) -> ServerOptions {
        ServerOptions::new(Instant::now() + Duration::from_secs(5), anonymous, password)
    }

    /// Run `accept` against `bytes` from a client; returns the result, everything
    /// the server wrote back, and how many times the credential callback ran.
    pub(super) async fn serve(
        bytes: &[u8],
        anonymous: bool,
        password: bool,
    ) -> (Result<IncomingRequest, ServerError>, Vec<u8>, usize) {
        let (mut peer, mut server) = duplex(64 * 1024);
        peer.write_all(bytes).await.unwrap();
        peer.shutdown().await.unwrap();
        let calls = Arc::new(AtomicUsize::new(0));
        let counted = Arc::clone(&calls);
        let result = accept(&mut server, &options(anonymous, password), move |_| {
            let counted = Arc::clone(&counted);
            async move {
                counted.fetch_add(1, Ordering::SeqCst);
                true
            }
        })
        .await;
        drop(server);
        let mut written = Vec::new();
        peer.read_to_end(&mut written).await.unwrap();
        (result, written, calls.load(Ordering::SeqCst))
    }

    #[cfg(not(feature = "cleartext-server"))]
    pub(super) const EXPECT_407: &[u8] = b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Resocks5-Secure\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";
    #[cfg(feature = "cleartext-server")]
    pub(super) const EXPECT_407: &[u8] = b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"resocks5\", charset=\"UTF-8\"\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";

    #[tokio::test]
    async fn rejected_http_requests_advertise_only_the_enabled_challenge() {
        for header in [
            "",
            "Proxy-Authorization: Basic !!!!\r\n",
            "Proxy-Authorization: Basic bm9jb2xvbg==\r\n",
            "Proxy-Authorization: Bearer token\r\n",
        ] {
            let request = format!("CONNECT example.com:443 HTTP/1.1\r\n{header}\r\n");
            for password in [false, true] {
                let (result, written, calls) = serve(request.as_bytes(), false, password).await;
                assert!(matches!(result, Err(ServerError::Authentication(_))));
                assert_eq!(written, EXPECT_407);
                assert_eq!(calls, 0);
                #[cfg(not(feature = "cleartext-server"))]
                assert!(!String::from_utf8_lossy(&written)
                    .to_ascii_lowercase()
                    .contains("basic"));
            }
        }
    }

    #[cfg(feature = "cleartext-server")]
    #[tokio::test]
    async fn enabled_cleartext_server_still_accepts_basic() {
        let (result, written, calls) = serve(
            b"CONNECT example.com:443 HTTP/1.1\r\nProxy-Authorization: Basic dXNlcjpwYXNz\r\n\r\n",
            false,
            true,
        )
        .await;
        assert_eq!(result.unwrap().target(), "example.com:443");
        assert!(written.is_empty());
        assert_eq!(calls, 1);
    }
}

#[cfg(not(feature = "cleartext-server"))]
mod server_side {
    use super::http_407::{serve, EXPECT_407};
    use resocks5_net::server::ServerError;

    /// SOCKS5 greeting offering the given methods, then (when a method was
    /// chosen) a CONNECT to `example.com:443`.
    fn socks_bytes(methods: &[u8]) -> Vec<u8> {
        let mut bytes = vec![5, u8::try_from(methods.len()).unwrap()];
        bytes.extend_from_slice(methods);
        bytes.extend_from_slice(&[5, 1, 0, 3, 11]);
        bytes.extend_from_slice(b"example.com");
        bytes.extend_from_slice(&443u16.to_be_bytes());
        bytes
    }

    /// A client that only knows UNAME/PASSWD is told "no acceptable method"
    /// (0xFF), even though the host asked for password auth, and the
    /// credential callback never runs. Mutation: offering 0x02 again answers
    /// `[5, 2]` and starts the sub-negotiation.
    #[tokio::test]
    async fn method_2_is_never_offered() {
        let (result, written, calls) = serve(&socks_bytes(&[2]), false, true).await;
        assert_eq!(written, [5, 255]);
        assert!(matches!(result, Err(ServerError::Authentication(_))));
        assert_eq!(calls, 0);
    }

    /// A client offering both picks the anonymous method when the host allows
    /// it, never 0x02. Mutation: preferring 0x02 over 0x00 answers `[5, 2]`.
    #[tokio::test]
    async fn anonymous_is_chosen_over_a_password() {
        let (result, written, calls) = serve(&socks_bytes(&[2, 0]), true, true).await;
        assert!(written.starts_with(&[5, 0]), "{written:?}");
        assert!(result.is_ok(), "{result:?}");
        assert_eq!(calls, 0);
    }

    /// Password-only host, client offers anonymous and password: nothing
    /// acceptable remains.
    #[tokio::test]
    async fn a_password_only_host_accepts_nobody() {
        let (result, written, calls) = serve(&socks_bytes(&[0, 2]), false, true).await;
        assert_eq!(written, [5, 255]);
        assert!(result.is_err());
        assert_eq!(calls, 0);
    }

    /// HTTP Basic is the password in base64: answered 407 without calling
    /// the credential callback, whatever the host options.
    #[tokio::test]
    async fn http_basic_is_answered_407() {
        let request =
            b"CONNECT example.com:443 HTTP/1.1\r\nProxy-Authorization: Basic dXNlcjpwYXNz\r\n\r\n";
        for (anonymous, password) in [(false, true), (true, true), (true, false)] {
            let (result, written, calls) = serve(request, anonymous, password).await;
            assert_eq!(
                written, EXPECT_407,
                "anonymous={anonymous} password={password}"
            );
            assert!(!String::from_utf8_lossy(&written)
                .to_ascii_lowercase()
                .contains("basic"));
            assert!(result.is_err());
            assert_eq!(
                calls, 0,
                "the callback must never see a clear-text password"
            );
        }
    }
}

#[cfg(not(feature = "cleartext-client"))]
mod client_side {
    use std::time::Duration;

    use resocks5_net::connect::{dial, http_connect_handshake, socks5_handshake, DialOptions};
    use resocks5_net::types::ProxyConfig;
    use resocks5_net::ConnectError;
    use tokio::io::{duplex, AsyncReadExt};
    use tokio::net::TcpListener;
    use tokio::time::timeout;

    /// The public SOCKS5 handshake refuses a user/password pair and writes
    /// nothing to the stream. Mutation: sending the greeting first fails the
    /// empty-read assertion.
    #[tokio::test]
    async fn socks5_handshake_sends_nothing() {
        let (client, mut server) = duplex(1024);
        let error = socks5_handshake(client, "example.com", 443, Some(("user", "secret-pw")))
            .await
            .unwrap_err();
        assert!(
            matches!(error, ConnectError::CleartextCredentialsRefused),
            "{error:?}"
        );
        let mut sent = Vec::new();
        server.read_to_end(&mut sent).await.unwrap();
        assert!(sent.is_empty(), "no byte may reach the upstream: {sent:?}");
    }

    /// Without credentials the same handshake still starts (the guard is
    /// about the password, not about SOCKS5).
    #[tokio::test]
    async fn socks5_without_credentials_still_greets() {
        let (client, mut server) = duplex(1024);
        let handshake = tokio::spawn(async move {
            let _ = socks5_handshake(client, "example.com", 443, None).await;
        });
        let mut greeting = [0u8; 3];
        server.read_exact(&mut greeting).await.unwrap();
        assert_eq!(greeting, [5, 1, 0]);
        handshake.abort();
    }

    /// The public HTTP CONNECT handshake to a plain-HTTP proxy refuses to
    /// send Basic credentials and writes nothing.
    #[tokio::test]
    async fn http_connect_to_a_plain_proxy_sends_nothing() {
        let (mut client, mut server) = duplex(1024);
        let proxy = ProxyConfig::http("up", 8080).with_auth("user", "secret-pw");
        let error = http_connect_handshake(&mut client, "example.com:443", &proxy)
            .await
            .unwrap_err();
        assert!(
            matches!(error, ConnectError::CleartextCredentialsRefused),
            "{error:?}"
        );
        drop(client);
        let mut sent = Vec::new();
        server.read_to_end(&mut sent).await.unwrap();
        assert!(sent.is_empty(), "no byte may reach the upstream: {sent:?}");
    }

    /// `dial` refuses before even connecting: the listener never sees a
    /// connection. Mutation: refusing only at the wire (after the connect)
    /// makes `accept` succeed.
    #[tokio::test]
    async fn dial_refuses_before_connecting() {
        for proxy in [
            |port| ProxyConfig::socks5("127.0.0.1", port).with_auth("user", "secret-pw"),
            |port| ProxyConfig::http("127.0.0.1", port).with_auth("user", "secret-pw"),
        ] {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let port = listener.local_addr().unwrap().port();
            let error = dial(&proxy(port), "example.com", 443, &DialOptions::new(), None)
                .await
                .map(|_| ())
                .unwrap_err();
            assert!(
                matches!(error, ConnectError::CleartextCredentialsRefused),
                "{error:?}"
            );
            assert!(
                timeout(Duration::from_millis(200), listener.accept())
                    .await
                    .is_err(),
                "the upstream must not even see a connection"
            );
        }
    }

    /// An HTTPS proxy is reached over TLS, so Basic inside it is not clear
    /// text and is not refused by this guard (without a connector the dial
    /// fails for a different, TLS reason).
    #[tokio::test]
    async fn https_upstream_credentials_are_not_a_cleartext_refusal() {
        let proxy = ProxyConfig::https("127.0.0.1", 9).with_auth("user", "secret-pw");
        let error = dial(&proxy, "example.com", 443, &DialOptions::new(), None)
            .await
            .map(|_| ())
            .unwrap_err();
        assert!(
            !matches!(error, ConnectError::CleartextCredentialsRefused),
            "{error:?}"
        );
    }

    /// A user name alone is never sent (credentials are a pair), so it is not a
    /// clear-text send either.
    #[tokio::test]
    async fn a_lone_user_name_is_not_refused() {
        let mut proxy = ProxyConfig::socks5("127.0.0.1", 9);
        proxy.user = Some("user".to_owned());
        let error = dial(&proxy, "example.com", 443, &DialOptions::new(), None)
            .await
            .map(|_| ())
            .unwrap_err();
        assert!(
            !matches!(error, ConnectError::CleartextCredentialsRefused),
            "{error:?}"
        );
    }

    /// The refusal is a local configuration fact: it does not count against
    /// the upstream's rating and a gateway answers its client with a general
    /// failure.
    #[test]
    fn the_refusal_is_not_the_upstreams_fault() {
        let error = ConnectError::CleartextCredentialsRefused;
        assert!(!error.counts_against_upstream());
        assert!(!error.is_upstream_down());
        assert_eq!(
            error.suggested_reply(),
            resocks5_net::server::Reply::GeneralFailure
        );
        assert!(error.to_string().contains("clear text"));
        assert!(!error.to_string().contains("secret"));
    }
}
