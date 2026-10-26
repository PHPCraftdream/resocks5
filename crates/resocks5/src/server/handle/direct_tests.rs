//! Direct-аккаунт передаёт данные без upstream; остальные политики сохраняются.

use std::sync::Arc;
use std::time::Duration;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio::time::{timeout, Instant};

use super::handle_client::handle_client;
use crate::auth::AuthState;
use crate::config::{AuthConfig, NetworkConfig, TlsFragmentConfig, User, UsersConfig};
use crate::logger::{LogConfig, Logger};
use resocks5_net::pool::ProxyPool;

const PAYLOAD: &[u8] = b"direct request\x00\xff";
const RESPONSE: &[u8] = b"direct response\xff\x00";

#[derive(Clone, Copy)]
enum Protocol {
    Socks5,
    Http,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Case {
    Direct,
    Pool,
    Anonymous,
    Disabled,
    WrongPassword,
    Banned,
    AtCapacity,
}

impl Case {
    fn auth_failure(self) -> bool {
        matches!(self, Self::Disabled | Self::WrongPassword)
    }

    fn http_status(self) -> u16 {
        match self {
            Self::Direct => 200,
            Self::Disabled | Self::WrongPassword => 407,
            Self::Banned => 403,
            Self::Pool | Self::Anonymous => 502,
            Self::AtCapacity => 503,
        }
    }
}

/// cancel-safe: NO — владеет клиентским сокетом; отмена закрывает соединение.
async fn client(mut stream: TcpStream, protocol: Protocol, case: Case, port: u16) {
    let anonymous = case == Case::Anonymous;
    let password = if case == Case::WrongPassword {
        "bad"
    } else {
        "pw"
    };
    match protocol {
        Protocol::Socks5 => {
            let method = if anonymous { 0 } else { 2 };
            stream.write_all(&[5, 1, method]).await.unwrap();
            let mut selected = [0; 2];
            stream.read_exact(&mut selected).await.unwrap();
            assert_eq!(selected, [5, method]);
            if !anonymous {
                let mut auth = vec![1, 5, b'a', b'l', b'i', b'c', b'e'];
                auth.push(u8::try_from(password.len()).unwrap());
                auth.extend_from_slice(password.as_bytes());
                stream.write_all(&auth).await.unwrap();
                let mut verdict = [0; 2];
                stream.read_exact(&mut verdict).await.unwrap();
                assert_eq!(verdict, [1, u8::from(case.auth_failure())]);
                if case.auth_failure() {
                    return;
                }
            }
            let mut request = vec![5, 1, 0, 1, 127, 0, 0, 1];
            request.extend_from_slice(&port.to_be_bytes());
            request.extend_from_slice(PAYLOAD);
            stream.write_all(&request).await.unwrap();
            let mut reply = [0; 10];
            stream.read_exact(&mut reply).await.unwrap();
            let expected = match case {
                Case::Direct => 0,
                Case::Banned => 2,
                Case::Pool | Case::Anonymous => 4,
                Case::AtCapacity => 1,
                Case::Disabled | Case::WrongPassword => unreachable!(),
            };
            assert_eq!(&reply[..2], &[5, expected]);
        }
        Protocol::Http => {
            let mut request = format!("CONNECT 127.0.0.1:{port} HTTP/1.1\r\n");
            if !anonymous {
                let credentials = STANDARD.encode(format!("alice:{password}"));
                request.push_str(&format!("Proxy-Authorization: Basic {credentials}\r\n"));
            }
            request.push_str("\r\n");
            let mut bytes = request.into_bytes();
            bytes.extend_from_slice(PAYLOAD);
            stream.write_all(&bytes).await.unwrap();
            let mut header = Vec::new();
            while !header.ends_with(b"\r\n\r\n") {
                assert!(header.len() < 4096);
                header.push(stream.read_u8().await.unwrap());
            }
            assert!(
                String::from_utf8_lossy(&header)
                    .starts_with(&format!("HTTP/1.1 {} ", case.http_status())),
                "неожиданный ответ: {:?}",
                String::from_utf8_lossy(&header)
            );
        }
    }
    if case == Case::Direct {
        let mut response = vec![0; RESPONSE.len()];
        stream.read_exact(&mut response).await.unwrap();
        assert_eq!(response, RESPONSE);
        stream.shutdown().await.unwrap();
        let mut trailing = Vec::new();
        stream.read_to_end(&mut trailing).await.unwrap();
        assert!(trailing.is_empty());
    }
}

/// cancel-safe: NO — отмена общего бюджета закрывает все три ноги обмена.
async fn exercise(protocol: Protocol, case: Case) {
    timeout(Duration::from_secs(20), async {
        let auth = Arc::new(
            AuthState::build(
                &AuthConfig {
                    allow_anonymous: true,
                },
                &UsersConfig {
                    users: vec![User {
                        name: "alice".into(),
                        hash: crate::auth::compute_hash("pw").unwrap(),
                        is_enabled: case != Case::Disabled,
                        direct: case != Case::Pool,
                        allowed_clients: Some("loopback".into()),
                    }],
                },
                "unused-direct-tests",
            )
            .unwrap(),
        );
        let target_std = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        target_std.set_nonblocking(true).unwrap();
        let port = target_std.local_addr().unwrap().port();
        let target = TcpListener::from_std(target_std.try_clone().unwrap()).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let no_rotator = None;
        let (sender, _receiver) = tokio::sync::mpsc::channel(64);
        let logger = Arc::new(Logger::new(sender, LogConfig::default()));
        let banned = Arc::new(if case == Case::Banned {
            regex::RegexSet::new([format!("^127[.]0[.]0[.]1:{port}$")]).unwrap()
        } else {
            regex::RegexSet::empty()
        });
        let pool = Arc::new(ProxyPool::new(
            Default::default(),
            Duration::from_secs(1),
            1,
        ));
        let frag = Arc::new(TlsFragmentConfig::default());
        // Для отказа pool нужен обычный CONNECT, не ранний recovery-ответ.
        let network = Arc::new(NetworkConfig {
            recover_host_from_payload: case == Case::Direct,
            ..Default::default()
        });
        let slots = if case == Case::AtCapacity { 0 } else { 1 };
        let direct_limiter = Arc::new(Semaphore::new(slots));
        let allowed = Some(Arc::new(
            crate::config::compile_allowed_clients("loopback").unwrap(),
        ));

        let server = async {
            let (stream, _) = listener.accept().await.unwrap();
            handle_client(
                stream,
                &auth,
                &no_rotator,
                &no_rotator,
                &no_rotator,
                &logger,
                &banned,
                &pool,
                &frag,
                &network,
                None,
                &direct_limiter,
                &allowed,
                Instant::now() + Duration::from_secs(10),
            )
            .await
        };
        let peer = async {
            let stream = TcpStream::connect(address).await.unwrap();
            client(stream, protocol, case, port).await;
        };
        let echo = async {
            if case != Case::Direct {
                return;
            }
            let (mut stream, _) = target.accept().await.unwrap();
            let mut payload = vec![0; PAYLOAD.len()];
            stream.read_exact(&mut payload).await.unwrap();
            assert_eq!(payload, PAYLOAD);
            stream.write_all(RESPONSE).await.unwrap();
            stream.shutdown().await.unwrap();
            let mut trailing = Vec::new();
            stream.read_to_end(&mut trailing).await.unwrap();
            assert!(trailing.is_empty());
        };
        let (result, (), ()) = tokio::join!(server, peer, echo);
        if matches!(case, Case::Direct | Case::AtCapacity) {
            result.unwrap();
        } else {
            assert!(result.is_err());
        }
        if case != Case::Direct {
            assert!(
                matches!(target_std.accept(), Err(e) if e.kind() == std::io::ErrorKind::WouldBlock)
            );
        }
        assert_eq!(direct_limiter.available_permits(), slots);
    })
    .await
    .expect("обмен обязан завершиться в общем бюджете");
}

#[tokio::test]
async fn direct_account_relays_bytes_without_any_upstream() {
    for protocol in [Protocol::Socks5, Protocol::Http] {
        exercise(protocol, Case::Direct).await;
    }
}

#[tokio::test]
async fn direct_is_not_a_fallback_for_pool_or_anonymous_clients() {
    for protocol in [Protocol::Socks5, Protocol::Http] {
        for case in [Case::Pool, Case::Anonymous] {
            exercise(protocol, case).await;
        }
    }
}

#[tokio::test]
async fn direct_preserves_auth_bans_and_concurrency_limits() {
    for protocol in [Protocol::Socks5, Protocol::Http] {
        for case in [
            Case::Disabled,
            Case::WrongPassword,
            Case::Banned,
            Case::AtCapacity,
        ] {
            exercise(protocol, case).await;
        }
    }
}
