use super::dial::*;
use super::tests_unit::{socks5_config, spawn_socks5_stub, test_logger};
use crate::config::NetworkConfig;
use crate::logger::Logger;
use regex::RegexSet;
use resocks5_net::chain::GateLevels;
use resocks5_net::connect::connect_chain;
use resocks5_net::pool::ProxyPool;
use resocks5_net::rotator::ProxyRotator;
use resocks5_net::types::{ProxyConfig, ProxyProtocol};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;
use tokio_rustls::TlsConnector;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use std::future::Future;
use std::pin::Pin;
use std::sync::Mutex;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use tokio_rustls::rustls::{ClientConfig, RootCertStore, ServerConfig};
use tokio_rustls::TlsAcceptor;

/// TEST-ONLY throwaway material: self-signed ECDSA P-256 end-entity
/// cert for `localhost` (CA:FALSE, serverAuth), generated 2026-09-08
/// for these stubs; never used outside `cargo test`.
const STUB_CERT_PEM: &str = r#"-----BEGIN CERTIFICATE-----
MIIBkTCCATegAwIBAgIUTnhc5opoloJUaX3/qEiEQBaGaj4wCgYIKoZIzj0EAwIw
FDESMBAGA1UEAwwJbG9jYWxob3N0MB4XDTI2MDkwODEwMjAyMVoXDTM2MDkwNTEw
MjAyMVowFDESMBAGA1UEAwwJbG9jYWxob3N0MFkwEwYHKoZIzj0CAQYIKoZIzj0D
AQcDQgAECLJv3u8HBhb3mmHOL/IQi8kHgskR+5uVPiGibOwNB/NesbAFYkEI9lyc
mwPJ6TYI5yOKs6R/YkF1gx7zfqAp26NnMGUwFAYDVR0RBA0wC4IJbG9jYWxob3N0
MAwGA1UdEwEB/wQCMAAwCwYDVR0PBAQDAgWgMBMGA1UdJQQMMAoGCCsGAQUFBwMB
MB0GA1UdDgQWBBQ9VXC74t1ItOQJpFl6tnp+7fLQHTAKBggqhkjOPQQDAgNIADBF
AiEA3zuXe3kNshyz5ke5q6iQZfVCSPQFI00rVKs938C278YCIFrUysrQGFAdsdll
zFEdGqtgbBEr1xadJtJyXJGBvdd0
-----END CERTIFICATE-----
"#;

const STUB_KEY_PEM: &str = r#"-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgRbNQhRHo9//xljJ5
228sdn61rvXR9Vby6uz92ef6LbKhRANCAAQIsm/e7wcGFveaYc4v8hCLyQeCyRH7
m5U+IaJs7A0H816xsAViQQj2XJybA8npNgjnI4qzpH9iQXWDHvN+oCnb
-----END PRIVATE KEY-----
"#;

fn pem_der(pem: &str) -> Vec<u8> {
    let b64: String = pem.lines().filter(|l| !l.starts_with("-----")).collect();
    B64.decode(b64).expect("valid base64 PEM body")
}

fn stub_tls_acceptor() -> TlsAcceptor {
    let cert = CertificateDer::from(pem_der(STUB_CERT_PEM));
    let key = PrivatePkcs8KeyDer::from(pem_der(STUB_KEY_PEM));
    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key.into())
        .expect("valid stub server config");
    TlsAcceptor::from(Arc::new(config))
}

pub(super) fn stub_tls_connector() -> TlsConnector {
    let mut roots = RootCertStore::empty();
    roots
        .add(CertificateDer::from(pem_der(STUB_CERT_PEM)))
        .expect("stub cert parses");
    let config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    TlsConnector::from(Arc::new(config))
}

/// One stub hop: which wire behaviour to expect next on the socket.
/// `pub(super)` so the sibling test modules can name answered
/// exchanges through [`StubLog`].
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) enum StubPhase {
    /// Answer a SOCKS5 exchange (records the requested target).
    Socks5,
    /// Answer an HTTP CONNECT (records the requested target).
    HttpConnect,
    /// TLS-accept the stream, then continue inside the TLS layer.
    TlsAccept,
}

fn stub_phases(proto: ProxyProtocol) -> Vec<StubPhase> {
    match proto {
        ProxyProtocol::Socks5 => vec![StubPhase::Socks5],
        ProxyProtocol::Http => vec![StubPhase::HttpConnect],
        ProxyProtocol::Https => vec![StubPhase::TlsAccept, StubPhase::HttpConnect],
    }
}

pub(super) type StubLog = Arc<Mutex<Vec<(StubPhase, String)>>>;

/// What the stub does with the client's payload AFTER the last
/// handshake phase completes.
#[derive(Clone)]
pub(super) enum Drain {
    /// Drain as fast as possible into the void (matrix tests: payload
    /// content is irrelevant there).
    Void,
    /// Drip-read at a paced rate and collect every byte. The sleep is
    /// scaled to the bytes actually read per call (commit edb1230):
    /// the TCP stack may deliver fewer bytes than `chunk`, and a flat
    /// per-read delay would inflate the total drain far past the
    /// intended rate. On EOF the stream is shut down cleanly — a TLS
    /// layer therefore emits `close_notify`, which a rustls peer needs
    /// to see a clean EOF instead of `UnexpectedEof`.
    Slow {
        chunk: usize,
        delay: Duration,
        collected: CollectedPayload,
    },
    /// Hold the connection open without ever reading again: the
    /// transport congests with zero confirmed progress — the
    /// dead-transport control for the zero-progress timeout. The
    /// parked task dies with the test runtime.
    Dead,
}

/// Every payload byte the stub has read so far.
pub(super) type CollectedPayload = Arc<Mutex<Vec<u8>>>;

/// Serve ONE client connection through its expected phase sequence.
/// The tunnel is a single socket: both hops' exchanges arrive here,
/// an Https hop nests the remaining phases inside a TLS layer. After
/// the last phase, hold the tunnel open until the client drops it.
trait Stream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Stream for T {}
type ErasedStream = Box<dyn Stream>;

fn serve_phases<'a>(
    stream: ErasedStream,
    phases: &'a [StubPhase],
    tls: &'a TlsAcceptor,
    log: &'a StubLog,
    drain: &'a Drain,
) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>> {
    Box::pin(async move {
        serve_phases_rec(stream, phases, tls, log, drain).await;
    })
}

/// Recursive driver behind [`serve_phases`]. Each level owns its
/// stream layer and hands it BACK once its subtree completed, so a
/// TLS level can clean-close itself (`shutdown`) afterwards: boxing
/// the layer as a `&mut` borrow would default the trait object to
/// `+ 'static`, and generic (non-boxed) async recursion would not
/// terminate at the type level.
async fn serve_phases_rec(
    mut stream: ErasedStream,
    phases: &[StubPhase],
    tls: &TlsAcceptor,
    log: &StubLog,
    drain: &Drain,
) -> Option<ErasedStream> {
    let Some((phase, rest)) = phases.split_first() else {
        drain_stream(&mut stream, drain).await;
        return Some(stream);
    };
    match phase {
        StubPhase::TlsAccept => {
            let Ok(tls_stream) = tls.accept(stream).await else {
                return None;
            };
            // `?`: on subtree failure the socket is already gone.
            let mut restored = Box::pin(serve_phases_rec(
                Box::new(tls_stream),
                rest,
                tls,
                log,
                drain,
            ))
            .await?;
            // Clean close of THIS TLS layer: close_notify, so a
            // rustls peer reads a clean EOF instead of a bare TCP
            // close (`UnexpectedEof`). A no-op on a dead socket.
            let _ = restored.shutdown().await;
            Some(restored)
        }
        StubPhase::Socks5 => {
            if let Some(target) = socks5_exchange(&mut stream).await {
                log.lock().unwrap().push((StubPhase::Socks5, target));
            }
            Box::pin(serve_phases_rec(Box::new(stream), rest, tls, log, drain)).await
        }
        StubPhase::HttpConnect => {
            if let Some(target) = http_connect_exchange(&mut stream).await {
                log.lock().unwrap().push((StubPhase::HttpConnect, target));
            }
            Box::pin(serve_phases_rec(Box::new(stream), rest, tls, log, drain)).await
        }
    }
}

/// Terminal behaviour shared by all stub connections: what happens to
/// the client's payload once the last handshake phase has been
/// answered.
async fn drain_stream(stream: &mut ErasedStream, drain: &Drain) {
    match drain {
        Drain::Void => {
            let mut buf = [0u8; 512];
            while stream.read(&mut buf).await.unwrap_or(0) != 0 {}
        }
        Drain::Slow {
            chunk,
            delay,
            collected,
        } => {
            let mut buf = vec![0u8; *chunk];
            let start = tokio::time::Instant::now();
            let mut total = 0usize;
            loop {
                let n = match stream.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => n,
                };
                collected.lock().unwrap().extend_from_slice(&buf[..n]);
                // Paced drain: the silence scales with the bytes actually
                // read (edb1230) — never a flat per-read sleep. Pace against
                // a deadline, not per-read sleeps: small TLS reads would
                // otherwise each round up to the OS timer tick (~15.6 ms on
                // Windows) and stretch the ~15 s drip toward the test budget.
                total += n;
                let due = start + delay.mul_f64(total as f64 / *chunk as f64);
                tokio::time::sleep_until(due).await;
            }
            let _ = stream.shutdown().await;
        }
        Drain::Dead => {
            std::future::pending::<()>().await;
        }
    }
}

/// Answer one no-auth SOCKS5 exchange; returns the requested target.
async fn socks5_exchange<S>(stream: &mut S) -> Option<String>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let mut greet = [0u8; 2];
    stream.read_exact(&mut greet).await.ok()?;
    if greet[0] != 0x05 {
        return None;
    }
    let mut methods = vec![0u8; greet[1] as usize];
    stream.read_exact(&mut methods).await.ok()?;
    stream.write_all(&[0x05, 0x00]).await.ok()?;

    let mut head = [0u8; 4];
    stream.read_exact(&mut head).await.ok()?;
    if head[0] != 0x05 || head[1] != 0x01 {
        return None;
    }
    let host = match head[3] {
        0x01 => {
            let mut o = [0u8; 4];
            stream.read_exact(&mut o).await.ok()?;
            std::net::Ipv4Addr::from(o).to_string()
        }
        0x03 => {
            let mut l = [0u8; 1];
            stream.read_exact(&mut l).await.ok()?;
            let mut d = vec![0u8; l[0] as usize];
            stream.read_exact(&mut d).await.ok()?;
            String::from_utf8(d).ok()?
        }
        0x04 => {
            let mut o = [0u8; 16];
            stream.read_exact(&mut o).await.ok()?;
            std::net::Ipv6Addr::from(o).to_string()
        }
        _ => return None,
    };
    let mut port = [0u8; 2];
    stream.read_exact(&mut port).await.ok()?;
    stream
        .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await
        .ok()?;
    Some(format!("{}:{}", host, u16::from_be_bytes(port)))
}

/// Answer one HTTP CONNECT; returns the requested target.
async fn http_connect_exchange<S>(stream: &mut S) -> Option<String>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let mut req = Vec::new();
    loop {
        let mut byte = [0u8; 1];
        stream.read_exact(&mut byte).await.ok()?;
        req.push(byte[0]);
        if req.ends_with(b"\r\n\r\n") {
            break;
        }
        if req.len() > 8192 {
            return None;
        }
    }
    let text = std::str::from_utf8(&req).ok()?;
    let line = text.split("\r\n").next()?;
    let target = line
        .strip_prefix("CONNECT ")?
        .split(' ')
        .next()?
        .to_string();
    stream
        .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
        .await
        .ok()?;
    Some(target)
}

/// Spawn a stub speaking `gate_proto` then `inner_proto` (in the
/// same order `use_gate` drives its two hops) on one listener; both
/// the gate and the inner config point at it. Payload is drained into
/// the void. Returns the address and the log of answered exchanges as
/// (phase, requested target).
pub(super) async fn spawn_protocol_stub(
    gate_proto: ProxyProtocol,
    inner_proto: ProxyProtocol,
) -> (SocketAddr, StubLog) {
    let (addr, log, _collected) = spawn_draining_stub(gate_proto, inner_proto, Drain::Void).await;
    (addr, log)
}

/// Loopback listener with a best-effort tiny receive buffer, the
/// same trick as `small_buffer_listener` in resocks5-net's
/// upstream_tls tests: accepted sockets inherit the listener's
/// window, so the drip — not OS auto-tuning a large one — paces the
/// slow-drain tests and the client's congestion onset is immediate.
/// Advisory only — the oversized payloads remain the guaranteed
/// backstop. (tokio 1.x exposes the buffer setter on `TcpSocket`
/// only, not on `TcpStream`, so it is applied pre-listen; socket2 is
/// not a dependency of this crate.)
async fn small_buffer_listener(addr: SocketAddr) -> std::io::Result<tokio::net::TcpListener> {
    let socket = match addr {
        SocketAddr::V4(_) => tokio::net::TcpSocket::new_v4()?,
        SocketAddr::V6(_) => tokio::net::TcpSocket::new_v6()?,
    };
    // Best-effort 1 KiB buffers (the repo's proven recipe from the
    // resocks5-net TLS tests): a tiny receive window empties fully
    // on every drip read, so each drip forces a TCP window update
    // and the client observes fresh writability — instead of the
    // receiver's silly-window rule suppressing updates and
    // blocking the sender completely. Advisory only; the oversized
    // payloads remain the guaranteed backstop.
    let _ = socket.set_recv_buffer_size(1024);
    let _ = socket.set_send_buffer_size(1024);
    socket.bind(addr)?;
    socket.listen(128)
}

/// Spawn a stub speaking `gate_proto` then `inner_proto` (in the
/// same order `use_gate` drives its two hops) on one listener; both
/// the gate and the inner config point at it. `drain` selects what
/// happens to the client's payload after the last handshake phase.
/// Returns the address, the exchange log as (phase, requested target),
/// and the payload collector (an empty vec for [`Drain::Void`] and
/// [`Drain::Dead`]).
pub(super) async fn spawn_draining_stub(
    gate_proto: ProxyProtocol,
    inner_proto: ProxyProtocol,
    drain: Drain,
) -> (SocketAddr, StubLog, CollectedPayload) {
    let phases: Vec<StubPhase> = stub_phases(gate_proto)
        .into_iter()
        .chain(stub_phases(inner_proto))
        .collect();
    let listener = small_buffer_listener("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    let addr = listener.local_addr().unwrap();
    // `localhost` may resolve to ::1 first; a stalled IPv6 connect
    // attempt would eat the pool's connect timeout, so serve both
    // loopback families on the same port.
    let v6 = small_buffer_listener(format!("[::1]:{}", addr.port()).parse().unwrap()).await;
    let collected: CollectedPayload = match &drain {
        Drain::Slow { collected, .. } => Arc::clone(collected),
        _ => Arc::new(Mutex::new(Vec::new())),
    };
    let log: StubLog = Arc::new(Mutex::new(Vec::new()));
    let tls = stub_tls_acceptor();
    let log_task = Arc::clone(&log);
    tokio::spawn(async move {
        if let Ok(v6) = v6 {
            let phases = phases.clone();
            let tls = tls.clone();
            let drain = drain.clone();
            let log6 = Arc::clone(&log_task);
            tokio::spawn(async move {
                while let Ok((sock, _)) = v6.accept().await {
                    let phases = phases.clone();
                    let tls = tls.clone();
                    let drain = drain.clone();
                    let log = Arc::clone(&log6);
                    tokio::spawn(async move {
                        serve_phases(Box::new(sock), &phases, &tls, &log, &drain).await;
                    });
                }
            });
        }
        while let Ok((sock, _)) = listener.accept().await {
            let phases = phases.clone();
            let tls = tls.clone();
            let drain = drain.clone();
            let log = Arc::clone(&log_task);
            tokio::spawn(async move {
                serve_phases(Box::new(sock), &phases, &tls, &log, &drain).await;
            });
        }
    });
    (addr, log, collected)
}

pub(super) fn stub_config(addr: SocketAddr, protocol: ProxyProtocol, is_gate: bool) -> ProxyConfig {
    let cfg = ProxyConfig::new(protocol, "localhost", addr.port());
    if is_gate {
        cfg.as_gate()
    } else {
        cfg
    }
}

/// One gate×inner combo end to end: `connect_chain` must complete both
/// handshakes speaking each hop's actual wire protocol, in order,
/// addressed first to the inner proxy and then to the target.
async fn run_matrix_combo(gate_proto: ProxyProtocol, inner_proto: ProxyProtocol) {
    let (addr, log) = spawn_protocol_stub(gate_proto, inner_proto).await;
    let gate = stub_config(addr, gate_proto, true).with_gate_level(1);
    let inner = stub_config(addr, inner_proto, false);
    let chain = ProxyConfig::chain([Arc::new(gate), Arc::new(inner.clone())]).unwrap();
    let pool = ProxyPool::new(Default::default(), Duration::from_secs(2), 4);
    let connector = stub_tls_connector();
    let tls = if gate_proto == ProxyProtocol::Https || inner_proto == ProxyProtocol::Https {
        Some(&connector)
    } else {
        None
    };
    let stream = timeout(
        Duration::from_secs(15),
        connect_chain(
            &chain,
            "example.com:443",
            &pool,
            Duration::from_secs(5),
            tls,
        ),
    )
    .await
    .expect("combo must not hang")
    .expect("chain succeeds");
    let sock = stream
        .as_tcp()
        .expect("gate tunnel exposes its real socket");
    sock.set_nodelay(true)
        .expect("set_nodelay reaches the gate socket");
    assert!(
        sock.nodelay().expect("nodelay readback"),
        "TCP_NODELAY must be observably applied on the gate socket"
    );
    let mut expected = Vec::new();
    for (proto, target) in [
        (gate_proto, format!("localhost:{}", inner.port)),
        (inner_proto, "example.com:443".to_string()),
    ] {
        let phase = match proto {
            ProxyProtocol::Socks5 => StubPhase::Socks5,
            ProxyProtocol::Http | ProxyProtocol::Https => StubPhase::HttpConnect,
        };
        expected.push((phase, target));
    }
    assert_eq!(
        *log.lock().unwrap(),
        expected,
        "wire exchanges gate={gate_proto:?} inner={inner_proto:?}"
    );
}
#[tokio::test]
async fn matrix_socks5_gate_socks5_inner() {
    run_matrix_combo(ProxyProtocol::Socks5, ProxyProtocol::Socks5).await;
}
#[tokio::test]
async fn matrix_socks5_gate_http_inner() {
    run_matrix_combo(ProxyProtocol::Socks5, ProxyProtocol::Http).await;
}
#[tokio::test]
async fn matrix_socks5_gate_https_inner() {
    run_matrix_combo(ProxyProtocol::Socks5, ProxyProtocol::Https).await;
}
#[tokio::test]
async fn matrix_http_gate_socks5_inner() {
    run_matrix_combo(ProxyProtocol::Http, ProxyProtocol::Socks5).await;
}
#[tokio::test]
async fn matrix_http_gate_http_inner() {
    run_matrix_combo(ProxyProtocol::Http, ProxyProtocol::Http).await;
}
#[tokio::test]
async fn matrix_http_gate_https_inner() {
    run_matrix_combo(ProxyProtocol::Http, ProxyProtocol::Https).await;
}
#[tokio::test]
async fn matrix_https_gate_socks5_inner() {
    run_matrix_combo(ProxyProtocol::Https, ProxyProtocol::Socks5).await;
}
#[tokio::test]
async fn matrix_https_gate_http_inner() {
    run_matrix_combo(ProxyProtocol::Https, ProxyProtocol::Http).await;
}
#[tokio::test]
async fn matrix_https_gate_https_inner() {
    run_matrix_combo(ProxyProtocol::Https, ProxyProtocol::Https).await;
}

#[tokio::test]
async fn https_hop_without_connector_is_rejected_without_credential_leak() {
    let (addr, _) = spawn_protocol_stub(ProxyProtocol::Https, ProxyProtocol::Socks5).await;
    let gate = stub_config(addr, ProxyProtocol::Https, true)
        .with_auth("alice", "s3cret")
        .with_gate_level(1);
    let inner = stub_config(addr, ProxyProtocol::Socks5, false);
    let chain = ProxyConfig::chain([Arc::new(gate), Arc::new(inner)]).unwrap();
    let pool = ProxyPool::new(Default::default(), Duration::from_secs(2), 4);
    let error = timeout(
        Duration::from_secs(5),
        connect_chain(
            &chain,
            "example.com:443",
            &pool,
            Duration::from_secs(2),
            None,
        ),
    )
    .await
    .expect("not hang")
    .err()
    .expect("missing TLS connector fails");
    assert_eq!(error.stage(), resocks5_net::connect::ChainStage::Connect);
    let rendered = format!("{}\n{}", error, error.error());
    assert!(
        rendered.contains("HTTPS upstream requires TLS connector"),
        "chain must name the missing connector, got: {rendered}"
    );
    assert!(!rendered.contains("alice"), "username leaked: {rendered}");
    assert!(!rendered.contains("s3cret"), "password leaked: {rendered}");
}
fn sharp_policy() -> resocks5_net::rating::RatingPolicy {
    resocks5_net::rating::RatingPolicy {
        half_life_sec: 3600.0,
        fail_penalty: 8.0,
        sand_max: 8.0,
        min_weight: 0.01,
        success_factor: 0.5,
    }
}
fn first_pick_fraction(r: &ProxyRotator, p: &ProxyConfig, n: u32) -> f64 {
    let mut hits = 0;
    for _ in 0..n {
        if r.pick_order()[0].port == p.port {
            hits += 1
        }
    }
    f64::from(hits) / f64::from(n)
}
#[tokio::test]
async fn cached_gate_connect_failure_penalizes_gate_not_inner_proxy() {
    let target = "example.com:443";
    let logger = test_logger();
    let banned = Arc::new(RegexSet::empty());
    let pool = Arc::new(ProxyPool::new(
        Default::default(),
        Duration::from_secs(2),
        4,
    ));
    let network = Arc::new(NetworkConfig {
        handshake_timeout_sec: 2,
        max_upstream_attempts: 2,
        ..Default::default()
    });
    let dead = socks5_config(SocketAddr::from(([127, 0, 0, 1], 1)), true).with_gate_level(1);
    let witness = socks5_config(SocketAddr::from(([127, 0, 0, 1], 2)), true).with_gate_level(1);
    let inner_a = socks5_config(spawn_socks5_stub().await, false);
    let inner_b = socks5_config(spawn_socks5_stub().await, false);
    let policy = sharp_policy();
    let v4 = Arc::new(ProxyRotator::with_policy(
        vec![inner_a.clone(), inner_b],
        policy,
    ));
    let gate_rotator = Arc::new(ProxyRotator::with_policy(
        vec![dead.clone(), witness.clone()],
        policy,
    ));
    let gates = Arc::new(GateLevels::new(vec![(1, gate_rotator.clone())]));
    let composite = ProxyConfig::chain([Arc::new(dead), Arc::new(inner_a.clone())]).unwrap();
    v4.link_proxy(target.to_string(), Arc::new(composite));
    let result = establish_connection(
        target,
        &gates,
        &None,
        &Some(v4.clone()),
        &logger,
        &banned,
        &pool,
        &network,
        None,
        None,
    )
    .await;
    assert!(result.is_ok(), "fallback: {:?}", result.err());
    let a = first_pick_fraction(&v4, &inner_a, 2000);
    assert!(a > 0.3, "inner pick {:.1}%", a * 100.0);
    let w = first_pick_fraction(&gate_rotator, &witness, 2000);
    assert!(w > 0.7, "witness pick {:.1}%", w * 100.0);
}
#[tokio::test]
async fn dead_gate_not_retried_against_second_proxy_within_one_call() {
    let target = "example.com:443";
    let banned = Arc::new(RegexSet::empty());
    let pool = Arc::new(ProxyPool::new(
        Default::default(),
        Duration::from_secs(2),
        4,
    ));
    let network = Arc::new(NetworkConfig {
        handshake_timeout_sec: 2,
        max_upstream_attempts: 10,
        ..Default::default()
    });
    let dead = socks5_config(SocketAddr::from(([127, 0, 0, 1], 1)), true).with_gate_level(1);
    let inner_a = socks5_config(spawn_socks5_stub().await, false);
    let inner_b = socks5_config(spawn_socks5_stub().await, false);
    let (tx, mut rx) = tokio::sync::mpsc::channel::<crate::logger::ELog>(64);
    let logger = Arc::new(Logger::new(
        tx,
        crate::logger::LogConfig {
            attempts: true,
            ..Default::default()
        },
    ));
    let gates = Arc::new(GateLevels::new(vec![(
        1,
        Arc::new(ProxyRotator::new(vec![dead])),
    )]));
    let v4 = Arc::new(ProxyRotator::new(vec![inner_a, inner_b]));
    let result = establish_connection(
        target,
        &gates,
        &None,
        &Some(v4),
        &logger,
        &banned,
        &pool,
        &network,
        None,
        None,
    )
    .await;
    assert!(result.is_ok(), "fallback: {:?}", result.err());
    let (mut gate, mut direct) = (0, 0);
    while let Ok(entry) = rx.try_recv() {
        let crate::logger::ELog::Log(msg) = entry else {
            continue;
        };
        if msg.contains("path=gate") {
            gate += 1
        } else if msg.contains("path=direct") {
            direct += 1
        }
    }
    assert_eq!(gate, 1);
    assert_eq!(direct, 1);
}
