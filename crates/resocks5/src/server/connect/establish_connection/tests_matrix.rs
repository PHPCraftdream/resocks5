use super::dial::*;
use super::tests_unit::{socks5_config, spawn_socks5_stub, test_logger};
use crate::config::NetworkConfig;
use crate::logger::Logger;
use regex::RegexSet;
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

fn stub_tls_connector() -> TlsConnector {
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
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum StubPhase {
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

type StubLog = Arc<Mutex<Vec<(StubPhase, String)>>>;

/// Serve ONE client connection through its expected phase sequence.
/// The tunnel is a single socket: both hops' exchanges arrive here,
/// an Https hop nests the remaining phases inside a TLS layer. After
/// the last phase, hold the tunnel open until the client drops it.
trait Stream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Stream for T {}
type ErasedStream = Box<dyn Stream>;

fn serve_phases<'a>(
    mut stream: ErasedStream,
    phases: &'a [StubPhase],
    tls: &'a TlsAcceptor,
    log: &'a StubLog,
) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>> {
    Box::pin(async move {
        let Some((phase, rest)) = phases.split_first() else {
            let mut buf = [0u8; 512];
            while stream.read(&mut buf).await.unwrap_or(0) != 0 {}
            return;
        };
        match phase {
            StubPhase::TlsAccept => {
                let Ok(tls_stream) = tls.accept(stream).await else {
                    return;
                };
                serve_phases(Box::new(tls_stream), rest, tls, log).await;
            }
            StubPhase::Socks5 => {
                if let Some(target) = socks5_exchange(&mut stream).await {
                    log.lock().unwrap().push((StubPhase::Socks5, target));
                }
                serve_phases(Box::new(stream), rest, tls, log).await;
            }
            StubPhase::HttpConnect => {
                if let Some(target) = http_connect_exchange(&mut stream).await {
                    log.lock().unwrap().push((StubPhase::HttpConnect, target));
                }
                serve_phases(Box::new(stream), rest, tls, log).await;
            }
        }
    })
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
/// the gate and the inner config point at it. Returns the address
/// and the log of answered exchanges as (phase, requested target).
async fn spawn_protocol_stub(
    gate_proto: ProxyProtocol,
    inner_proto: ProxyProtocol,
) -> (SocketAddr, StubLog) {
    let phases: Vec<StubPhase> = stub_phases(gate_proto)
        .into_iter()
        .chain(stub_phases(inner_proto))
        .collect();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    // `localhost` may resolve to ::1 first; a stalled IPv6 connect
    // attempt would eat the pool's connect timeout, so serve both
    // loopback families on the same port.
    let v6 = tokio::net::TcpListener::bind(format!("[::1]:{}", addr.port())).await;
    let log: StubLog = Arc::new(Mutex::new(Vec::new()));
    let tls = stub_tls_acceptor();
    let log_task = Arc::clone(&log);
    tokio::spawn(async move {
        if let Ok(v6) = v6 {
            let phases = phases.clone();
            let tls = tls.clone();
            let log6 = Arc::clone(&log_task);
            tokio::spawn(async move {
                while let Ok((sock, _)) = v6.accept().await {
                    let phases = phases.clone();
                    let tls = tls.clone();
                    let log = Arc::clone(&log6);
                    tokio::spawn(async move {
                        serve_phases(Box::new(sock), &phases, &tls, &log).await;
                    });
                }
            });
        }
        while let Ok((sock, _)) = listener.accept().await {
            let phases = phases.clone();
            let tls = tls.clone();
            let log = Arc::clone(&log_task);
            tokio::spawn(async move {
                serve_phases(Box::new(sock), &phases, &tls, &log).await;
            });
        }
    });
    (addr, log)
}

fn stub_config(addr: SocketAddr, protocol: ProxyProtocol, is_gate: bool) -> ProxyConfig {
    ProxyConfig {
        protocol,
        ip: resocks5_net::types::IP::V4,
        host: "localhost".to_string(),
        port: addr.port(),
        user: None,
        password: None,
        is_gate,
        gate: None,
    }
}

/// One gate×inner combo end to end: `use_gate` must complete both
/// handshakes speaking each hop's actual wire protocol, in order,
/// addressed first to the inner proxy and then to the target.
async fn run_matrix_combo(gate_proto: ProxyProtocol, inner_proto: ProxyProtocol) {
    let (addr, log) = spawn_protocol_stub(gate_proto, inner_proto).await;
    let gate = stub_config(addr, gate_proto, true);
    let inner = stub_config(addr, inner_proto, false);
    let pool = ProxyPool::new(Default::default(), Duration::from_secs(2), 4);
    let connector = stub_tls_connector();
    let tls_connector = if gate_proto == ProxyProtocol::Https || inner_proto == ProxyProtocol::Https
    {
        Some(&connector)
    } else {
        None
    };

    let tunneled = timeout(
        Duration::from_secs(15),
        use_gate(
            "example.com:443",
            &gate,
            &inner,
            &pool,
            Duration::from_secs(5),
            tls_connector,
        ),
    )
    .await
    .expect("combo must not hang")
    .expect("gate tunnel must complete");

    // Socket options must reach the REAL gate socket through the
    // erasure. Across the 9 rows this exercises all three erased
    // shapes — plain (`UpstreamStream`), single TLS, and double
    // TLS — with an observable TCP_NODELAY round-trip, not just a
    // non-error return.
    let gate_socket = tunneled
        .as_tcp()
        .expect("gate tunnel exposes its real socket");
    gate_socket
        .set_nodelay(true)
        .expect("set_nodelay reaches the gate socket");
    assert!(
        gate_socket.nodelay().expect("nodelay readback"),
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
    let got = log.lock().unwrap().clone();
    assert_eq!(
        got, expected,
        "wire exchanges for gate={:?} inner={:?}",
        gate_proto, inner_proto
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
    let (addr, _log) = spawn_protocol_stub(ProxyProtocol::Https, ProxyProtocol::Socks5).await;
    let mut gate = stub_config(addr, ProxyProtocol::Https, true);
    gate.user = Some("alice".to_string());
    gate.password = Some("s3cret".to_string());
    let inner = stub_config(addr, ProxyProtocol::Socks5, false);
    let pool = ProxyPool::new(Default::default(), Duration::from_secs(2), 4);

    let err = timeout(
        Duration::from_secs(5),
        use_gate(
            "example.com:443",
            &gate,
            &inner,
            &pool,
            Duration::from_secs(2),
            None,
        ),
    )
    .await
    .expect("must not hang")
    .err()
    .expect("HTTPS hop without a TLS connector must fail");

    let chain: Vec<String> = err.chain().map(|c| c.to_string()).collect();
    assert!(
        chain
            .iter()
            .any(|c| c.contains("HTTPS upstream requires TLS connector")),
        "chain must name the missing connector, got: {:?}",
        chain
    );
    let joined = chain.join("\n");
    assert!(!joined.contains("alice"), "username leaked: {}", joined);
    assert!(!joined.contains("s3cret"), "password leaked: {}", joined);
}

/// Rating policy where ONE failure saturates the sand completely
/// (`fail_penalty == sand_max`) and decay is negligible over a test
/// run: a penalized upstream weighs exactly `min_weight` = 0.01 vs
/// 1.0 for a pristine one, so sampling `pick_order` separates the
/// two within a few thousand draws (same technique as the
/// rotator's own `record_failure_lowers_pick_probability`).
fn sharp_policy() -> resocks5_net::rating::RatingPolicy {
    resocks5_net::rating::RatingPolicy {
        half_life_sec: 3600.0,
        fail_penalty: 8.0,
        sand_max: 8.0,
        min_weight: 0.01,
        success_factor: 0.5,
    }
}

/// Fraction of `n` weighted-random picks that put `proxy` first.
fn first_pick_fraction(rotator: &ProxyRotator, proxy: &ProxyConfig, n: u32) -> f64 {
    let mut hits = 0u32;
    for _ in 0..n {
        if rotator.pick_order()[0].port == proxy.port {
            hits += 1;
        }
    }
    f64::from(hits) / f64::from(n)
}

#[tokio::test]
async fn cached_gate_connect_failure_penalizes_gate_not_inner_proxy() {
    // R2-19: the cached-route retry of a gate composite must apply
    // the same per-stage classification as the gates phase. The
    // gate is unreachable (GateConnect): the inner proxy — never
    // touched — keeps its rating, while the gate itself takes the
    // penalty (and is excluded from the later gates phase).
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
        // One cache attempt, then the gates phase must bail before
        // any pairing: budget 2 minus the direct reserve of 1. So
        // the witness gate below is never attempted and its rating
        // stays pristine as the control.
        max_upstream_attempts: 2,
        ..Default::default()
    });
    let dead_gate = socks5_config(SocketAddr::from(([127, 0, 0, 1], 1)), true);
    let witness_gate = socks5_config(SocketAddr::from(([127, 0, 0, 1], 2)), true);
    let inner_a = socks5_config(spawn_socks5_stub().await, false);
    let inner_b = socks5_config(spawn_socks5_stub().await, false);
    let mut composite = inner_a.clone();
    composite.gate = Some(Arc::new(dead_gate.clone()));

    let policy = sharp_policy();
    let v4 = Arc::new(ProxyRotator::with_policy(
        vec![inner_a.clone(), inner_b.clone()],
        policy,
    ));
    v4.link_proxy(target.to_string(), Arc::new(composite));
    let gates = Arc::new(ProxyRotator::with_policy(
        vec![dead_gate, witness_gate.clone()],
        policy,
    ));

    let result = establish_connection(
        target,
        &Some(gates.clone()),
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
    assert!(
        result.is_ok(),
        "direct fallback must serve the target: {:?}",
        result.as_ref().err()
    );

    // The inner proxy was spared: both inners still weigh ~1.0, so
    // either may be picked first about half the time. Before the
    // fix the cached failure landed on the composite's inner
    // identity (~1% first-pick).
    let frac_a = first_pick_fraction(&v4, &inner_a, 2000);
    assert!(
        frac_a > 0.3,
        "untouched inner proxy picked first only {:.1}%, expected ~50%",
        frac_a * 100.0
    );

    // The gate took the penalty: the never-attempted witness gate
    // must now dominate the gate rotator's picks. Before the fix
    // both gates stayed pristine (~50%).
    let frac_witness = first_pick_fraction(&gates, &witness_gate, 2000);
    assert!(
        frac_witness > 0.7,
        "spared witness gate picked first only {:.1}%, expected ~99%",
        frac_witness * 100.0
    );
}

#[tokio::test]
async fn dead_gate_not_retried_against_second_proxy_within_one_call() {
    // R2-19: once a gate fails at GateConnect against the FIRST
    // proxy, the same call must not burn another attempt pairing
    // it with the NEXT proxy — the dead-gate short-circuit takes
    // effect immediately, not at the next outer-loop entry. The
    // budget is deliberately generous so only the short-circuit
    // (not the budget) can stop the gates phase.
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
    let dead_gate = socks5_config(SocketAddr::from(([127, 0, 0, 1], 1)), true);
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

    let gates = Arc::new(ProxyRotator::new(vec![dead_gate]));
    let v4 = Arc::new(ProxyRotator::new(vec![inner_a, inner_b]));

    let result = establish_connection(
        target,
        &Some(gates),
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
    assert!(
        result.is_ok(),
        "direct fallback must serve the target: {:?}",
        result.as_ref().err()
    );

    // Each `use_gate` attempt logs exactly one `attempt ... path=gate`
    // line; the direct fallback logs `path=direct`.
    let mut gate_attempts = 0u32;
    let mut direct_attempts = 0u32;
    while let Ok(entry) = rx.try_recv() {
        let crate::logger::ELog::Log(msg) = entry else {
            continue;
        };
        if msg.contains("path=gate") {
            gate_attempts += 1;
        } else if msg.contains("path=direct") {
            direct_attempts += 1;
        }
    }
    assert_eq!(
        gate_attempts, 1,
        "a gate proven dead against the first proxy must not be \
         re-tried against the second within the same call"
    );
    assert_eq!(
        direct_attempts, 1,
        "the direct fallback must still run exactly once"
    );
}
