use super::establish_connection;
use crate::logger::Logger;
use regex::RegexSet;
use resocks5_net::chain::GateLevels;
use resocks5_net::connect::HostPort;
use resocks5_net::pool::ProxyPool;
use resocks5_net::rotator::ProxyRotator;
use resocks5_net::types::{ProxyConfig, ProxyProtocol};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_rustls::{TlsAcceptor, TlsConnector};

struct AbortOnDrop(JoinHandle<()>);
impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}
trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}
type BoxIo = Box<dyn Io>;
struct Hop {
    addr: SocketAddr,
    records: Arc<Mutex<Vec<String>>>,
    _task: AbortOnDrop,
}

async fn exchange<S: AsyncRead + AsyncWrite + Unpin>(
    s: &mut S,
    proto: ProxyProtocol,
) -> Option<String> {
    let mut first = [0; 1];
    s.read_exact(&mut first).await.ok()?;
    if (proto == ProxyProtocol::Socks5) != (first[0] == 5) {
        return None;
    }
    if first[0] == 5 {
        let mut greeting = [0; 2];
        s.read_exact(&mut greeting).await.ok()?;
        if greeting != [1, 0] {
            return None;
        }
        s.write_all(&[5, 0]).await.ok()?;
        let mut head = [0; 4];
        s.read_exact(&mut head).await.ok()?;
        if head[..3] != [5, 1, 0] {
            return None;
        }
        let host = match head[3] {
            1 => {
                let mut b = [0; 4];
                s.read_exact(&mut b).await.ok()?;
                std::net::Ipv4Addr::from(b).to_string()
            }
            3 => {
                let mut n = [0; 1];
                s.read_exact(&mut n).await.ok()?;
                let mut b = vec![0; n[0] as usize];
                s.read_exact(&mut b).await.ok()?;
                String::from_utf8(b).ok()?
            }
            4 => {
                let mut b = [0; 16];
                s.read_exact(&mut b).await.ok()?;
                std::net::Ipv6Addr::from(b).to_string()
            }
            _ => return None,
        };
        let mut p = [0; 2];
        s.read_exact(&mut p).await.ok()?;
        s.write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 0]).await.ok()?;
        Some(HostPort::format(&host, u16::from_be_bytes(p)))
    } else {
        let mut req = vec![first[0]];
        while !req.ends_with(b"\r\n\r\n") {
            let mut b = [0; 1];
            s.read_exact(&mut b).await.ok()?;
            req.push(b[0]);
            if req.len() > 8192 {
                return None;
            }
        }
        let line = std::str::from_utf8(&req).ok()?.split("\r\n").next()?;
        let target = line.strip_prefix("CONNECT ")?.split(' ').next()?.to_owned();
        s.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
            .await
            .ok()?;
        Some(target)
    }
}
async fn serve(
    mut io: BoxIo,
    proto: ProxyProtocol,
    tls: TlsAcceptor,
    log: Arc<Mutex<Vec<String>>>,
) {
    if proto == ProxyProtocol::Https {
        let Ok(s) = tls.accept(io).await else { return };
        io = Box::new(s);
    }
    let Some(next) = exchange(&mut io, proto).await else {
        return;
    };
    log.lock().unwrap().push(next.clone());
    let Ok(mut upstream) = TcpStream::connect(&next).await else {
        return;
    };
    let _ = tokio::io::copy_bidirectional(&mut io, &mut upstream).await;
}
async fn spawn_hop(proto: ProxyProtocol) -> Hop {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let records = Arc::new(Mutex::new(Vec::new()));
    let output = Arc::clone(&records);
    let tls = super::tests_matrix::stub_tls_acceptor();
    let task = tokio::spawn(async move {
        let mut children = tokio::task::JoinSet::new();
        loop {
            tokio::select! {
                accepted=listener.accept()=>{ let Ok((socket,_))=accepted else{break}; let log=Arc::clone(&output); let tls=tls.clone(); children.spawn(async move{serve(Box::new(socket),proto,tls,log).await;}); }
                Some(_)=children.join_next(), if !children.is_empty()=>{}
            }
        }
        while children.join_next().await.is_some() {}
    });
    Hop {
        addr,
        records,
        _task: AbortOnDrop(task),
    }
}
fn config(h: &Hop, p: ProxyProtocol, rank: u8) -> ProxyConfig {
    ProxyConfig::new(
        p,
        if p == ProxyProtocol::Https {
            "localhost".to_owned()
        } else {
            h.addr.ip().to_string()
        },
        h.addr.port(),
    )
    .with_gate_level(rank)
}

#[tokio::test]
async fn three_level_mixed_protocol_chain_forwards_each_hop_once() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let first = spawn_hop(ProxyProtocol::Socks5).await;
        let second = spawn_hop(ProxyProtocol::Http).await;
        let third = spawn_hop(ProxyProtocol::Https).await;
        let exit = spawn_hop(ProxyProtocol::Socks5).await;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_addr = listener.local_addr().unwrap();
        let target_task = AbortOnDrop(tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let mut b = [0; 8];
            s.read_exact(&mut b).await.unwrap();
            s.write_all(&b).await.unwrap();
        }));
        let target = HostPort::format(&target_addr.ip().to_string(), target_addr.port());
        let configs = vec![
            config(&first, ProxyProtocol::Socks5, 3),
            config(&second, ProxyProtocol::Http, 2),
            config(&third, ProxyProtocol::Https, 1),
        ];
        let gates = Arc::new(GateLevels::new(
            configs
                .into_iter()
                .map(|c| (c.gate_level, Arc::new(ProxyRotator::new(vec![c]))))
                .collect(),
        ));
        let exit_config = ProxyConfig::new(
            ProxyProtocol::Socks5,
            exit.addr.ip().to_string(),
            exit.addr.port(),
        );
        let exit_rotator = Arc::new(ProxyRotator::new(vec![exit_config]));
        let pool = Arc::new(ProxyPool::new(
            Default::default(),
            Duration::from_secs(3),
            8,
        ));
        let network = Arc::new(crate::config::NetworkConfig {
            handshake_timeout_sec: 3,
            ..Default::default()
        });
        let (tx, _) = mpsc::channel(16);
        let logger = Arc::new(Logger::new(tx, crate::logger::LogConfig::default()));
        let connector: TlsConnector = super::tests_matrix::stub_tls_connector();
        let mut stream = establish_connection(
            &target,
            &gates,
            &Some(exit_rotator),
            &None,
            &logger,
            &Arc::new(RegexSet::empty()),
            &pool,
            &network,
            None,
            Some(&connector),
        )
        .await
        .unwrap();
        stream.write_all(b"chain123").await.unwrap();
        let mut echoed = [0; 8];
        stream.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed, b"chain123");
        assert_eq!(
            *first.records.lock().unwrap(),
            vec![second.addr.to_string()]
        );
        assert_eq!(
            *second.records.lock().unwrap(),
            vec![format!("localhost:{}", third.addr.port())]
        );
        assert_eq!(*third.records.lock().unwrap(), vec![exit.addr.to_string()]);
        assert_eq!(*exit.records.lock().unwrap(), vec![target]);
        drop((stream, target_task));
    })
    .await
    .expect("whole chain flow timed out");
}

#[tokio::test]
async fn capacity_regression_falls_back_then_reuses_inner_gate() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let outer_a = spawn_hop(ProxyProtocol::Socks5).await;
        let outer_b = spawn_hop(ProxyProtocol::Socks5).await;
        let middle_a = spawn_hop(ProxyProtocol::Socks5).await;
        let middle_b = spawn_hop(ProxyProtocol::Socks5).await;
        let inner = spawn_hop(ProxyProtocol::Socks5).await;
        let exit_a = spawn_hop(ProxyProtocol::Socks5).await;
        let exit_b = spawn_hop(ProxyProtocol::Socks5).await;
        let target_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_addr = target_listener.local_addr().unwrap();
        let target = HostPort::format(&target_addr.ip().to_string(), target_addr.port());
        let mut target_task = AbortOnDrop(tokio::spawn(async move {
            let mut sockets = Vec::new();
            for _ in 0..3 {
                sockets.push(target_listener.accept().await.unwrap().0);
            }
            drop(sockets);
        }));

        let outer_a_config = config(&outer_a, ProxyProtocol::Socks5, 3);
        let middle_a_config = config(&middle_a, ProxyProtocol::Socks5, 2);
        let inner_config = config(&inner, ProxyProtocol::Socks5, 1);
        let outer_a_rotator = Arc::new(ProxyRotator::new(vec![outer_a_config]));
        let middle_a_rotator = Arc::new(ProxyRotator::new(vec![middle_a_config]));
        let inner_rotator = Arc::new(
            ProxyRotator::try_with_quarantine(
                vec![inner_config.clone()],
                Default::default(),
                resocks5_net::rating::QuarantinePolicy::default().with_threshold(1),
                8,
                Duration::from_secs(60),
            )
            .unwrap(),
        );
        let gates_a = Arc::new(GateLevels::new(vec![
            (3, outer_a_rotator),
            (2, middle_a_rotator),
            (1, inner_rotator.clone()),
        ]));
        let exit_a_config = ProxyConfig::new(
            ProxyProtocol::Socks5,
            exit_a.addr.ip().to_string(),
            exit_a.addr.port(),
        );
        let exit_a_rotator = Arc::new(ProxyRotator::new(vec![exit_a_config]));
        let pool = Arc::new(ProxyPool::new(
            Default::default(),
            Duration::from_secs(3),
            1,
        ));
        let network = Arc::new(crate::config::NetworkConfig {
            max_upstream_attempts: 2,
            handshake_timeout_sec: 3,
            ..Default::default()
        });
        let (tx, mut logs) = mpsc::channel(32);
        let logger = Arc::new(Logger::new(
            tx,
            crate::logger::LogConfig {
                attempts: true,
                ..Default::default()
            },
        ));
        let banned = Arc::new(RegexSet::empty());
        let connector: TlsConnector = super::tests_matrix::stub_tls_connector();
        let first = establish_connection(
            &target,
            &gates_a,
            &Some(exit_a_rotator),
            &None,
            &logger,
            &banned,
            &pool,
            &network,
            None,
            Some(&connector),
        )
        .await
        .unwrap();
        let outer_b_rotator = Arc::new(ProxyRotator::new(vec![config(
            &outer_b,
            ProxyProtocol::Socks5,
            3,
        )]));
        let middle_b_config = config(&middle_b, ProxyProtocol::Socks5, 2);
        let middle_b_rotator = Arc::new(ProxyRotator::new(vec![middle_b_config.clone()]));
        let gates_b = Arc::new(GateLevels::new(vec![
            (3, outer_b_rotator),
            (2, middle_b_rotator.clone()),
            (1, inner_rotator.clone()),
        ]));
        let exit_b_config = ProxyConfig::new(
            ProxyProtocol::Socks5,
            exit_b.addr.ip().to_string(),
            exit_b.addr.port(),
        );
        let exit_b_rotator = Arc::new(ProxyRotator::new(vec![exit_b_config]));
        let second = establish_connection(
            &target,
            &gates_b,
            &Some(exit_b_rotator.clone()),
            &None,
            &logger,
            &banned,
            &pool,
            &network,
            None,
            Some(&connector),
        )
        .await
        .unwrap();
        let entries: Vec<String> = std::iter::from_fn(|| logs.try_recv().ok())
            .filter_map(|entry| match entry {
                crate::logger::ELog::Log(line) => Some(line),
                _ => None,
            })
            .collect();
        assert!(
            entries.iter().any(|line| line.contains("path=gate")
                && line.contains("outcome=fail")
                && line.contains("upstream cap reached")),
            "missing capacity gate failure: {entries:?}"
        );
        assert!(
            entries
                .iter()
                .any(|line| line.contains("path=direct") && line.contains("outcome=ok")),
            "missing direct fallback success: {entries:?}"
        );
        assert_eq!(
            *inner.records.lock().unwrap(),
            vec![exit_a.addr.to_string()]
        );
        assert!(middle_b.records.lock().unwrap().is_empty());
        assert!(!inner_rotator.is_quarantined(&inner_config));

        let target_key = target.clone();
        drop((first, second));
        exit_b_rotator.unlink_proxy(&target_key);
        let third = establish_connection(
            &target,
            &gates_b,
            &Some(exit_b_rotator),
            &None,
            &logger,
            &banned,
            &pool,
            &network,
            None,
            Some(&connector),
        )
        .await
        .unwrap();
        assert_eq!(
            *inner.records.lock().unwrap(),
            vec![exit_a.addr.to_string(), exit_b.addr.to_string()]
        );
        assert_eq!(
            *middle_b.records.lock().unwrap(),
            vec![inner.addr.to_string()]
        );
        assert!(!inner_rotator.is_quarantined(&inner_config));
        drop(third);
        (&mut target_task.0).await.unwrap();
    })
    .await
    .expect("capacity regression flow timed out");
}
