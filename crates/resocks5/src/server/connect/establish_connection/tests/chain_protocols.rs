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
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::{TlsAcceptor, TlsConnector};

struct OwnedTask(JoinHandle<()>);
impl Drop for OwnedTask {
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
    _task: OwnedTask,
}

async fn exchange<S: AsyncRead + AsyncWrite + Unpin>(stream: &mut S) -> Option<String> {
    let mut first = [0; 1];
    stream.read_exact(&mut first).await.ok()?;
    if first[0] == 5 {
        let mut tail = [0; 2];
        stream.read_exact(&mut tail).await.ok()?;
        if tail != [1, 0] { return None; }
        stream.write_all(&[5, 0]).await.ok()?;
        let mut head = [0; 4];
        stream.read_exact(&mut head).await.ok()?;
        if head[..3] != [5, 1, 0] { return None; }
        let host = match head[3] {
            1 => { let mut b = [0; 4]; stream.read_exact(&mut b).await.ok()?; std::net::Ipv4Addr::from(b).to_string() }
            3 => { let mut n = [0; 1]; stream.read_exact(&mut n).await.ok()?; let mut b = vec![0; n[0] as usize]; stream.read_exact(&mut b).await.ok()?; String::from_utf8(b).ok()? }
            4 => { let mut b = [0; 16]; stream.read_exact(&mut b).await.ok()?; std::net::Ipv6Addr::from(b).to_string() }
            _ => return None,
        };
        let mut port = [0; 2]; stream.read_exact(&mut port).await.ok()?;
        stream.write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 0]).await.ok()?;
        Some(HostPort::format(&host, u16::from_be_bytes(port)))
    } else {
        let mut req = vec![first[0]];
        while !req.ends_with(b"\r\n\r\n") {
            let mut b = [0; 1]; stream.read_exact(&mut b).await.ok()?; req.push(b[0]);
            if req.len() > 8192 { return None; }
        }
        let line = std::str::from_utf8(&req).ok()?.split("\r\n").next()?;
        let target = line.strip_prefix("CONNECT ")?.split(' ').next()?.to_owned();
        stream.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n").await.ok()?;
        Some(target)
    }
}

async fn serve(mut io: BoxIo, protocol: ProxyProtocol, tls: TlsAcceptor, records: Arc<Mutex<Vec<String>>>) {
    if protocol == ProxyProtocol::Https {
        let Ok(stream) = tls.accept(io).await else { return; };
        io = Box::new(stream);
    }
    let Some(next) = exchange(&mut io).await else { return; };
    records.lock().unwrap().push(next.clone());
    let Ok(mut upstream) = TcpStream::connect(&next).await else { return; };
    let _ = tokio::io::copy_bidirectional(&mut io, &mut upstream).await;
}

async fn hop(protocol: ProxyProtocol) -> Hop {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let records = Arc::new(Mutex::new(Vec::new()));
    let output = Arc::clone(&records);
    let tls = super::tests_matrix::stub_tls_acceptor();
    let task = tokio::spawn(async move {
        loop {
            let Ok((socket, _)) = listener.accept().await else { break; };
            let records = Arc::clone(&output);
            let tls = tls.clone();
            tokio::spawn(async move { serve(Box::new(socket), protocol, tls, records).await; });
        }
    });
    Hop { addr, records, _task: OwnedTask(task) }
}

fn cfg(hop: &Hop, protocol: ProxyProtocol, rank: u8) -> ProxyConfig {
    ProxyConfig::new(protocol, hop.addr.ip().to_string(), hop.addr.port()).with_gate_level(rank)
}

#[tokio::test]
async fn three_level_mixed_protocol_chain_forwards_each_hop_once() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let first = hop(ProxyProtocol::Socks5).await;
        let second = hop(ProxyProtocol::Http).await;
        let third = hop(ProxyProtocol::Https).await;
        let exit = hop(ProxyProtocol::Socks5).await;
        let target_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_addr = target_listener.local_addr().unwrap();
        let target_task = OwnedTask(tokio::spawn(async move {
            let (mut socket, _) = target_listener.accept().await.unwrap();
            let mut bytes = [0; 8];
            socket.read_exact(&mut bytes).await.unwrap();
            socket.write_all(&bytes).await.unwrap();
        }));
        let target = HostPort::format(&target_addr.ip().to_string(), target_addr.port());
        let configs = vec![cfg(&first, ProxyProtocol::Socks5, 3), cfg(&second, ProxyProtocol::Http, 2), cfg(&third, ProxyProtocol::Https, 1)];
        let gates = Arc::new(GateLevels::new(configs.into_iter().map(|config| (config.gate_level, Arc::new(ProxyRotator::new(vec![config])))).collect()));
        let exit_cfg = ProxyConfig::new(ProxyProtocol::Socks5, exit.addr.ip().to_string(), exit.addr.port());
        let exit_rotator = Arc::new(ProxyRotator::new(vec![exit_cfg]));
        let pool = Arc::new(ProxyPool::new(Default::default(), Duration::from_secs(3), 8));
        let network = Arc::new(crate::config::NetworkConfig { handshake_timeout_sec: 3, ..Default::default() });
        let (log_tx, _) = mpsc::channel(32);
        let logger = Arc::new(Logger::new(log_tx, crate::logger::LogConfig::default()));
        let connector: TlsConnector = super::tests_matrix::stub_tls_connector();
        let mut stream = establish_connection(&target, &gates, &Some(exit_rotator), &None, &logger, &Arc::new(RegexSet::empty()), &pool, &network, Some(connector), Some(ServerName::try_from("localhost").unwrap())).await.unwrap();
        stream.write_all(b"chain123").await.unwrap();
        let mut echoed = [0; 8];
        stream.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed, b"chain123");
        assert_eq!(*first.records.lock().unwrap(), vec![second.addr.to_string()]);
        assert_eq!(*second.records.lock().unwrap(), vec![third.addr.to_string()]);
        assert_eq!(*third.records.lock().unwrap(), vec![exit.addr.to_string()]);
        assert_eq!(*exit.records.lock().unwrap(), vec![target]);
        drop((stream, target_task));
    }).await.expect("whole chain flow timed out");
}
