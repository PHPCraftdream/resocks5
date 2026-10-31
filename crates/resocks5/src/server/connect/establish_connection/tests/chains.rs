use super::establish_connection;
use crate::logger::Logger;
use regex::RegexSet;
use resocks5_net::chain::GateLevels;
use resocks5_net::connect::{AnyUpstream, HostPort};
use resocks5_net::pool::ProxyPool;
use resocks5_net::rotator::ProxyRotator;
use resocks5_net::types::ProxyConfig;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio::task::{JoinHandle, JoinSet};

struct Stub {
    addr: SocketAddr,
    task: JoinHandle<()>,
}
impl Drop for Stub {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn spawn_stub(tx: mpsc::Sender<String>) -> Stub {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let mut children = JoinSet::new();
        loop {
            tokio::select! {
                accepted = listener.accept() => {
                    let Ok((mut socket, _)) = accepted else { break; };
                    let tx = tx.clone();
                    children.spawn(async move {
                        let mut greeting = [0u8; 3];
                        if socket.read_exact(&mut greeting).await.is_err() { return; }
                        if greeting[0] != 5 || socket.write_all(&[5, 0]).await.is_err() { return; }
                        let mut head = [0u8; 4];
                        if socket.read_exact(&mut head).await.is_err() || head[0] != 5 || head[1] != 1 { return; }
                        let host = match head[3] {
                            1 => {
                                let mut b = [0u8; 4];
                                if socket.read_exact(&mut b).await.is_err() { return; }
                                std::net::Ipv4Addr::from(b).to_string()
                            }
                            3 => {
                                let mut n = [0u8; 1];
                                if socket.read_exact(&mut n).await.is_err() { return; }
                                let mut b = vec![0; n[0] as usize];
                                if socket.read_exact(&mut b).await.is_err() { return; }
                                let Ok(host) = String::from_utf8(b) else { return; };
                                host
                            }
                            4 => {
                                let mut b = [0u8; 16];
                                if socket.read_exact(&mut b).await.is_err() { return; }
                                std::net::Ipv6Addr::from(b).to_string()
                            }
                            _ => return,
                        };
                        let mut port = [0u8; 2];
                        if socket.read_exact(&mut port).await.is_err() { return; }
                        let destination = HostPort::format(&host, u16::from_be_bytes(port));
                        if tx.send(destination.clone()).await.is_err() { return; }
                        let Ok(mut upstream) = TcpStream::connect(&destination).await else {
                            let _ = socket.write_all(&[5, 5, 0, 1, 0, 0, 0, 0, 0, 0]).await;
                            return;
                        };
                        if socket.write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 0]).await.is_err() { return; }
                        let _ = tokio::io::copy_bidirectional(&mut socket, &mut upstream).await;
                    });
                }
                Some(_) = children.join_next(), if !children.is_empty() => {}
            }
        }
    });
    Stub { addr, task }
}

fn config(addr: SocketAddr, rank: u8) -> ProxyConfig {
    ProxyConfig::socks5(addr.ip().to_string(), addr.port()).with_gate_level(rank)
}

#[tokio::test]
async fn three_level_chain_reaches_target_in_order() {
    let (tx, mut rx) = mpsc::channel(16);
    let a = spawn_stub(tx.clone()).await;
    let b = spawn_stub(tx.clone()).await;
    let c = spawn_stub(tx.clone()).await;
    let d = spawn_stub(tx.clone()).await;
    let (target_listener, target_addr) = {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        (listener, addr)
    };
    let target_task = tokio::spawn(async move {
        let (mut stream, _) = target_listener.accept().await.unwrap();
        let mut marker = [0u8; 7];
        stream.read_exact(&mut marker).await.unwrap();
        stream.write_all(&marker).await.unwrap();
    });

    let gate3 = Arc::new(ProxyRotator::new(vec![config(a.addr, 3)]));
    let gate2 = Arc::new(ProxyRotator::new(vec![config(b.addr, 2)]));
    let gate1 = Arc::new(ProxyRotator::new(vec![config(c.addr, 1)]));
    let exit = Arc::new(ProxyRotator::new(vec![config(d.addr, 0)]));
    let gates = Arc::new(GateLevels::new(vec![(3, gate3), (2, gate2), (1, gate1)]));
    let pool = Arc::new(ProxyPool::new(
        Default::default(),
        Duration::from_secs(3),
        8,
    ));
    let network = Arc::new(crate::config::NetworkConfig {
        handshake_timeout_sec: 3,
        ..Default::default()
    });
    let (log_tx, _) = mpsc::channel(32);
    let logger = Arc::new(Logger::new(log_tx, crate::logger::LogConfig::default()));
    let target = format!("{}:{}", target_addr.ip(), target_addr.port());

    let mut stream = establish_connection(
        &target,
        &gates,
        &Some(exit.clone()),
        &None,
        &logger,
        &Arc::new(RegexSet::empty()),
        &pool,
        &network,
        None,
        None,
    )
    .await
    .unwrap();
    stream.write_all(b"marker!").await.unwrap();
    let mut echoed = [0u8; 7];
    stream.read_exact(&mut echoed).await.unwrap();
    assert_eq!(&echoed, b"marker!");
    let mut received = Vec::new();
    for _ in 0..4 {
        received.push(
            tokio::time::timeout(Duration::from_secs(5), rx.recv())
                .await
                .unwrap()
                .unwrap(),
        );
    }
    assert_eq!(
        received,
        vec![
            b.addr.to_string(),
            c.addr.to_string(),
            d.addr.to_string(),
            target.clone()
        ]
    );
    target_task.await.unwrap();
    drop(stream);
    drop((a, b, c, d));
}

async fn echo_target() -> (SocketAddr, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut marker = [0u8; 7];
        stream.read_exact(&mut marker).await.unwrap();
        stream.write_all(&marker).await.unwrap();
    });
    (addr, task)
}

async fn echo_target_twice() -> (SocketAddr, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        for _ in 0..2 {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut marker = [0u8; 7];
            stream.read_exact(&mut marker).await.unwrap();
            stream.write_all(&marker).await.unwrap();
        }
    });
    (addr, task)
}

fn setup_chain(addrs: &[SocketAddr], ranks: &[u8]) -> (Arc<GateLevels>, Arc<ProxyRotator>) {
    let gates = ranks
        .iter()
        .zip(addrs)
        .map(|(&rank, &addr)| (rank, Arc::new(ProxyRotator::new(vec![config(addr, rank)]))))
        .collect();
    let exit = Arc::new(ProxyRotator::new(vec![ProxyConfig::socks5(
        addrs[ranks.len()].ip().to_string(),
        addrs[ranks.len()].port(),
    )]));
    (Arc::new(GateLevels::new(gates)), exit)
}

async fn connect_echo(
    gates: &Arc<GateLevels>,
    exit: &Arc<ProxyRotator>,
    pool: &Arc<ProxyPool>,
    addr: SocketAddr,
    config: crate::logger::LogConfig,
) -> (AnyUpstream, mpsc::Receiver<crate::logger::ELog>) {
    let network = Arc::new(crate::config::NetworkConfig {
        handshake_timeout_sec: 3,
        ..Default::default()
    });
    let (log_tx, log_rx) = mpsc::channel(32);
    let logger = Arc::new(Logger::new(log_tx, config));
    let stream = establish_connection(
        &HostPort::format(&addr.ip().to_string(), addr.port()),
        gates,
        &Some(exit.clone()),
        &None,
        &logger,
        &Arc::new(RegexSet::empty()),
        pool,
        &network,
        None,
        None,
    )
    .await
    .unwrap();
    (stream, log_rx)
}

#[tokio::test]
async fn rank_gaps_two_levels_forward_in_chain_order() {
    let (tx, mut rx) = mpsc::channel(16);
    let a = spawn_stub(tx.clone()).await;
    let b = spawn_stub(tx.clone()).await;
    let c = spawn_stub(tx).await;
    let (target, target_task) = echo_target().await;
    let (gates, exit) = setup_chain(&[a.addr, c.addr, b.addr], &[3, 1]);
    let pool = Arc::new(ProxyPool::new(
        Default::default(),
        Duration::from_secs(3),
        8,
    ));
    let (mut stream, _logs) = connect_echo(&gates, &exit, &pool, target, Default::default()).await;
    stream.write_all(b"marker!").await.unwrap();
    let mut echoed = [0u8; 7];
    stream.read_exact(&mut echoed).await.unwrap();
    assert_eq!(&echoed, b"marker!");
    let mut destinations = Vec::new();
    for _ in 0..3 {
        destinations.push(
            tokio::time::timeout(Duration::from_secs(5), rx.recv())
                .await
                .unwrap()
                .unwrap(),
        );
    }
    assert_eq!(
        destinations,
        vec![
            c.addr.to_string(),
            b.addr.to_string(),
            HostPort::format(&target.ip().to_string(), target.port())
        ]
    );
    target_task.await.unwrap();
}

#[tokio::test]
async fn three_level_sticky_route_is_reused() {
    let (tx, mut rx) = mpsc::channel(16);
    let a = spawn_stub(tx.clone()).await;
    let b = spawn_stub(tx.clone()).await;
    let c = spawn_stub(tx.clone()).await;
    let d = spawn_stub(tx).await;
    let (target, target_task) = echo_target_twice().await;
    let (gates, exit) = setup_chain(&[a.addr, b.addr, c.addr, d.addr], &[3, 2, 1]);
    let pool = Arc::new(ProxyPool::new(
        Default::default(),
        Duration::from_secs(3),
        8,
    ));
    let (mut first, _) = connect_echo(&gates, &exit, &pool, target, Default::default()).await;
    first.write_all(b"marker!").await.unwrap();
    let mut echoed = [0u8; 7];
    first.read_exact(&mut echoed).await.unwrap();
    assert_eq!(&echoed, b"marker!");
    let sticky_key = HostPort::format(&target.ip().to_string(), target.port());
    let cached = exit.get_linked(&sticky_key).unwrap();
    assert_eq!(cached.chain_nodes().len(), 4);
    drop(first);
    let (mut second, mut logs) = connect_echo(
        &gates,
        &exit,
        &pool,
        target,
        crate::logger::LogConfig {
            cache_hits: true,
            ..Default::default()
        },
    )
    .await;
    second.write_all(b"marker!").await.unwrap();
    second.read_exact(&mut echoed).await.unwrap();
    assert_eq!(&echoed, b"marker!");
    let hit = tokio::time::timeout(Duration::from_secs(5), logs.recv())
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(hit, crate::logger::ELog::Log(ref msg) if msg.contains("Cache used for")));
    drop(second);
    target_task.await.unwrap();
    let mut destinations = Vec::new();
    for _ in 0..8 {
        destinations.push(
            tokio::time::timeout(Duration::from_secs(5), rx.recv())
                .await
                .unwrap()
                .unwrap(),
        );
    }
    let first_route = vec![
        b.addr.to_string(),
        c.addr.to_string(),
        d.addr.to_string(),
        sticky_key.clone(),
    ];
    assert_eq!(destinations, [first_route.clone(), first_route].concat());
}

#[tokio::test]
async fn dead_middle_alternative_does_not_block_request() {
    let (tx, mut rx) = mpsc::channel(16);
    let outer = spawn_stub(tx.clone()).await;
    let (dead_listener, dead_addr) = {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        (listener, addr)
    };
    let dead_task = tokio::spawn(async move {
        let (mut socket, _) = dead_listener.accept().await.unwrap();
        let mut greeting = [0u8; 3];
        socket.read_exact(&mut greeting).await.unwrap();
        socket.write_all(&[5, 0]).await.unwrap();
        let mut head = [0u8; 4];
        socket.read_exact(&mut head).await.unwrap();
        let len = match head[3] {
            1 => 4,
            3 => {
                let mut n = [0u8; 1];
                socket.read_exact(&mut n).await.unwrap();
                n[0] as usize
            }
            4 => 16,
            _ => panic!("invalid SOCKS address type"),
        };
        let mut rest = vec![0u8; len + 2];
        socket.read_exact(&mut rest).await.unwrap();
        socket
            .write_all(&[5, 5, 0, 1, 0, 0, 0, 0, 0, 0])
            .await
            .unwrap();
    });
    let healthy = spawn_stub(tx.clone()).await;
    let exit_stub = spawn_stub(tx).await;
    let (target, target_task) = echo_target().await;
    let rank3 = Arc::new(ProxyRotator::new(vec![config(outer.addr, 3)]));
    let rank2 = Arc::new(ProxyRotator::new(vec![
        config(dead_addr, 2),
        config(healthy.addr, 2),
    ]));
    let gates = Arc::new(GateLevels::new(vec![(3, rank3), (2, rank2)]));
    let exit = Arc::new(ProxyRotator::new(vec![ProxyConfig::socks5(
        exit_stub.addr.ip().to_string(),
        exit_stub.addr.port(),
    )]));
    let target_key = HostPort::format(&target.ip().to_string(), target.port());
    let bad_chain = ProxyConfig::chain([
        Arc::new(config(outer.addr, 3)),
        Arc::new(config(dead_addr, 2)),
        Arc::new(ProxyConfig::socks5(
            exit_stub.addr.ip().to_string(),
            exit_stub.addr.port(),
        )),
    ])
    .unwrap();
    exit.link_proxy(target_key.clone(), Arc::new(bad_chain));
    let pool = Arc::new(ProxyPool::new(
        Default::default(),
        Duration::from_secs(3),
        8,
    ));
    let (mut stream, _) = connect_echo(&gates, &exit, &pool, target, Default::default()).await;
    stream.write_all(b"marker!").await.unwrap();
    let mut echoed = [0u8; 7];
    tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut echoed))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&echoed, b"marker!");
    let mut destinations = Vec::new();
    for _ in 0..4 {
        destinations.push(
            tokio::time::timeout(Duration::from_secs(5), rx.recv())
                .await
                .unwrap()
                .unwrap(),
        );
    }
    assert_eq!(
        destinations,
        vec![
            dead_addr.to_string(),
            healthy.addr.to_string(),
            exit_stub.addr.to_string(),
            target_key
        ]
    );
    dead_task.await.unwrap();
    target_task.await.unwrap();
}

#[tokio::test]
async fn every_chain_node_capacity_is_held_until_stream_drop() {
    let (tx, mut _rx) = mpsc::channel(16);
    let a = spawn_stub(tx.clone()).await;
    let b = spawn_stub(tx.clone()).await;
    let c = spawn_stub(tx.clone()).await;
    let d = spawn_stub(tx).await;
    let (target, target_task) = echo_target().await;
    let (gates, exit) = setup_chain(&[a.addr, b.addr, c.addr, d.addr], &[3, 2, 1]);
    let pool = Arc::new(ProxyPool::new(
        Default::default(),
        Duration::from_secs(3),
        1,
    ));
    let stream = connect_echo(&gates, &exit, &pool, target, Default::default())
        .await
        .0;
    for stub in [&a, &b, &c, &d] {
        let cfg = ProxyConfig::socks5(stub.addr.ip().to_string(), stub.addr.port());
        assert!(pool.reserve_permit(&cfg).is_err());
    }
    drop(stream);
    for stub in [&a, &b, &c, &d] {
        let cfg = ProxyConfig::socks5(stub.addr.ip().to_string(), stub.addr.port());
        assert!(pool.reserve_permit(&cfg).is_ok());
    }
    target_task.abort();
}
