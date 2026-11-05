//! One-connection SOCKS5 GSSAPI server for interoperability checks against a
//! third-party client (`curl --socks5-gssapi`), over the system Kerberos.
//!
//! `cargo run -p resocks5-net --features gssapi-system --example gssapi_interop_server -- 127.0.0.1:1081 socks@kdc.test.local`
//!
//! Prints `READY <addr>`, serves one client, then prints
//! `principal=<name> target=<host:port> level=<protection>` and exits. After the
//! SOCKS reply (protected) it reads the client's HTTP request head and answers
//! `ok`, so `curl --socks5-hostname ... http://host/` has a body to compare.
//! Run by `.github/checks/kdc-test.sh`, which needs a KDC; not a proxy.

use std::net::SocketAddr;
use std::time::Duration;

use resocks5_net::gssapi::system::SystemBackend;
use resocks5_net::gssapi::{GssAcceptor, Protection};
use resocks5_net::server::{accept_with, AuthMethods, NoSecrets, Reply, ServerOptions};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::time::{timeout, Instant};

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() -> anyhow::Result<()> {
    let mut args = std::env::args().skip(1);
    let listen: SocketAddr = args
        .next()
        .ok_or_else(|| anyhow::anyhow!("missing loopback listen address"))?
        .parse()?;
    let service = args
        .next()
        .ok_or_else(|| anyhow::anyhow!("missing service (service@host)"))?;
    anyhow::ensure!(listen.ip().is_loopback(), "loopback only");
    let listener = TcpListener::bind(listen).await?;
    println!("READY {}", listener.local_addr()?);

    let (mut client, _) = timeout(Duration::from_secs(60), listener.accept()).await??;
    // curl has no per-message protection: it takes level 0 (and refuses any other).
    let acceptor = GssAcceptor::new(SystemBackend::new().with_acceptor(service).shared())
        .with_protection(Protection::None);
    let options = ServerOptions::new(Instant::now() + Duration::from_secs(20), false, true);
    let methods = AuthMethods::<NoSecrets>::gssapi(&acceptor);
    let request = accept_with(&mut client, &options, &methods).await?;
    println!(
        "principal={} target={} method={:?}",
        request.username().unwrap_or("-"),
        request.target(),
        request.auth_method()
    );
    // Level 0: the reply below is plain SOCKS5.
    request.reply(&mut client, Reply::Established).await?;
    // The tunnel is plain: the client's HTTP request head, then our answer.
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") && head.len() < 8192 {
        if timeout(Duration::from_secs(20), client.read(&mut byte)).await?? == 0 {
            break;
        }
        head.push(byte[0]);
    }
    client
        .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
        .await?;
    client.shutdown().await?;
    Ok(())
}
