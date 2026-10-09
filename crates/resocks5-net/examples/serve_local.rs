//! Finite two-client smart-port demo with real, allowlisted local TCP egress.
//!
//! Start a local echo service separately, then run:
//! `cargo run -p resocks5-net --no-default-features --example serve_local -- 127.0.0.1:20083 127.0.0.1:20084`
//! Exactly two inbound connections are handled sequentially. Demo credentials
//! are `demo:demo`; do not use this fixed credential policy in production.

use std::net::SocketAddr;
use std::time::Duration;

use resocks5_net::connect::tunnel::tunnel_with_timeouts;
use resocks5_net::server::{accept, Reply, ServerOptions};
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{timeout, Instant};

#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    let mut args = std::env::args().skip(1);
    let listen: SocketAddr = args
        .next()
        .ok_or_else(|| anyhow::anyhow!("missing loopback listen address"))?
        .parse()?;
    let target: SocketAddr = args
        .next()
        .ok_or_else(|| anyhow::anyhow!("missing loopback echo target"))?
        .parse()?;
    anyhow::ensure!(args.next().is_none(), "expected listen and target only");
    anyhow::ensure!(
        listen.ip().is_loopback() && target.ip().is_loopback(),
        "demo requires loopback addresses"
    );
    let target_authority = target.to_string();
    let listener = TcpListener::bind(listen).await?;
    println!(
        "READY {} target={} clients=2 auth=demo:demo",
        listener.local_addr()?,
        target
    );
    for _ in 0..2 {
        let (mut client, _) = timeout(Duration::from_secs(30), listener.accept()).await??;
        let deadline = Instant::now() + Duration::from_secs(5);
        let result = async {
            let mut req = accept(
                &mut client,
                &ServerOptions::new(deadline, false, true),
                |credentials| async move {
                    // External policy belongs here. Production hosts may await their
                    // own bounded verifier; this literal demo account is not a KDF.
                    credentials.username() == "demo" && credentials.password() == "demo"
                },
            )
            .await?;
            if req.target() != target_authority {
                req.reply(&mut client, Reply::Forbidden).await?;
                anyhow::bail!("target is not the explicit local allowlist entry");
            }
            // A real TCP dial, not a fabricated stream or automatic echo fallback.
            // A Tor-backed host can substitute its own egress future here without
            // changing inbound framing or the authentication closure.
            let mut upstream =
                match timeout(Duration::from_secs(5), TcpStream::connect(target)).await {
                    Ok(Ok(stream)) => stream,
                    _ => {
                        req.reply(&mut client, Reply::UpstreamUnavailable).await?;
                        anyhow::bail!("local egress dial failed");
                    }
                };
            req.reply(&mut client, Reply::Established).await?;
            let prefix = req.take_pipeline();
            // Terminal on partial write/timeout: never replay a prefix.
            timeout(Duration::from_secs(5), upstream.write_all(&prefix)).await??;
            tunnel_with_timeouts(
                &mut client,
                upstream,
                Duration::from_secs(5),
                Duration::from_secs(15),
            )
            .await?;
            Ok::<(), anyhow::Error>(())
        };
        // Also bounds stalled response writes, including error replies.
        match timeout(Duration::from_secs(25), result).await {
            Ok(Ok(())) => println!("client complete"),
            Ok(Err(error)) => eprintln!("client failed: {error}"),
            Err(_) => eprintln!("client lifetime exhausted"),
        }
        // No resumption after cancellation: discard the client and owned egress.
    }
    Ok(())
}
