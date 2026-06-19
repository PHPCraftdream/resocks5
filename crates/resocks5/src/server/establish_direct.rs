use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::anyhow;
use regex::RegexSet;
use tokio::net::TcpStream;
use tokio::time::timeout;

use resocks5_net::pool::AnyUpstream;

use crate::config::NetworkConfig;
use crate::logger::Logger;

pub async fn establish_direct(
    target_addr: &str,
    banned: &Arc<RegexSet>,
    logger: &Arc<Logger>,
    network: &Arc<NetworkConfig>,
    client_user: &str,
) -> anyhow::Result<AnyUpstream> {
    let ctag = format!(" [client={}]", client_user);

    if banned.is_match(target_addr) {
        logger.banned_target(|| format!("Target address {} is banned{}", target_addr, ctag));
        return Err(anyhow!("Banned target address"));
    }

    let t0 = Instant::now();
    let connect_dur = Duration::from_secs(network.connect_timeout_sec);

    match timeout(connect_dur, TcpStream::connect(target_addr)).await {
        Ok(Ok(s)) => {
            let _ = s.set_nodelay(true);
            let ms = t0.elapsed().as_millis();
            logger.attempt(|| {
                format!(
                    "attempt target={} path=local outcome=ok dur={}ms{}",
                    target_addr, ms, ctag
                )
            });
            Ok(AnyUpstream::Direct(s))
        }
        Ok(Err(e)) => {
            let ms = t0.elapsed().as_millis();
            logger.attempt(|| {
                format!(
                    "attempt target={} path=local outcome=fail dur={}ms err={}{}",
                    target_addr, ms, e, ctag
                )
            });
            Err(anyhow!("direct TcpStream::connect failed: {}", e))
        }
        Err(_) => {
            let ms = t0.elapsed().as_millis();
            logger.attempt(|| {
                format!(
                    "attempt target={} path=local outcome=fail dur={}ms err=timeout({:?}){}",
                    target_addr, ms, connect_dur, ctag
                )
            });
            Err(anyhow!("direct connect timeout after {:?}", connect_dur))
        }
    }
}
