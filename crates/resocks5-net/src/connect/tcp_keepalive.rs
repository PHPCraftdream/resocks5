use std::time::Duration;

use socket2::{SockRef, TcpKeepalive};
use tokio::net::TcpStream;

/// Enable TCP keepalive on `stream` with the given idle interval.
///
/// After `idle_secs` of silence on either direction the kernel starts
/// sending keepalive probes; a non-responsive peer gets its socket
/// closed with an error, which propagates up through the I/O futures
/// and breaks any tunnel that would otherwise leak.
///
/// `idle_secs == 0` is treated as "disabled" and the call is a no-op.
/// `with_interval` and `with_retries` are not portable across all
/// platforms — we only set the idle time, the platform's own defaults
/// govern probe interval/count.
pub fn set_keepalive(stream: &TcpStream, idle_secs: u64) -> std::io::Result<()> {
    if idle_secs == 0 {
        return Ok(());
    }
    let sock = SockRef::from(stream);
    let ka = TcpKeepalive::new().with_time(Duration::from_secs(idle_secs));
    sock.set_tcp_keepalive(&ka)
}
