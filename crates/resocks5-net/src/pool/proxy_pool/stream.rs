use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio::sync::OwnedSemaphorePermit;

/// A TCP socket to an upstream proxy, plus the per-upstream
/// concurrent-connection permits for every node of the tunnel it
/// carries. A direct connect holds exactly one; a gate-tunneled
/// connect holds one per hop (gate + inner proxy) even though the
/// whole chain is a single TCP socket. Dropping the struct releases
/// all permits and closes the socket — that is the whole point of
/// the wrapper: the cap is held for the lifetime of the tunnel and
/// freed the moment forwarding ends.
#[derive(Debug)]
pub struct UpstreamStream {
    pub(super) stream: TcpStream,
    /// Kept private so callers can't shuffle permits between tunnels;
    /// `attach_permit` is the only way to add one.
    pub(super) _permit: OwnedSemaphorePermit,
    pub(super) extra_permits: Vec<OwnedSemaphorePermit>,
}

impl UpstreamStream {
    /// Direct access to the underlying socket for `&self`-only ops
    /// like `set_nodelay`, `set_keepalive`. Hidden behind a method so
    /// callers can't accidentally clone-out the TcpStream and bypass
    /// the permit.
    pub fn as_tcp(&self) -> &TcpStream {
        &self.stream
    }

    /// Forward `set_nodelay` to the inner socket — needed by the TLS
    /// fragmentation path which sets NODELAY just before splitting
    /// the ClientHello into multiple TCP segments.
    pub fn set_nodelay(&self, nodelay: bool) -> io::Result<()> {
        self.stream.set_nodelay(nodelay)
    }

    /// Attach one more per-upstream cap permit to this tunnel. Used by
    /// the gate path (`establish_connection::use_gate`): the inner
    /// proxy is reached THROUGH the gate's single socket, so its slot
    /// exists only as accounting — held here so it is released exactly
    /// when the tunnel ends, alongside the socket and the gate's own
    /// permit.
    pub fn attach_permit(&mut self, permit: OwnedSemaphorePermit) {
        self.extra_permits.push(permit);
    }
}

impl AsyncRead for UpstreamStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_read(cx, buf)
    }
}

impl AsyncWrite for UpstreamStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.stream).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.stream).poll_write_vectored(cx, bufs)
    }
    fn is_write_vectored(&self) -> bool {
        self.stream.is_write_vectored()
    }
}
