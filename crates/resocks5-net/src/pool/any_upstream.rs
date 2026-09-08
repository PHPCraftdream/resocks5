//! Type-erased upstream streams: plain, TLS-wrapped, direct, or gate-tunnelled.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;

use crate::pool::proxy_pool::UpstreamStream;

/// Object-safe stream trait for the gate-tunnel path: the async halves
/// plus access to the tunnel's innermost real TCP socket.
///
/// Implemented individually for exactly the shapes a gate tunnel can
/// produce — [`UpstreamStream`], [`TlsStream`] over a nested
/// [`AsyncReadWrite`], `Box<T>`, and a raw [`TcpStream`] — so
/// `as_tcp`/`set_nodelay` keep reaching the gate socket through up to
/// two TLS layers. There is deliberately NO blanket impl: the socket
/// accessors need per-type behaviour, which a blanket impl cannot
/// override (and would collide with, E0119).
pub trait AsyncReadWrite: AsyncRead + AsyncWrite + Send + Sync + Unpin {
    /// Best-effort reference to the tunnel's innermost real
    /// `TcpStream` (for a gate tunnel: the gate socket), digging
    /// through any TLS layers.
    fn as_tcp(&self) -> Option<&TcpStream>;

    /// Forward `set_nodelay` to the innermost real socket.
    fn set_nodelay(&self, nodelay: bool) -> io::Result<()>;
}

impl AsyncReadWrite for UpstreamStream {
    fn as_tcp(&self) -> Option<&TcpStream> {
        Some(UpstreamStream::as_tcp(self))
    }
    fn set_nodelay(&self, nodelay: bool) -> io::Result<()> {
        UpstreamStream::set_nodelay(self, nodelay)
    }
}

impl<S: AsyncReadWrite> AsyncReadWrite for TlsStream<S> {
    fn as_tcp(&self) -> Option<&TcpStream> {
        self.get_ref().0.as_tcp()
    }
    fn set_nodelay(&self, nodelay: bool) -> io::Result<()> {
        self.get_ref().0.set_nodelay(nodelay)
    }
}

impl<T: AsyncReadWrite + ?Sized> AsyncReadWrite for Box<T> {
    fn as_tcp(&self) -> Option<&TcpStream> {
        (**self).as_tcp()
    }
    fn set_nodelay(&self, nodelay: bool) -> io::Result<()> {
        (**self).set_nodelay(nodelay)
    }
}

impl AsyncReadWrite for TcpStream {
    fn as_tcp(&self) -> Option<&TcpStream> {
        Some(self)
    }
    fn set_nodelay(&self, nodelay: bool) -> io::Result<()> {
        TcpStream::set_nodelay(self, nodelay)
    }
}

/// Type-erased stream half for the gate-tunnel path.
///
/// The concrete layering of a gate tunnel (plain, TLS, or TLS-in-TLS)
/// depends on BOTH the gate's and the inner proxy's protocols — up to
/// `TlsStream<TlsStream<UpstreamStream>>` — so instead of enumerating
/// that matrix as distinct enum variants, the gate path erases it into
/// a single boxed pair of stream halves. The innermost socket is always
/// the gate connection; permits attached before wrapping still live
/// inside and are released on drop. Socket access digs through the
/// layers via [`AsyncReadWrite::as_tcp`].
pub type BoxedUpstream = Box<dyn AsyncReadWrite>;

/// A connected upstream, abstracted over whether it is plaintext,
/// TLS-wrapped, or a direct (no-proxy) connection.
///
/// Implements [`AsyncRead`] + [`AsyncWrite`] so callers (tunnelling, TLS
/// fragmentation) can treat the variants uniformly. Adding variants is
/// expected; the enum is `#[non_exhaustive]` so downstream crates are
/// forced to keep a fallback arm.
#[non_exhaustive]
pub enum AnyUpstream {
    /// A plaintext tunnelled socket (SOCKS5 or HTTP CONNECT upstream).
    Plain(UpstreamStream),
    /// A TLS-wrapped tunnel (HTTPS upstream).
    Tls(Box<TlsStream<UpstreamStream>>),
    /// A direct `TcpStream` to the target (bypass user, no upstream proxy).
    Direct(TcpStream),
    /// A gate-tunnelled upstream. The stream may be plain, TLS, or
    /// nested TLS depending on both the gate's and the inner proxy's
    /// protocol, hence the erasure. Dropping this variant drops the
    /// erased stream, releasing every tunnel permit. `as_tcp` and
    /// `set_nodelay` still reach the tunnel's one real TCP connection
    /// (the gate socket) through the erasure, so keepalive and
    /// TLS-fragmentation nodelay keep working for gate-routed tunnels.
    Gate(BoxedUpstream),
}

impl AnyUpstream {
    /// Best-effort `&TcpStream` reference for socket-level options. For
    /// [`AnyUpstream::Gate`], this digs through up to two TLS layers to
    /// the gate socket.
    pub fn as_tcp(&self) -> Option<&TcpStream> {
        match self {
            AnyUpstream::Plain(s) => Some(s.as_tcp()),
            AnyUpstream::Tls(s) => Some(s.get_ref().0.as_tcp()),
            AnyUpstream::Direct(s) => Some(s),
            AnyUpstream::Gate(s) => s.as_tcp(),
        }
    }

    /// Forward `set_nodelay` to the underlying socket.
    pub fn set_nodelay(&self, nodelay: bool) -> io::Result<()> {
        match self {
            AnyUpstream::Plain(s) => s.set_nodelay(nodelay),
            AnyUpstream::Tls(s) => s.get_ref().0.set_nodelay(nodelay),
            AnyUpstream::Direct(s) => s.set_nodelay(nodelay),
            AnyUpstream::Gate(s) => s.set_nodelay(nodelay),
        }
    }
}

impl AsyncRead for AnyUpstream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            AnyUpstream::Plain(s) => Pin::new(s).poll_read(cx, buf),
            AnyUpstream::Tls(s) => Pin::new(s).poll_read(cx, buf),
            AnyUpstream::Direct(s) => Pin::new(s).poll_read(cx, buf),
            AnyUpstream::Gate(s) => Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for AnyUpstream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            AnyUpstream::Plain(s) => Pin::new(s).poll_write(cx, buf),
            AnyUpstream::Tls(s) => Pin::new(s).poll_write(cx, buf),
            AnyUpstream::Direct(s) => Pin::new(s).poll_write(cx, buf),
            AnyUpstream::Gate(s) => Pin::new(s).poll_write(cx, buf),
        }
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            AnyUpstream::Plain(s) => Pin::new(s).poll_flush(cx),
            AnyUpstream::Tls(s) => Pin::new(s).poll_flush(cx),
            AnyUpstream::Direct(s) => Pin::new(s).poll_flush(cx),
            AnyUpstream::Gate(s) => Pin::new(s).poll_flush(cx),
        }
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            AnyUpstream::Plain(s) => Pin::new(s).poll_shutdown(cx),
            AnyUpstream::Tls(s) => Pin::new(s).poll_shutdown(cx),
            AnyUpstream::Direct(s) => Pin::new(s).poll_shutdown(cx),
            AnyUpstream::Gate(s) => Pin::new(s).poll_shutdown(cx),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn direct_variant_roundtrips_bytes() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            tokio::io::AsyncWriteExt::write_all(&mut sock, b"ping")
                .await
                .unwrap();
            // drop sock
        });

        let stream = TcpStream::connect(addr).await.unwrap();
        let mut upstream = AnyUpstream::Direct(stream);

        let mut buf = [0u8; 4];
        upstream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping");
    }

    #[tokio::test]
    async fn gate_variant_roundtrips_bytes_and_exposes_socket() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            tokio::io::AsyncWriteExt::write_all(&mut sock, b"pong")
                .await
                .unwrap();
        });

        let stream = TcpStream::connect(addr).await.unwrap();
        let mut upstream = AnyUpstream::Gate(Box::new(stream));

        // Socket access digs through the erasure to the real socket.
        let tcp = upstream.as_tcp().expect("gate variant exposes its socket");
        tcp.set_nodelay(true).unwrap();
        assert!(tcp.nodelay().unwrap(), "TCP_NODELAY applied");

        let mut buf = [0u8; 4];
        upstream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"pong");
    }
}
