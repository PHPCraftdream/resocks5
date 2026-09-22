//! Type-erased upstream streams: plain, TLS-wrapped, direct, or gate-tunnelled.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
#[cfg(feature = "tls")]
use tokio_rustls::client::TlsStream;

use crate::pool::proxy_pool::UpstreamStream;
use crate::progress::ProgressReportingWriter;

/// Object-safe stream trait for the gate-tunnel path: the async halves
/// plus access to the tunnel's innermost real TCP socket.
///
/// Implemented individually for exactly the shapes a gate tunnel can
/// produce — [`UpstreamStream`], `TlsStream` over a nested
/// [`AsyncReadWrite`], [`ProgressReportingWriter`] over a nested
/// [`AsyncReadWrite`], `Box<T>`, and a raw [`TcpStream`] — so
/// `as_tcp`/`set_nodelay` keep reaching the gate socket through up to
/// two TLS layers plus the progress-reporting wrapper the gate dialer
/// puts around the raw transport. There is deliberately NO blanket
/// impl: the socket accessors need per-type behaviour, which a blanket
/// impl cannot override (and would collide with, E0119).
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

#[cfg(feature = "tls")]
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

impl<S: AsyncReadWrite> AsyncReadWrite for ProgressReportingWriter<S> {
    fn as_tcp(&self) -> Option<&TcpStream> {
        self.get_ref().as_tcp()
    }
    fn set_nodelay(&self, nodelay: bool) -> io::Result<()> {
        self.get_ref().set_nodelay(nodelay)
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
    /// A TLS-wrapped tunnel (HTTPS upstream). The raw transport underneath
    /// the TLS layer is wrapped in a `ProgressReportingWriter`, so
    /// confirmed below-TLS write progress is reported into enclosing
    /// confirmed-progress scopes (idle-bounded sends, tunnel activity
    /// tracking).
    #[cfg(feature = "tls")]
    Tls(Box<TlsStream<ProgressReportingWriter<UpstreamStream>>>),
    /// A direct `TcpStream` to the target (bypass user, no upstream proxy).
    Direct(TcpStream),
    /// A gate-tunnelled upstream. The stream may be plain, TLS, or
    /// nested TLS depending on both the gate's and the inner proxy's
    /// protocol, hence the erasure. Dropping this variant drops the
    /// erased stream, releasing every tunnel permit. `as_tcp` and
    /// `set_nodelay` still reach the tunnel's one real TCP connection
    /// (the gate socket) through the erasure, so keepalive and
    /// TLS-fragmentation nodelay keep working for gate-routed tunnels.
    /// The raw gate transport at the base of the erased stack is
    /// wrapped in a [`ProgressReportingWriter`] by the gate dialer, so
    /// confirmed write progress below the FIRST TLS hop is reported
    /// into enclosing confirmed-progress scopes (idle-bounded sends,
    /// tunnel activity tracking) exactly as for `AnyUpstream::Tls`.
    Gate(BoxedUpstream),
}

impl AnyUpstream {
    /// Best-effort `&TcpStream` reference for socket-level options. For
    /// [`AnyUpstream::Gate`], this digs through up to two TLS layers to
    /// the gate socket.
    pub fn as_tcp(&self) -> Option<&TcpStream> {
        match self {
            AnyUpstream::Plain(s) => Some(s.as_tcp()),
            #[cfg(feature = "tls")]
            AnyUpstream::Tls(s) => Some(s.get_ref().0.get_ref().as_tcp()),
            AnyUpstream::Direct(s) => Some(s),
            AnyUpstream::Gate(s) => s.as_tcp(),
        }
    }

    /// Forward `set_nodelay` to the underlying socket.
    pub fn set_nodelay(&self, nodelay: bool) -> io::Result<()> {
        match self {
            AnyUpstream::Plain(s) => s.set_nodelay(nodelay),
            #[cfg(feature = "tls")]
            AnyUpstream::Tls(s) => s.get_ref().0.get_ref().set_nodelay(nodelay),
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
            #[cfg(feature = "tls")]
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
            #[cfg(feature = "tls")]
            AnyUpstream::Tls(s) => Pin::new(s).poll_write(cx, buf),
            AnyUpstream::Direct(s) => Pin::new(s).poll_write(cx, buf),
            AnyUpstream::Gate(s) => Pin::new(s).poll_write(cx, buf),
        }
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            AnyUpstream::Plain(s) => Pin::new(s).poll_flush(cx),
            #[cfg(feature = "tls")]
            AnyUpstream::Tls(s) => Pin::new(s).poll_flush(cx),
            AnyUpstream::Direct(s) => Pin::new(s).poll_flush(cx),
            AnyUpstream::Gate(s) => Pin::new(s).poll_flush(cx),
        }
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            AnyUpstream::Plain(s) => Pin::new(s).poll_shutdown(cx),
            #[cfg(feature = "tls")]
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

    /// The progress-reporting wrapper must be usable as the erased base
    /// of a gate stack: object-safe boxing, socket reach-through for
    /// `as_tcp`/`set_nodelay`, and confirmed-progress reporting into an
    /// enclosing scope.
    #[tokio::test]
    async fn progress_reporting_writer_boxes_reaches_socket_and_reports() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            // Consume the client's write BEFORE dropping, so the peer
            // never writes into a fully-closed socket (the RST that a
            // closed peer answers with would also discard the buffered
            // `ping` below and flake the read_exact on Windows).
            let mut consumed = [0u8; 4];
            sock.read_exact(&mut consumed).await.unwrap();
            tokio::io::AsyncWriteExt::write_all(&mut sock, b"ping")
                .await
                .unwrap();
        });

        let progress = crate::progress::FlushProgress::new();
        let mut upstream: BoxedUpstream = Box::new(ProgressReportingWriter::new(
            TcpStream::connect(addr).await.unwrap(),
        ));

        let tcp = upstream
            .as_tcp()
            .expect("the wrapper must expose the innermost socket");
        tcp.set_nodelay(true).unwrap();
        assert!(tcp.nodelay().unwrap(), "TCP_NODELAY applied");

        let before = progress.total();
        crate::progress::confirmed_scope(progress.clone(), async {
            tokio::io::AsyncWriteExt::write_all(&mut upstream, b"ping")
                .await
                .unwrap();
        })
        .await;
        assert_eq!(
            progress.total() - before,
            4,
            "every byte written below the wrapper must be reported"
        );

        let mut buf = [0u8; 4];
        upstream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping", "reads pass straight through");
    }
}
