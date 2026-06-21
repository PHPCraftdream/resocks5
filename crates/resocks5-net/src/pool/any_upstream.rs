//! Type-erased upstream stream: plain TCP, TLS-wrapped, or a direct socket.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;

use crate::pool::proxy_pool::UpstreamStream;

/// A connected upstream, abstracted over whether it is plaintext,
/// TLS-wrapped, or a direct (no-proxy) connection.
///
/// Implements [`AsyncRead`] + [`AsyncWrite`] so callers (tunnelling, TLS
/// fragmentation) can treat all three variants uniformly.
pub enum AnyUpstream {
    /// A plaintext tunnelled socket (SOCKS5 or HTTP CONNECT upstream).
    Plain(UpstreamStream),
    /// A TLS-wrapped tunnel (HTTPS upstream).
    Tls(Box<TlsStream<UpstreamStream>>),
    /// A direct `TcpStream` to the target (bypass user, no upstream proxy).
    Direct(TcpStream),
}

impl AnyUpstream {
    /// Best-effort `&TcpStream` reference for socket-level options.
    pub fn as_tcp(&self) -> Option<&TcpStream> {
        match self {
            AnyUpstream::Plain(s) => Some(s.as_tcp()),
            AnyUpstream::Tls(s) => Some(s.get_ref().0.as_tcp()),
            AnyUpstream::Direct(s) => Some(s),
        }
    }

    /// Forward `set_nodelay` to the underlying socket.
    pub fn set_nodelay(&self, nodelay: bool) -> io::Result<()> {
        match self {
            AnyUpstream::Plain(s) => s.set_nodelay(nodelay),
            AnyUpstream::Tls(s) => s.get_ref().0.set_nodelay(nodelay),
            AnyUpstream::Direct(s) => s.set_nodelay(nodelay),
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
        }
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            AnyUpstream::Plain(s) => Pin::new(s).poll_flush(cx),
            AnyUpstream::Tls(s) => Pin::new(s).poll_flush(cx),
            AnyUpstream::Direct(s) => Pin::new(s).poll_flush(cx),
        }
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            AnyUpstream::Plain(s) => Pin::new(s).poll_shutdown(cx),
            AnyUpstream::Tls(s) => Pin::new(s).poll_shutdown(cx),
            AnyUpstream::Direct(s) => Pin::new(s).poll_shutdown(cx),
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
}
