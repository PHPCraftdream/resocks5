//! Wraps a stream so bytes over-read with an inbound request header (the request's
//! pipeline) are served before the stream itself.

use std::fmt;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::IncomingRequest;

/// A stream wrapper serving a buffered prefix of bytes before the wrapped stream.
pub struct Prefixed<S> {
    prefix: Vec<u8>,
    pos: usize,
    inner: S,
}

impl<S> Prefixed<S> {
    /// Serve `prefix` bytes before anything from the wrapped stream.
    pub fn new(prefix: Vec<u8>, inner: S) -> Self {
        Self {
            prefix,
            pos: 0,
            inner,
        }
    }

    /// Prefix bytes not yet served.
    pub fn prefix_remaining(&self) -> &[u8] {
        &self.prefix[self.pos..]
    }

    /// Shared reference to the wrapped stream.
    pub fn get_ref(&self) -> &S {
        &self.inner
    }

    /// Mutable reference to the wrapped stream.
    pub fn get_mut(&mut self) -> &mut S {
        &mut self.inner
    }

    /// Unwrap: the unserved prefix bytes and the wrapped stream.
    pub fn into_parts(self) -> (Vec<u8>, S) {
        let mut prefix = self.prefix;
        prefix.drain(..self.pos);
        (prefix, self.inner)
    }

    /// Unwrap, dropping any unserved prefix bytes.
    pub fn into_inner(self) -> S {
        self.inner
    }
}

/// Serves prefix bytes first: while any prefix byte remains, `inner` is never
/// polled and a single read returns prefix bytes only (never a mix); EOF comes
/// only from the inner. Requires `S: Unpin`.
///
/// cancel-safe: dropping a read future loses no prefix byte, because the prefix
/// position advances exactly when bytes are copied into the caller's buffer.
impl<S: AsyncRead + Unpin> AsyncRead for Prefixed<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // `Prefixed<S>` is `Unpin` because `S: Unpin`, which makes `get_mut` legal.
        let this = self.get_mut();
        let remaining = &this.prefix[this.pos..];
        if !remaining.is_empty() {
            if buf.remaining() == 0 {
                return Poll::Ready(Ok(()));
            }
            let n = remaining.len().min(buf.remaining());
            buf.put_slice(&remaining[..n]);
            this.pos += n;
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}

/// Pure pass-through to the inner stream, independent of prefix state.
/// Requires `S: Unpin`.
impl<S: AsyncWrite + Unpin> AsyncWrite for Prefixed<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

/// Shows only the prefix length and served position, never the prefix bytes,
/// and does not require `S: Debug`.
impl<S> fmt::Debug for Prefixed<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Prefixed")
            .field("prefix_len", &self.prefix.len())
            .field("prefix_pos", &self.pos)
            .finish_non_exhaustive()
    }
}

impl IncomingRequest {
    /// Wrap `stream` so this request's over-read pipeline bytes are served first.
    /// Consumes the request, moving the pipeline out (like [`IncomingRequest::take_pipeline`]).
    pub fn into_prefixed<S>(mut self, stream: S) -> Prefixed<S> {
        let prefix = self.take_pipeline();
        Prefixed::new(prefix, stream)
    }
}
