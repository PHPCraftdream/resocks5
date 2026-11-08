//! HTTP proxy-header authentication shared by the inbound server and the
//! upstream HTTP connector (feature `secure-auth`).
//!
//! The scheme is `Resocks5-Secure`: the [`secure_auth`](crate::secure_auth)
//! exchange (SOCKS5 method 0x80), one protocol message per HTTP round,
//! base64-encoded in `Proxy-Authorization` / `Proxy-Authenticate` (RFC 9110
//! section 11). A round is one `CONNECT` request carrying the client's
//! token and one `407` carrying the server's, on a kept-alive connection.
//! The server's last token travels in `Proxy-Authenticate` of the `200` (as
//! RFC 4559 does for mutual authentication), and the client verifies it
//! before trusting the tunnel; a refusal is a `407` with `Connection: close`.
//!
//! [`Pipe`] runs a stream-oriented exchange (`server_authenticate`,
//! `client_authenticate`) over such rounds: every `flush` of the exchange
//! ends one outgoing message, and a read that finds no input waits for the
//! next incoming one (or sees EOF after [`Pipe::close_input`]).

// Without `secure-auth` only the header helpers are used.
#![cfg_attr(not(feature = "secure-auth"), allow(dead_code))]

use std::collections::VecDeque;
use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};

use base64::{engine::general_purpose, Engine as _};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// The `secure_auth` exchange over HTTP.
pub(crate) const SECURE: &str = "Resocks5-Secure";
/// RFC 7617 clear-text Basic credentials.
pub(crate) const BASIC: &str = "Basic";

/// Most rounds an exchange may take (enrollment is the longest: two CONNECT
/// rounds plus the credential-less probe).
pub(crate) const MAX_ROUNDS: usize = 4;

/// Split a `Proxy-Authorization` / `Proxy-Authenticate` value into its scheme
/// and its (possibly empty) token. A single SP separates them (RFC 9110
/// section 11.4); extra blanks around the token are tolerated.
pub(crate) fn split_credentials(value: &str) -> (&str, &str) {
    let value = value.trim();
    match value.split_once(' ') {
        Some((scheme, token)) => (scheme, token.trim()),
        None => (value, ""),
    }
}

/// The token of `scheme` in a header value, decoded; `None` for another
/// scheme, an empty token or invalid base64.
pub(crate) fn decode_token(value: &str, scheme: &str) -> Option<Vec<u8>> {
    let (got, token) = split_credentials(value);
    if !got.eq_ignore_ascii_case(scheme) || token.is_empty() {
        return None;
    }
    general_purpose::STANDARD.decode(token).ok()
}

/// `scheme base64(token)`, a header value.
pub(crate) fn encode_token(scheme: &str, token: &[u8]) -> String {
    format!("{scheme} {}", general_purpose::STANDARD.encode(token))
}

#[derive(Default)]
struct State {
    input: VecDeque<u8>,
    input_closed: bool,
    pending: Vec<u8>,
    outgoing: VecDeque<Vec<u8>>,
    reader: Option<Waker>,
    driver: Option<Waker>,
}

/// An in-memory, message-delimited duplex for running a stream-oriented
/// exchange over HTTP rounds; see the module docs. Both halves are polled in
/// one task: the exchange through [`Pipe::end`], the round driver through
/// [`Pipe::next_message`] / [`Pipe::push`].
#[derive(Clone, Default)]
pub(crate) struct Pipe(Arc<Mutex<State>>);

impl Pipe {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    fn state(&self) -> std::sync::MutexGuard<'_, State> {
        self.0.lock().expect("pipe lock")
    }

    /// The exchange's side of the pipe.
    pub(crate) fn end(&self) -> PipeEnd {
        PipeEnd(self.clone())
    }

    /// Feed one incoming message to the exchange.
    pub(crate) fn push(&self, message: &[u8]) {
        let mut state = self.state();
        state.input.extend(message);
        if let Some(waker) = state.reader.take() {
            waker.wake();
        }
    }

    /// No more input will come: a waiting read of the exchange sees EOF.
    pub(crate) fn close_input(&self) {
        let mut state = self.state();
        state.input_closed = true;
        if let Some(waker) = state.reader.take() {
            waker.wake();
        }
    }

    /// A message the exchange has finished (flushed) and the driver has not
    /// taken yet.
    pub(crate) fn take_message(&self) -> Option<Vec<u8>> {
        self.state().outgoing.pop_front()
    }

    /// Wait for the exchange's next finished message.
    pub(crate) async fn next_message(&self) -> Vec<u8> {
        std::future::poll_fn(|cx| {
            let mut state = self.state();
            match state.outgoing.pop_front() {
                Some(message) => Poll::Ready(message),
                None => {
                    state.driver = Some(cx.waker().clone());
                    Poll::Pending
                }
            }
        })
        .await
    }
}

/// The exchange's half of a [`Pipe`].
pub(crate) struct PipeEnd(Pipe);

impl AsyncRead for PipeEnd {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let mut state = self.0.state();
        if state.input.is_empty() {
            if state.input_closed {
                return Poll::Ready(Ok(()));
            }
            state.reader = Some(cx.waker().clone());
            return Poll::Pending;
        }
        let n = buf.remaining().min(state.input.len());
        let bytes: Vec<u8> = state.input.drain(..n).collect();
        buf.put_slice(&bytes);
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for PipeEnd {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.0.state().pending.extend_from_slice(bytes);
        Poll::Ready(Ok(bytes.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut state = self.0.state();
        if !state.pending.is_empty() {
            let message = std::mem::take(&mut state.pending);
            state.outgoing.push_back(message);
            if let Some(waker) = state.driver.take() {
                waker.wake();
            }
        }
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.poll_flush(cx)
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;

    /// Splits and decodes tolerate extra blanks and case, and reject other
    /// schemes, empty tokens and bad base64. Mutation: accepting a token
    /// without the scheme prefix (or with a wrong one) fails this test.
    #[test]
    fn credentials_split_and_tokens_round_trip() {
        assert_eq!(
            split_credentials("Resocks5-Secure  YWJj "),
            ("Resocks5-Secure", "YWJj")
        );
        assert_eq!(split_credentials("Basic"), ("Basic", ""));
        let value = encode_token(SECURE, b"\x01\x02");
        assert_eq!(decode_token(&value, "resocks5-secure"), Some(vec![1, 2]));
        assert_eq!(decode_token(&value, "Negotiate"), None);
        assert_eq!(decode_token("Resocks5-Secure", SECURE), None);
        assert_eq!(decode_token("Resocks5-Secure !!", SECURE), None);
    }

    /// Flushes delimit messages; a read waits for pushed input and sees EOF
    /// after `close_input`. Mutation: delivering writes before the flush (or
    /// merging two flushed messages) changes the observed messages.
    #[tokio::test]
    async fn flushes_delimit_messages_and_reads_wait_for_input() {
        let pipe = Pipe::new();
        let mut end = pipe.end();
        let exchange = async {
            end.write_all(b"he").await.unwrap();
            end.write_all(b"llo").await.unwrap();
            end.flush().await.unwrap();
            let mut got = [0u8; 3];
            end.read_exact(&mut got).await.unwrap();
            end.write_all(&got).await.unwrap();
            end.flush().await.unwrap();
            let mut rest = Vec::new();
            end.read_to_end(&mut rest).await.unwrap();
            rest
        };
        let driver = async {
            assert_eq!(pipe.next_message().await, b"hello");
            pipe.push(b"abc");
            assert_eq!(pipe.next_message().await, b"abc");
            pipe.push(b"z");
            pipe.close_input();
        };
        let (rest, ()) = tokio::join!(exchange, driver);
        assert_eq!(rest, b"z");
        assert_eq!(pipe.take_message(), None);
    }
}
