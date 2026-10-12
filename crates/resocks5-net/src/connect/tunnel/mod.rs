//! Bidirectional copy with activity tracking and bounded teardown.

use std::future::poll_fn;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::Poll;
use std::time::Duration;

use crate::progress::{confirmed_scope, FlushProgress};
use tokio::io::{copy_bidirectional_with_sizes, AsyncRead, AsyncWrite};
use tokio::time::Instant;

/// How a [`tunnel_with_timeouts`] transfer ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum TunnelEnd {
    /// Both directions reached EOF (half-close semantics preserved:
    /// each direction finishes independently).
    Eof,
    /// The idle deadline broke the loop.
    IdleTimeout,
    /// The total-lifetime deadline broke the loop.
    LifetimeTimeout,
}

/// Structured result of [`tunnel_with_timeouts`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct TunnelOutcome {
    /// How the transfer ended.
    pub end: TunnelEnd,
    /// Bytes read from `a` and confirmed written into `b` by the
    /// destination's `poll_write` — the client→upstream leg only.
    pub a_to_b: u64,
    /// Bytes read from `b` and confirmed written into `a` — the
    /// upstream→client leg only.
    pub b_to_a: u64,
}

/// Forward bytes until both directions reach EOF, a timeout fires, or I/O fails.
/// Half-closes are propagated while the other direction continues to flow.
///
/// Returns a [`TunnelOutcome`] describing how the transfer ended and how
/// many bytes each leg forwarded. The counters include only bytes
/// forwarded through the tunnel itself — bytes moved by any earlier
/// handshake or prelude phase before this function is called are not
/// counted. `a_to_b` counts bytes confirmed written into `b` (the
/// destination's `poll_write`), `b_to_a` the mirror image; both are
/// valid on the timeout paths, and may undercount bytes accepted by an
/// in-flight buffering wrapper that only reaches the wire during a
/// later flush.
///
/// `idle` measures time since the last successful read or write in either
/// direction. Progress confirmed inside a wrapping TLS/buffering stack — a
/// `ProgressReportingWriter` below the tracked stream, reported through the
/// tunnel's shared `FlushProgress` — counts as activity too: bytes moved
/// inside the wrapper while the outer write/flush/shutdown is still
/// unresolved are activity, not idleness. `max_lifetime` also bounds
/// stalled writes
/// and shutdowns.
/// A zero duration disables the corresponding deadline. On timeout, shutdown
/// is attempted once on each stream before dropping both; teardown never waits
/// indefinitely for a peer to accept buffered data.
///
/// cancel-safe: NO — cancellation can discard buffered bytes. Both owned
/// streams and their permits are dropped; the transfer must not be resumed.
pub async fn tunnel_with_timeouts<A, B>(
    a: A,
    b: B,
    idle: Duration,
    max_lifetime: Duration,
) -> io::Result<TunnelOutcome>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    let activity = Activity {
        epoch: Instant::now(),
        nanos: AtomicU64::new(0),
    };
    let bytes = Bytes {
        a_to_b: AtomicU64::new(0),
        b_to_a: AtomicU64::new(0),
    };
    let confirmed = FlushProgress::new();
    let mut a = Tracked {
        inner: a,
        activity: &activity,
        confirmed: &confirmed,
        forwarded: &bytes.b_to_a,
    };
    let mut b = Tracked {
        inner: b,
        activity: &activity,
        confirmed: &confirmed,
        forwarded: &bytes.a_to_b,
    };
    confirmed_scope(confirmed.clone(), async {
        let end = {
            let transfer = copy_bidirectional_with_sizes(&mut a, &mut b, 16 * 1024, 16 * 1024);
            let lifetime = tokio::time::sleep(max_lifetime);
            let idle_timer = tokio::time::sleep(idle);
            tokio::pin!(transfer, lifetime, idle_timer);
            loop {
                tokio::select! {
                    biased;
                    _ = &mut lifetime, if !max_lifetime.is_zero() => {
                        break TunnelEnd::LifetimeTimeout;
                    }
                    _ = &mut idle_timer, if !idle.is_zero() => {
                        let last = activity.epoch + Duration::from_nanos(activity.nanos.load(Ordering::Relaxed));
                        let deadline = last + idle;
                        if Instant::now() >= deadline {
                            break TunnelEnd::IdleTimeout;
                        }
                        idle_timer.as_mut().reset(deadline);
                    }
                    result = &mut transfer => {
                        return result.map(|_| TunnelOutcome {
                            end: TunnelEnd::Eof,
                            a_to_b: bytes.a_to_b.load(Ordering::Relaxed),
                            b_to_a: bytes.b_to_a.load(Ordering::Relaxed),
                        });
                    }
                }
            }
        };
        poll_fn(|cx| {
            let _ = Pin::new(&mut a.inner).poll_shutdown(cx);
            let _ = Pin::new(&mut b.inner).poll_shutdown(cx);
            Poll::Ready(())
        })
        .await;
        Ok(TunnelOutcome {
            end,
            a_to_b: bytes.a_to_b.load(Ordering::Relaxed),
            b_to_a: bytes.b_to_a.load(Ordering::Relaxed),
        })
    })
    .await
}

mod tracked;

use tracked::{Activity, Bytes, Tracked};

#[cfg(test)]
mod tests;
