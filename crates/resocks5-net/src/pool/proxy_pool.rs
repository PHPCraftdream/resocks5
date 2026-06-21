//! ## Lifecycle
//!
//! - At startup `spawn_refill_for(proxy)` launches one task per unique
//!   `(host, port)` upstream. Each task keeps its own queue topped up
//!   to `spare_per_proxy`.
//! - On `checkout`, we pop one socket. If its age exceeds
//!   `max_session_age_sec` (defends against silent idle-disconnects on
//!   the proxy side) we discard it and pop the next. The refill task
//!   notices the queue is below target and reconnects.
//! - On a checkout that finds the queue empty (or all stale), the
//!   caller falls back to a fresh `TcpStream::connect`. The pool is a
//!   best-effort accelerator, never a hard dependency.
//!
//! ## Per-upstream concurrent-connection cap
//!
//! A `Semaphore` is kept per `(host, port)`. Every `acquire` first
//! takes one permit; the permit is held inside the returned
//! `UpstreamStream` and released when that stream is dropped. The cap
//! defends the upstream provider's per-account / per-IP connection
//! limit — without it a burst of client requests opens hundreds of
//! sockets in parallel, the provider blocks our IP or account, and
//! every subsequent SOCKS5 handshake times out for the duration of
//! their cool-down (observed symptom: 10-second handshake timeouts on
//! every direct attempt, while via-Tor still works because each Tor
//! circuit sources from a different exit IP).

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use anyhow::anyhow;
use crossbeam_queue::ArrayQueue;
use dashmap::DashMap;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio::sync::{Notify, OwnedSemaphorePermit, Semaphore};
use tokio::time::{sleep, timeout};

use crate::pool::PoolConfig;
use crate::types::ProxyConfig;

/// Sentinel error returned when the per-upstream semaphore is full.
/// `establish_connection` uses `downcast_ref::<AtCapacity>()` to
/// distinguish "our load" from "upstream is broken" — the former
/// must NOT feed the sand-model failure signal.
pub struct AtCapacity {
    /// The host of the upstream whose cap was hit.
    pub host: String,
    /// The port of the upstream whose cap was hit.
    pub port: u16,
}

impl std::fmt::Display for AtCapacity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "upstream cap reached for {}:{}", self.host, self.port)
    }
}

impl std::fmt::Debug for AtCapacity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "AtCapacity({}:{})", self.host, self.port)
    }
}

impl std::error::Error for AtCapacity {}

/// A TCP socket to an upstream proxy, plus the per-upstream
/// concurrent-connection permit. Dropping the struct releases the
/// permit and closes the socket — that order is the whole point of
/// the wrapper: the cap is held for the lifetime of the tunnel and
/// freed the moment forwarding ends.
#[derive(Debug)]
pub struct UpstreamStream {
    stream: TcpStream,
    _permit: OwnedSemaphorePermit,
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

/// One pre-warmed TCP socket plus its creation timestamp, used to
/// reject stale entries on `checkout`.
struct PreWarmed {
    stream: TcpStream,
    created_at: Instant,
}

/// Per-proxy state: the queue itself plus a `Notify` used by the
/// refill task to react instantly when a slot frees up.
struct ProxySpares {
    queue: ArrayQueue<PreWarmed>,
    /// `notify_one` on every successful pop so the refill task wakes
    /// immediately and reconnects rather than discovering the empty
    /// slot on its next periodic timer.
    notify: Notify,
}

/// `(host, port)` key — auth differences live above the TCP layer
/// and don't affect socket reuse, and the per-account/per-IP quota
/// that the semaphore defends is keyed the same way.
type ProxyKey = (String, u16);

/// `host:port` for log messages — upstream credentials (both user
/// and password) are intentionally NOT included, since the username
/// half of a SOCKS5 cred is itself sensitive enough to keep out of
/// log files, shell scrollback, and shipped diagnostics.
pub(crate) fn upstream_endpoint(proxy: &ProxyConfig) -> String {
    format!("{}:{}", proxy.host, proxy.port)
}

/// Pre-connect TCP pool plus a per-upstream concurrency cap.
///
/// See the module docs for the full lifecycle. Construct with
/// [`ProxyPool::new`]; `connect_timeout` and the per-upstream cap are fixed
/// for the pool's lifetime, while the [`PoolConfig`] fields (master switch,
/// spares, max age) are read via [`enabled`](ProxyPool::enabled).
pub struct ProxyPool {
    config: PoolConfig,
    /// Maximum time to wait for a TCP `connect` to an upstream. Without
    /// this cap a dead proxy stalls callers for the full kernel SYN
    /// timeout (tens of seconds on Linux). Applied to both the
    /// fallback connect in `acquire` and the background refill loop.
    connect_timeout: Duration,
    /// Hard cap on concurrent in-flight TCP connections per upstream
    /// `(host, port)`. Enforced via `upstream_caps`.
    max_per_upstream: usize,
    pools: DashMap<ProxyKey, Arc<ProxySpares>>,
    /// Per-upstream semaphores. Lazily created on first `acquire` for
    /// each `(host, port)` and kept alive (cheap — one tiny Semaphore
    /// per upstream forever) so concurrent acquires share the same
    /// permit pool.
    upstream_caps: DashMap<ProxyKey, Arc<Semaphore>>,
}

impl ProxyPool {
    /// Create a new pool.
    ///
    /// `connect_timeout` bounds every TCP `connect` (both the fallback in
    /// [`acquire`](ProxyPool::acquire) and the background refill loop).
    /// `max_per_upstream` caps concurrent live connections per `(host, port)`;
    /// `0` is clamped up to `1` (a zero-permit pool would brick every acquire).
    pub fn new(config: PoolConfig, connect_timeout: Duration, max_per_upstream: usize) -> Self {
        // Tokio's Semaphore requires at least one permit; treat `0`
        // configuration as "1" to avoid hard-bricking the pool.
        let max_per_upstream = max_per_upstream.max(1);
        Self {
            config,
            connect_timeout,
            max_per_upstream,
            pools: DashMap::new(),
            upstream_caps: DashMap::new(),
        }
    }

    /// Convenience for `establish_connection` / `use_gate` to skip the
    /// pool path entirely when disabled.
    pub fn enabled(&self) -> bool {
        self.config.enabled
    }

    /// Get-or-create the semaphore that caps concurrent live
    /// connections to this `(host, port)`. First-acquire for a new
    /// upstream allocates the Semaphore inline.
    fn upstream_semaphore(&self, host: &str, port: u16) -> Arc<Semaphore> {
        let key = (host.to_string(), port);
        if let Some(s) = self.upstream_caps.get(&key) {
            return s.value().clone();
        }
        // Race-safe insert: another caller may have populated the
        // entry between our get() and entry().or_insert_with(). DashMap
        // serialises the entry, so whichever lands first wins and the
        // other reads it back.
        self.upstream_caps
            .entry(key)
            .or_insert_with(|| Arc::new(Semaphore::new(self.max_per_upstream)))
            .value()
            .clone()
    }

    /// "Give me a TCP socket to this proxy, fast if you can" — the
    /// standard entry point used by every connect path.
    ///
    /// Two-step acquisition:
    /// 1. Take one permit from the per-upstream semaphore. If the cap
    ///    is hit, fail fast — the caller (`establish_connection`)
    ///    will try the next proxy instead of waiting.
    /// 2. Pop a pre-warmed socket from the pool, or fall back to a
    ///    fresh `TcpStream::connect` under `connect_timeout`.
    ///
    /// Returns `UpstreamStream` so the permit lives exactly as long as
    /// the socket and the slot is released on drop.
    pub async fn acquire(&self, proxy: &ProxyConfig) -> anyhow::Result<UpstreamStream> {
        let endpoint = upstream_endpoint(proxy);

        // Per-upstream concurrency cap.
        let sem = self.upstream_semaphore(&proxy.host, proxy.port);
        let permit = sem.try_acquire_owned().map_err(|_| {
            anyhow::Error::new(AtCapacity {
                host: proxy.host.clone(),
                port: proxy.port,
            })
        })?;

        if let Some(stream) = self.checkout(proxy) {
            return Ok(UpstreamStream {
                stream,
                _permit: permit,
            });
        }
        let stream = match timeout(
            self.connect_timeout,
            TcpStream::connect(format!("{}:{}", proxy.host, proxy.port)),
        )
        .await
        {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => {
                return Err(anyhow!("connect to {}: {}", endpoint, e));
            }
            Err(_) => {
                return Err(anyhow!(
                    "connect timeout ({}s) to {}",
                    self.connect_timeout.as_secs(),
                    endpoint
                ));
            }
        };
        Ok(UpstreamStream {
            stream,
            _permit: permit,
        })
    }

    /// Try to take a fresh pre-warmed socket for the given proxy.
    /// Returns `None` when the pool is disabled, no entry exists yet,
    /// the queue is empty, or every entry has aged out.
    pub fn checkout(&self, proxy: &ProxyConfig) -> Option<TcpStream> {
        if !self.config.enabled {
            return None;
        }
        let key = (proxy.host.clone(), proxy.port);
        let spares = self.pools.get(&key)?.value().clone();
        let max_age = Duration::from_secs(self.config.max_session_age_sec);
        let now = Instant::now();
        // Drop stale entries lazily on checkout. Each pop notifies the
        // refill task so it can replenish whatever we drained.
        loop {
            let Some(pw) = spares.queue.pop() else {
                spares.notify.notify_one();
                return None;
            };
            spares.notify.notify_one();
            if now.saturating_duration_since(pw.created_at) <= max_age {
                return Some(pw.stream);
            }
            // stale — drop and try the next.
        }
    }

    /// Launch a long-lived refill task for `proxy`. Idempotent: if a
    /// task is already running for the same `(host, port)`, this is a
    /// no-op.
    pub fn spawn_refill_for(&self, proxy: Arc<ProxyConfig>) {
        if !self.config.enabled {
            return;
        }
        let key = (proxy.host.clone(), proxy.port);
        if self.pools.contains_key(&key) {
            return; // Already running for this proxy.
        }
        let target = self.config.spare_per_proxy.max(1);
        let max_age = Duration::from_secs(self.config.max_session_age_sec);
        let spares = Arc::new(ProxySpares {
            queue: ArrayQueue::new(target),
            notify: Notify::new(),
        });
        self.pools.insert(key, spares.clone());

        // The refill loop:
        // - top up to `target` while space available
        // - on connect failure, exponential backoff (capped at 10s) so
        //   a dead proxy doesn't burn CPU
        // - then wait either for a `notify` (slot freed by checkout)
        //   or for `max_age` (time to proactively recycle stale)
        let connect_timeout = self.connect_timeout;
        tokio::spawn(async move {
            let addr = format!("{}:{}", proxy.host, proxy.port);
            let mut backoff = Duration::from_millis(100);
            loop {
                while spares.queue.len() < target {
                    match timeout(connect_timeout, TcpStream::connect(&addr)).await {
                        Ok(Ok(stream)) => {
                            let pw = PreWarmed {
                                stream,
                                created_at: Instant::now(),
                            };
                            // Best-effort push: queue may have filled
                            // up while we were connecting (concurrent
                            // refill iteration succeeded first), in
                            // which case we drop this socket.
                            let _ = spares.queue.push(pw);
                            backoff = Duration::from_millis(100);
                        }
                        // Both kinds of failure (connect error or
                        // timeout) feed the same exponential backoff
                        // so a dead proxy doesn't burn CPU on retries.
                        Ok(Err(_)) | Err(_) => {
                            sleep(backoff).await;
                            backoff = (backoff * 2).min(Duration::from_secs(10));
                        }
                    }
                }
                // Queue full. Wait for either a checkout (notify) or
                // the max-age deadline (then we recycle whatever sits
                // in the queue at that point).
                tokio::select! {
                    _ = spares.notify.notified() => {}
                    _ = sleep(max_age) => {
                        // Drain everything older than max_age. A simple
                        // pop-and-rebuild — small target so the cost
                        // is microseconds.
                        let now = Instant::now();
                        let mut keepers: Vec<PreWarmed> = Vec::new();
                        while let Some(pw) = spares.queue.pop() {
                            if now.saturating_duration_since(pw.created_at) <= max_age {
                                keepers.push(pw);
                            }
                        }
                        for pw in keepers {
                            let _ = spares.queue.push(pw);
                        }
                    }
                }
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{ProxyProtocol, IP as IPV};

    fn make_proxy(host: &str, port: u16) -> ProxyConfig {
        ProxyConfig {
            protocol: ProxyProtocol::Socks5,
            ip: IPV::V4,
            host: host.to_string(),
            port,
            user: None,
            password: None,
            is_gate: false,
            gate: None,
        }
    }

    /// Bind a listener on a free local port and immediately accept-
    /// loop in the background — gives us a reachable upstream that
    /// completes TCP connect (so we exercise the success path of
    /// `pool.acquire`).
    async fn ephemeral_listener() -> (tokio::net::TcpListener, u16) {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        (l, port)
    }

    #[tokio::test]
    async fn acquire_succeeds_below_cap_and_fails_fast_at_cap() {
        // 2-permit semaphore: the third concurrent acquire must fail
        // immediately instead of waiting.
        let pool = ProxyPool::new(PoolConfig::default(), Duration::from_secs(2), 2);
        let (listener, port) = ephemeral_listener().await;
        // accept in background so connect() resolves promptly
        tokio::spawn(async move {
            loop {
                if listener.accept().await.is_err() {
                    break;
                }
            }
        });
        let proxy = make_proxy("127.0.0.1", port);

        let a = pool.acquire(&proxy).await.expect("first acquire");
        let b = pool.acquire(&proxy).await.expect("second acquire");
        let err = pool.acquire(&proxy).await.expect_err("third must fail");
        assert!(
            err.downcast_ref::<AtCapacity>().is_some(),
            "unexpected error: {}",
            err
        );
        // Keep first two alive until here.
        drop((a, b));
    }

    #[tokio::test]
    async fn slot_is_released_on_stream_drop() {
        let pool = ProxyPool::new(PoolConfig::default(), Duration::from_secs(2), 1);
        let (listener, port) = ephemeral_listener().await;
        tokio::spawn(async move {
            loop {
                if listener.accept().await.is_err() {
                    break;
                }
            }
        });
        let proxy = make_proxy("127.0.0.1", port);

        let first = pool.acquire(&proxy).await.unwrap();
        assert!(pool.acquire(&proxy).await.is_err(), "should be at capacity");
        drop(first);
        // Permit released → next acquire succeeds.
        let _second = pool.acquire(&proxy).await.expect("after drop");
    }

    #[tokio::test]
    async fn different_upstreams_have_independent_caps() {
        let pool = ProxyPool::new(PoolConfig::default(), Duration::from_secs(2), 1);
        let (l1, p1) = ephemeral_listener().await;
        let (l2, p2) = ephemeral_listener().await;
        tokio::spawn(async move {
            loop {
                if l1.accept().await.is_err() {
                    break;
                }
            }
        });
        tokio::spawn(async move {
            loop {
                if l2.accept().await.is_err() {
                    break;
                }
            }
        });
        let proxy_a = make_proxy("127.0.0.1", p1);
        let proxy_b = make_proxy("127.0.0.1", p2);

        // Cap=1 each — both should succeed because they're on
        // different (host, port) keys.
        let _a = pool.acquire(&proxy_a).await.unwrap();
        let _b = pool.acquire(&proxy_b).await.unwrap();
    }

    #[tokio::test]
    async fn cap_hit_produces_at_capacity_error() {
        let pool = ProxyPool::new(PoolConfig::default(), Duration::from_secs(2), 1);
        let (listener, port) = ephemeral_listener().await;
        tokio::spawn(async move {
            loop {
                if listener.accept().await.is_err() {
                    break;
                }
            }
        });
        let proxy = make_proxy("127.0.0.1", port);

        let _hold = pool.acquire(&proxy).await.unwrap();
        let err = pool.acquire(&proxy).await.expect_err("should be at cap");
        assert!(
            err.downcast_ref::<AtCapacity>().is_some(),
            "expected AtCapacity, got: {}",
            err
        );
    }

    #[test]
    fn zero_max_per_upstream_clamped_to_one() {
        // A misconfigured `max_per_upstream: 0` would otherwise mean
        // "Semaphore with zero permits" → every acquire fails. Clamp
        // to 1 so the pool stays minimally usable.
        let pool = ProxyPool::new(PoolConfig::default(), Duration::from_secs(2), 0);
        assert_eq!(pool.max_per_upstream, 1);
    }
}
