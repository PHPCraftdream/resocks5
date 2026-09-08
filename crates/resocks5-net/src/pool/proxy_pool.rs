//! ## Lifecycle
//!
//! - At startup `spawn_refill_for(proxy)` launches one task per unique
//!   `(host, port)` upstream (creation is atomic — concurrent callers
//!   race through a single `DashMap::entry`, so exactly one task per
//!   key exists). Each task keeps its own queue topped up to
//!   `spare_per_proxy`.
//! - On `checkout`, we pop one socket. If its age exceeds
//!   `max_session_age_sec` (defends against silent idle-disconnects on
//!   the proxy side) we discard it and pop the next. The refill task
//!   notices the queue is below target and reconnects.
//! - On a checkout that finds the queue empty (or all stale), the
//!   caller falls back to a fresh `TcpStream::connect`. The pool is a
//!   best-effort accelerator, never a hard dependency.
//! - Dropping the pool aborts its refill tasks — no task outlives the
//!   pool it serves.
//!
//! ## Per-upstream concurrent-connection cap
//!
//! A `Semaphore` is kept per `(host, port)`. Pre-warmed spares take
//! their permit BEFORE connecting, so `max_per_upstream` bounds REAL
//! live TCP connections (spares + active) per upstream, and on
//! `acquire` the spare's already-held permit travels with the
//! connection instead of a second one being reserved. A fresh
//! fallback `connect` first takes one permit. The permit is held
//! inside the returned `UpstreamStream` and released when that stream
//! is dropped. The cap
//! defends the upstream provider's per-account / per-IP connection
//! limit — without it a burst of client requests opens hundreds of
//! sockets in parallel, the provider blocks our IP or account, and
//! every subsequent SOCKS5 handshake times out for the duration of
//! their cool-down (observed symptom: 10-second handshake timeouts on
//! every direct attempt, while via-Tor still works because each Tor
//! circuit sources from a different exit IP).
//!
//! Gate-tunneled connections additionally hold a socket-less permit
//! for the inner proxy (see `reserve_permit`), so direct traffic and
//! gate-routed traffic draw on the same cap.

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
#[derive(Clone)]
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
/// concurrent-connection permits for every node of the tunnel it
/// carries. A direct connect holds exactly one; a gate-tunneled
/// connect holds one per hop (gate + inner proxy) even though the
/// whole chain is a single TCP socket. Dropping the struct releases
/// all permits and closes the socket — that is the whole point of
/// the wrapper: the cap is held for the lifetime of the tunnel and
/// freed the moment forwarding ends.
#[derive(Debug)]
pub struct UpstreamStream {
    stream: TcpStream,
    /// Kept private so callers can't shuffle permits between tunnels;
    /// `attach_permit` is the only way to add one.
    _permits: Vec<OwnedSemaphorePermit>,
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
        self._permits.push(permit);
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

/// One pre-warmed TCP socket plus its creation timestamp (used to
/// reject stale entries on `checkout`) and the per-upstream cap
/// permit it was granted before connecting — carrying the permit in
/// the struct is what makes spares count against
/// `max_per_upstream`, and lets the permit travel with the
/// connection on `acquire` instead of being re-reserved.
struct PreWarmed {
    stream: TcpStream,
    created_at: Instant,
    permit: OwnedSemaphorePermit,
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
    /// Background refill tasks, one per `(host, port)`. Kept so
    /// `Drop` can abort them — otherwise a dropped pool would leave
    /// tasks opening sockets forever. A `std` Mutex suffices: the
    /// guard is only ever held synchronously, never across an await.
    refill_tasks: std::sync::Mutex<Vec<tokio::task::JoinHandle<()>>>,
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
            refill_tasks: std::sync::Mutex::new(Vec::new()),
        }
    }

    /// Abort every refill task this pool spawned. Called on drop so
    /// a discarded pool stops opening sockets in the background.
    /// `abort()` is sync and non-blocking; cancellation drops the
    /// task's in-flight permit/stream locals at its await point. The
    /// lock is recovered from poisoning rather than panicking — Drop
    /// must never panic.
    fn abort_refill_tasks(&self) {
        let mut tasks = self
            .refill_tasks
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for handle in tasks.drain(..) {
            handle.abort();
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

    /// Take one slot from `(host, port)`'s concurrency-cap semaphore
    /// WITHOUT opening a TCP connection or checking out a pooled
    /// socket. The single choke point through which every path
    /// accounts a node of a tunnel against `max_per_upstream`:
    /// `acquire` calls it for the socket it opens, and the gate path
    /// (`establish_connection::use_gate`) calls it for the inner proxy
    /// of a chain — that tunnel holds a live connection to the proxy
    /// through the gate, so it must consume the same cap as a direct
    /// connection even though no dedicated socket exists for it.
    ///
    /// Fails fast with an [`AtCapacity`] error when the cap is hit;
    /// never waits. The caller MUST keep the returned permit alive for
    /// as long as the connection it accounts is alive —
    /// [`UpstreamStream::attach_permit`] is the intended way for
    /// tunneled hops.
    pub fn reserve_permit(&self, proxy: &ProxyConfig) -> anyhow::Result<OwnedSemaphorePermit> {
        let sem = self.upstream_semaphore(&proxy.host, proxy.port);
        sem.try_acquire_owned().map_err(|_| {
            anyhow::Error::new(AtCapacity {
                host: proxy.host.clone(),
                port: proxy.port,
            })
        })
    }

    /// "Give me a TCP socket to this proxy, fast if you can" — the
    /// standard entry point used by every connect path.
    ///
    /// Two-step acquisition:
    /// 1. Pop a pre-warmed socket. Its already-held cap permit
    ///    travels with the connection — no second reserve (that
    ///    would silently over-tighten the cap). This succeeds even
    ///    when the semaphore is empty, which is correct: the spare
    ///    genuinely holds a real socket + permit.
    /// 2. No spare available: take one permit from the per-upstream
    ///    semaphore (fail fast with `AtCapacity` when the cap is
    ///    hit) and open a fresh `TcpStream::connect` under
    ///    `connect_timeout`.
    ///
    /// Returns `UpstreamStream` so the permit lives exactly as long as
    /// the socket and the slot is released on drop.
    pub async fn acquire(&self, proxy: &ProxyConfig) -> anyhow::Result<UpstreamStream> {
        let endpoint = upstream_endpoint(proxy);

        // Step 1: pre-warmed socket — its permit comes with it.
        if let Some(pw) = self.checkout_prewarmed(proxy) {
            return Ok(UpstreamStream {
                stream: pw.stream,
                _permits: vec![pw.permit],
            });
        }

        // Step 2: fresh connect under the cap.
        let permit = self.reserve_permit(proxy)?;
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
            _permits: vec![permit],
        })
    }

    /// Try to take a pre-warmed socket (with its bundled cap permit)
    /// for the given proxy. Returns `None` when the pool is disabled,
    /// no entry exists yet, the queue is empty, or every entry has
    /// aged out.
    fn checkout_prewarmed(&self, proxy: &ProxyConfig) -> Option<PreWarmed> {
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
                return Some(pw);
            }
            // stale — drop (releasing its socket and cap permit)
            // and try the next.
        }
    }

    /// Try to take a fresh pre-warmed socket for the given proxy.
    /// Returns `None` when the pool is disabled, no entry exists yet,
    /// the queue is empty, or every entry has aged out.
    ///
    /// When called directly (not via [`acquire`](ProxyPool::acquire))
    /// the bundled cap permit is dropped with the socket — this path
    /// is deliberately zero-accounting.
    pub fn checkout(&self, proxy: &ProxyConfig) -> Option<TcpStream> {
        self.checkout_prewarmed(proxy).map(|pw| pw.stream)
    }

    /// Launch a long-lived refill task for `proxy`. Idempotent: if a
    /// task is already running for the same `(host, port)`, this is a
    /// no-op. Creation is atomic — concurrent callers race through a
    /// single `DashMap::entry`, so exactly one constructs the
    /// `ProxySpares` and spawns; at most one refill task per
    /// `(host, port)` exists for the pool's lifetime. The task handle
    /// is retained and aborted when the pool drops.
    pub fn spawn_refill_for(&self, proxy: Arc<ProxyConfig>) {
        if !self.config.enabled {
            return;
        }
        let key = (proxy.host.clone(), proxy.port);
        let target = self.config.spare_per_proxy.max(1);
        let max_age = Duration::from_secs(self.config.max_session_age_sec);
        // Race-safe get-or-create: DashMap serialises the entry, so
        // whichever caller lands first constructs the ProxySpares and
        // spawns the refill task; losers read the same Arc back and
        // return. No await inside the closure — it's a sync fn.
        let mut won_race = false;
        let spares = self
            .pools
            .entry(key)
            .or_insert_with(|| {
                won_race = true;
                Arc::new(ProxySpares {
                    queue: ArrayQueue::new(target),
                    notify: Notify::new(),
                })
            })
            .value()
            .clone();
        if !won_race {
            return; // Already running for this proxy.
        }

        // The refill loop:
        // - top up to `target` while space available
        // - on connect failure, exponential backoff (capped at 10s) so
        //   a dead proxy doesn't burn CPU
        // - then wait either for a `notify` (slot freed by checkout)
        //   or for `max_age` (time to proactively recycle stale)
        let connect_timeout = self.connect_timeout;
        // Cap semaphore captured at spawn time: every pre-warmed
        // socket reserves a permit BEFORE connecting, so spares +
        // active together never exceed `max_per_upstream`.
        let sem = self.upstream_semaphore(&proxy.host, proxy.port);
        let handle = tokio::spawn(async move {
            let addr = format!("{}:{}", proxy.host, proxy.port);
            let mut backoff = Duration::from_millis(100);
            loop {
                while spares.queue.len() < target {
                    // Reserve a cap slot first; when the cap is full
                    // there is no point opening a socket we must not
                    // keep — back off and retry.
                    let Ok(permit) = sem.clone().try_acquire_owned() else {
                        sleep(backoff).await;
                        backoff = (backoff * 2).min(Duration::from_secs(10));
                        continue;
                    };
                    match timeout(connect_timeout, TcpStream::connect(&addr)).await {
                        Ok(Ok(stream)) => {
                            let pw = PreWarmed {
                                stream,
                                created_at: Instant::now(),
                                permit,
                            };
                            // Best-effort push: queue may have filled
                            // up while we were connecting (concurrent
                            // refill iteration succeeded first), in
                            // which case we drop this socket — and
                            // with it the cap permit.
                            let _ = spares.queue.push(pw);
                            backoff = Duration::from_millis(100);
                        }
                        // Both kinds of failure (connect error or
                        // timeout) feed the same exponential backoff
                        // so a dead proxy doesn't burn CPU on retries.
                        // Release the reserved slot first — a dead or
                        // slow proxy must not pin cap slots while it
                        // backs off.
                        Ok(Err(_)) | Err(_) => {
                            drop(permit);
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
        self.refill_tasks
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(handle);
    }
}

impl Drop for ProxyPool {
    fn drop(&mut self) {
        self.abort_refill_tasks();
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

    #[test]
    fn reserve_permit_enforces_cap_and_releases_on_drop() {
        // Pure accounting: no TCP connect happens, so an unreachable
        // host is fine — the semaphore is created lazily from the
        // config alone.
        let pool = ProxyPool::new(PoolConfig::default(), Duration::from_secs(2), 2);
        let proxy = make_proxy("203.0.113.1", 1080);

        let a = pool.reserve_permit(&proxy).expect("first reserve");
        let b = pool.reserve_permit(&proxy).expect("second reserve");
        let err = pool.reserve_permit(&proxy).expect_err("cap is 2");
        assert!(
            err.downcast_ref::<AtCapacity>().is_some(),
            "expected AtCapacity, got: {}",
            err
        );
        drop((a, b));
        let _c = pool.reserve_permit(&proxy).expect("released on drop");
    }

    #[tokio::test]
    async fn attached_permit_is_released_with_the_stream() {
        // The gate path's shape: acquire (1 slot) + a logical reserve
        // for the inner hop (2nd slot); dropping the tunnel must free
        // BOTH.
        let pool = ProxyPool::new(PoolConfig::default(), Duration::from_secs(2), 2);
        let (listener, port) = ephemeral_listener().await;
        tokio::spawn(async move {
            loop {
                if listener.accept().await.is_err() {
                    break;
                }
            }
        });
        let proxy = make_proxy("127.0.0.1", port);

        let mut stream = pool.acquire(&proxy).await.expect("acquire");
        stream.attach_permit(pool.reserve_permit(&proxy).expect("reserve inner hop"));
        assert!(
            pool.acquire(&proxy).await.is_err(),
            "acquire + attached reserve must consume both slots"
        );
        drop(stream);
        let _a = pool.acquire(&proxy).await.expect("socket slot back");
        let _b = pool.reserve_permit(&proxy).expect("attached slot back");
    }

    // ---- Refill-task / spare-accounting tests -----------------------
    //
    // These use `start_paused = true` + `advance`: real local-TCP
    // connects complete fine under paused time; only timers (the
    // refill backoff) need advancing. `max_session_age_sec: 3600`
    // keeps the age-out path well out of reach of the small advances
    // used to drive progress.

    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Shared accept/open counters for the counting listener.
    #[derive(Default)]
    struct Counters {
        accepted: AtomicUsize,
        open: AtomicUsize,
    }

    impl Counters {
        fn accepted(&self) -> usize {
            self.accepted.load(Ordering::SeqCst)
        }
        fn open(&self) -> usize {
            self.open.load(Ordering::SeqCst)
        }
    }

    /// Accept-loop that counts total accepted connections and
    /// currently-open peer sockets. Each accepted socket is held by a
    /// handler task that reads until EOF; a guard decrements `open`
    /// when the socket drops (peer closed or task ends), so `open`
    /// drains to 0 once the pool-side sockets are gone.
    async fn counting_listener(l: tokio::net::TcpListener, counters: Arc<Counters>) {
        loop {
            let Ok((sock, _)) = l.accept().await else {
                break;
            };
            counters.accepted.fetch_add(1, Ordering::SeqCst);
            counters.open.fetch_add(1, Ordering::SeqCst);
            struct OpenGuard(Arc<Counters>);
            impl Drop for OpenGuard {
                fn drop(&mut self) {
                    self.0.open.fetch_sub(1, Ordering::SeqCst);
                }
            }
            let guard = OpenGuard(counters.clone());
            tokio::spawn(async move {
                let _guard = guard;
                use tokio::io::AsyncReadExt;
                let mut sock = sock;
                let mut buf = [0u8; 64];
                loop {
                    match sock.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(_) => {}
                    }
                }
            });
        }
    }

    /// Drive paused time in bounded steps until `cond` holds, so the
    /// tests are deterministic rather than timing-dependent. Total
    /// advanced time stays far below `max_session_age_sec = 3600`.
    ///
    /// `cond` here waits on REAL socket I/O (a loopback TCP
    /// connect/accept), not just virtual timers. `tokio::time::advance`
    /// only fast-forwards tokio's paused clock — it does nothing to
    /// give the OS a chance to actually finish a pending handshake, and
    /// `yield_now` alone doesn't either. Under `start_paused = true`,
    /// with nothing but virtual-time advancement and cooperative
    /// yields, this loop can iterate its full budget in well under a
    /// millisecond of REAL wall-clock time in a release build — not
    /// necessarily enough real time for the kernel to complete a
    /// loopback handshake, which flaked this exact wait on this exact
    /// build profile. A tiny REAL (blocking) sleep forces genuine
    /// wall-clock progress every iteration without touching tokio's
    /// own paused clock, so real I/O actually gets a chance to land.
    async fn quiesce(cond: impl Fn() -> bool) {
        for _ in 0..500 {
            if cond() {
                return;
            }
            tokio::time::advance(Duration::from_millis(100)).await;
            std::thread::sleep(Duration::from_millis(1));
            tokio::task::yield_now().await;
        }
        panic!("condition did not become true within the advance budget");
    }

    fn pool_cfg(spare_per_proxy: usize) -> PoolConfig {
        PoolConfig {
            enabled: true,
            spare_per_proxy,
            max_session_age_sec: 3600,
        }
    }

    #[tokio::test(start_paused = true)]
    async fn concurrent_spawn_refill_for_races_to_single_task() {
        let counters = Arc::new(Counters::default());
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        tokio::spawn(counting_listener(l, counters.clone()));

        // Cap 5 — deliberately above the spare target so permits
        // never bind; this test isolates the race, not the cap.
        // connect_timeout is generous (not 2s): `quiesce` advances the
        // paused clock in 100ms steps regardless of real I/O progress,
        // so under real scheduling delay (e.g. a loaded machine) the
        // virtual clock can outrun a real, still-in-flight
        // `TcpStream::connect` and trip a short internal timeout,
        // aborting a connect the OS was about to complete — the client
        // fd closes right after the server's `accept()` already counted
        // it, flaking `open()` below `accepted()`. A large timeout here
        // can never legitimately fire in this test.
        let pool = Arc::new(ProxyPool::new(pool_cfg(3), Duration::from_secs(120), 5));
        let proxy = Arc::new(make_proxy("127.0.0.1", port));

        // 8 concurrent callers race to spawn for the SAME (host, port).
        let mut tasks = Vec::new();
        for _ in 0..8 {
            let pool = pool.clone();
            let proxy = proxy.clone();
            tasks.push(tokio::spawn(async move {
                pool.spawn_refill_for(proxy);
            }));
        }
        for t in tasks {
            t.await.unwrap();
        }

        quiesce(|| pool.pools.len() == 1 && counters.accepted() == 3).await;

        // Exactly one ProxySpares entry and exactly one refill task's
        // worth of connections (target 3). The old contains_key+insert
        // code let two winners spawn, yielding 6+ accepts and an
        // orphaned task filling a queue unreachable through the map.
        assert_eq!(pool.pools.len(), 1);
        assert_eq!(counters.accepted(), 3);
        assert_eq!(counters.open(), 3);
    }

    #[tokio::test(start_paused = true)]
    async fn dropping_pool_stops_refill_task() {
        let counters = Arc::new(Counters::default());
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        tokio::spawn(counting_listener(l, counters.clone()));

        // See the comment in `concurrent_spawn_refill_for_races_to_single_task`
        // for why this needs a generous connect_timeout under `quiesce`.
        let pool = ProxyPool::new(pool_cfg(2), Duration::from_secs(120), 4);
        let proxy = Arc::new(make_proxy("127.0.0.1", port));
        let key = (proxy.host.clone(), proxy.port);
        pool.spawn_refill_for(proxy);

        // Wait for the full steady state: both spares connected AND in
        // the queue, so the refill task is parked with no connects in
        // flight and the drop is side-effect-free on the accept count.
        quiesce(|| {
            counters.accepted() == 2
                && pool.pools.get(&key).map(|s| s.queue.len()).unwrap_or(0) == 2
        })
        .await;
        let n = counters.accepted();
        assert_eq!(counters.open(), 2, "both spare sockets open");

        // Dropping the pool aborts the refill task, so no further
        // connects ever happen, and the spare sockets die with it.
        drop(pool);
        for _ in 0..50 {
            assert!(
                counters.accepted() <= n,
                "refill task connected after pool drop"
            );
            if counters.open() == 0 {
                break;
            }
            tokio::time::advance(Duration::from_secs(3600)).await;
            tokio::task::yield_now().await;
        }
        assert_eq!(counters.open(), 0, "spare sockets must die with the pool");
        assert!(counters.accepted() <= n);
    }

    #[tokio::test(start_paused = true)]
    async fn spares_and_active_share_one_cap() {
        let counters = Arc::new(Counters::default());
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        tokio::spawn(counting_listener(l, counters.clone()));

        // Target 4 spares, cap 5. Steady state after the first
        // acquire+refill: spares(4) + actives(1) = 5 sockets, all 5
        // permits held, 5 accepted total — and no further connects for
        // the rest of the test (no age-out, no drops: a popped spare
        // IS the active socket, and the refill has no free permit).
        // See the comment in `concurrent_spawn_refill_for_races_to_single_task`
        // for why this needs a generous connect_timeout under `quiesce`.
        let pool = Arc::new(ProxyPool::new(pool_cfg(4), Duration::from_secs(120), 5));
        let proxy = make_proxy("127.0.0.1", port);
        let key = (proxy.host.clone(), proxy.port);
        pool.spawn_refill_for(Arc::new(proxy.clone()));

        quiesce(|| {
            counters.accepted() == 4
                && pool.pools.get(&key).map(|s| s.queue.len()).unwrap_or(0) == 4
        })
        .await;
        assert_eq!(counters.open(), 4, "4 real spare sockets");
        assert_eq!(
            pool.upstream_caps.get(&key).unwrap().available_permits(),
            1,
            "4 spares hold 4 of 5 permits"
        );

        let mut streams = Vec::new();
        for i in 1..=5 {
            streams.push(pool.acquire(&proxy).await.expect("acquire"));
            if i == 1 {
                // Immediately after the spare-path acquire the refill
                // task has not been polled yet (no yield point since
                // the notify), so exactly 4 slots are held and 1 is
                // free — proving the spare's permit was REUSED, not
                // double-reserved (a second reserve would give 0 here).
                assert_eq!(
                    pool.upstream_caps.get(&key).unwrap().available_permits(),
                    1,
                    "spare-path acquire must not consume an extra permit"
                );
                // Wait for the refill to finish re-topping: push
                // recorded and the last permit consumed → fully
                // settled 5 held / 5 open.
                quiesce(|| {
                    counters.accepted() == 5
                        && pool.pools.get(&key).map(|s| s.queue.len()).unwrap_or(0) == 4
                        && pool.upstream_caps.get(&key).unwrap().available_permits() == 0
                })
                .await;
            } else {
                // No permit free → refill cannot open anything.
                tokio::task::yield_now().await;
            }
            assert!(
                counters.open() <= 5,
                "open={} exceeded cap at acquire #{}",
                counters.open(),
                i
            );
            assert_eq!(
                pool.upstream_caps.get(&key).unwrap().available_permits(),
                0,
                "all 5 slots held after quiescence at acquire #{}",
                i
            );
        }

        // Steady state: 5 live sockets (4 remaining spares were
        // consumed one-by-one as actives... precisely: after acquire 1
        // + refill, 4 spares + 1 active; acquires 2..5 pop those 4
        // spares as actives, refill blocked by the full cap).
        assert_eq!(counters.open(), 5);
        assert_eq!(
            counters.accepted(),
            5,
            "no socket churn beyond the initial 5"
        );
        assert_eq!(
            pool.pools.get(&key).unwrap().queue.len(),
            0,
            "queue drained into actives"
        );

        // Queue empty + semaphore exhausted → fail fast with AtCapacity.
        let err = pool.acquire(&proxy).await.expect_err("6th acquire");
        assert!(
            err.downcast_ref::<AtCapacity>().is_some(),
            "expected AtCapacity, got: {}",
            err
        );
        assert!(counters.open() <= 5);
        assert_eq!(counters.accepted(), 5);
    }
}
