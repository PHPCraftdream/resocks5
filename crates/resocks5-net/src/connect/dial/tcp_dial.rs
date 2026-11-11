use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use tokio::net::TcpStream;
use tokio::time::{timeout, Instant};

use crate::connect::DialOptions;
use crate::error::{ConnectError, Stage, TimeoutKind};
use crate::types::ProxyConfig;

/// `host:port` for log messages — upstream credentials (both user
/// and password) are intentionally NOT included, since the username
/// half of a SOCKS5 cred is itself sensitive enough to keep out of
/// log files, shell scrollback, and shipped diagnostics.
#[cfg(any(feature = "pool", feature = "tls"))]
pub(crate) fn upstream_endpoint(proxy: &ProxyConfig) -> String {
    format!("{}:{}", proxy.host, proxy.port)
}

/// The whole-call budget of one dial (`DialOptions::total_timeout`), shared by
/// every stage so that the classification of a timeout never depends on which
/// timer the runtime happens to wake first.
///
/// Each stage asks [`Budget::stage`] for its own timer length: the stage's
/// bound, cut down to what is left of the budget. When the budget is the
/// binding limit (left <= the stage bound, so an equal pair counts as the
/// budget) the stage's expiry is the total deadline, and [`Budget::total_won`]
/// says so; a stage error is only reported when its own bound was strictly
/// tighter.
pub(crate) struct Budget {
    deadline: Option<Instant>,
    binding: AtomicBool,
}

impl Budget {
    /// No whole-call limit (the pool-backed chain dial has none).
    #[cfg(feature = "pool")]
    pub(crate) fn unbounded() -> Self {
        Self::start(None)
    }

    /// Start the clock now. A budget too large to represent is no limit.
    pub(crate) fn start(total: Option<Duration>) -> Self {
        Self {
            deadline: total.and_then(|t| Instant::now().checked_add(t)),
            binding: AtomicBool::new(false),
        }
    }

    /// The timer length for a stage that starts now and is bounded by `bound`.
    pub(crate) fn stage(&self, bound: Duration) -> Duration {
        let Some(deadline) = self.deadline else {
            return bound;
        };
        let left = deadline.saturating_duration_since(Instant::now());
        let binding = left <= bound;
        self.binding.store(binding, Ordering::Relaxed);
        if binding {
            left
        } else {
            bound
        }
    }

    /// Whether the stage that ran last was cut by the budget: its timeout is
    /// the total deadline.
    pub(crate) fn total_won(&self) -> bool {
        self.binding.load(Ordering::Relaxed)
    }
}

/// Plain TCP dial to the proxy under `connect_timeout`.
///
/// The address is passed as `(host, port)`: `ProxyConfig.host` has no
/// IPv6 brackets, so formatting `host:port` would mangle `::1` and fall
/// into the blocking system resolver.
pub(crate) async fn tcp_dial(
    proxy: &ProxyConfig,
    connect_timeout: Duration,
) -> Result<TcpStream, ConnectError> {
    let endpoint = || format!("{}:{}", proxy.host, proxy.port);
    match timeout(
        connect_timeout,
        TcpStream::connect((proxy.host.as_str(), proxy.port)),
    )
    .await
    {
        Ok(Ok(s)) => Ok(s),
        Ok(Err(e)) => Err(ConnectError::Io {
            stage: Stage::Connect,
            endpoint: Some(endpoint()),
            source: e,
        }),
        Err(_) => Err(ConnectError::Timeout {
            stage: Stage::Connect,
            kind: TimeoutKind::TcpConnect,
            endpoint: endpoint(),
            after: connect_timeout,
        }),
    }
}

/// Apply the [`DialOptions`] socket options to the socket to `proxy`.
pub(crate) fn apply_socket_options(
    stream: &TcpStream,
    proxy: &ProxyConfig,
    opts: &DialOptions,
) -> Result<(), ConnectError> {
    let io = |source| ConnectError::Io {
        stage: Stage::Connect,
        endpoint: Some(format!("{}:{}", proxy.host, proxy.port)),
        source,
    };
    if opts.nodelay {
        stream.set_nodelay(true).map_err(io)?;
    }
    if let Some(idle) = opts.keepalive {
        let keepalive = socket2::TcpKeepalive::new().with_time(idle);
        #[cfg(any(
            target_os = "android",
            target_os = "dragonfly",
            target_os = "freebsd",
            target_os = "fuchsia",
            target_os = "illumos",
            target_os = "ios",
            target_os = "visionos",
            target_os = "linux",
            target_os = "macos",
            target_os = "netbsd",
            target_os = "tvos",
            target_os = "watchos",
            target_os = "windows",
            target_os = "cygwin",
        ))]
        let keepalive = if let Some(interval) = opts.keepalive_interval {
            keepalive.with_interval(interval)
        } else {
            keepalive
        };
        socket2::SockRef::from(stream)
            .set_tcp_keepalive(&keepalive)
            .map_err(io)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn proxy(host: &str, port: u16) -> ProxyConfig {
        ProxyConfig::socks5(host, port)
    }

    #[tokio::test]
    async fn dial_succeeds_against_listener() {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        let s = tcp_dial(&proxy("127.0.0.1", port), Duration::from_secs(2))
            .await
            .expect("dial");
        assert_eq!(s.peer_addr().unwrap().port(), port);
    }

    #[tokio::test]
    async fn refused_is_io_connect_with_endpoint() {
        // Port 0 fails immediately everywhere (a closed port retries ~2s on Windows).
        let port = 0;
        let err = tcp_dial(&proxy("127.0.0.1", port), Duration::from_secs(5))
            .await
            .expect_err("port 0");
        assert!(
            matches!(
                &err,
                ConnectError::Io { stage: Stage::Connect, endpoint: Some(e), .. }
                    if *e == format!("127.0.0.1:{port}")
            ),
            "got: {err:?}"
        );
        assert!(
            err.to_string()
                .contains(&format!("connect to 127.0.0.1:{port}: ")),
            "got: {err}"
        );
    }

    #[tokio::test]
    async fn unroutable_ends_in_connect_stage_error() {
        // TEST-NET-1 (RFC 5737): Timeout, or Io where the network is unreachable.
        let err = tcp_dial(&proxy("203.0.113.1", 1080), Duration::from_millis(300))
            .await
            .expect_err("must not connect");
        match &err {
            ConnectError::Timeout {
                stage: Stage::Connect,
                kind: TimeoutKind::TcpConnect,
                endpoint,
                after,
            } => {
                assert_eq!(endpoint, "203.0.113.1:1080");
                assert_eq!(*after, Duration::from_millis(300));
                assert_eq!(err.to_string(), "connect timeout (0s) to 203.0.113.1:1080");
            }
            ConnectError::Io {
                stage: Stage::Connect,
                ..
            } => assert!(err.to_string().contains("203.0.113.1:1080")),
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[tokio::test(start_paused = true)]
    async fn the_budget_cuts_a_stage_only_when_it_binds() {
        let unbounded = Budget::start(None);
        assert_eq!(
            unbounded.stage(Duration::from_secs(9)),
            Duration::from_secs(9)
        );
        assert!(!unbounded.total_won());

        let budget = Budget::start(Some(Duration::from_secs(10)));
        assert_eq!(budget.stage(Duration::from_secs(4)), Duration::from_secs(4));
        assert!(!budget.total_won());
        tokio::time::advance(Duration::from_secs(4)).await;
        // 6 s left: a 6 s stage is the budget (a tie goes to the total) ...
        assert_eq!(budget.stage(Duration::from_secs(6)), Duration::from_secs(6));
        assert!(budget.total_won());
        // ... a 5 s stage is its own, and the flag follows the stage that ran last.
        assert_eq!(budget.stage(Duration::from_secs(5)), Duration::from_secs(5));
        assert!(!budget.total_won());
        assert_eq!(
            budget.stage(Duration::from_secs(60)),
            Duration::from_secs(6)
        );
        assert!(budget.total_won());
        tokio::time::advance(Duration::from_secs(60)).await;
        assert_eq!(budget.stage(Duration::from_secs(1)), Duration::ZERO);
        assert!(budget.total_won());
    }

    #[test]
    fn a_budget_too_large_to_represent_is_no_limit() {
        let budget = Budget::start(Some(Duration::MAX));
        assert_eq!(budget.stage(Duration::from_secs(3)), Duration::from_secs(3));
        assert!(!budget.total_won());
    }
}
