use tokio::sync::mpsc::Sender;

use crate::logger::ELog;

use crate::logger::LogConfig;

/// Wraps the channel sender plus the per-type flags. Cloned cheaply via
/// `Arc<Logger>` from `run_server` into each connection task.
///
/// The channel is bounded — under sudden load spikes the producer side
/// uses `try_send`, dropping the log line if the consumer can't keep up
/// rather than blocking the proxy task. Lost logs are the right
/// trade-off here: tunnels must not stall because the terminal is slow.
pub struct Logger {
    sender: Sender<ELog>,
    cfg: LogConfig,
}

impl Logger {
    pub fn new(sender: Sender<ELog>, cfg: LogConfig) -> Self {
        Self { sender, cfg }
    }

    fn send_info(&self, msg: String) {
        // `try_send` returns Err on Full or Closed — we silently drop
        // either way. A backed-up consumer means logs are lost (better
        // than blocking the hot path); a closed receiver means the
        // logger task is gone (server shutdown), nothing to do.
        let _ = self.sender.try_send(ELog::Log(msg));
    }

    fn send_error(&self, msg: String) {
        let _ = self.sender.try_send(ELog::Error(msg));
    }

    pub fn lifecycle(&self, msg: impl FnOnce() -> String) {
        if self.cfg.lifecycle {
            self.send_info(msg());
        }
    }

    pub fn cache_attempt(&self, msg: impl FnOnce() -> String) {
        if self.cfg.cache_attempts {
            self.send_info(msg());
        }
    }

    pub fn cache_hit(&self, msg: impl FnOnce() -> String) {
        if self.cfg.cache_hits {
            self.send_info(msg());
        }
    }

    pub fn cache_write(&self, msg: impl FnOnce() -> String) {
        if self.cfg.cache_writes {
            self.send_info(msg());
        }
    }

    pub fn proxy_failure(&self, msg: impl FnOnce() -> String) {
        if self.cfg.proxy_failures {
            self.send_error(msg());
        }
    }

    pub fn banned_target(&self, msg: impl FnOnce() -> String) {
        if self.cfg.banned_targets {
            self.send_error(msg());
        }
    }

    pub fn connection_error(&self, msg: impl FnOnce() -> String) {
        if self.cfg.connection_errors {
            self.send_error(msg());
        }
    }

    pub fn attempt(&self, msg: impl FnOnce() -> String) {
        if self.cfg.attempts {
            self.send_info(msg());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use tokio::sync::mpsc;

    /// Build a Logger with every flag turned off — useful for proving
    /// that the closure inside `logger.<type>(|| ...)` is never even
    /// invoked when the corresponding flag is `false`.
    fn all_off() -> LogConfig {
        LogConfig {
            lifecycle: false,
            cache_attempts: false,
            cache_hits: false,
            cache_writes: false,
            proxy_failures: false,
            banned_targets: false,
            connection_errors: false,
            attempts: false,
        }
    }

    fn all_on() -> LogConfig {
        LogConfig {
            lifecycle: true,
            cache_attempts: true,
            cache_hits: true,
            cache_writes: true,
            proxy_failures: true,
            banned_targets: true,
            connection_errors: true,
            attempts: true,
        }
    }

    #[test]
    fn closure_never_called_when_flag_is_off() {
        let (tx, _rx) = mpsc::channel::<ELog>(4);
        let log = Logger::new(tx, all_off());

        // FnOnce closure with `Cell` so we can observe whether the
        // closure body ran, without violating the FnOnce / move
        // semantics.
        let called = Cell::new(false);
        log.lifecycle(|| {
            called.set(true);
            "x".to_string()
        });
        assert!(!called.get(), "lifecycle off → closure must not run");

        let called = Cell::new(false);
        log.cache_hit(|| {
            called.set(true);
            "x".to_string()
        });
        assert!(!called.get(), "cache_hits off → closure must not run");

        let called = Cell::new(false);
        log.connection_error(|| {
            called.set(true);
            "x".to_string()
        });
        assert!(
            !called.get(),
            "connection_errors off → closure must not run"
        );
    }

    #[tokio::test]
    async fn enabled_flags_route_to_correct_variant() {
        let (tx, mut rx) = mpsc::channel::<ELog>(16);
        let log = Logger::new(tx, all_on());

        log.lifecycle(|| "info-1".to_string());
        log.cache_hit(|| "info-2".to_string());
        log.connection_error(|| "err-1".to_string());
        log.banned_target(|| "err-2".to_string());
        drop(log); // close sender so recv returns None after drain

        let mut info = 0;
        let mut err = 0;
        while let Some(e) = rx.recv().await {
            match e {
                ELog::Log(_) => info += 1,
                ELog::Error(_) => err += 1,
            }
        }
        // lifecycle + cache_hit → info; connection_error + banned_target → error.
        assert_eq!(info, 2);
        assert_eq!(err, 2);
    }

    /// Bounded channel: when full, `try_send` returns Err and the log
    /// is silently dropped. Producer must NOT block — that's the whole
    /// point of switching from `unbounded_channel` + `.send`.
    #[tokio::test]
    async fn drops_silently_when_channel_full() {
        // Capacity 2 → 3rd line gets dropped.
        let (tx, mut rx) = mpsc::channel::<ELog>(2);
        let log = Logger::new(tx, all_on());

        log.lifecycle(|| "msg-1".to_string());
        log.lifecycle(|| "msg-2".to_string());
        log.lifecycle(|| "msg-3-dropped".to_string());
        drop(log);

        // Exactly two messages survive; the third must NOT be there.
        let mut surviving = 0;
        while let Some(e) = rx.recv().await {
            match e {
                ELog::Log(s) => {
                    assert_ne!(s, "msg-3-dropped");
                    surviving += 1;
                }
                ELog::Error(_) => unreachable!(),
            }
        }
        assert_eq!(surviving, 2);
    }

    /// Dropping the receiver before sending must not panic — try_send
    /// returns Err(Closed) which we silently ignore. Validates that a
    /// crashed log-consumer task can't take the producer down with it.
    #[tokio::test]
    async fn does_not_panic_after_receiver_dropped() {
        let (tx, rx) = mpsc::channel::<ELog>(4);
        drop(rx);
        let log = Logger::new(tx, all_on());
        log.lifecycle(|| "post-drop".to_string());
        log.connection_error(|| "post-drop-err".to_string());
        // No panic, no hang — that's the assertion.
    }
}
