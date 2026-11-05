use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use chrono::Local;
use tokio::io::AsyncWriteExt;
use tokio::spawn;
use tokio::sync::mpsc;

use crate::logger::{self, ELog};

/// Bound on ANY stderr diagnostic (see [`emit_bounded_stderr`]). One
/// line should never need more — whether it is the shutdown path or the
/// log-drain failure path.
const DIAGNOSTIC_TIMEOUT_SEC: u64 = 1;

/// Bound on joining the log-drain task at shutdown. The normal path
/// needs microseconds: dropping the last `Arc<Logger>` closes the
/// channel and the drain loop exits on `recv() == None`. Five seconds
/// is ample headroom for flushing a full 2048-slot backlog plus the
/// `BufWriter`, while keeping the worst case far below the 30 s tunnel
/// drain (`SHUTDOWN_DRAIN_SEC`) — a log flush must never dominate
/// shutdown.
/// On expiry the drain task is detached and un-flushed lines are lost
/// by design; the bounded runtime teardown guarantees the detached
/// task's wedged write cannot extend process exit.
const LOG_DRAIN_TIMEOUT_SEC: u64 = 5;

/// Best-effort diagnostic writer for log-drain failures (file logger
/// cannot be opened or written). Contract: emitting must never block
/// the worker thread synchronously — awaiting the returned future
/// yields to the runtime, so even a wedged sink only parks this task,
/// never the executor. Never report an emitting failure through any
/// sink: there is nothing left to report to.
trait DiagnosticWriter: Send + 'static {
    fn emit(&self, message: String) -> Pin<Box<dyn Future<Output = ()> + Send + '_>>;
}

/// Production sink: the diagnostic goes through `tokio::io::stderr()`
/// (blocking pool, yields to the runtime) under
/// [`DIAGNOSTIC_TIMEOUT_SEC`]; on expiry the message is dropped
/// silently — best-effort by design.
struct StderrDiagnostics;

impl DiagnosticWriter for StderrDiagnostics {
    fn emit(&self, message: String) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        Box::pin(emit_bounded_stderr(message))
    }
}

/// Spawn the async log-drain task. Returns the `JoinHandle` so shutdown
/// can wait for the queue to flush instead of letting runtime teardown
/// silently cancel the task mid-`recv()` (a timeout instead detaches
/// it; the bounded teardown then abandons any wedged write — see
/// `SHUTDOWN_TEARDOWN_TIMEOUT_SEC`).
pub(super) fn spawn_log_drain(
    log_receiver: mpsc::Receiver<ELog>,
    file_log_cfg: crate::config::FileLogConfig,
) -> tokio::task::JoinHandle<()> {
    spawn(run_log_drain(log_receiver, file_log_cfg, StderrDiagnostics))
}

/// Body of the async log-drain task, spawned by `run_server_inner`.
///
/// A file open/write/flush failure is NOT swallowed: the first failure
/// is reported through the [`DiagnosticWriter`] seam — bounded stderr,
/// never a synchronous `eprintln!` on the worker — and the task falls
/// back to console-only for the rest of the run, avoiding one
/// diagnostic per queued message once the disk is full or a network
/// share has dropped.
async fn run_log_drain(
    mut log_receiver: mpsc::Receiver<ELog>,
    file_log_cfg: crate::config::FileLogConfig,
    diagnostics: impl DiagnosticWriter,
) {
    let mut out = tokio::io::stdout();
    let mut err = tokio::io::stderr();

    let mut file: Option<tokio::io::BufWriter<tokio::fs::File>> = if file_log_cfg.enabled {
        match tokio::fs::OpenOptions::new()
            .append(true)
            .create(true)
            .open(&file_log_cfg.path)
            .await
        {
            Ok(f) => Some(tokio::io::BufWriter::new(f)),
            Err(e) => {
                diagnostics
                    .emit(format!(
                        "file logger: failed to open {}: {} — continuing in console-only mode",
                        file_log_cfg.path, e
                    ))
                    .await;
                None
            }
        }
    } else {
        None
    };

    while let Some(log_message) = log_receiver.recv().await {
        let now = Local::now().format("%Y-%m-%d %H:%M:%S");
        let line = match &log_message {
            ELog::Log(message) | ELog::Error(message) => {
                format!("{}: {}\n", now, message)
            }
        };

        let write_err = match file.as_mut() {
            Some(f) => write_and_flush_line(f, &line).await.err(),
            None => None,
        };
        if let Some(e) = write_err {
            diagnostics
                .emit(file_write_error_message(&file_log_cfg.path, &e))
                .await;
            file = None;
        }

        if file.is_none() || file_log_cfg.also_console {
            match log_message {
                ELog::Log(_) => {
                    let _ = out.write_all(line.as_bytes()).await;
                }
                ELog::Error(_) => {
                    let _ = err.write_all(line.as_bytes()).await;
                }
            }
        }
    }
}

/// Join the log-drain task at shutdown. Dropping `logger` (the last
/// `Arc<Logger>`) closes the log channel, letting the drain task finish
/// flushing whatever is still queued — including messages logged during
/// `server::run_server`'s own shutdown sequence. Bounded so a channel
/// that somehow never closes can't hang the process; on timeout we
/// complain on stderr because the file logger itself may be what's
/// stuck — via a diagnostic that is itself bounded (see
/// [`emit_bounded_stderr`]), and the runtime teardown that follows
/// is bounded too (`SHUTDOWN_TEARDOWN_TIMEOUT_SEC`), so a wedged sink
/// costs at most its grace periods, never an indefinite hang. Lines
/// still un-flushed when a budget elapses are lost by design.
pub(super) async fn shutdown_log_drain(
    logger: Arc<logger::Logger>,
    drain: tokio::task::JoinHandle<()>,
) {
    shutdown_log_drain_with(logger, drain, &StderrDiagnostics).await;
}

/// [`shutdown_log_drain`] with the diagnostic sink injected (test seam).
async fn shutdown_log_drain_with(
    logger: Arc<logger::Logger>,
    drain: tokio::task::JoinHandle<()>,
    diagnostics: &impl DiagnosticWriter,
) {
    drop(logger);
    match tokio::time::timeout(Duration::from_secs(LOG_DRAIN_TIMEOUT_SEC), drain).await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => {
            diagnostics
                .emit(format!("log drain task failed: {e}\n"))
                .await;
        }
        Err(_) => {
            diagnostics
                .emit(format!(
                    "warning: log drain did not finish within {LOG_DRAIN_TIMEOUT_SEC}s — \
                     recently queued log lines may have been lost\n"
                ))
                .await;
        }
    }
}

/// Bounded stderr diagnostic that cannot itself wedge the exit path.
/// A synchronous `eprintln!` does a blocking `write()` — when the
/// drain already timed out because a sink stopped accepting bytes, the
/// same sink may be stderr, and the warning would hang forever. The
/// write goes through `tokio::io::stderr()` (blocking pool, yields to
/// the runtime) with its own budget; on expiry the message is dropped
/// silently — nothing further can be done, and bounded exit is the
/// point of this code path.
async fn emit_bounded_stderr(message: String) {
    let mut err = tokio::io::stderr();
    let _ = tokio::time::timeout(
        Duration::from_secs(DIAGNOSTIC_TIMEOUT_SEC),
        err.write_all(message.as_bytes()),
    )
    .await;
}

/// One write+flush of a formatted log line. Flushed per line (existing
/// behavior — review R27 re-evaluates that separately); the flush error
/// must surface, not vanish into `let _ =`.
async fn write_and_flush_line(
    f: &mut tokio::io::BufWriter<tokio::fs::File>,
    line: &str,
) -> std::io::Result<()> {
    f.write_all(line.as_bytes()).await?;
    f.flush().await
}

/// Pure diagnostic for a failed file-log write/flush, so it can be
/// unit-tested without capturing process stderr.
pub(super) fn file_write_error_message(path: &str, err: &std::io::Error) -> String {
    format!(
        "file logger: write to {path} failed: {err} — \
         falling back to console-only logging for the rest of this run"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    /// A sink that records being called and never completes: the await
    /// on `emit` parks forever, exactly what a wedged sink looks like.
    struct NeverEmit {
        called: Arc<AtomicU64>,
    }

    impl DiagnosticWriter for NeverEmit {
        fn emit(&self, _message: String) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
            self.called.fetch_add(1, Ordering::Relaxed);
            Box::pin(std::future::pending())
        }
    }

    /// `#[tokio::test]` is a current-thread (single-worker) runtime —
    /// exactly the hazard shape from finding (N): a synchronous
    /// `eprintln!` (or any blocking wait) in the failure path would
    /// starve the only worker and the heartbeat would stop ticking.
    #[tokio::test]
    async fn drain_open_failure_diagnostic_yields_and_reports_through_the_seam() {
        let called = Arc::new(AtomicU64::new(0));
        let (tx, rx) = mpsc::channel::<ELog>(16);
        let cfg = crate::config::FileLogConfig {
            enabled: true,
            also_console: false,
            // Nonexistent directory => open() fails with NotFound.
            path: std::env::temp_dir()
                .join("resocks5_test_no_such_dir_for_file_log")
                .join("nested")
                .join("resocks5.log")
                .display()
                .to_string(),
        };

        tokio::spawn(run_log_drain(
            rx,
            cfg,
            NeverEmit {
                called: called.clone(),
            },
        ));
        tx.send(ELog::Log("first line".to_string())).await.unwrap();

        // Wait for the open-failure diagnostic through the seam.
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while called.load(Ordering::Relaxed) < 1 {
            assert!(
                std::time::Instant::now() < deadline,
                "drain never reached the open-failure diagnostic through the seam"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        // One queued message, one diagnostic; after the open failure
        // `file` is `None`, so the write-failure branch cannot fire.
        assert_eq!(called.load(Ordering::Relaxed), 1);

        // Heartbeat on the SAME runtime proves the drain task yields
        // instead of blocking the only worker thread.
        let ticks = Arc::new(AtomicU64::new(0));
        let heartbeat = {
            let ticks = ticks.clone();
            tokio::spawn(async move {
                loop {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    ticks.fetch_add(1, Ordering::Relaxed);
                }
            })
        };
        tokio::time::sleep(Duration::from_millis(150)).await;
        let t0 = ticks.load(Ordering::Relaxed);
        tokio::time::sleep(Duration::from_millis(500)).await;
        let t1 = ticks.load(Ordering::Relaxed);
        heartbeat.abort();
        assert!(
            t1 - t0 >= 3,
            "heartbeat starved while the drain awaited its diagnostic: t0={t0} t1={t1}"
        );
    }

    /// Records the paused-clock instant of the first diagnostic.
    struct StampEmit {
        at: Arc<std::sync::Mutex<Option<tokio::time::Instant>>>,
    }

    impl DiagnosticWriter for StampEmit {
        fn emit(&self, _message: String) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
            *self.at.lock().unwrap() = Some(tokio::time::Instant::now());
            Box::pin(std::future::ready(()))
        }
    }

    /// A drain that never completes is given up on at exactly the 5 s
    /// budget, measured on the virtual clock: the diagnostic (and so the
    /// return) happens at 5 s, neither before nor after. Real stderr is out
    /// of the loop (injected sink), so only the paused clock decides the
    /// timing. Mutation: `LOG_DRAIN_TIMEOUT_SEC` 5 -> 4 or 5 -> 6 fails the
    /// exact-offset assertion; removing the give-up never emits.
    #[tokio::test(start_paused = true)]
    async fn shutdown_drain_gives_up_exactly_at_the_budget() {
        let (tx, _rx) = mpsc::channel::<ELog>(4);
        let logger = Arc::new(crate::logger::Logger::new(
            tx,
            crate::logger::LogConfig::default(),
        ));
        let drain = tokio::spawn(std::future::pending::<()>());
        let at = Arc::new(std::sync::Mutex::new(None));
        let start = tokio::time::Instant::now();
        shutdown_log_drain_with(logger, drain, &StampEmit { at: at.clone() }).await;
        let stamped = at
            .lock()
            .unwrap()
            .expect("the give-up diagnostic must be emitted");
        // The timer wheel rounds a deadline up to the next millisecond.
        let offset = stamped - start;
        assert!(
            offset >= Duration::from_secs(5) && offset < Duration::from_millis(5100),
            "give-up must fire at the 5 s budget on the virtual clock: {offset:?}"
        );
    }
}
