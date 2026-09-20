use std::sync::Arc;
use std::time::Duration;

use chrono::Local;
use tokio::io::AsyncWriteExt;
use tokio::spawn;
use tokio::sync::mpsc;

use crate::logger::{self, ELog};

/// Ceiling on one shutdown-time stderr diagnostic (see
/// [`emit_shutdown_diagnostic`]). One line should never need more.
const SHUTDOWN_DIAGNOSTIC_TIMEOUT_SEC: u64 = 1;

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

/// Body of the async log-drain task, spawned by `run_server_inner`.
/// Returns the `JoinHandle` so shutdown can wait for the queue to flush
/// instead of letting runtime teardown silently cancel the task
/// mid-`recv()` (a timeout instead detaches it; the bounded teardown
/// then abandons any wedged write — see
/// [`SHUTDOWN_TEARDOWN_TIMEOUT_SEC`]).
///
/// A file write/flush failure is NOT swallowed: the first failure is
/// reported on stderr and the task falls back to console-only for the
/// rest of the run — mirroring the open-failure path above and avoiding
/// one stderr line per queued message once the disk is full or a
/// network share has dropped.
pub(super) fn spawn_log_drain(
    mut log_receiver: mpsc::Receiver<ELog>,
    file_log_cfg: crate::config::FileLogConfig,
) -> tokio::task::JoinHandle<()> {
    spawn(async move {
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
                    eprintln!(
                        "file logger: failed to open {}: {} — continuing in console-only mode",
                        file_log_cfg.path, e
                    );
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
                eprintln!("{}", file_write_error_message(&file_log_cfg.path, &e));
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
    })
}

/// Join the log-drain task at shutdown. Dropping `logger` (the last
/// `Arc<Logger>`) closes the log channel, letting the drain task finish
/// flushing whatever is still queued — including messages logged during
/// `server::run_server`'s own shutdown sequence. Bounded so a channel
/// that somehow never closes can't hang the process; on timeout we
/// complain on stderr because the file logger itself may be what's
/// stuck — via a diagnostic that is itself bounded (see
/// [`emit_shutdown_diagnostic`]), and the runtime teardown that follows
/// is bounded too (`SHUTDOWN_TEARDOWN_TIMEOUT_SEC`), so a wedged sink
/// costs at most its grace periods, never an indefinite hang. Lines
/// still un-flushed when a budget elapses are lost by design.
pub(super) async fn shutdown_log_drain(
    logger: Arc<logger::Logger>,
    drain: tokio::task::JoinHandle<()>,
) {
    drop(logger);
    match tokio::time::timeout(Duration::from_secs(LOG_DRAIN_TIMEOUT_SEC), drain).await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => {
            emit_shutdown_diagnostic(format!("log drain task failed: {e}\n")).await;
        }
        Err(_) => {
            emit_shutdown_diagnostic(format!(
                "warning: log drain did not finish within {LOG_DRAIN_TIMEOUT_SEC}s — \
                 recently queued log lines may have been lost\n"
            ))
            .await;
        }
    }
}

/// Shutdown-time stderr diagnostic that cannot itself wedge the exit
/// path. A synchronous `eprintln!` does a blocking `write()` — when the
/// drain already timed out because a sink stopped accepting bytes, the
/// same sink may be stderr, and the warning would hang forever. The
/// write goes through `tokio::io::stderr()` (blocking pool, yields to
/// the runtime) with its own budget; on expiry the message is dropped
/// silently — nothing further can be done, and bounded exit is the
/// point of this code path.
async fn emit_shutdown_diagnostic(message: String) {
    let mut err = tokio::io::stderr();
    let _ = tokio::time::timeout(
        Duration::from_secs(SHUTDOWN_DIAGNOSTIC_TIMEOUT_SEC),
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
