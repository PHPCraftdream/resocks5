use std::future::Future;
use std::time::Duration;

use anyhow::Result;

use super::startup::run_server_inner;

/// Ceiling on runtime teardown after the async body returns.
///
/// The `#[tokio::main]` this replaces dropped the `Runtime` implicitly
/// at the end of `main`, and `Runtime::drop` waits WITHOUT any timeout
/// for every outstanding blocking-pool operation (tokio 1.43.1
/// `BlockingPool::drop` → `shutdown(None)`). The log-drain task's
/// `tokio::io::stdout/stderr/fs` writes dispatch to that pool
/// (`io/blocking.rs::poll_write`), so a sink that stopped accepting
/// bytes — a stalled pipe reader, a hung filesystem write — would hang
/// process exit forever (review R5-06). `shutdown_timeout` waits at
/// most this long for blocking work, then abandons it.
///
/// Loss policy: log lines still parked in a wedged write when this
/// budget elapses are LOST, by design — a deliberate, bounded exit
/// beats an indefinite hang. Five seconds mirrors the drain budget's
/// intent (short grace, ample for a full backlog flush); drain join +
/// diagnostic + teardown together stay far below the 30 s tunnel drain
/// (`SHUTDOWN_DRAIN_SEC`).
pub(super) const SHUTDOWN_TEARDOWN_TIMEOUT_SEC: u64 = 5;

/// Sync entry point: the async work lives in [`run_server_inner`];
/// [`run_with_bounded_teardown`] owns the runtime so its teardown is
/// bounded even if the body panics. The `?` peels only the
/// runtime-build-failure layer — the inner `Result` is this function's
/// result.
pub(crate) fn run_server() -> Result<()> {
    run_with_bounded_teardown(run_server_inner())?
}

/// Run `future` on an explicitly owned multi-thread runtime whose
/// teardown is bounded: the `Runtime` is an explicit local that ends in
/// `shutdown_timeout` (budget: [`SHUTDOWN_TEARDOWN_TIMEOUT_SEC`])
/// instead of an unbounded implicit `Drop` — see that const's
/// documentation for why an implicit drop must never own the runtime
/// (`Runtime::drop` waits without any timeout for every outstanding
/// blocking-pool operation, review R5-06).
///
/// `catch_unwind` keeps a panicking body from unwinding past the
/// bounded teardown (unwinding would drop the `Runtime` and block
/// without limit on stuck blocking-pool I/O); the panic hook has
/// already printed the message, and `resume_unwind` preserves the
/// original unwind. The returned `Result` reflects only runtime-build
/// failure — the future's own output is handed back unchanged.
pub(super) fn run_with_bounded_teardown<F: Future>(future: F) -> Result<F::Output> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    let result =
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| runtime.block_on(future)));
    runtime.shutdown_timeout(Duration::from_secs(SHUTDOWN_TEARDOWN_TIMEOUT_SEC));
    match result {
        Ok(result) => Ok(result),
        Err(panic) => std::panic::resume_unwind(panic),
    }
}
