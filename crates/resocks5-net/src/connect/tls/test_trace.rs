//! Failure-only diagnostics for the timing-sensitive TLS drip tests.
//!
//! Everything is recorded cheaply while a test runs and printed to stderr
//! only when the test thread is panicking (the harness shows a failing
//! test's captured output), or always when `RESOCKS5_TRACE` is set.
//!
//! What a report answers: how fast the drip server really ran (read sizes,
//! requested vs actual sleeps), whether the runtime or the OS timer stalled
//! (heartbeat lateness, `std::thread::sleep` resolution), and when bytes
//! reached the server (a 500 ms throughput timeline).

use std::fmt::Write as _;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

const MAX_EVENTS: usize = 300;
const HEARTBEAT: Duration = Duration::from_millis(10);
const SAMPLE_EVERY: Duration = Duration::from_millis(500);

/// A bounded, timestamped event log.
pub(super) struct Trace {
    started: Instant,
    events: Mutex<(Vec<(Duration, String)>, usize)>,
}

impl Trace {
    fn new() -> Self {
        Self {
            started: Instant::now(),
            events: Mutex::new((Vec::new(), 0)),
        }
    }

    /// Record one event; past the cap only a drop counter grows.
    pub(super) fn note(&self, message: impl Into<String>) {
        let at = self.started.elapsed();
        let mut guard = self.events.lock().unwrap_or_else(PoisonError::into_inner);
        if guard.0.len() < MAX_EVENTS {
            guard.0.push((at, message.into()));
        } else {
            guard.1 += 1;
        }
    }

    fn render(&self) -> String {
        let guard = self.events.lock().unwrap_or_else(PoisonError::into_inner);
        let mut out = String::new();
        for (at, message) in &guard.0 {
            let _ = writeln!(out, "  [{:>9.3?}] {message}", at);
        }
        if guard.1 > 0 {
            let _ = writeln!(out, "  ... {} more events dropped", guard.1);
        }
        out
    }
}

/// Counters for the dripping server loop.
pub(super) struct DripStats {
    reads: AtomicUsize,
    bytes: AtomicUsize,
    min_read: AtomicUsize,
    max_read: AtomicUsize,
    small_reads: AtomicUsize,
    short_sleeps: AtomicUsize,
    requested_sleep_us: AtomicU64,
    actual_sleep_us: AtomicU64,
    max_overshoot_us: AtomicU64,
    max_read_gap_us: AtomicU64,
}

impl DripStats {
    fn new() -> Self {
        Self {
            reads: AtomicUsize::new(0),
            bytes: AtomicUsize::new(0),
            min_read: AtomicUsize::new(usize::MAX),
            max_read: AtomicUsize::new(0),
            small_reads: AtomicUsize::new(0),
            short_sleeps: AtomicUsize::new(0),
            requested_sleep_us: AtomicU64::new(0),
            actual_sleep_us: AtomicU64::new(0),
            max_overshoot_us: AtomicU64::new(0),
            max_read_gap_us: AtomicU64::new(0),
        }
    }

    /// One `read()` returned `n` bytes, `gap` after the previous sleep ended.
    pub(super) fn record_read(&self, n: usize, gap: Duration) {
        if n > 0 {
            self.reads.fetch_add(1, Ordering::Relaxed);
            self.bytes.fetch_add(n, Ordering::Relaxed);
            self.min_read.fetch_min(n, Ordering::Relaxed);
            self.max_read.fetch_max(n, Ordering::Relaxed);
            if n < 1024 {
                self.small_reads.fetch_add(1, Ordering::Relaxed);
            }
        }
        self.max_read_gap_us
            .fetch_max(micros(gap), Ordering::Relaxed);
    }

    /// One drip sleep: what was asked and how long it really took.
    pub(super) fn record_sleep(&self, requested: Duration, actual: Duration) {
        // Sleeps below one timer tick are rounded up to a whole tick by the
        // OS timer, the way tiny reads can make a drip run far below its rate.
        if requested < Duration::from_millis(2) {
            self.short_sleeps.fetch_add(1, Ordering::Relaxed);
        }
        self.requested_sleep_us
            .fetch_add(micros(requested), Ordering::Relaxed);
        self.actual_sleep_us
            .fetch_add(micros(actual), Ordering::Relaxed);
        self.max_overshoot_us
            .fetch_max(micros(actual.saturating_sub(requested)), Ordering::Relaxed);
    }

    pub(super) fn reads(&self) -> usize {
        self.reads.load(Ordering::Relaxed)
    }

    pub(super) fn bytes(&self) -> usize {
        self.bytes.load(Ordering::Relaxed)
    }

    /// One-line summary, also used inside the server's own timeout error.
    pub(super) fn render(&self) -> String {
        let reads = self.reads();
        let bytes = self.bytes();
        let requested = self.requested_sleep_us.load(Ordering::Relaxed);
        let actual = self.actual_sleep_us.load(Ordering::Relaxed);
        let min_read = self.min_read.load(Ordering::Relaxed);
        format!(
            "drip: {reads} reads, {bytes} B, read size min {} / mean {} / max {} B \
             ({} reads under 1 KiB, {} sleeps under 2 ms asked); \
             sleeps asked {:?} took {:?} (x{:.2}), worst overshoot {:?}; \
             longest wait for data {:?}",
            if min_read == usize::MAX { 0 } else { min_read },
            bytes.checked_div(reads).unwrap_or(0),
            self.max_read.load(Ordering::Relaxed),
            self.small_reads.load(Ordering::Relaxed),
            self.short_sleeps.load(Ordering::Relaxed),
            Duration::from_micros(requested),
            Duration::from_micros(actual),
            if requested == 0 {
                0.0
            } else {
                actual as f64 / requested as f64
            },
            Duration::from_micros(self.max_overshoot_us.load(Ordering::Relaxed)),
            Duration::from_micros(self.max_read_gap_us.load(Ordering::Relaxed)),
        )
    }
}

/// Lateness of the runtime heartbeat (a 10 ms `tokio::time::sleep` loop).
struct Jitter {
    ticks: AtomicU64,
    late_sum_us: AtomicU64,
    late_max_us: AtomicU64,
    over_50ms: AtomicU64,
    over_250ms: AtomicU64,
}

impl Jitter {
    fn new() -> Self {
        Self {
            ticks: AtomicU64::new(0),
            late_sum_us: AtomicU64::new(0),
            late_max_us: AtomicU64::new(0),
            over_50ms: AtomicU64::new(0),
            over_250ms: AtomicU64::new(0),
        }
    }

    fn record(&self, late: Duration) {
        self.ticks.fetch_add(1, Ordering::Relaxed);
        self.late_sum_us.fetch_add(micros(late), Ordering::Relaxed);
        self.late_max_us.fetch_max(micros(late), Ordering::Relaxed);
        if late > Duration::from_millis(50) {
            self.over_50ms.fetch_add(1, Ordering::Relaxed);
        }
        if late > Duration::from_millis(250) {
            self.over_250ms.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn render(&self) -> String {
        let ticks = self.ticks.load(Ordering::Relaxed);
        let mean = self
            .late_sum_us
            .load(Ordering::Relaxed)
            .checked_div(ticks)
            .unwrap_or(0);
        format!(
            "heartbeat ({HEARTBEAT:?} period): {ticks} ticks, mean lateness {:?}, max {:?}, \
             >50ms: {}, >250ms: {}",
            Duration::from_micros(mean),
            Duration::from_micros(self.late_max_us.load(Ordering::Relaxed)),
            self.over_50ms.load(Ordering::Relaxed),
            self.over_250ms.load(Ordering::Relaxed),
        )
    }
}

fn micros(duration: Duration) -> u64 {
    u64::try_from(duration.as_micros()).unwrap_or(u64::MAX)
}

/// Measure the OS sleep resolution: on Windows `thread::sleep(1ms)` takes
/// ~15.6 ms unless some process raised the system timer resolution, and
/// every short `tokio::time::sleep` inherits that rounding.
fn timer_probe() -> String {
    let mut out = String::new();
    for (label, ask) in [
        ("1ms", Duration::from_millis(1)),
        ("10ms", Duration::from_millis(10)),
    ] {
        let rounds = 8u32;
        let mut total = Duration::ZERO;
        let mut worst = Duration::ZERO;
        for _ in 0..rounds {
            let t = Instant::now();
            std::thread::sleep(ask);
            let took = t.elapsed();
            total += took;
            worst = worst.max(took);
        }
        let _ = writeln!(
            out,
            "std::thread::sleep({label}) at test start: mean {:?}, worst {worst:?} over {rounds}",
            total / rounds
        );
    }
    out
}

/// Per-test diagnostics. Create it first thing in the test; it prints the
/// report when dropped during a panic, and aborts its heartbeat task.
pub(super) struct Diag {
    pub(super) trace: Arc<Trace>,
    pub(super) drip: Arc<DripStats>,
    jitter: Arc<Jitter>,
    timer_probe: String,
    test: &'static str,
    started: Instant,
    heartbeat: tokio::task::JoinHandle<()>,
}

impl Diag {
    /// Must be called inside a Tokio runtime (it spawns the heartbeat).
    pub(super) fn new(test: &'static str) -> Self {
        let timer_probe = timer_probe();
        let trace = Arc::new(Trace::new());
        let drip = Arc::new(DripStats::new());
        let jitter = Arc::new(Jitter::new());
        let heartbeat = tokio::spawn({
            let (trace, drip, jitter) = (trace.clone(), drip.clone(), jitter.clone());
            async move {
                let mut sampled_at = Instant::now();
                let mut sampled_bytes = 0usize;
                loop {
                    let before = Instant::now();
                    tokio::time::sleep(HEARTBEAT).await;
                    let late = before.elapsed().saturating_sub(HEARTBEAT);
                    jitter.record(late);
                    if late > Duration::from_millis(250) {
                        trace.note(format!(
                            "heartbeat was {late:?} late (runtime or timer stall)"
                        ));
                    }
                    if sampled_at.elapsed() >= SAMPLE_EVERY {
                        let bytes = drip.bytes();
                        trace.note(format!(
                            "server has received {bytes} B (+{} B in {:?})",
                            bytes - sampled_bytes,
                            sampled_at.elapsed()
                        ));
                        sampled_at = Instant::now();
                        sampled_bytes = bytes;
                    }
                }
            }
        });
        Self {
            trace,
            drip,
            jitter,
            timer_probe,
            test,
            started: Instant::now(),
            heartbeat,
        }
    }

    fn report(&self) -> String {
        let mut out = String::new();
        let _ = writeln!(
            out,
            "==== diagnostics for {} (ran {:?}) ====",
            self.test,
            self.started.elapsed()
        );
        let _ = writeln!(
            out,
            "os {} / {}, available_parallelism {:?}, thread {:?}",
            std::env::consts::OS,
            std::env::consts::ARCH,
            std::thread::available_parallelism().map(|n| n.get()),
            std::thread::current().name()
        );
        out.push_str(&self.timer_probe);
        let _ = writeln!(out, "{}", self.jitter.render());
        let _ = writeln!(out, "{}", self.drip.render());
        let _ = writeln!(out, "events:");
        out.push_str(&self.trace.render());
        out.push_str("==== end of diagnostics ====");
        out
    }
}

impl Drop for Diag {
    fn drop(&mut self) {
        self.heartbeat.abort();
        if std::thread::panicking() || std::env::var_os("RESOCKS5_TRACE").is_some() {
            eprintln!("{}", self.report());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trace_is_bounded_and_counts_dropped_events() {
        let trace = Trace::new();
        for i in 0..(MAX_EVENTS + 7) {
            trace.note(format!("event {i}"));
        }
        let text = trace.render();
        assert!(text.contains("event 0"));
        assert!(text.contains(&format!("event {}", MAX_EVENTS - 1)));
        assert!(!text.contains(&format!("event {MAX_EVENTS} ")));
        assert!(text.contains("7 more events dropped"), "{text}");
    }

    #[test]
    fn drip_stats_report_sizes_ratio_and_small_counts() {
        let stats = DripStats::new();
        stats.record_read(100, Duration::from_millis(5));
        stats.record_sleep(Duration::from_millis(1), Duration::from_millis(16));
        stats.record_read(8192, Duration::from_millis(30));
        stats.record_sleep(Duration::from_millis(40), Duration::from_millis(46));
        // The EOF read counts neither as a read nor as bytes.
        stats.record_read(0, Duration::from_millis(2));
        assert_eq!(stats.reads(), 2);
        assert_eq!(stats.bytes(), 8292);
        let text = stats.render();
        assert!(text.contains("2 reads, 8292 B"), "{text}");
        assert!(text.contains("min 100 / mean 4146 / max 8192 B"), "{text}");
        assert!(
            text.contains("1 reads under 1 KiB, 1 sleeps under 2 ms asked"),
            "{text}"
        );
        // 41 ms asked, 62 ms taken.
        assert!(text.contains("(x1.51)"), "{text}");
        assert!(text.contains("worst overshoot 15ms"), "{text}");
        assert!(text.contains("longest wait for data 30ms"), "{text}");
    }

    #[test]
    fn drip_stats_without_reads_do_not_divide_by_zero() {
        let text = DripStats::new().render();
        assert!(
            text.contains("0 reads, 0 B, read size min 0 / mean 0 / max 0 B"),
            "{text}"
        );
        assert!(text.contains("(x0.00)"), "{text}");
    }

    #[test]
    fn jitter_counts_the_thresholds() {
        let jitter = Jitter::new();
        jitter.record(Duration::from_millis(5));
        jitter.record(Duration::from_millis(60));
        jitter.record(Duration::from_millis(300));
        let text = jitter.render();
        assert!(text.contains("3 ticks"), "{text}");
        assert!(text.contains("max 300ms"), "{text}");
        assert!(text.contains(">50ms: 2, >250ms: 1"), "{text}");
    }

    #[tokio::test]
    async fn diag_report_contains_every_section() {
        let diag = Diag::new("report_test");
        diag.trace.note("marker-event");
        diag.drip.record_read(10, Duration::ZERO);
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(
            diag.jitter.ticks.load(Ordering::Relaxed) > 0,
            "the heartbeat task must be ticking"
        );
        let report = diag.report();
        for needle in [
            "diagnostics for report_test",
            "available_parallelism",
            "std::thread::sleep(1ms)",
            "std::thread::sleep(10ms)",
            "heartbeat (10ms period)",
            "drip: 1 reads, 10 B",
            "events:",
            "marker-event",
            "end of diagnostics",
        ] {
            assert!(report.contains(needle), "missing {needle:?} in\n{report}");
        }
    }
}
