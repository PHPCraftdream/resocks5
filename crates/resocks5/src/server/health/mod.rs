//! Upstream health that survives a restart.
//!
//! The quarantine picture (which upstreams are dead, for how long, how many
//! times they tripped) is saved to `resocks5.health.ktav` and put back at
//! start-up, so a fresh process does not spend client requests rediscovering
//! dead upstreams: they come back quarantined or on probation and the
//! background probes decide.
//!
//! Records are keyed by routing group (`v6`, `v4`, `gate<rank>`), so one endpoint in two groups keeps two health cells.
//!
//! Passwords are never written.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::config::users_file::{sibling_path, write_atomic, UsersFileLock};
use crate::logger::Logger;
use resocks5_net::pool::ProxyPool;
use resocks5_net::rating::{Health, UpstreamState};
use resocks5_net::rotator::{ProxyRotator, UpstreamHealth};
use resocks5_net::types::ProxyConfig;

#[cfg(test)]
mod tests;
#[cfg(test)]
mod writer_tests;

pub(crate) const STATE_ALIVE: &str = "alive";
pub(crate) const STATE_QUARANTINED: &str = "quarantined";
pub(crate) const STATE_PROBATION: &str = "probation";

/// One upstream's saved record.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub(crate) struct HealthEntry {
    /// `protocol://[user@]host:port` (no password).
    pub(crate) upstream: String,
    /// Gate level (number of leading `*`), `0` for an ordinary upstream.
    #[serde(default)]
    pub(crate) gate: u8,
    /// Routing group the rotator belongs to (`v6`, `v4`, `gate<rank>`).
    /// Empty in records saved before the field existed: those apply to every
    /// group holding the same (upstream, gate) pair.
    #[serde(default)]
    pub(crate) group: String,
    /// `alive`, `quarantined` or `probation`.
    pub(crate) state: String,
    /// Quarantine seconds left at `saved_at`.
    #[serde(default)]
    pub(crate) remaining_sec: u64,
    /// How many times the upstream was quarantined.
    #[serde(default)]
    pub(crate) trips: u32,
    /// Consecutive hard failures.
    #[serde(default)]
    pub(crate) failures: u32,
}

/// One routing group's rotator plus the stable name its saved records are
/// keyed under: the same endpoint in two groups keeps two health cells.
#[derive(Clone)]
pub(crate) struct HealthGroup {
    pub(crate) name: String,
    pub(crate) rotator: Arc<ProxyRotator>,
}

/// The whole `resocks5.health.ktav`.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub(crate) struct HealthFile {
    /// Unix seconds when the snapshot was taken.
    #[serde(default)]
    pub(crate) saved_at: u64,
    #[serde(default)]
    pub(crate) upstreams: Vec<HealthEntry>,
}

/// What [`restore`] put back.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Restored {
    pub(crate) quarantined: usize,
    pub(crate) probation: usize,
}

impl Restored {
    pub(crate) fn total(self) -> usize {
        self.quarantined + self.probation
    }
}

pub(crate) fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

fn upstream_label(proxy: &ProxyConfig) -> String {
    let protocol = format!("{:?}", proxy.protocol).to_lowercase();
    match &proxy.user {
        Some(user) => format!("{protocol}://{user}@{}:{}", proxy.host, proxy.port),
        None => format!("{protocol}://{}:{}", proxy.host, proxy.port),
    }
}

fn state_name(state: UpstreamState) -> &'static str {
    match state {
        UpstreamState::Quarantined => STATE_QUARANTINED,
        UpstreamState::Probation => STATE_PROBATION,
        _ => STATE_ALIVE,
    }
}

/// Snapshot of every upstream of every group.
pub(crate) fn snapshot(groups: &[HealthGroup], now: u64) -> HealthFile {
    let mut upstreams = Vec::new();
    for group in groups {
        for entry in group.rotator.health() {
            upstreams.push(HealthEntry {
                upstream: upstream_label(&entry.proxy),
                gate: entry.proxy.gate_level,
                group: group.name.clone(),
                state: state_name(entry.health.state).to_owned(),
                remaining_sec: entry.health.remaining.as_secs(),
                trips: entry.health.trips,
                failures: entry.health.consecutive,
            });
        }
    }
    HealthFile {
        saved_at: now,
        upstreams,
    }
}

/// What changes the saved picture: everything but the countdown and the
/// timestamp.
fn signature(file: &HealthFile) -> Vec<(&str, &str, u8, &str, u32, u32)> {
    file.upstreams
        .iter()
        .map(|e| {
            (
                e.upstream.as_str(),
                e.group.as_str(),
                e.gate,
                e.state.as_str(),
                e.trips,
                e.failures,
            )
        })
        .collect()
}

/// Put saved quarantines back. A quarantine that ran out while the process
/// was down becomes probation; unknown upstreams and unreadable states are
/// skipped (the proxy list may have changed).
///
/// Records match under `(upstream, gate, group)`. A record with an empty
/// group comes from a build without the field and is applied to EVERY group
/// holding the (upstream, gate) pair — the old last-record-wins behaviour.
pub(crate) fn restore(groups: &[HealthGroup], file: &HealthFile, now: u64) -> Restored {
    let idle = Duration::from_secs(now.saturating_sub(file.saved_at));
    let saved: HashMap<(String, u8, String), &HealthEntry> = file
        .upstreams
        .iter()
        .map(|e| ((e.upstream.clone(), e.gate, e.group.clone()), e))
        .collect();
    let mut restored = Restored::default();
    for group in groups {
        let entries: Vec<UpstreamHealth> = group
            .rotator
            .all_proxies()
            .iter()
            .filter_map(|proxy| {
                let label = upstream_label(proxy);
                // New key first; an empty group is the pre-group fallback.
                let entry = saved
                    .get(&(label.clone(), proxy.gate_level, group.name.clone()))
                    .or_else(|| saved.get(&(label, proxy.gate_level, String::new())))?;
                let left = Duration::from_secs(entry.remaining_sec).saturating_sub(idle);
                let (state, left) = match entry.state.as_str() {
                    STATE_QUARANTINED if !left.is_zero() => (UpstreamState::Quarantined, left),
                    STATE_QUARANTINED | STATE_PROBATION => {
                        (UpstreamState::Probation, Duration::ZERO)
                    }
                    _ => return None,
                };
                Some(UpstreamHealth::new(
                    proxy.clone(),
                    Health::new(state, left, entry.trips, entry.failures),
                ))
            })
            .collect();
        group.rotator.restore_health(&entries);
        for entry in &entries {
            if group.rotator.is_quarantined(&entry.proxy) {
                match entry.health.state {
                    UpstreamState::Quarantined => restored.quarantined += 1,
                    _ => restored.probation += 1,
                }
            }
        }
    }
    restored
}

/// Read the saved picture. `Ok(None)` when there is no file yet.
pub(crate) fn load(path: &Path) -> Result<Option<HealthFile>> {
    if !path.exists() {
        return Ok(None);
    }
    ktav::from_file(path)
        .map(Some)
        .with_context(|| format!("read {}", path.display()))
}

/// Outcome of [`resume`].
#[derive(Debug, Default)]
pub(crate) struct Resumed {
    /// The file as read, `None` when absent or unreadable.
    pub(crate) saved: Option<HealthFile>,
    /// What was put back into the rotators.
    pub(crate) restored: Restored,
    /// Why the file was ignored, when it was unreadable.
    pub(crate) warning: Option<String>,
}

/// Read the file at `path` and put its quarantines back. A missing file is
/// a normal first start; an unreadable one is reported and ignored.
pub(crate) fn resume(groups: &[HealthGroup], path: &Path, now: u64) -> Resumed {
    match load(path) {
        Ok(Some(file)) => Resumed {
            restored: restore(groups, &file, now),
            saved: Some(file),
            warning: None,
        },
        Ok(None) => Resumed::default(),
        Err(error) => Resumed {
            warning: Some(format!("ignoring {}: {error:#}", path.display())),
            ..Resumed::default()
        },
    }
}

/// Handle to the running saver. The module holds the health file's
/// cross-process lock for the whole run and is its only writer;
/// [`HealthSaver::finish`] is the only supported shutdown: it stops the
/// loop and writes the last snapshot itself, so two writers never race
/// over the same temp file, and the lock is released only after that
/// final write. `task` is `None` when persistence was disabled at
/// start-up; `finish` then does nothing.
pub(crate) struct HealthSaver {
    stop: Arc<tokio::sync::Notify>,
    task: Option<tokio::task::JoinHandle<()>>,
    /// Held for the saver's lifetime: no other process may clean up or
    /// write the health file (or its temp) in the meantime.
    lock: Option<UsersFileLock>,
    /// Best-effort shutdown reports go through the logger's non-blocking
    /// channel: a full stderr pipe must not stall the exit.
    logger: Arc<Logger>,
}

/// Budget for each shutdown step (stop hand-off, final write). A blocking
/// write already in flight cannot be cancelled, so past the budget the
/// snapshot is lost on purpose instead of racing a second writer.
const FINISH_BUDGET: Duration = Duration::from_secs(3);

/// Budget for acquiring the health file's cross-process lock at start-up.
/// A live holder keeps it for the whole server run: losing the race means
/// another instance owns the file and this process runs read-only.
const LOCK_BUDGET: Duration = Duration::from_millis(200);

impl HealthSaver {
    /// Stop protocol: signal stop, wait for the loop to end (bounded), then
    /// write one final snapshot through the same offloaded path. Waiting for
    /// the loop first is what keeps the final write the only writer; the
    /// cross-process lock is released only after it. When persistence was
    /// disabled at start-up this is a no-op. Writer failures are reported
    /// through the logger's non-blocking channel, never through stderr.
    pub(crate) async fn finish(self, groups: &[HealthGroup], path: &Path) {
        let Self {
            stop,
            task,
            lock,
            logger,
        } = self;
        // Nothing was ever written: shutdown stays a no-op.
        let Some(mut task) = task else {
            return;
        };
        stop.notify_one();
        match tokio::time::timeout(FINISH_BUDGET, &mut task).await {
            Ok(Ok(())) => {}
            // The writer task itself died (panic): like a save error.
            Ok(Err(error)) => {
                logger.proxy_failure(|| format!("health writer task failed: {error:#}"))
            }
            Err(_) => {
                task.abort();
                logger.proxy_failure(|| {
                    format!(
                        "the health writer did not stop in {FINISH_BUDGET:?}; continuing without a final snapshot"
                    )
                });
                return;
            }
        }
        save_final(groups, path, &logger).await;
        drop(lock);
    }
}

/// Start-up: put the saved quarantines back, hand the due ones to the
/// background probes, then keep the file current. The health file's
/// cross-process lock is taken first: a second instance in the same
/// directory loses the race and runs with persistence disabled — its
/// saver does nothing and [`HealthSaver::finish`] is a no-op (the
/// restore read still happened). Returns the saver handle — call
/// [`HealthSaver::finish`] at shutdown — and whether a saved picture
/// was found: then the start-up reachability check is redundant.
///
/// `groups` covers every rotator (snapshot/restore/save), but only `direct` —
/// the rotators the dial path reaches on its own, outermost gate and exits —
/// gets the post-restore probes: an inner gate is only reachable through its
/// prefix, and a direct TCP probe would falsely re-quarantine a healthy one
/// while stealing its probation slot from the chain probe.
pub(crate) fn start(
    groups: Vec<HealthGroup>,
    direct: Vec<Arc<ProxyRotator>>,
    pool: Arc<ProxyPool>,
    path: PathBuf,
    every: Duration,
    probe_timeout: Duration,
    logger: Arc<Logger>,
) -> (HealthSaver, bool) {
    let resumed = resume(&groups, &path, unix_now());
    let found = resumed.saved.is_some();
    if let Some(warning) = &resumed.warning {
        println!("warning: {warning}");
    }
    // Before any cleanup or write: without it a second instance would
    // delete the running writer's temp mid-write (flock/LockFileEx via
    // the shared users-file sentinel; released by the OS on death).
    let lock = match UsersFileLock::acquire_with_timeout(&path, LOCK_BUDGET) {
        Ok(lock) => Some(lock),
        Err(error) => {
            logger.proxy_failure(|| {
                format!(
                    "health file {} is locked by another process; persistence is disabled: {error:#}",
                    path.display()
                )
            });
            None
        }
    };
    // The baseline is the state as it is on disk right after the restore,
    // taken BEFORE any probe below can change a health cell: otherwise an
    // early probe result would be its own baseline and the first round
    // would see "no change" while the file still holds the old picture.
    let initial = found.then(|| snapshot(&groups, unix_now()));
    if found {
        let restored = resumed.restored;
        logger.lifecycle(|| {
            format!(
                "health: restored {} dead upstream(s) from {} ({} quarantined, {} on probation)",
                restored.total(),
                path.display(),
                restored.quarantined,
                restored.probation
            )
        });
        // Post-restore probes for the directly dialed rotators only
        // (the dispatch rework hooks in here).
        for rotator in &direct {
            crate::server::connect::establish_connection::spawn_due_probes(
                rotator,
                &pool,
                &logger,
                probe_timeout,
            );
        }
    }
    // Single-owner window: under the lock a temp left by a crashed
    // previous run can be reclaimed. `write_atomic` creates its temp
    // with `create_new` and every later save would fail on it otherwise.
    if lock.is_some() {
        remove_stale_temp(&path, &logger);
    }
    let stop = Arc::new(tokio::sync::Notify::new());
    let task = lock.is_some().then(|| {
        tokio::spawn(run_saver(
            groups,
            path,
            every,
            initial,
            Arc::clone(&logger),
            Arc::clone(&stop),
        ))
    });
    (
        HealthSaver {
            stop,
            task,
            lock,
            logger,
        },
        found,
    )
}

/// Remove the health's own leftover `<path>.tmp` (`Ok(false)` when there
/// was none). Callers hold the health file's cross-process lock, so no
/// other writer can own this temp. The users file's temp is a deliberate
/// crash-recovery copy with its own semantics and is never touched here.
fn reclaim_own_temp(path: &Path) -> Result<bool> {
    let temp = sibling_path(path, ".tmp");
    match std::fs::remove_file(&temp) {
        Ok(()) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(anyhow::Error::new(error).context(format!("remove {}", temp.display()))),
    }
}

/// Start-up cleanup, only after the lock is held: a temp left by a
/// crashed previous run (or kept by a failed Windows commit) would fail
/// every save at the `create_new`.
fn remove_stale_temp(path: &Path, logger: &Logger) {
    let temp = sibling_path(path, ".tmp");
    match reclaim_own_temp(path) {
        Ok(true) => logger.lifecycle(|| format!("health: removed stale temp {}", temp.display())),
        Ok(false) => {}
        Err(error) => {
            logger.proxy_failure(|| format!("could not remove {}: {error:#}", temp.display()))
        }
    }
}

/// Replace the file atomically.
pub(crate) fn save(path: &Path, file: &HealthFile) -> Result<()> {
    write_atomic(path, file)
}

/// One health-file write: the ktav serialization and the I/O run on the
/// blocking pool, so no async worker sits on storage. A panicked writer is
/// reported like a save error. The health's own temp is reclaimed before
/// EVERY attempt: Windows keeps it behind on a failed commit, and
/// `write_atomic` creates the temp with `create_new` — without the
/// reclaim one kept temp would fail every later save. A failed removal
/// is a save error like any other.
async fn save_offloaded(path: PathBuf, file: HealthFile) -> Result<()> {
    match tokio::task::spawn_blocking(move || {
        reclaim_own_temp(&path)?;
        save(&path, &file)
    })
    .await
    {
        Ok(result) => result,
        Err(error) => Err(anyhow::Error::new(error).context("health writer task failed")),
    }
}

/// The shutdown snapshot: the same offloaded write as a round, bounded by
/// [`FINISH_BUDGET`]. Failures and timeouts are reported through the
/// logger's non-blocking channel — losing the last picture beats
/// blocking the exit on a full stderr pipe.
async fn save_final(groups: &[HealthGroup], path: &Path, logger: &Logger) {
    let file = snapshot(groups, unix_now());
    match tokio::time::timeout(FINISH_BUDGET, save_offloaded(path.to_path_buf(), file)).await {
        Ok(Ok(())) => {}
        Ok(Err(error)) => {
            logger.proxy_failure(|| format!("could not save {}: {error:#}", path.display()))
        }
        Err(_) => logger.proxy_failure(|| {
            format!(
                "saving {} timed out; continuing without the final snapshot",
                path.display()
            )
        }),
    }
}

/// Save a snapshot now; used by tests to seed a file (the production
/// shutdown path is [`HealthSaver::finish`]).
#[cfg(test)]
pub(crate) fn save_now(groups: &[HealthGroup], path: &Path) {
    if let Err(error) = save(path, &snapshot(groups, unix_now())) {
        eprintln!("warning: could not save {}: {error:#}", path.display());
    }
}

/// Save every `every` while the picture changes; a failure is logged once
/// per streak and retried on the next round. A missing baseline counts as
/// a change, so the first round always writes. `stop` ends the loop: it is
/// selected against the tick, so no round save starts after it fired and the
/// caller can write the final snapshot alone.
pub(crate) async fn run_saver(
    groups: Vec<HealthGroup>,
    path: PathBuf,
    every: Duration,
    initial: Option<HealthFile>,
    logger: Arc<Logger>,
    stop: Arc<tokio::sync::Notify>,
) {
    let mut last = initial;
    let mut failing = false;
    let mut ticker = tokio::time::interval(every);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    ticker.tick().await;
    loop {
        tokio::select! {
            biased;
            _ = stop.notified() => break,
            _ = ticker.tick() => {},
        }
        let current = snapshot(&groups, unix_now());
        if last
            .as_ref()
            .is_some_and(|l| signature(l) == signature(&current))
        {
            continue;
        }
        match save_offloaded(path.clone(), current.clone()).await {
            Ok(()) => {
                failing = false;
                last = Some(current);
            }
            Err(error) => {
                if !failing {
                    logger
                        .proxy_failure(|| format!("Could not save {}: {error:#}", path.display()));
                }
                failing = true;
            }
        }
    }
}
