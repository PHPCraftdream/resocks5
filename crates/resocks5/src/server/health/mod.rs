//! Upstream health that survives a restart.
//!
//! The quarantine picture (which upstreams are dead, for how long, how many
//! times they tripped) is saved to `resocks5.health.ktav` and put back at
//! start-up, so a fresh process does not spend client requests rediscovering
//! dead upstreams: they come back quarantined or on probation and the
//! background probes decide. Passwords are never written.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::config::users_file::write_atomic;
use crate::logger::Logger;
use resocks5_net::rating::{Health, UpstreamState};
use resocks5_net::rotator::{ProxyRotator, UpstreamHealth};
use resocks5_net::types::ProxyConfig;

#[cfg(test)]
mod tests;

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

/// Snapshot of every upstream of every rotator.
pub(crate) fn snapshot(rotators: &[Arc<ProxyRotator>], now: u64) -> HealthFile {
    let upstreams = rotators
        .iter()
        .flat_map(|rotator| rotator.health())
        .map(|entry| HealthEntry {
            upstream: upstream_label(&entry.proxy),
            gate: entry.proxy.gate_level,
            state: state_name(entry.health.state).to_owned(),
            remaining_sec: entry.health.remaining.as_secs(),
            trips: entry.health.trips,
            failures: entry.health.consecutive,
        })
        .collect();
    HealthFile {
        saved_at: now,
        upstreams,
    }
}

/// What changes the saved picture: everything but the countdown and the
/// timestamp.
fn signature(file: &HealthFile) -> Vec<(&str, u8, &str, u32, u32)> {
    file.upstreams
        .iter()
        .map(|e| {
            (
                e.upstream.as_str(),
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
pub(crate) fn restore(rotators: &[Arc<ProxyRotator>], file: &HealthFile, now: u64) -> Restored {
    let idle = Duration::from_secs(now.saturating_sub(file.saved_at));
    let saved: HashMap<(String, u8), &HealthEntry> = file
        .upstreams
        .iter()
        .map(|e| ((e.upstream.clone(), e.gate), e))
        .collect();
    let mut restored = Restored::default();
    for rotator in rotators {
        let entries: Vec<UpstreamHealth> = rotator
            .all_proxies()
            .iter()
            .filter_map(|proxy| {
                let entry = saved.get(&(upstream_label(proxy), proxy.gate_level))?;
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
        rotator.restore_health(&entries);
        for entry in &entries {
            if rotator.is_quarantined(&entry.proxy) {
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
pub(crate) fn resume(rotators: &[Arc<ProxyRotator>], path: &Path, now: u64) -> Resumed {
    match load(path) {
        Ok(Some(file)) => Resumed {
            restored: restore(rotators, &file, now),
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

/// Start-up: put the saved quarantines back, hand the due ones to the
/// background probes, then keep the file current. The returned task runs
/// until aborted; save once more after aborting it.
pub(crate) fn start(
    rotators: Vec<Arc<ProxyRotator>>,
    path: PathBuf,
    every: Duration,
    probe_timeout: Duration,
    logger: Arc<Logger>,
) -> tokio::task::JoinHandle<()> {
    let resumed = resume(&rotators, &path, unix_now());
    if let Some(warning) = &resumed.warning {
        println!("warning: {warning}");
    }
    if resumed.saved.is_some() {
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
        for rotator in &rotators {
            crate::server::connect::establish_connection::spawn_due_probes(
                rotator,
                &logger,
                probe_timeout,
            );
        }
    }
    let initial = resumed.saved.map(|_| snapshot(&rotators, unix_now()));
    tokio::spawn(run_saver(rotators, path, every, initial, logger))
}

/// Replace the file atomically.
pub(crate) fn save(path: &Path, file: &HealthFile) -> Result<()> {
    write_atomic(path, file)
}

/// Save a snapshot now; used at shutdown. Failures only warn.
pub(crate) fn save_now(rotators: &[Arc<ProxyRotator>], path: &Path) {
    if let Err(error) = save(path, &snapshot(rotators, unix_now())) {
        eprintln!("warning: could not save {}: {error:#}", path.display());
    }
}

/// Save every `every` while the picture changes; a failure is logged once
/// per streak and retried on the next round.
pub(crate) async fn run_saver(
    rotators: Vec<Arc<ProxyRotator>>,
    path: PathBuf,
    every: Duration,
    initial: Option<HealthFile>,
    logger: Arc<Logger>,
) {
    let mut last = initial;
    let mut failing = false;
    let mut ticker = tokio::time::interval(every);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    ticker.tick().await;
    loop {
        ticker.tick().await;
        let current = snapshot(&rotators, unix_now());
        if last
            .as_ref()
            .is_some_and(|l| signature(l) == signature(&current))
        {
            continue;
        }
        match save(&path, &current) {
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
