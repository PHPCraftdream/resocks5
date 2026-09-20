use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};

use super::platform;
use super::sibling_path;

/// How long to wait for the users-file lock before giving up. A holder
/// keeps it only for one read-modify-write-commit (milliseconds). The
/// lock is released by the OS when the holder dies, so a timeout means
/// the lock is genuinely held by a live process — there is no stale
/// lock file to delete manually.
const LOCK_TIMEOUT: Duration = Duration::from_secs(10);
const LOCK_POLL: Duration = Duration::from_millis(10);

/// Advisory cross-process lock on the users file, released on drop.
///
/// Acquisition opens the shared sentinel `<target>.lock` (created once,
/// reused by every contender — never deleted) and takes a non-blocking
/// OS exclusive lock on it (`flock(LOCK_EX|LOCK_NB)` on unix,
/// `LockFileEx(LOCKFILE_EXCLUSIVE_LOCK|LOCKFILE_FAIL_IMMEDIATELY)` on
/// windows). The OS releases the lock if the holder dies — crash,
/// `SIGKILL`, or `std::process::exit` all close fds/handles during
/// teardown — so a timeout means the lock is genuinely held by a live
/// process, not "possibly orphaned".
#[derive(Debug)]
pub(crate) struct UsersFileLock {
    #[allow(dead_code)]
    lock_path: PathBuf,
    file: File, // the OS handle/fd holding the advisory lock; closing it releases the lock
}

impl UsersFileLock {
    pub(crate) fn acquire(users_path: &Path) -> Result<Self> {
        Self::acquire_with_timeout(users_path, LOCK_TIMEOUT)
    }

    pub(crate) fn acquire_with_timeout(users_path: &Path, timeout: Duration) -> Result<Self> {
        let lock_path = sibling_path(users_path, ".lock");
        // Create, NOT create_new: all contenders share one file/inode so
        // their flock/LockFileEx calls actually contend with each other.
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false) // sentinel is reused across acquirers; pid line is diagnostic-only
            .open(&lock_path)
            .with_context(|| format!("open {}", lock_path.display()))?;
        let deadline = Instant::now() + timeout;
        loop {
            match platform::try_exclusive_lock(&file) {
                Ok(()) => {
                    // PID is diagnostics-only.
                    let mut f = &file;
                    let _ = writeln!(f, "{}", std::process::id());
                    return Ok(Self { lock_path, file });
                }
                Err(e) if platform::is_lock_busy(&e) => {
                    if Instant::now() >= deadline {
                        bail!(
                            "timed out waiting for users-file lock {} — another \
                             resocks5 process is holding it (the OS releases the \
                             lock automatically if that process dies)",
                            lock_path.display()
                        );
                    }
                    std::thread::sleep(LOCK_POLL);
                }
                Err(e) => {
                    return Err(e).with_context(|| format!("lock {}", lock_path.display()));
                }
            }
        }
    }
}

impl Drop for UsersFileLock {
    fn drop(&mut self) {
        // Best-effort graceful release. We do NOT delete the lock file:
        // unlinking the sentinel while a contender already holds a handle
        // to it would let a third process create a fresh inode and "win"
        // the lock on a different file (the classic flock-unlink race).
        // The zero-byte leftover is harmless and reused by the next
        // acquirer. Closing `self.file` (field drop, right after this)
        // also releases the lock — the explicit unlock is just the
        // graceful fast path.
        let _ = platform::unlock(&self.file);
    }
}
