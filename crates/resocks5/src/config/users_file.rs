//! Atomic, cross-process-safe persistence for the users file
//! (`resocks5.users.ktav`).
//!
//! Both the server (init-claim) and the CLI write this file, possibly at
//! the same time. Two guarantees are needed:
//!
//! - **No torn writes:** `ktav::to_file` truncates the target before
//!   writing, so an error or a killed process mid-write can leave a
//!   truncated file behind. Every write here goes to `<target>.tmp` in
//!   the same directory (same filesystem, so the rename is atomic) and
//!   is then renamed over the target. `std::fs::rename` corresponds to
//!   `MoveFileExW(MOVEFILE_REPLACE_EXISTING)` on Windows, so replacing
//!   an existing file works on both platforms, and any failure before
//!   the rename leaves the previous file untouched.
//!
//! - **No lost updates across processes:** the in-process `RwLock` in
//!   `AuthState` cannot coordinate the server with a separate CLI
//!   process. Writers take a `<target>.lock` lock (atomic create-new
//!   convention) and re-read the file under it, so a change merges into
//!   what is currently on disk instead of overwriting it with a stale
//!   snapshot.

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};

use crate::config::UsersConfig;

/// How long to wait for the users-file lock before giving up. A holder
/// keeps it only for one read-modify-write-rename (milliseconds); a
/// timeout means a stale lock left by a killed process — deleting the
/// lock file is then safe.
const LOCK_TIMEOUT: Duration = Duration::from_secs(10);
const LOCK_POLL: Duration = Duration::from_millis(10);

/// Serialize `config` as ktav and atomically replace the file at
/// `path` (temp file in the same directory + rename).
pub(crate) fn write_atomic(path: &Path, config: &UsersConfig) -> Result<()> {
    let text = ktav::to_string(config).context("serialize users")?;
    let tmp = sibling_path(path, ".tmp");

    let write_tmp = || -> Result<()> {
        let mut f = File::create(&tmp).with_context(|| format!("create {}", tmp.display()))?;
        f.write_all(text.as_bytes())
            .with_context(|| format!("write {}", tmp.display()))?;
        // Flush before the rename so the replaced file is fully on disk,
        // not sitting in the OS cache while the old content is gone.
        f.sync_all()
            .with_context(|| format!("flush {}", tmp.display()))?;
        Ok(())
    };
    if let Err(e) = write_tmp() {
        let _ = fs::remove_file(&tmp);
        return Err(e);
    }

    if let Err(e) = fs::rename(&tmp, path) {
        let _ = fs::remove_file(&tmp);
        return Err(e)
            .with_context(|| format!("replace {} with {}", path.display(), tmp.display()));
    }
    Ok(())
}

/// `<path><suffix>` in the same directory (`a/users.ktav` →
/// `a/users.ktav.tmp`).
fn sibling_path(path: &Path, suffix: &str) -> PathBuf {
    let mut os = path.as_os_str().to_os_string();
    os.push(suffix);
    PathBuf::from(os)
}

/// Advisory cross-process lock on the users file, released on drop.
///
/// Acquisition is an atomic `create_new` of `<target>.lock`: exactly
/// one process wins, losers poll until the file disappears or the
/// timeout expires. The winner's pid is recorded for diagnostics.
#[derive(Debug)]
pub(crate) struct UsersFileLock {
    lock_path: PathBuf,
}

impl UsersFileLock {
    pub(crate) fn acquire(users_path: &Path) -> Result<Self> {
        Self::acquire_with_timeout(users_path, LOCK_TIMEOUT)
    }

    pub(crate) fn acquire_with_timeout(users_path: &Path, timeout: Duration) -> Result<Self> {
        let lock_path = sibling_path(users_path, ".lock");
        let deadline = Instant::now() + timeout;
        loop {
            match OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&lock_path)
            {
                Ok(mut f) => {
                    let _ = writeln!(f, "{}", std::process::id());
                    return Ok(Self { lock_path });
                }
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                    if Instant::now() >= deadline {
                        bail!(
                            "timed out waiting for users-file lock {} — another \
                             resocks5 process may be holding it; if none is running, \
                             delete the lock file and retry",
                            lock_path.display()
                        );
                    }
                    std::thread::sleep(LOCK_POLL);
                }
                Err(e) => {
                    return Err(e).with_context(|| format!("create {}", lock_path.display()));
                }
            }
        }
    }
}

impl Drop for UsersFileLock {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.lock_path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::User;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn unique_path(tag: &str) -> PathBuf {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let i = COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "resocks5_users_file_test_{}_{}_{}.ktav",
            std::process::id(),
            tag,
            i
        ))
    }

    fn user(name: &str, hash: &str) -> User {
        User {
            name: name.to_string(),
            hash: hash.to_string(),
            is_enabled: true,
            direct: false,
        }
    }

    fn cleanup(path: &Path) {
        let _ = fs::remove_file(path);
        let _ = fs::remove_file(sibling_path(path, ".tmp"));
        let _ = fs::remove_file(sibling_path(path, ".lock"));
    }

    #[test]
    fn write_atomic_replaces_existing_file() {
        let path = unique_path("replace");
        let v1 = UsersConfig {
            users: vec![user("alice", "hash-1")],
        };
        let v2 = UsersConfig {
            users: vec![user("alice", "hash-1"), user("bob", "hash-2")],
        };

        write_atomic(&path, &v1).unwrap();
        // Second write must replace, not append or fail.
        write_atomic(&path, &v2).unwrap();

        let loaded: UsersConfig = ktav::from_file(&path).unwrap();
        assert_eq!(loaded.users.len(), 2);
        assert_eq!(loaded.users[1].name, "bob");
        // The temp file is gone after a successful write.
        assert!(!sibling_path(&path, ".tmp").exists());
        cleanup(&path);
    }

    #[test]
    fn tmp_write_failure_leaves_original_intact() {
        let path = unique_path("tmpfail");
        let v1 = UsersConfig {
            users: vec![user("alice", "hash-1")],
        };
        write_atomic(&path, &v1).unwrap();
        let original = fs::read_to_string(&path).unwrap();

        // Sabotage: a DIRECTORY where the temp file would be created —
        // the write fails before the target is ever touched.
        let tmp = sibling_path(&path, ".tmp");
        fs::create_dir(&tmp).unwrap();

        let v2 = UsersConfig {
            users: vec![user("alice", "hash-1"), user("bob", "hash-2")],
        };
        assert!(write_atomic(&path, &v2).is_err());

        assert_eq!(fs::read_to_string(&path).unwrap(), original);
        let loaded: UsersConfig = ktav::from_file(&path).unwrap();
        assert_eq!(loaded.users.len(), 1);

        fs::remove_dir(&tmp).unwrap();
        cleanup(&path);
    }

    // Windows-only: replacing a file that another handle has open
    // without FILE_SHARE_DELETE fails in MoveFileExW. This pins the
    // rename-failure path with the original file already present.
    #[cfg(windows)]
    #[test]
    fn rename_failure_over_open_file_leaves_original_intact() {
        use std::io::Read;
        use std::os::windows::fs::OpenOptionsExt;

        const FILE_SHARE_READ: u32 = 0x1;

        let path = unique_path("renamefail");
        let v1 = UsersConfig {
            users: vec![user("alice", "hash-1")],
        };
        write_atomic(&path, &v1).unwrap();

        // Hold the target open denying delete/write → rename must fail.
        let mut held = OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ)
            .open(&path)
            .unwrap();

        let v2 = UsersConfig {
            users: vec![user("bob", "hash-2")],
        };
        assert!(write_atomic(&path, &v2).is_err());

        let mut original = String::new();
        held.read_to_string(&mut original).unwrap();
        drop(held);

        let loaded: UsersConfig = ktav::from_file(&path).unwrap();
        assert_eq!(loaded.users.len(), 1);
        assert_eq!(loaded.users[0].name, "alice");
        assert!(original.contains("alice"));
        cleanup(&path);
    }

    #[test]
    fn lock_is_exclusive_and_released_on_drop() {
        let path = unique_path("lock");
        let lock_path = sibling_path(&path, ".lock");

        let l1 = UsersFileLock::acquire_with_timeout(&path, Duration::from_secs(1)).unwrap();
        assert!(lock_path.exists());

        // Second acquirer (same or different process) must time out.
        let err =
            UsersFileLock::acquire_with_timeout(&path, Duration::from_millis(50)).unwrap_err();
        assert!(err.to_string().contains("timed out"));

        drop(l1);
        assert!(!lock_path.exists(), "lock file must be removed on drop");

        // And the lock is re-acquirable after release.
        let l2 = UsersFileLock::acquire_with_timeout(&path, Duration::from_millis(500)).unwrap();
        drop(l2);
        assert!(!lock_path.exists());
        cleanup(&path);
    }
}
