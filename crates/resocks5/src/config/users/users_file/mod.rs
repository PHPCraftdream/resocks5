//! Atomic, cross-process-safe persistence for the users file
//! (`resocks5.users.ktav`).
//!
//! Both the server (init-claim) and the CLI write this file, possibly at
//! the same time. Three guarantees are needed:
//!
//! - **No torn writes:** `ktav::to_file` truncates the target before
//!   writing, so an error or a killed process mid-write can leave a
//!   truncated file behind. Every write here goes to `<target>.tmp` in
//!   the same directory (same filesystem, so the commit is a single
//!   atomic name-space operation) and is then committed over the target
//!   via [`platform::commit`]. On unix the commit is `fs::rename`; on
//!   Windows it is `ReplaceFileW` (which preserves the replaced file's
//!   DACL and attributes) with a plain rename fallback for a first
//!   write. The temp file is private from the very start — mode `0600`
//!   on unix, a protected owner-only DACL on windows — before any
//!   content is written, and a replacement inherits the replaced file's
//!   mode (unix) or DACL (windows) — see [`write_atomic`] for the exact
//!   durability model.
//!
//! - **No lost updates across processes:** the in-process `RwLock` in
//!   `AuthState` cannot coordinate the server with a separate CLI
//!   process. Writers take a `<target>.lock` advisory lock (OS file
//!   lock, not file existence) and re-read the file under it, so a
//!   change merges into what is currently on disk instead of
//!   overwriting it with a stale snapshot.
//!
//! - **No orphaned locks:** the lock is held by an open file
//!   descriptor/handle on the OS level (`flock` on unix, `LockFileEx`
//!   on windows). The kernel releases it when the owning process dies
//!   — crash, `SIGKILL`, or `std::process::exit` all close fds/handles
//!   during teardown — so no manual lock-file cleanup is ever needed.

use std::fs;
#[cfg(not(windows))]
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

mod lock;

#[cfg(unix)]
#[path = "platform_unix.rs"]
mod platform;
#[cfg(windows)]
#[path = "platform_windows.rs"]
mod platform;
#[cfg(not(any(unix, windows)))]
#[path = "platform_other.rs"]
mod platform;

#[cfg(all(test, windows))]
pub(crate) mod test_support;

#[cfg(test)]
mod tests;

pub(crate) use lock::UsersFileLock;

/// Serialize `config` as ktav and atomically replace the file at `path`.
///
/// Durability model (exact):
///
/// - **Content:** the serialized bytes are written to `<target>.tmp` and
///   fsync'd (`sync_all`) *before* the commit step, so the new content
///   survives a process crash at any point.
/// - **Commit:** a single atomic name-space operation — `fs::rename` on
///   unix; `ReplaceFileW` on windows when the target already exists
///   (plain rename for a first write).
/// - **Power loss:** on unix the parent directory is fsync'd after the
///   commit, so the new name is durable across OS crash/power loss on
///   filesystems honoring fsync(2) (macOS fsync is best-effort — it does
///   not force a disk flush). On windows name-replacement durability
///   across power loss is NOT guaranteed (NTFS metadata journaling, and
///   std cannot open a directory handle for `FlushFileBuffers`, while
///   `REPLACEFILE_WRITE_THROUGH` is documented as unsupported);
///   process-crash safety still holds.
/// - **Undetermined outcomes:** if an error is reported after the commit
///   step itself succeeded (unix directory-sync failure, or windows
///   `ERROR_UNABLE_TO_MOVE_REPLACEMENT{,_2}`), the caller must assume
///   the replacement MAY have landed — the outcome is undetermined, not
///   "old file intact". The error context names the temp path holding
///   the only copy of the new content where applicable.
/// - **Permissions / DACL:** on unix the replacement ends up with
///   exactly the mode of the file it replaces; a brand-new file is
///   created `0600` (credentials-adjacent, owner-only from creation).
///   Owner/group are not transferred — that would require privileges.
///   The temp is created `0600` and chmod'ed to the target's mode while
///   still private. On windows `ReplaceFileW` preserves the replaced
///   file's DACL/attributes, and the temp file is created with a
///   protected owner-only DACL (SDDL `D:P(A;;FA;;;OW)` — the analogue
///   of unix `0600`) so credential content never sits under the
///   directory's (possibly wider) inherited DACL — not in the temp, not
///   in a leftover crash-recovery copy, and not in any brand-new file
///   (a first write renames the already-protected temp into
///   place).
pub(crate) fn write_atomic<T: serde::Serialize>(path: &Path, config: &T) -> Result<()> {
    let text = ktav::to_string(config).context("serialize config")?;
    let tmp = sibling_path(path, ".tmp");

    #[cfg(unix)]
    let existing_mode = existing_target_mode(path)?;

    // Cleanup is allowed only after this call creates the file.
    #[cfg(windows)]
    let mut f = platform::create_private_tmp(&tmp).with_context(|| {
        format!(
            "create {}; any existing recovery file was preserved",
            tmp.display()
        )
    })?;
    #[cfg(not(windows))]
    let mut f = {
        let mut opts = OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        opts.open(&tmp).with_context(|| {
            format!(
                "create {}; any existing recovery file was preserved",
                tmp.display()
            )
        })?
    };
    let write_result = (|| -> Result<()> {
        #[cfg(unix)]
        if let Some(mode) = existing_mode {
            use std::os::unix::fs::PermissionsExt;
            // Apply the replaced file's mode via the open fd (fchmod)
            // BEFORE sync_all, while the temp is still the private file.
            f.set_permissions(fs::Permissions::from_mode(mode))
                .with_context(|| format!("chmod {} to {:o}", tmp.display(), mode))?;
        }
        f.write_all(text.as_bytes())
            .with_context(|| format!("write {}", tmp.display()))?;
        // Flush before the commit so the replaced file is fully on disk,
        // not sitting in the OS cache while the old content is gone.
        f.sync_all()
            .with_context(|| format!("flush {}", tmp.display()))?;
        Ok(())
    })();
    drop(f);
    if let Err(e) = write_result {
        let _ = fs::remove_file(&tmp);
        return Err(e);
    }

    platform::commit(&tmp, path)
}

/// Mode of the existing target file, if any (`None` = first write).
#[cfg(unix)]
fn existing_target_mode(path: &Path) -> Result<Option<u32>> {
    use std::os::unix::fs::PermissionsExt;
    match fs::metadata(path) {
        Ok(md) => Ok(Some(md.permissions().mode())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
    }
}

/// `<path><suffix>` in the same directory (`a/users.ktav` →
/// `a/users.ktav.tmp`).
pub(crate) fn sibling_path(path: &Path, suffix: &str) -> PathBuf {
    let mut os = path.as_os_str().to_os_string();
    os.push(suffix);
    PathBuf::from(os)
}
