use std::fs::{self, File};
use std::io;
use std::os::fd::{AsRawFd, RawFd};
use std::os::raw::c_int;
use std::path::Path;

use anyhow::{Context, Result};

const LOCK_EX: c_int = 2;
const LOCK_NB: c_int = 4;
const LOCK_UN: c_int = 8;

extern "C" {
    // flock(2): BSD/Linux/macOS libc — linked into every Rust unix target.
    fn flock(fd: RawFd, operation: c_int) -> c_int;
}

pub(super) fn try_exclusive_lock(file: &File) -> io::Result<()> {
    // SAFETY: `file` is a live open fd, so `file.as_raw_fd()` is valid
    // for the duration of this call; `flock` touches no user memory.
    let rc = unsafe { flock(file.as_raw_fd(), LOCK_EX | LOCK_NB) };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

pub(super) fn unlock(file: &File) -> io::Result<()> {
    // SAFETY: same as `try_exclusive_lock` — valid open fd, no user memory.
    let rc = unsafe { flock(file.as_raw_fd(), LOCK_UN) };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

pub(super) fn is_lock_busy(e: &io::Error) -> bool {
    // EWOULDBLOCK == EAGAIN on all supported unix targets.
    e.kind() == io::ErrorKind::WouldBlock
}

/// Atomic commit: rename the temp over the target, then fsync the
/// parent directory so the new name is durable.
pub(super) fn commit(tmp: &Path, path: &Path) -> Result<()> {
    if let Err(e) = fs::rename(tmp, path) {
        let _ = fs::remove_file(tmp);
        return Err(e)
            .with_context(|| format!("replace {} with {}", path.display(), tmp.display()));
    }
    if let Err(e) = sync_parent_dir(path) {
        // The rename already landed; the old file is gone and the new
        // content is visible under the target name. The commit outcome
        // is undetermined only in the durability sense — the caller
        // must NOT assume the old file is intact.
        return Err(e).with_context(|| {
            format!(
                "sync parent directory after replacing {} with {} — the \
                 replacement itself has already taken effect, the commit \
                 outcome is undetermined",
                path.display(),
                tmp.display()
            )
        });
    }
    Ok(())
}

/// fsync the directory so the new directory entry (the rename) is
/// durable across OS crash / power loss on filesystems honoring
/// fsync(2).
fn sync_parent_dir(path: &Path) -> io::Result<()> {
    let parent = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    let dir = File::open(parent)?;
    dir.sync_all()
}
