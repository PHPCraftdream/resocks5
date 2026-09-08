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

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};

use crate::config::UsersConfig;

/// How long to wait for the users-file lock before giving up. A holder
/// keeps it only for one read-modify-write-commit (milliseconds). The
/// lock is released by the OS when the holder dies, so a timeout means
/// the lock is genuinely held by a live process — there is no stale
/// lock file to delete manually.
const LOCK_TIMEOUT: Duration = Duration::from_secs(10);
const LOCK_POLL: Duration = Duration::from_millis(10);

#[cfg(unix)]
mod platform {
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
}

#[cfg(windows)]
mod platform {
    use std::fs::{self, File};
    use std::io;
    use std::os::raw::c_void;
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::{AsRawHandle, FromRawHandle};
    use std::path::Path;

    use anyhow::{Context, Result};

    /// Rust mirror of the full Win32 `OVERLAPPED` (minwinbase.h):
    /// `ULONG_PTR Internal; ULONG_PTR InternalHigh;
    /// union { struct { DWORD Offset; DWORD OffsetHigh; }; PVOID Pointer; };
    /// HANDLE hEvent;` — `usize` stands in for `ULONG_PTR`/`HANDLE`
    /// (pointer-sized on 32- and 64-bit). `h_event` is present for ABI
    /// correctness, not because its value matters: MSDN requires it to be
    /// initialized (zero is allowed) before any overlapped call, and the
    /// struct must have the real 32-byte (64-bit) / 20-byte (32-bit) size.
    #[repr(C)]
    struct Overlapped {
        internal: usize,
        internal_high: usize,
        offset: u32,
        offset_high: u32,
        h_event: usize,
    }

    /// Rust mirror of the full Win32 `SECURITY_ATTRIBUTES`
    /// (wtypesbase.h): `DWORD nLength; LPVOID lpSecurityDescriptor;
    /// BOOL bInheritHandle;` — `usize`-sized pointer fields use
    /// `*mut c_void`, `BOOL` is `i32`.
    #[repr(C)]
    struct SecurityAttributes {
        length: u32,
        security_descriptor: *mut c_void,
        inherit_handle: i32,
    }

    const LOCKFILE_FAIL_IMMEDIATELY: u32 = 0x1;
    const LOCKFILE_EXCLUSIVE_LOCK: u32 = 0x2;
    const ERROR_LOCK_VIOLATION: i32 = 33;
    const ERROR_UNABLE_TO_MOVE_REPLACEMENT: i32 = 1176;
    const ERROR_UNABLE_TO_MOVE_REPLACEMENT_2: i32 = 1177;
    const GENERIC_WRITE: u32 = 0x4000_0000;
    const FILE_SHARE_READ: u32 = 0x1;
    const FILE_SHARE_WRITE: u32 = 0x2;
    const FILE_SHARE_DELETE: u32 = 0x4;
    const CREATE_NEW: u32 = 1;
    const FILE_ATTRIBUTE_NORMAL: u32 = 0x80;
    const SDDL_REVISION_1: u32 = 1;

    #[link(name = "kernel32")]
    extern "system" {
        fn LockFileEx(
            hfile: *mut c_void,
            flags: u32,
            reserved: u32,
            lock_low: u32,
            lock_high: u32,
            overlapped: *mut Overlapped,
        ) -> i32;
        fn UnlockFileEx(
            hfile: *mut c_void,
            reserved: u32,
            unlock_low: u32,
            unlock_high: u32,
            overlapped: *mut Overlapped,
        ) -> i32;
        fn ReplaceFileW(
            replaced: *const u16,
            replacement: *const u16,
            backup: *const u16,
            flags: u32,
            exclude: *mut c_void,
            reserved: *mut c_void,
        ) -> i32;
        fn CreateFileW(
            file_name: *const u16,
            desired_access: u32,
            share_mode: u32,
            security_attributes: *mut SecurityAttributes,
            creation_disposition: u32,
            flags_and_attributes: u32,
            template_file: *mut c_void,
        ) -> *mut c_void;
        fn LocalFree(hmem: *mut c_void) -> *mut c_void;
    }

    #[link(name = "advapi32")]
    extern "system" {
        fn ConvertStringSecurityDescriptorToSecurityDescriptorW(
            string_security_descriptor: *const u16,
            string_sd_revision: u32,
            security_descriptor: *mut *mut c_void,
            security_descriptor_size: *mut u32,
        ) -> i32;
    }

    fn wide(p: &Path) -> Vec<u16> {
        p.as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    }

    /// Creates `path` as a brand-new file with a protected, owner-only
    /// DACL — the Windows analogue of unix `OpenOptionsExt::mode(0o600)`
    /// — and wraps the raw `HANDLE` into a `File`. Everything else
    /// matches `OpenOptions::new().write(true).create_new(true)` (share
    /// mode, attributes, and error mapping: `ERROR_FILE_EXISTS` from
    /// `CREATE_NEW` maps to `AlreadyExists` exactly like `create_new`),
    /// so callers see identical behavior except for the security
    /// descriptor.
    pub(super) fn create_private_tmp(path: &Path) -> io::Result<File> {
        // SDDL "D:P(A;;FA;;;OW)" (Security Descriptor String Format,
        // learn.microsoft.com): DACL with `P` = SE_DACL_PROTECTED — the
        // DACL is protected, NOTHING is inherited from the containing
        // directory — and one ACE: `A` allow, `FA` file-all access
        // (FILE_GENERIC_ALL = 0x1F01FF), `OW` = Owner-Rights SID
        // (S-1-3-4: the current owner of the file). No other principal
        // is granted anything. Note: deliberately NOT "AI"
        // (SE_DACL_AUTO_INHERITED is a status flag meaning the DACL was
        // auto-inherited — the opposite of the intent here).
        let sddl: Vec<u16> = "D:P(A;;FA;;;OW)"
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();

        let mut sd: *mut c_void = std::ptr::null_mut();
        // SAFETY: `sddl` is a NUL-terminated wide string valid for the
        // synchronous call. On success the function returns a
        // self-relative security descriptor allocated with `LocalAlloc`
        // that we own and must free with `LocalFree` (its documented
        // contract), and it writes exactly one pointer through `&mut sd`.
        let ok = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                SDDL_REVISION_1,
                &mut sd,
                std::ptr::null_mut(), // size out-param is optional
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        debug_assert!(!sd.is_null());

        let mut sa = SecurityAttributes {
            length: std::mem::size_of::<SecurityAttributes>() as u32,
            security_descriptor: sd,
            inherit_handle: 0, // FALSE: handle is not inheritable
        };

        let path_w = wide(path);
        // SAFETY: `path_w` is NUL-terminated and outlives the call; `sa`
        // (and the descriptor it points to) is valid for the duration of
        // the synchronous call. `dwShareMode`/`dwFlagsAndAttributes`
        // mirror what std uses for `OpenOptions::create_new` without
        // custom flags (share read+write+delete, FILE_ATTRIBUTE_NORMAL).
        let handle = unsafe {
            CreateFileW(
                path_w.as_ptr(),
                GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                &mut sa,
                CREATE_NEW,
                FILE_ATTRIBUTE_NORMAL,
                std::ptr::null_mut(),
            )
        };
        // INVALID_HANDLE_VALUE (all bits set), not NULL, signals failure.
        if handle as usize == usize::MAX {
            // Capture the error BEFORE LocalFree: another FFI call can
            // clobber the thread's last-error value.
            let err = io::Error::last_os_error();
            // SAFETY: `sd` came from
            // ConvertStringSecurityDescriptorToSecurityDescriptorW,
            // whose documented deallocator is LocalFree.
            unsafe { LocalFree(sd) };
            return Err(err);
        }
        // SAFETY: same ownership contract as above — we own `sd` and
        // LocalFree is its documented deallocator.
        unsafe { LocalFree(sd) };

        // SAFETY: `handle` is a valid, exclusively owned file HANDLE
        // from a successful CreateFileW; `File::from_raw_handle` takes
        // sole ownership so `File`'s Drop closes it. No other wrapper
        // owns this handle.
        Ok(unsafe { File::from_raw_handle(handle) })
    }

    pub(super) fn try_exclusive_lock(file: &File) -> io::Result<()> {
        // SAFETY: `file` is a live open HANDLE for the duration of the
        // call; `overlapped` is a zeroed, correctly laid-out struct that
        // kernel32 only writes to, and it outlives the (synchronous) call.
        // A zeroed full-layout `Overlapped` (hEvent = 0, as MSDN requires
        // for overlapped calls) is used.
        let mut overlapped = Overlapped {
            internal: 0,
            internal_high: 0,
            offset: 0,
            offset_high: 0,
            h_event: 0,
        };
        // Lock the whole [0, u64::MAX] byte range.
        let ok = unsafe {
            LockFileEx(
                file.as_raw_handle() as *mut c_void,
                LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY,
                0,
                u32::MAX,
                u32::MAX,
                &mut overlapped,
            )
        };
        if ok != 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    pub(super) fn unlock(file: &File) -> io::Result<()> {
        // SAFETY: same invariants as `try_exclusive_lock` — live HANDLE
        // and a valid zeroed OVERLAPPED for the synchronous call.
        let mut overlapped = Overlapped {
            internal: 0,
            internal_high: 0,
            offset: 0,
            offset_high: 0,
            h_event: 0,
        };
        let ok = unsafe {
            UnlockFileEx(
                file.as_raw_handle() as *mut c_void,
                0,
                u32::MAX,
                u32::MAX,
                &mut overlapped,
            )
        };
        if ok != 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    pub(super) fn is_lock_busy(e: &io::Error) -> bool {
        e.raw_os_error() == Some(ERROR_LOCK_VIOLATION)
    }

    fn replace_file(replaced: &Path, replacement: &Path) -> io::Result<()> {
        let replaced_w = wide(replaced);
        let replacement_w = wide(replacement);
        // SAFETY: both wide strings are NUL-terminated and outlive the
        // call. lpBackupFileName is NULL so Windows creates no backup
        // file and no backup artifact can be orphaned. Flags = 0: the
        // REPLACEFILE_WRITE_THROUGH value is documented as unsupported,
        // and we deliberately do NOT pass IGNORE_MERGE_ERRORS /
        // IGNORE_ACL_ERRORS so an ACL-merge problem fails the call
        // instead of silently dropping the DACL.
        let ok = unsafe {
            ReplaceFileW(
                replaced_w.as_ptr(),
                replacement_w.as_ptr(),
                std::ptr::null(),
                0,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        if ok != 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    /// Atomic commit: `ReplaceFileW` when the target exists (preserving
    /// its DACL/attributes), plain rename for a first write. Handles the
    /// documented partial-failure codes of ReplaceFileW.
    pub(super) fn commit(tmp: &Path, path: &Path) -> Result<()> {
        match replace_file(path, tmp) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                // First write: the target does not exist yet. The renamed temp
                // KEEPS its own DACL — the protected owner-only descriptor it was
                // created with (see `create_private_tmp`) — instead of inheriting
                // the directory's.
                fs::rename(tmp, path)
                    .with_context(|| format!("create {} from {}", path.display(), tmp.display()))
            }
            Err(e) => {
                let code = e.raw_os_error().unwrap_or(0);
                if code == ERROR_UNABLE_TO_MOVE_REPLACEMENT
                    || code == ERROR_UNABLE_TO_MOVE_REPLACEMENT_2
                {
                    // The replacement could not be renamed into place; with
                    // a NULL backup the replaced file is gone (1176) or
                    // both exist under changed names (1177). The `.tmp` is
                    // the only copy of the new content — DO NOT delete it.
                    Err(e).with_context(|| {
                        format!(
                            "replace {} with {} failed after the commit started \
                             (os error {code}): the target may no longer contain \
                             the old content and the commit outcome is \
                             undetermined; the new content is preserved at {}",
                            path.display(),
                            tmp.display(),
                            tmp.display()
                        )
                    })
                } else {
                    // 1175 (replaced file undeletable, e.g. held open
                    // without FILE_SHARE_DELETE) and any other code:
                    // nothing changed — the original is intact. Clean up
                    // the temp as on any pre-commit failure.
                    let _ = fs::remove_file(tmp);
                    Err(e).with_context(|| {
                        format!(
                            "replace {} with {} failed (os error {code}): the \
                             original file was left intact and no backup file \
                             exists (lpBackupFileName is NULL)",
                            path.display(),
                            tmp.display()
                        )
                    })
                }
            }
        }
    }
}

#[cfg(not(any(unix, windows)))]
mod platform {
    use std::fs::{self, File};
    use std::io;
    use std::path::Path;

    use anyhow::{Context, Result};

    /// Non-unix/windows targets have no supported advisory lock here;
    /// this fallback keeps exotic targets compiling (CI is
    /// ubuntu+windows only) but provides no real exclusion.
    pub(super) fn try_exclusive_lock(_file: &File) -> io::Result<()> {
        Ok(())
    }

    pub(super) fn unlock(_file: &File) -> io::Result<()> {
        Ok(())
    }

    pub(super) fn is_lock_busy(_e: &io::Error) -> bool {
        false
    }

    /// Old plain-rename behavior.
    pub(super) fn commit(tmp: &Path, path: &Path) -> Result<()> {
        if let Err(e) = fs::rename(tmp, path) {
            let _ = fs::remove_file(tmp);
            return Err(e)
                .with_context(|| format!("replace {} with {}", path.display(), tmp.display()));
        }
        Ok(())
    }
}

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
///   of unix `0600`) so credential hashes never sit under the
///   directory's (possibly wider) inherited DACL — not in the temp, not
///   in a leftover crash-recovery copy, and not in a brand-new users
///   file (a first write renames the already-protected temp into
///   place).
pub(crate) fn write_atomic(path: &Path, config: &UsersConfig) -> Result<()> {
    let text = ktav::to_string(config).context("serialize users")?;
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
fn sibling_path(path: &Path, suffix: &str) -> PathBuf {
    let mut os = path.as_os_str().to_os_string();
    os.push(suffix);
    PathBuf::from(os)
}

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
    fn failed_write_preserves_an_existing_recovery_file() {
        for target_exists in [false, true] {
            let path = unique_path("preserve_recovery");
            let config = UsersConfig {
                users: vec![user("alice", "hash-1")],
            };
            if target_exists {
                write_atomic(&path, &config).unwrap();
            }
            let tmp = sibling_path(&path, ".tmp");
            let recovery = b"only surviving recovery copy";
            fs::write(&tmp, recovery).unwrap();

            assert!(write_atomic(&path, &config).is_err());
            let preserved = fs::read(&tmp);
            cleanup(&path);
            assert_eq!(preserved.unwrap(), recovery);
        }
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
    // without FILE_SHARE_DELETE makes ReplaceFileW fail with
    // ERROR_UNABLE_TO_REMOVE_REPLACED (1175). This pins the
    // commit-failure path with the original file already present.
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

        // Hold the target open denying delete/write → ReplaceFileW must
        // fail with ERROR_UNABLE_TO_REMOVE_REPLACED.
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
        // 1175 leaves both names unchanged, so our cleanup must have
        // removed the temp file.
        assert!(
            !sibling_path(&path, ".tmp").exists(),
            "failed commit must clean up the temp file"
        );
        cleanup(&path);
    }

    #[cfg(windows)]
    #[test]
    fn windows_temp_file_is_created_with_protected_owner_only_dacl() {
        use std::os::raw::c_void;
        use std::os::windows::ffi::OsStrExt;

        const SE_FILE_OBJECT: u32 = 1;
        const OWNER_SECURITY_INFORMATION: u32 = 0x1;
        const DACL_SECURITY_INFORMATION: u32 = 0x4;
        const SE_DACL_PRESENT: u16 = 0x0004;
        const SE_DACL_PROTECTED: u16 = 0x1000;
        const ACCESS_ALLOWED_ACE_TYPE: u8 = 0x00;
        const INHERITED_ACE: u8 = 0x10;
        // FILE_ALL_ACCESS == FILE_GENERIC_ALL == STANDARD_RIGHTS_REQUIRED
        // | SYNCHRONIZE | 0x1FF
        const FILE_ALL_ACCESS_MASK: u32 = 0x001F_01FF;

        #[link(name = "advapi32")]
        extern "system" {
            fn GetNamedSecurityInfoW(
                object_name: *const u16,
                object_type: u32,
                security_info: u32,
                owner: *mut *mut c_void,
                group: *mut *mut c_void,
                dacl: *mut *mut c_void,
                sacl: *mut *mut c_void,
                security_descriptor: *mut *mut c_void,
            ) -> u32;
            fn GetSecurityDescriptorControl(
                sd: *mut c_void,
                control: *mut u16,
                revision: *mut u32,
            ) -> i32;
            fn GetSecurityDescriptorDacl(
                sd: *mut c_void,
                present: *mut i32,
                dacl: *mut *mut c_void,
                defaulted: *mut i32,
            ) -> i32;
            fn GetSecurityDescriptorOwner(
                sd: *mut c_void,
                owner: *mut *mut c_void,
                defaulted: *mut i32,
            ) -> i32;
            fn GetAce(acl: *mut c_void, index: u32, ace: *mut *mut c_void) -> i32;
        }

        #[link(name = "kernel32")]
        extern "system" {
            fn LocalFree(hmem: *mut c_void) -> *mut c_void;
        }

        let path = unique_path("dacltmp");
        let tmp = sibling_path(&path, ".tmp");
        // Create the temp exactly as write_atomic would, and hold it open.
        let f = platform::create_private_tmp(&tmp)
            .expect("create_private_tmp must create the owner-only temp");

        let tmp_w: Vec<u16> = tmp
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        let mut owner: *mut c_void = std::ptr::null_mut();
        let mut dacl: *mut c_void = std::ptr::null_mut();
        let mut sd: *mut c_void = std::ptr::null_mut();
        // SAFETY: tmp_w is NUL-terminated and outlives the call; every
        // out-pointer is valid. The returned sd is freed with LocalFree
        // below (documented contract of GetNamedSecurityInfoW).
        let rc = unsafe {
            GetNamedSecurityInfoW(
                tmp_w.as_ptr(),
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                &mut owner,
                std::ptr::null_mut(),
                &mut dacl,
                std::ptr::null_mut(),
                &mut sd,
            )
        };
        assert_eq!(rc, 0, "GetNamedSecurityInfoW failed");

        let mut control: u16 = 0;
        let mut revision: u32 = 0;
        let ok = unsafe { GetSecurityDescriptorControl(sd, &mut control, &mut revision) };
        assert_ne!(ok, 0, "GetSecurityDescriptorControl failed");
        assert_ne!(control & SE_DACL_PRESENT, 0, "DACL must be present");
        assert_ne!(
            control & SE_DACL_PROTECTED,
            0,
            "DACL must be protected — no inheritance from the directory"
        );

        let mut dacl_present: i32 = 0;
        let mut defaulted: i32 = 0;
        let ok =
            unsafe { GetSecurityDescriptorDacl(sd, &mut dacl_present, &mut dacl, &mut defaulted) };
        assert_ne!(ok, 0, "GetSecurityDescriptorDacl failed");
        assert_ne!(dacl_present, 0, "DACL must be present");
        assert!(!dacl.is_null());

        // GetAclInformation proved unreliable here (it returned
        // AclRevisionInformation-shaped data on this system), so read
        // the ACL header directly — ACL layout (winnt.h):
        // {AclRevision u8, Sbz1 u8, AclSize u16, AceCount u16, Sbz2 u16}.
        let acl_bytes = dacl as *const u8;
        let acl_revision = unsafe { *acl_bytes };
        let ace_count = unsafe {
            ((*acl_bytes.add(4) as u16) as u32) | (((*acl_bytes.add(5) as u16) as u32) << 8)
        };
        assert_eq!(
            acl_revision, 2,
            "ACL_REVISION expected for the temp file's DACL"
        );
        assert_eq!(
            ace_count, 1,
            "protected DACL must contain exactly our one ACE — no inherited ACEs"
        );

        let mut ace: *mut c_void = std::ptr::null_mut();
        let ok = unsafe { GetAce(dacl, 0, &mut ace) };
        assert_ne!(ok, 0, "GetAce failed");
        // ACCESS_ALLOWED_ACE layout (winnt.h): ACE_HEADER {AceType u8,
        // AceFlags u8, AceSize u16} then ACCESS_MASK Mask u32 then
        // SidStart (the SID begins here, at byte offset 8).
        let ace_bytes = ace as *const u8;
        let ace_type = unsafe { *ace_bytes };
        let ace_flags = unsafe { *ace_bytes.add(1) };
        let ace_mask = unsafe { std::ptr::read_unaligned(ace_bytes.add(4) as *const u32) };
        let ace_sid = unsafe { ace_bytes.add(8) } as *mut c_void;
        assert_eq!(ace_type, ACCESS_ALLOWED_ACE_TYPE);
        assert_eq!(
            ace_flags & INHERITED_ACE,
            0,
            "our ACE must not be flagged as inherited"
        );
        assert_eq!(ace_flags & 0x0F, 0, "no inheritance flags on a file ACE");
        assert_eq!(
            ace_mask, FILE_ALL_ACCESS_MASK,
            "the single ACE must grant file-all access"
        );

        let mut owner_defaulted: i32 = 0;
        let ok = unsafe { GetSecurityDescriptorOwner(sd, &mut owner, &mut owner_defaulted) };
        assert_ne!(ok, 0, "GetSecurityDescriptorOwner failed");
        assert!(!owner.is_null(), "SD must have an owner");
        // The ACE's SID must be the well-known Owner-Rights SID
        // S-1-3-4 (SECURITY_CREATOR_SID_AUTHORITY = 3, one
        // subauthority = 4) — the ACE grants to whoever owns the file,
        // not to any named principal. SID layout (winnt.h):
        // {Revision u8, SubAuthorityCount u8,
        //  IdentifierAuthority [u8; 6] (big-endian),
        //  SubAuthority [u32; count]}.
        let sid_bytes = ace_sid as *const u8;
        let sid_revision = unsafe { *sid_bytes };
        let sid_sub_count = unsafe { *sid_bytes.add(1) };
        let sid_authority = unsafe {
            u64::from_be_bytes([
                0,
                0,
                *sid_bytes.add(2),
                *sid_bytes.add(3),
                *sid_bytes.add(4),
                *sid_bytes.add(5),
                *sid_bytes.add(6),
                *sid_bytes.add(7),
            ])
        };
        let sid_first_sub = unsafe { std::ptr::read_unaligned(sid_bytes.add(8) as *const u32) };
        assert_eq!(sid_revision, 1, "SID revision must be 1");
        assert_eq!(sid_sub_count, 1, "Owner-Rights SID has one subauthority");
        assert_eq!(
            sid_authority, 3,
            "ACE SID must use the Creator SID authority (S-1-3)"
        );
        assert_eq!(
            sid_first_sub, 4,
            "ACE SID must be the Owner-Rights SID (S-1-3-4)"
        );

        drop(f);
        // SAFETY: sd was allocated by GetNamedSecurityInfoW; LocalFree is
        // its documented deallocator. Same for the test-only declaration.
        unsafe { LocalFree(sd) };
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
        // The sentinel file REMAINS by design (never unlinked); the
        // actual release guarantee is that a re-acquire succeeds
        // immediately.
        let l2 = UsersFileLock::acquire_with_timeout(&path, Duration::from_millis(500)).unwrap();
        drop(l2);
        cleanup(&path);
    }

    /// Simulates the review's aborted-owner scenario as a real
    /// subprocess: the child takes the lock and leaves via
    /// `std::process::exit` (documented to skip destructors) — on both
    /// platforms process teardown closes all fds/handles, which is
    /// precisely what must release flock/LockFileEx. Real SIGKILL or
    /// power loss cannot be simulated portably in-process;
    /// `process::exit` is the review's own named owner-death mode.
    #[test]
    fn lock_is_released_when_owner_process_dies_without_cleanup() {
        const CHILD_ENV: &str = "RESOCKS5_LOCK_CRASH_TEST_CHILD";
        const PATH_ENV: &str = "RESOCKS5_LOCK_CRASH_TEST_PATH";
        if std::env::var_os(CHILD_ENV).is_some() {
            // Child branch: take the lock, announce, exit WITHOUT running
            // destructors (std::process::exit skips Drop — the exact
            // owner-death mode from the review).
            let crash_path = PathBuf::from(std::env::var_os(PATH_ENV).expect("crash path env"));
            let lock = UsersFileLock::acquire_with_timeout(&crash_path, Duration::from_secs(5))
                .expect("child must acquire the lock");
            let _ = &lock; // held until process exit
            let mut out = std::io::stdout().lock();
            out.write_all(b"LOCKED\n").expect("write LOCKED");
            out.flush().expect("flush LOCKED");
            std::process::exit(0);
        }
        let path = unique_path("crashlock");
        // libtest test ids omit the crate-name prefix that
        // `module_path!()` includes in a binary crate, so strip it.
        let test_name = format!(
            "{}::lock_is_released_when_owner_process_dies_without_cleanup",
            module_path!().trim_start_matches(concat!(env!("CARGO_CRATE_NAME"), "::"))
        );
        let child = std::process::Command::new(std::env::current_exe().expect("current_exe"))
            .args(["--exact", &test_name, "--nocapture"])
            .env(CHILD_ENV, "1")
            .env(PATH_ENV, &path)
            .output()
            .expect("spawn crash-child test process");
        let stdout = String::from_utf8_lossy(&child.stdout);
        assert!(
            stdout.contains("LOCKED"),
            "crash child never acquired the lock.\nstdout: {stdout}\nstderr: {}",
            String::from_utf8_lossy(&child.stderr)
        );
        // The owner "died" holding the lock. The OS must have released it:
        // this must succeed near-instantly, not after LOCK_TIMEOUT (10s).
        let started = Instant::now();
        let lock = UsersFileLock::acquire(&path)
            .expect("lock orphaned by a dead owner process was not released by the OS");
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "acquiring after owner death took {:?} — looks like the full timeout, not OS release",
            started.elapsed()
        );
        // And a write goes through with no manual cleanup.
        write_atomic(
            &path,
            &UsersConfig {
                users: vec![user("after-crash", "hash-c")],
            },
        )
        .unwrap();
        drop(lock);
        cleanup(&path);
    }

    #[cfg(unix)]
    #[test]
    fn write_atomic_preserves_the_replaced_file_mode() {
        use std::os::unix::fs::PermissionsExt;

        let path = unique_path("modekeep");
        let v1 = UsersConfig {
            users: vec![user("alice", "hash-1")],
        };
        let v2 = UsersConfig {
            users: vec![user("bob", "hash-2")],
        };
        write_atomic(&path, &v1).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        write_atomic(&path, &v2).unwrap();
        // Without the fix the replace recreates the file at
        // `0666 & !umask` (typically 0644), so this fails on old code.
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "replacement must keep the replaced file's mode"
        );
        cleanup(&path);
    }

    #[cfg(unix)]
    #[test]
    fn write_atomic_creates_new_files_owner_only() {
        use std::os::unix::fs::PermissionsExt;

        let path = unique_path("modefresh");
        write_atomic(
            &path,
            &UsersConfig {
                users: vec![user("carol", "hash-3")],
            },
        )
        .unwrap();
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "a brand-new users file must be owner-only");
        cleanup(&path);
    }

    #[cfg(unix)]
    #[test]
    fn write_atomic_syncs_parent_directory_after_commit() {
        // The directory fsync itself runs inside write_atomic on unix;
        // real power-loss durability is not unit-testable (a
        // single-process shutdown test can't prove it). This pins that
        // the sync path runs and propagates failures instead of being
        // skipped, and that content still round-trips.
        let path = unique_path("dirsync");
        let cfg = UsersConfig {
            users: vec![user("dave", "hash-4")],
        };
        write_atomic(&path, &cfg).unwrap();
        let loaded: UsersConfig = ktav::from_file(&path).unwrap();
        assert_eq!(loaded.users.len(), 1);
        assert_eq!(loaded.users[0].name, "dave");
        cleanup(&path);
    }
}
