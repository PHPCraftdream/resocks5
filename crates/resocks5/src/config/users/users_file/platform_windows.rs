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

fn wide(p: &Path) -> io::Result<Vec<u16>> {
    const SEP: u16 = b'\\' as u16;
    const QUERY: u16 = b'?' as u16;
    let mut encoded: Vec<u16> = p.as_os_str().encode_wide().collect();
    if encoded.contains(&0) {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "NUL in path"));
    }
    // Normalize before adding a verbatim prefix: it disables slash/dot processing.
    if !encoded.is_empty()
        && !encoded.starts_with(&[SEP, SEP, QUERY, SEP])
        && !encoded.starts_with(&[SEP, QUERY, QUERY, SEP])
    {
        let absolute = std::path::absolute(p)?;
        encoded = absolute.as_os_str().encode_wide().collect();
        if encoded.len() >= 248 {
            use std::path::{Component, Prefix};
            if let Some(Component::Prefix(prefix)) = absolute.components().next() {
                match prefix.kind() {
                    Prefix::Disk(_) => {
                        encoded.splice(..0, r"\\?\".encode_utf16());
                    }
                    Prefix::UNC(_, _) => {
                        encoded.splice(..2, r"\\?\UNC\".encode_utf16());
                    }
                    _ => {}
                }
            }
        }
    }
    encoded.push(0);
    Ok(encoded)
}

#[test]
fn wide_normalizes_long_unc_and_preserves_verbatim_paths() {
    let tail = "x".repeat(250);
    let unc = format!(r"\\server\share\folder\..\{tail}");
    let verbatim = format!(r"\\?\UNC\server\share\{tail}");
    let expected: Vec<u16> = verbatim.encode_utf16().chain([0]).collect();
    assert_eq!(wide(Path::new(&unc)).unwrap(), expected);
    assert_eq!(wide(Path::new(&verbatim)).unwrap(), expected);
}

/// Creates `path` as a brand-new file with a protected, owner-only
/// DACL — the Windows analogue of unix `OpenOptionsExt::mode(0o600)`
/// — and wraps the owned `HANDLE` into a `File`. Existing paths
/// fail with `AlreadyExists`, like `OpenOptions::create_new`.
pub(super) fn create_private_tmp(path: &Path) -> io::Result<File> {
    let path_w = wide(path)?;
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
    let replaced_w = wide(replaced)?;
    let replacement_w = wide(replacement)?;
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
