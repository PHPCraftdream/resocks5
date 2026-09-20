use super::*;
use crate::config::User;
use crate::config::UsersConfig;
#[cfg(windows)]
use std::fs::OpenOptions;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

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
fn windows_private_temp_rejects_nul_without_creating_a_prefix_file() {
    use std::ffi::OsString;
    use std::os::windows::ffi::{OsStrExt, OsStringExt};

    let prefix = unique_path("nulpath");
    let mut encoded: Vec<u16> = prefix.as_os_str().encode_wide().collect();
    encoded.extend([0, u16::from(b'x')]);
    let invalid = PathBuf::from(OsString::from_wide(&encoded));
    let expected = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&invalid)
        .unwrap_err()
        .kind();
    let result = platform::create_private_tmp(&invalid);
    let actual = result.as_ref().err().map(std::io::Error::kind);
    let prefix_created = prefix.exists();
    drop(result);
    cleanup(&prefix);
    assert_eq!(actual, Some(expected));
    assert!(!prefix_created, "NUL must not truncate the requested path");
}

#[cfg(windows)]
#[test]
fn windows_private_temp_supports_long_paths() {
    let root = unique_path("longpath");
    fs::create_dir(&root).unwrap();
    let dir = root
        .join("a".repeat(80))
        .join("b".repeat(80))
        .join("c".repeat(80));
    fs::create_dir_all(&dir).unwrap();
    let path = dir.join("users.tmp");
    let standard = OpenOptions::new().write(true).create_new(true).open(&path);
    assert!(
        standard.is_ok(),
        "std must support this fixture: {standard:?}"
    );
    drop(standard);
    fs::remove_file(&path).unwrap();
    let result = (|| -> Result<UsersConfig> {
        drop(platform::create_private_tmp(&path)?);
        fs::remove_file(&path)?;
        write_atomic(
            &path,
            &UsersConfig {
                users: vec![user("alice", "one")],
            },
        )?;
        write_atomic(
            &path,
            &UsersConfig {
                users: vec![user("bob", "two")],
            },
        )?;
        Ok(ktav::from_file(&path)?)
    })();
    fs::remove_dir_all(&root).unwrap();
    let loaded = result.expect("long-path creation and replacement must succeed");
    assert_eq!(loaded.users.len(), 1);
    assert_eq!(loaded.users[0].name, "bob");
}

#[cfg(windows)]
#[test]
fn windows_temp_file_is_created_with_protected_owner_only_dacl() {
    let path = unique_path("dacltmp");
    let tmp = sibling_path(&path, ".tmp");
    let file = platform::create_private_tmp(&tmp).unwrap();
    // The helper queries the live file and asserts; catch the verdict so
    // the handle is dropped and the temp cleaned up even when an
    // assertion fails, then re-raise the original panic.
    let verdict = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        test_support::assert_owner_only_dacl(&tmp);
    }));
    drop(file);
    cleanup(&path);
    if let Err(panic) = verdict {
        std::panic::resume_unwind(panic);
    }
}

#[test]
fn lock_is_exclusive_and_released_on_drop() {
    let path = unique_path("lock");
    let lock_path = sibling_path(&path, ".lock");

    let l1 = UsersFileLock::acquire_with_timeout(&path, Duration::from_secs(1)).unwrap();
    assert!(lock_path.exists());

    // Second acquirer (same or different process) must time out.
    let err = UsersFileLock::acquire_with_timeout(&path, Duration::from_millis(50)).unwrap_err();
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
