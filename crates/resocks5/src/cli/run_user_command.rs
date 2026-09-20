use std::io::IsTerminal;
use std::path::Path;

use anyhow::{anyhow, bail, Context, Result};

use crate::auth;
use crate::cli::UserAction;
use crate::config::users_file::{write_atomic, UsersFileLock};
use crate::config::{self, User, UsersConfig};

/// One logical change to the users file. Built against the state loaded
/// at startup, but applied against the CURRENT on-disk state at commit
/// time — see `commit_op_to`.
enum UserOp {
    /// Add a user with a real Argon2id hash.
    Add(User),
    /// Add a user with the `hash: "init"` placeholder — the first
    /// successful authentication for this username records the password.
    AddInit(User),
    SetPassword {
        name: String,
        hash: String,
    },
    Remove {
        name: String,
    },
    SetEnabled {
        name: String,
        enabled: bool,
    },
    SetDirect {
        name: String,
        direct: bool,
    },
}

// Manual impl instead of `#[derive(Debug)]` so password hashes are
// never rendered (logs, test-failure messages, panic output).
impl std::fmt::Debug for UserOp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UserOp::Add(u) => write!(f, "Add({})", u.name),
            UserOp::AddInit(u) => write!(f, "AddInit({})", u.name),
            UserOp::SetPassword { name, .. } => write!(f, "SetPassword({name})"),
            UserOp::Remove { name } => write!(f, "Remove({name})"),
            UserOp::SetEnabled { name, enabled } => {
                write!(f, "SetEnabled({name}, {enabled})")
            }
            UserOp::SetDirect { name, direct } => write!(f, "SetDirect({name}, {direct})"),
        }
    }
}

/// Run the user-management subcommand and return. The caller dispatches
/// to the server in the absence of a subcommand. Only the users config
/// is loaded — or auto-created on a fresh install through the same
/// protected first-run path the full startup uses — so `resocks5 users
/// add admin` just works without starting the server first. Main and
/// proxy-list configs are deliberately neither read nor parsed nor
/// created here: a users subcommand has no use for them, and a broken
/// sibling file must not break user management.
pub fn run_user_command(action: UserAction) -> Result<()> {
    let users = config::load_or_init::load_or_init_users_at(Path::new(config::USERS_PATH))?;

    let op = match action {
        UserAction::Add { name } => add_user(&users, &name)?,
        UserAction::AddInit { name } => add_init_user(&users, &name)?,
        UserAction::SetPassword { name } => set_password(&users, &name)?,
        UserAction::Remove { name, yes } => match remove_user(&users, &name, yes)? {
            Some(op) => op,
            None => return Ok(()), // interactive confirmation declined
        },
        UserAction::List => return list_users(&users),
        UserAction::Enable { name } => set_enabled(&users, &name, true)?,
        UserAction::Disable { name } => set_enabled(&users, &name, false)?,
        UserAction::Direct { name } => set_direct(&users, &name, true)?,
        UserAction::Pool { name } => set_direct(&users, &name, false)?,
    };

    commit_op_to(Path::new(config::USERS_PATH), &op)
}

fn add_user(users: &UsersConfig, name: &str) -> Result<UserOp> {
    validate_name(name)?;
    if users.users.iter().any(|u| u.name == name) {
        bail!("user '{}' already exists", name);
    }
    let password = read_new_password()?;
    let hash = auth::compute_hash(&password)?;
    Ok(UserOp::Add(build_added_user(name, hash)))
}

fn build_added_user(name: &str, hash: String) -> User {
    User {
        name: name.to_string(),
        hash,
        is_enabled: true,
        direct: false,
    }
}

/// Create a user with `hash: "init"` — the first successful
/// authentication for this username will record the submitted
/// password as the real Argon2id hash and update the file.
fn add_init_user(users: &UsersConfig, name: &str) -> Result<UserOp> {
    validate_name(name)?;
    if users.users.iter().any(|u| u.name == name) {
        bail!("user '{}' already exists", name);
    }
    Ok(UserOp::AddInit(User {
        name: name.to_string(),
        hash: "init".to_string(),
        is_enabled: true,
        direct: false,
    }))
}

fn set_password(users: &UsersConfig, name: &str) -> Result<UserOp> {
    // Early existence check so the prompt is not wasted on a typo'd
    // name; re-validated against fresh disk state at commit time.
    find_user(users, name)?;
    let password = read_new_password()?;
    let hash = auth::compute_hash(&password)?;
    Ok(UserOp::SetPassword {
        name: name.to_string(),
        hash,
    })
}

fn remove_user(users: &UsersConfig, name: &str, skip_confirm: bool) -> Result<Option<UserOp>> {
    find_user(users, name)?;
    if !skip_confirm && std::io::stdin().is_terminal() {
        let confirmed = confirm(&format!("Remove user '{}'?", name))?;
        if !confirmed {
            println!("Cancelled.");
            return Ok(None);
        }
    }
    Ok(Some(UserOp::Remove {
        name: name.to_string(),
    }))
}

fn list_users(users: &UsersConfig) -> Result<()> {
    if users.users.is_empty() {
        println!("(no users configured — server runs without authentication)");
        return Ok(());
    }
    println!("{:<24} {:<10} {:<6}", "NAME", "STATUS", "MODE");
    for u in &users.users {
        let status = if u.is_enabled { "enabled" } else { "disabled" };
        let mode = if u.direct { "direct" } else { "pool" };
        println!("{:<24} {:<10} {:<6}", u.name, status, mode);
    }
    Ok(())
}

fn set_enabled(users: &UsersConfig, name: &str, enabled: bool) -> Result<UserOp> {
    find_user(users, name)?;
    Ok(UserOp::SetEnabled {
        name: name.to_string(),
        enabled,
    })
}

fn set_direct(users: &UsersConfig, name: &str, direct: bool) -> Result<UserOp> {
    find_user(users, name)?;
    Ok(UserOp::SetDirect {
        name: name.to_string(),
        direct,
    })
}

fn commit_op_to(path: &Path, op: &UserOp) -> Result<()> {
    commit_op_locked(path, op)?;
    report(op);
    Ok(())
}

/// Apply `op` under the cross-process lock and atomically replace the
/// file. The lock guard lives only inside this function: it is dropped
/// on return, BEFORE any success output is printed, so a slow or
/// stalled stdout can never keep other CLI writers or server-side
/// init-claims blocked out of the users file.
///
/// The `UsersConfig` loaded at startup can be stale by the time we get
/// here: a running server may have persisted an init-claim, or a second
/// CLI invocation may have made another edit. Writing that stale
/// snapshot back would silently revert those changes, so the operation
/// is applied to what the file actually contains right now.
fn commit_op_locked(path: &Path, op: &UserOp) -> Result<()> {
    let _lock = UsersFileLock::acquire(path).with_context(|| format!("lock {}", path.display()))?;
    let mut fresh: UsersConfig =
        ktav::from_file(path).with_context(|| format!("read {}", path.display()))?;
    apply_op(op, &mut fresh)?;
    write_atomic(path, &fresh)?;
    Ok(())
}

/// Apply one operation to an in-memory users list, validating against
/// THAT list (the fresh on-disk state at commit time).
fn apply_op(op: &UserOp, users: &mut UsersConfig) -> Result<()> {
    match op {
        UserOp::Add(user) | UserOp::AddInit(user) => {
            if users.users.iter().any(|u| u.name == user.name) {
                bail!("user '{}' already exists", user.name);
            }
            users.users.push(user.clone());
        }
        UserOp::SetPassword { name, hash } => {
            find_user_mut(users, name)?.hash = hash.clone();
        }
        UserOp::Remove { name } => {
            let pos = user_position(users, name)?;
            users.users.remove(pos);
        }
        UserOp::SetEnabled { name, enabled } => {
            find_user_mut(users, name)?.is_enabled = *enabled;
        }
        UserOp::SetDirect { name, direct } => {
            find_user_mut(users, name)?.direct = *direct;
        }
    }
    Ok(())
}

/// Success messages, printed only after the change is actually on disk.
fn report(op: &UserOp) {
    match op {
        UserOp::Add(user) => println!("Added user '{}'.", user.name),
        UserOp::AddInit(user) => println!(
            "Added user '{}' with placeholder hash. The first client to authenticate \
             as this user claims the password.",
            user.name
        ),
        UserOp::SetPassword { name, .. } => println!("Updated password for user '{}'.", name),
        UserOp::Remove { name } => println!("Removed user '{}'.", name),
        UserOp::SetEnabled { name, enabled } => println!(
            "User '{}' is now {}.",
            name,
            if *enabled { "enabled" } else { "disabled" }
        ),
        UserOp::SetDirect { name, direct } => println!(
            "User '{}' is now {}.",
            name,
            if *direct { "direct" } else { "pool-routed" }
        ),
    }
}

fn find_user<'a>(users: &'a UsersConfig, name: &str) -> Result<&'a User> {
    users
        .users
        .iter()
        .find(|u| u.name == name)
        .ok_or_else(|| anyhow!("user '{}' not found", name))
}

fn find_user_mut<'a>(users: &'a mut UsersConfig, name: &str) -> Result<&'a mut User> {
    users
        .users
        .iter_mut()
        .find(|u| u.name == name)
        .ok_or_else(|| anyhow!("user '{}' not found", name))
}

fn user_position(users: &UsersConfig, name: &str) -> Result<usize> {
    users
        .users
        .iter()
        .position(|u| u.name == name)
        .ok_or_else(|| anyhow!("user '{}' not found", name))
}

/// Read a password twice with no echo and confirm they match. On a
/// non-TTY stdin (CI / piped), reads a single line — useful for
/// scripted setup, but undocumented to keep the default workflow
/// interactive.
fn read_new_password() -> Result<String> {
    if !std::io::stdin().is_terminal() {
        let p = rpassword::read_password().context("read password from stdin")?;
        validate_password(&p)?;
        return Ok(p);
    }
    let p1 = rpassword::prompt_password("Password: ")?;
    validate_password(&p1)?;
    let p2 = rpassword::prompt_password("Confirm password: ")?;
    if p1 != p2 {
        bail!("passwords did not match");
    }
    Ok(p1)
}

fn confirm(msg: &str) -> Result<bool> {
    use std::io::{stdin, stdout, Write};
    print!("{} [y/N] ", msg);
    stdout().flush()?;
    let mut answer = String::new();
    stdin().read_line(&mut answer)?;
    Ok(matches!(answer.trim(), "y" | "Y" | "yes" | "Yes"))
}

fn validate_name(name: &str) -> Result<()> {
    if name.is_empty() {
        bail!("username is empty");
    }
    if name.len() > 255 {
        bail!("username too long (max 255 bytes per RFC 1929)");
    }
    if name.contains(':') {
        bail!("username contains ':' — would collide with the SOCKS5 user/pass parser");
    }
    Ok(())
}

fn validate_password(password: &str) -> Result<()> {
    if password.is_empty() {
        bail!("empty password");
    }
    if password.len() > 255 {
        bail!("password too long (max 255 bytes per RFC 1929)");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::Duration;

    use crate::config::load_or_init::load_or_init_users_at;

    fn fresh() -> UsersConfig {
        UsersConfig { users: vec![] }
    }

    fn temp_users_path(tag: &str) -> std::path::PathBuf {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let i = COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "resocks5_cli_test_{}_{}_{}.ktav",
            std::process::id(),
            tag,
            i
        ))
    }

    fn user_with_hash(name: &str, hash: &str) -> User {
        User {
            name: name.to_string(),
            hash: hash.to_string(),
            is_enabled: true,
            direct: false,
        }
    }

    #[test]
    fn add_init_creates_user_with_sentinel_hash() {
        let u = fresh();
        let op = add_init_user(&u, "alice").unwrap();
        let UserOp::AddInit(added) = op else {
            panic!("expected AddInit op");
        };
        assert_eq!(added.name, "alice");
        assert_eq!(added.hash, "init");
        assert!(added.is_enabled);
    }

    #[test]
    fn add_init_rejects_duplicate_name() {
        // add_init_user validates against the list it is given without
        // mutating it, so the colliding user must already be present.
        let u = UsersConfig {
            users: vec![user_with_hash("alice", "init")],
        };
        let err = add_init_user(&u, "alice").unwrap_err();
        assert!(err.to_string().contains("already exists"));
    }

    #[test]
    fn apply_add_init_rejects_duplicate_at_commit_time() {
        let mut u = fresh();
        let op = add_init_user(&fresh(), "alice").unwrap();
        apply_op(&op, &mut u).unwrap();
        assert_eq!(u.users.len(), 1);
        let err = apply_op(&op, &mut u).unwrap_err();
        assert!(err.to_string().contains("already exists"));
        assert_eq!(u.users.len(), 1, "failed apply must not half-add");
    }

    #[test]
    fn add_init_rejects_existing_user_regardless_of_hash() {
        // The clash check is by name — pre-existing real Argon2id user
        // must also block an add-init of the same name (otherwise
        // someone could silently downgrade a real account to a
        // claim-on-first-login state).
        let u = UsersConfig {
            users: vec![User {
                name: "bob".into(),
                hash: "$argon2id$v=19$m=5120,t=2,p=1$abc$def".into(),
                is_enabled: true,
                direct: false,
            }],
        };
        let err = add_init_user(&u, "bob").unwrap_err();
        assert!(err.to_string().contains("already exists"));
    }

    #[test]
    fn add_init_validates_name() {
        let u = fresh();
        let err = add_init_user(&u, "").unwrap_err();
        assert!(err.to_string().contains("empty"));

        let err = add_init_user(&u, "has:colon").unwrap_err();
        assert!(err.to_string().contains("':'"));

        let long: String = "x".repeat(256);
        let err = add_init_user(&u, &long).unwrap_err();
        assert!(err.to_string().contains("too long"));
    }

    #[test]
    fn validate_password_enforces_socks5_length_bounds() {
        // 256 single-byte chars: over the RFC 1929 one-byte PASSWD
        // length prefix.
        let err = validate_password(&"a".repeat(256)).unwrap_err();
        assert!(err.to_string().contains("too long"));

        // "é" is two bytes in UTF-8: 128 characters but 256 bytes —
        // the limit is byte length, not character count.
        assert_eq!("é".repeat(128).len(), 256);
        let err = validate_password(&"é".repeat(128)).unwrap_err();
        assert!(err.to_string().contains("too long"));

        // Boundaries stay legal: 1 byte, 255 bytes, and 127 two-byte
        // chars + 1 ASCII char = 255 bytes.
        assert!(validate_password("x").is_ok());
        assert!(validate_password(&"a".repeat(255)).is_ok());
        let mixed_255 = format!("{}x", "é".repeat(127));
        assert_eq!(mixed_255.len(), 255);
        assert!(validate_password(&mixed_255).is_ok());

        // Empty is still rejected, with the original message.
        let err = validate_password("").unwrap_err();
        assert!(err.to_string().contains("empty"));
    }

    #[test]
    fn add_init_independent_of_existing_real_users() {
        // Coexists with normally-managed accounts.
        let u = UsersConfig {
            users: vec![User {
                name: "alice".into(),
                hash: "$argon2id$v=19$m=5120,t=2,p=1$abc$def".into(),
                is_enabled: true,
                direct: false,
            }],
        };
        let op = add_init_user(&u, "bob").unwrap();
        let mut after = u.clone();
        apply_op(&op, &mut after).unwrap();
        assert_eq!(after.users.len(), 2);
        assert_eq!(after.users[0].name, "alice");
        assert_eq!(after.users[1].name, "bob");
        assert_eq!(after.users[1].hash, "init");
        // Alice's hash is unchanged.
        assert!(after.users[0].hash.starts_with("$argon2id$"));
    }

    #[test]
    fn direct_command_flips_flag_in_users_config() {
        let mut u = UsersConfig {
            users: vec![User {
                name: "alice".into(),
                hash: "init".into(),
                is_enabled: true,
                direct: false,
            }],
        };
        let op = set_direct(&u, "alice", true).unwrap();
        apply_op(&op, &mut u).unwrap();
        assert!(u.users[0].direct);
    }

    #[test]
    fn pool_command_flips_flag_back_to_false() {
        let mut u = UsersConfig {
            users: vec![User {
                name: "alice".into(),
                hash: "init".into(),
                is_enabled: true,
                direct: true,
            }],
        };
        let op = set_direct(&u, "alice", false).unwrap();
        apply_op(&op, &mut u).unwrap();
        assert!(!u.users[0].direct);
    }

    #[test]
    fn direct_command_unknown_user_errors_without_mutating() {
        let mut u = fresh();
        let op = add_init_user(&fresh(), "alice").unwrap();
        apply_op(&op, &mut u).unwrap();

        let err = set_direct(&u, "nobody", true).unwrap_err();
        assert!(err.to_string().contains("not found"));

        // Apply-time re-validation also rejects unknown names.
        let op = UserOp::SetDirect {
            name: "nobody".into(),
            direct: true,
        };
        assert!(apply_op(&op, &mut u).is_err());
        assert!(!u.users[0].direct);
    }

    #[test]
    fn set_enabled_op_flips_flag_at_apply_time() {
        let mut u = UsersConfig {
            users: vec![User {
                name: "alice".into(),
                hash: "init".into(),
                is_enabled: false,
                direct: false,
            }],
        };
        let op = set_enabled(&u, "alice", true).unwrap();
        apply_op(&op, &mut u).unwrap();
        assert!(u.users[0].is_enabled);
    }

    #[test]
    fn set_password_op_updates_hash_at_apply_time() {
        let mut u = UsersConfig {
            users: vec![User {
                name: "alice".into(),
                hash: "old".into(),
                is_enabled: true,
                direct: false,
            }],
        };
        let op = UserOp::SetPassword {
            name: "alice".into(),
            hash: "new".into(),
        };
        apply_op(&op, &mut u).unwrap();
        assert_eq!(u.users[0].hash, "new");
    }

    #[test]
    fn remove_op_removes_only_named_user() {
        let mut u = UsersConfig {
            users: vec![user_with_hash("alice", "h1"), user_with_hash("bob", "h2")],
        };
        let op = UserOp::Remove {
            name: "alice".into(),
        };
        apply_op(&op, &mut u).unwrap();
        assert_eq!(u.users.len(), 1);
        assert_eq!(u.users[0].name, "bob");
    }

    #[test]
    fn remove_op_built_for_existing_user() {
        // Non-TTY stdin in tests → no confirmation prompt.
        let u = UsersConfig {
            users: vec![user_with_hash("alice", "h1")],
        };
        let op = remove_user(&u, "alice", true).unwrap().unwrap();
        let UserOp::Remove { name } = op else {
            panic!("expected Remove op");
        };
        assert_eq!(name, "alice");

        assert!(remove_user(&u, "nobody", true).is_err());
    }

    #[test]
    fn add_init_user_defaults_to_pool_mode() {
        let u = fresh();
        let op = add_init_user(&u, "carol").unwrap();
        let UserOp::AddInit(added) = op else {
            panic!("expected AddInit op");
        };
        assert!(!added.direct);
    }

    #[test]
    fn build_added_user_defaults_to_pool_mode() {
        let user = build_added_user("dave", "somehash".into());
        assert!(!user.direct);
        assert!(user.is_enabled);
        assert_eq!(user.name, "dave");
    }

    // ─── commit-time merge with on-disk state (R13, CLI side) ───────

    #[test]
    fn commit_applies_op_on_top_of_current_disk_state() {
        let path = temp_users_path("merge");
        // On-disk state written by someone else (the server or a second
        // CLI) AFTER our command loaded an empty user list.
        write_atomic(
            &path,
            &UsersConfig {
                users: vec![user_with_hash("alice", "hash-a")],
            },
        )
        .unwrap();

        // Our op was built against the stale (empty) snapshot.
        let op = UserOp::AddInit(User {
            name: "carol".into(),
            hash: "init".into(),
            is_enabled: true,
            direct: false,
        });
        commit_op_to(&path, &op).unwrap();

        // Final file must contain BOTH the external edit and our change.
        let loaded: UsersConfig = ktav::from_file(&path).unwrap();
        assert_eq!(loaded.users.len(), 2);
        assert_eq!(
            loaded
                .users
                .iter()
                .find(|u| u.name == "alice")
                .unwrap()
                .hash,
            "hash-a"
        );
        assert_eq!(
            loaded
                .users
                .iter()
                .find(|u| u.name == "carol")
                .unwrap()
                .hash,
            "init"
        );

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn commit_add_rejects_name_that_appeared_on_disk() {
        let path = temp_users_path("collide");
        write_atomic(
            &path,
            &UsersConfig {
                users: vec![user_with_hash("alice", "hash-a")],
            },
        )
        .unwrap();

        let op = UserOp::Add(User {
            name: "alice".into(),
            hash: "hash-new".into(),
            is_enabled: true,
            direct: false,
        });
        let err = commit_op_to(&path, &op).unwrap_err();
        assert!(err.to_string().contains("already exists"));

        // Disk state is untouched by the failed commit.
        let loaded: UsersConfig = ktav::from_file(&path).unwrap();
        assert_eq!(loaded.users.len(), 1);
        assert_eq!(loaded.users[0].hash, "hash-a");

        let _ = std::fs::remove_file(&path);
    }

    // ─── R8-05: lock must not span the success report ───────────────

    /// A unique temp DIRECTORY for the users-only load tests, following
    /// the load_or_init.rs `unique_dir` pattern.
    fn unique_cli_dir() -> std::path::PathBuf {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let i = COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("resocks5_cli_r806_{}_{}", std::process::id(), i));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn users_file_lock_released_before_report_prints() {
        let path = temp_users_path("lock_release");
        write_atomic(&path, &fresh()).unwrap();

        let op = UserOp::AddInit(User {
            name: "carol".into(),
            hash: "init".into(),
            is_enabled: true,
            direct: false,
        });

        // This is commit_op_to's mutating work; its lock scope ends
        // here — the guard is dropped when commit_op_locked returns.
        commit_op_locked(&path, &op).unwrap();

        // If the guard were still held across the report/print step,
        // this acquisition must time out and fail.
        let probe_path = path.clone();
        let probe = std::thread::spawn(move || {
            UsersFileLock::acquire_with_timeout(&probe_path, Duration::from_secs(5)).unwrap()
        });
        let probe_lock = probe
            .join()
            .expect("probe must acquire the lock once commit_op_locked returned");
        drop(probe_lock);

        // The success print happens only after the lock was proven
        // free — commit first, report after.
        report(&op);

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(format!("{}.lock", path.display()));
    }

    #[test]
    fn users_only_load_succeeds_despite_broken_or_absent_sibling_configs() {
        // Scenario 1: a MALFORMED sibling config. The old shared
        // load_or_init() aborted the whole command on the unreadable
        // proxy list; the users-only path must not even parse it.
        let dir = unique_cli_dir();
        let users_path = dir.join(config::USERS_PATH);
        write_atomic(
            &users_path,
            &UsersConfig {
                users: vec![user_with_hash("alice", "hash-a")],
            },
        )
        .unwrap();
        let proxy_path = dir.join(config::PROXY_LIST_PATH);
        std::fs::write(&proxy_path, "this is definitely not a ktav document\n").unwrap();

        // The exact call run_user_command now makes.
        let users = load_or_init_users_at(&users_path).unwrap();
        assert_eq!(users.users.len(), 1);
        assert_eq!(users.users[0].name, "alice");

        // Prove the sibling really is unparseable — the old shared
        // load_or_init path would have failed on it.
        assert!(ktav::from_file::<config::ProxyListConfig, _>(&proxy_path).is_err());
        assert!(
            !dir.join(config::MAIN_PATH).exists(),
            "users subcommands must not create other configs as a side effect"
        );
        let _ = std::fs::remove_dir_all(&dir);

        // Scenario 2: an ABSENT sibling. The old full load_or_init
        // would have created an empty proxy list here as a side
        // effect; the users-only path must leave it untouched.
        let dir = unique_cli_dir();
        let users_path = dir.join(config::USERS_PATH);
        write_atomic(
            &users_path,
            &UsersConfig {
                users: vec![user_with_hash("bob", "hash-b")],
            },
        )
        .unwrap();

        let users = load_or_init_users_at(&users_path).unwrap();
        assert_eq!(users.users.len(), 1);
        assert!(users_path.exists(), "users file must exist afterwards");
        assert!(
            !dir.join(config::PROXY_LIST_PATH).exists(),
            "users subcommands must not create the proxy list as a side effect"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
