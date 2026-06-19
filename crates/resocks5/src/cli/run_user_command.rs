use std::io::IsTerminal;

use anyhow::{anyhow, bail, Context, Result};

use crate::auth;
use crate::cli::UserAction;
use crate::config::{self, User, UsersConfig};

/// Run the user-management subcommand and return. The caller dispatches
/// to the server in the absence of a subcommand. Configs are auto-created
/// here too — running `resocks5 users add admin` on a fresh install must
/// just work; users shouldn't have to start the server first.
pub fn run_user_command(action: UserAction) -> Result<()> {
    let configs = config::load_or_init()?;
    let mut users = configs.users;

    match action {
        UserAction::Add { name } => add_user(&mut users, &name)?,
        UserAction::AddInit { name } => add_init_user(&mut users, &name)?,
        UserAction::SetPassword { name } => set_password(&mut users, &name)?,
        UserAction::Remove { name, yes } => remove_user(&mut users, &name, yes)?,
        UserAction::List => return list_users(&users),
        UserAction::Enable { name } => set_enabled(&mut users, &name, true)?,
        UserAction::Disable { name } => set_enabled(&mut users, &name, false)?,
        UserAction::Direct { name } => set_direct(&mut users, &name, true)?,
        UserAction::Pool { name } => set_direct(&mut users, &name, false)?,
    }

    write_users(&users)?;
    Ok(())
}

fn add_user(users: &mut UsersConfig, name: &str) -> Result<()> {
    validate_name(name)?;
    if users.users.iter().any(|u| u.name == name) {
        bail!("user '{}' already exists", name);
    }
    let password = read_new_password()?;
    let hash = auth::compute_hash(&password)?;
    let user = build_added_user(name, hash);
    users.users.push(user);
    println!("Added user '{}'.", name);
    Ok(())
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
fn add_init_user(users: &mut UsersConfig, name: &str) -> Result<()> {
    validate_name(name)?;
    if users.users.iter().any(|u| u.name == name) {
        bail!("user '{}' already exists", name);
    }
    users.users.push(User {
        name: name.to_string(),
        hash: "init".to_string(),
        is_enabled: true,
        direct: false,
    });
    println!(
        "Added user '{}' with placeholder hash. The first client to authenticate \
         as this user claims the password.",
        name
    );
    Ok(())
}

fn set_password(users: &mut UsersConfig, name: &str) -> Result<()> {
    let user = users
        .users
        .iter_mut()
        .find(|u| u.name == name)
        .ok_or_else(|| anyhow!("user '{}' not found", name))?;
    let password = read_new_password()?;
    user.hash = auth::compute_hash(&password)?;
    println!("Updated password for user '{}'.", name);
    Ok(())
}

fn remove_user(users: &mut UsersConfig, name: &str, skip_confirm: bool) -> Result<()> {
    let pos = users
        .users
        .iter()
        .position(|u| u.name == name)
        .ok_or_else(|| anyhow!("user '{}' not found", name))?;
    if !skip_confirm && std::io::stdin().is_terminal() {
        let confirmed = confirm(&format!("Remove user '{}'?", name))?;
        if !confirmed {
            println!("Cancelled.");
            return Ok(());
        }
    }
    users.users.remove(pos);
    println!("Removed user '{}'.", name);
    Ok(())
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

fn set_enabled(users: &mut UsersConfig, name: &str, enabled: bool) -> Result<()> {
    let user = users
        .users
        .iter_mut()
        .find(|u| u.name == name)
        .ok_or_else(|| anyhow!("user '{}' not found", name))?;
    user.is_enabled = enabled;
    println!(
        "User '{}' is now {}.",
        name,
        if enabled { "enabled" } else { "disabled" }
    );
    Ok(())
}

fn set_direct(users: &mut UsersConfig, name: &str, direct: bool) -> Result<()> {
    let user = users
        .users
        .iter_mut()
        .find(|u| u.name == name)
        .ok_or_else(|| anyhow!("user '{}' not found", name))?;
    user.direct = direct;
    println!(
        "User '{}' is now {}.",
        name,
        if direct { "direct" } else { "pool-routed" }
    );
    Ok(())
}

/// Read a password twice with no echo and confirm they match. On a
/// non-TTY stdin (CI / piped), reads a single line — useful for
/// scripted setup, but undocumented to keep the default workflow
/// interactive.
fn read_new_password() -> Result<String> {
    if !std::io::stdin().is_terminal() {
        let p = rpassword::read_password().context("read password from stdin")?;
        if p.is_empty() {
            bail!("empty password");
        }
        return Ok(p);
    }
    let p1 = rpassword::prompt_password("Password: ")?;
    if p1.is_empty() {
        bail!("empty password");
    }
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

fn write_users(users: &UsersConfig) -> Result<()> {
    ktav::to_file(users, config::USERS_PATH)
        .with_context(|| format!("write {}", config::USERS_PATH))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fresh() -> UsersConfig {
        UsersConfig { users: vec![] }
    }

    #[test]
    fn add_init_creates_user_with_sentinel_hash() {
        let mut u = fresh();
        add_init_user(&mut u, "alice").unwrap();
        assert_eq!(u.users.len(), 1);
        let added = &u.users[0];
        assert_eq!(added.name, "alice");
        assert_eq!(added.hash, "init");
        assert!(added.is_enabled);
    }

    #[test]
    fn add_init_rejects_duplicate_name() {
        let mut u = fresh();
        add_init_user(&mut u, "alice").unwrap();
        let err = add_init_user(&mut u, "alice").unwrap_err();
        assert!(err.to_string().contains("already exists"));
        // Still only one user — no half-added state.
        assert_eq!(u.users.len(), 1);
    }

    #[test]
    fn add_init_rejects_existing_user_regardless_of_hash() {
        // The clash check is by name — pre-existing real Argon2id user
        // must also block an add-init of the same name (otherwise
        // someone could silently downgrade a real account to a
        // claim-on-first-login state).
        let mut u = UsersConfig {
            users: vec![User {
                name: "bob".into(),
                hash: "$argon2id$v=19$m=5120,t=2,p=1$abc$def".into(),
                is_enabled: true,
                direct: false,
            }],
        };
        let err = add_init_user(&mut u, "bob").unwrap_err();
        assert!(err.to_string().contains("already exists"));
        // Original hash untouched.
        assert!(u.users[0].hash.starts_with("$argon2id$"));
    }

    #[test]
    fn add_init_validates_name() {
        let mut u = fresh();
        let err = add_init_user(&mut u, "").unwrap_err();
        assert!(err.to_string().contains("empty"));
        assert!(u.users.is_empty());

        let err = add_init_user(&mut u, "has:colon").unwrap_err();
        assert!(err.to_string().contains("':'"));
        assert!(u.users.is_empty());

        let long: String = "x".repeat(256);
        let err = add_init_user(&mut u, &long).unwrap_err();
        assert!(err.to_string().contains("too long"));
        assert!(u.users.is_empty());
    }

    #[test]
    fn add_init_independent_of_existing_real_users() {
        // Coexists with normally-managed accounts.
        let mut u = UsersConfig {
            users: vec![User {
                name: "alice".into(),
                hash: "$argon2id$v=19$m=5120,t=2,p=1$abc$def".into(),
                is_enabled: true,
                direct: false,
            }],
        };
        add_init_user(&mut u, "bob").unwrap();
        assert_eq!(u.users.len(), 2);
        assert_eq!(u.users[1].name, "bob");
        assert_eq!(u.users[1].hash, "init");
        // Alice's hash is unchanged.
        assert!(u.users[0].hash.starts_with("$argon2id$"));
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
        set_direct(&mut u, "alice", true).unwrap();
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
        set_direct(&mut u, "alice", false).unwrap();
        assert!(!u.users[0].direct);
    }

    #[test]
    fn direct_command_unknown_user_errors_without_mutating() {
        let mut u = fresh();
        add_init_user(&mut u, "alice").unwrap();
        let snapshot_direct = u.users[0].direct;
        let err = set_direct(&mut u, "nobody", true).unwrap_err();
        assert!(err.to_string().contains("not found"));
        assert_eq!(u.users[0].direct, snapshot_direct);
    }

    #[test]
    fn add_init_user_defaults_to_pool_mode() {
        let mut u = fresh();
        add_init_user(&mut u, "carol").unwrap();
        assert!(!u.users[0].direct);
    }

    #[test]
    fn build_added_user_defaults_to_pool_mode() {
        let user = build_added_user("dave", "somehash".into());
        assert!(!user.direct);
        assert!(user.is_enabled);
        assert_eq!(user.name, "dave");
    }
}
