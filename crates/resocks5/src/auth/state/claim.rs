use std::path::Path;
use std::sync::Arc;

use anyhow::anyhow;
use resocks5_net::secure_auth::UserSecret;

use super::AuthState;
use crate::auth::secret::encode_secret;
use crate::config::users_file::{write_atomic, UsersFileLock};
use crate::config::{User, UsersConfig};

/// Sentinel value placed in a `User.hash` to indicate that the secret has
/// not been chosen yet — the first enrolling client sets it. Anything else
/// is treated as a stored secret.
pub(crate) const INIT_HASH: &str = "init";

impl AuthState {
    /// Store `secret` for `name` if, and only if, it is still `"init"`;
    /// `true` when this call stored it (in memory and on disk).
    ///
    /// cancel-safe: YES for the caller — an admitted persist finishes on the
    /// blocking pool even if this future is dropped; its permit and the
    /// claim mutex are held until it does.
    pub(crate) async fn claim_secret(self: &Arc<Self>, name: &str, secret: UserSecret) -> bool {
        let Some(index) = self
            .entries
            .get(name)
            .filter(|u| u.enabled)
            .map(|u| u.index)
        else {
            return false;
        };
        if !self.is_unclaimed(index) {
            return false;
        }
        let Ok(permit) = self.claim_slots.clone().acquire_owned().await else {
            return false;
        };
        let stored = encode_secret(&secret);
        let state = Arc::clone(self);
        let name = name.to_owned();
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            state.claim_commit(&name, index, stored)
        })
        .await
        .unwrap_or(false)
    }

    /// The persist+publish critical section, serialised on `claim_lock`
    /// (not the users `RwLock`, so lookups proceed while the cross-process
    /// file I/O runs). The sentinel is re-checked under the lock: a racer
    /// queued behind a committed winner never reaches persistence.
    pub(super) fn claim_commit(&self, name: &str, index: usize, stored: String) -> bool {
        let _claim_guard = self.claim_lock.lock().expect("claim mutex poisoned");
        if !self.is_unclaimed(index) {
            return false;
        }
        // The fallback list is used only when the users file does not exist
        // yet; build it (a whole-list clone) only then.
        let fallback_users = if Path::new(&self.users_path).exists() {
            None
        } else {
            let mut snapshot = self.users.read().expect("users RwLock poisoned").clone();
            snapshot[index].hash = stored.clone();
            Some(snapshot)
        };
        // Persist on top of what is CURRENTLY on disk, not the startup
        // snapshot: a CLI process may have edited the file since.
        match persist_claim(Path::new(&self.users_path), name, &stored, fallback_users) {
            ClaimPersist::Written => {
                self.users.write().expect("users RwLock poisoned")[index].hash = stored;
                true
            }
            ClaimPersist::DiskHashChanged(disk_hash) => {
                // A secret landed on disk meanwhile (a concurrent CLI edit or
                // another server process): disk wins, adopt it.
                self.users.write().expect("users RwLock poisoned")[index].hash = disk_hash;
                false
            }
            ClaimPersist::Failed(e) => {
                eprintln!(
                    "init-claim: failed to persist {} after first login of '{}': {}",
                    self.users_path, name, e
                );
                false
            }
        }
    }

    fn is_unclaimed(&self, index: usize) -> bool {
        self.users.read().expect("users RwLock poisoned")[index].hash == INIT_HASH
    }
}

/// Outcome of the cross-process persist of an init-claim.
pub(super) enum ClaimPersist {
    /// The claimed secret was merged into the on-disk file.
    Written,
    /// The on-disk value for this user is no longer the `"init"` sentinel;
    /// carries it. Nothing was written.
    DiskHashChanged(String),
    /// Nothing was written; carries the reason.
    Failed(anyhow::Error),
}

/// Merge a single init-claim into the users file under the cross-process
/// file lock, then atomically replace the file.
///
/// `fallback_users` (the caller's full in-memory list, with the claimed
/// value already applied) is consumed only when the file does not exist
/// yet: the first claim then creates it. If the file vanished after the
/// caller looked, there is nothing to merge into and the claim fails closed.
pub(super) fn persist_claim(
    path: &Path,
    name: &str,
    stored: &str,
    fallback_users: Option<Vec<User>>,
) -> ClaimPersist {
    let _lock = match UsersFileLock::acquire(path) {
        Ok(lock) => lock,
        Err(e) => return ClaimPersist::Failed(e.context("acquire users-file lock")),
    };

    if !path.exists() {
        let Some(fallback_users) = fallback_users else {
            return ClaimPersist::Failed(anyhow!(
                "users file {} disappeared before the claim could be persisted",
                path.display()
            ));
        };
        let cfg = UsersConfig {
            users: fallback_users,
        };
        return match write_atomic(path, &cfg) {
            Ok(()) => ClaimPersist::Written,
            Err(e) => ClaimPersist::Failed(e),
        };
    }

    let mut disk: UsersConfig = match ktav::from_file(path) {
        Ok(cfg) => cfg,
        Err(e) => {
            return ClaimPersist::Failed(
                anyhow::Error::new(e).context(format!("read {}", path.display())),
            )
        }
    };

    let Some(user) = disk.users.iter_mut().find(|u| u.name == name) else {
        return ClaimPersist::Failed(anyhow!(
            "user '{}' no longer exists in {} — removed by a concurrent CLI edit, \
             not re-adding it",
            name,
            path.display()
        ));
    };

    if user.hash != INIT_HASH {
        return ClaimPersist::DiskHashChanged(user.hash.clone());
    }

    user.hash = stored.to_string();
    match write_atomic(path, &disk) {
        Ok(()) => ClaimPersist::Written,
        Err(e) => ClaimPersist::Failed(e),
    }
}
