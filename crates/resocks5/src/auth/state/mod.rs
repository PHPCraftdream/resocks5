use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex, RwLock};

use anyhow::{anyhow, Result};
use resocks5_net::secure_auth::{DecoyKey, KdfParams, StoredUser};
use tokio::sync::Semaphore;

use crate::auth::params::enrollment_floor;
use crate::auth::secret::parse_secret;
use crate::config::{AuthConfig, User, UsersConfig};

mod claim;
pub(crate) mod gssapi;
mod store;

pub(crate) use claim::INIT_HASH;
pub use store::PeerStore;

#[cfg(test)]
mod tests;

struct UserEntry {
    index: usize,
    enabled: bool,
    direct: bool,
    /// Скомпилированное при старте пользовательское правило
    /// `allowed_clients` (`None` = не ограничивает). Снапшот запуска:
    /// пере-компиляции в рантайме нет.
    allowed: Option<crate::config::AllowedClients>,
}

/// Server-side auth bundle, built once at startup and shared with each
/// connection-handling task via `Arc<AuthState>`: the users list as loaded
/// from disk, the policy flag, and the decoy key for unknown names. Each
/// connection authenticates through a [`PeerStore`] (`peer_store`), which
/// adds the user's `allowed_clients` rule for that peer.
///
/// Users are a startup snapshot: CLI password and policy changes require a
/// server restart. Only init enrollments update the stored secrets at runtime.
///
/// ## Init-on-first-login
///
/// A user whose `hash` is the literal string `"init"` is a placeholder: the
/// first client that authenticates as it enrolls its secret (sealed, see
/// `resocks5_net::secure_auth`), which is written into both the in-memory
/// state and `resocks5.users.ktav`; from then on it is a normal account.
/// Concurrent enrollments serialise on `claim_lock` (held across the
/// cross-process persist) and re-check the sentinel under it, so exactly one
/// wins; the losers are denied and log in normally afterwards. Persistence
/// runs on the blocking pool behind its own admission cap (`claim_slots`).
pub struct AuthState {
    /// `RwLock`: enrollment is the only writer, lookups read in parallel.
    /// Guards are held only briefly; persistence runs outside them.
    users: RwLock<Vec<User>>,
    /// Serialises enrollments within this process, across the re-check,
    /// the persist and the publish. The cross-process `UsersFileLock`
    /// inside `persist_claim` serialises against other processes. A std
    /// Mutex is correct: it is held only inside `spawn_blocking`.
    claim_lock: Mutex<()>,
    entries: HashMap<String, UserEntry>,
    /// Admission cap for enrollment persistence: the permit is awaited
    /// asynchronously before the `spawn_blocking` and moves into it, so a
    /// pile-up of enrollments occupies at most two blocking threads, and a
    /// cancelled waiter none.
    claim_slots: Arc<Semaphore>,
    /// Mirrors `auth.allow_anonymous` from `resocks5.main.ktav`. When
    /// `true`, the server advertises SOCKS5 method `0x00` to clients
    /// (and serves HTTP without Proxy-Authorization); when `false`, only
    /// authenticated clients are accepted.
    pub allow_anonymous: bool,
    /// Answers unknown, disabled and filtered names like a wrong password.
    decoy: DecoyKey,
    /// The cheapest derivation an enrollment may use.
    enrollment_floor: KdfParams,
    /// Path to `resocks5.users.ktav` (parameter so tests can point at a
    /// temp file). Used only by enrollment.
    users_path: String,
    /// GSSAPI acceptor, when `auth.gssapi_service` is set.
    #[cfg(feature = "gssapi")]
    gssapi: Option<resocks5_net::gssapi::GssAcceptor>,
}

impl AuthState {
    pub fn build(
        auth_cfg: &AuthConfig,
        users: &UsersConfig,
        users_path: impl Into<String>,
    ) -> Result<Self> {
        let users_path = users_path.into();
        let mut entries = HashMap::with_capacity(users.users.len());
        for (index, user) in users.users.iter().enumerate() {
            // Компилируем правило КАЖДОГО пользователя — включая disabled
            // и дубликаты имён: невалидная строка обязана валить старт с
            // понятной ошибкой, а не притворяться отсутствием правила.
            // Для дубликатов имени в `entries` попадает первая (first
            // wins) — как и раньше.
            let allowed = match &user.allowed_clients {
                Some(spec) => Some(crate::config::compile_allowed_clients(spec).map_err(|e| {
                    anyhow!(
                        "{users_path}: пользователь {:?}: allowed_clients: {e}",
                        user.name
                    )
                })?),
                None => None,
            };
            entries.entry(user.name.clone()).or_insert(UserEntry {
                index,
                enabled: user.is_enabled,
                direct: user.direct,
                allowed,
            });
        }
        warn_unusable_secrets(&users.users, &users_path);
        #[cfg(feature = "gssapi")]
        let gssapi = gssapi::configured_acceptor(auth_cfg)?;
        #[cfg(not(feature = "gssapi"))]
        gssapi::refuse_without_support(auth_cfg)?;
        Ok(Self {
            users: RwLock::new(users.users.clone()),
            claim_lock: Mutex::new(()),
            entries,
            claim_slots: Arc::new(Semaphore::new(2)),
            allow_anonymous: auth_cfg.allow_anonymous,
            decoy: DecoyKey::generate().map_err(|e| anyhow!("decoy key: {e}"))?,
            enrollment_floor: enrollment_floor(),
            users_path,
            #[cfg(feature = "gssapi")]
            gssapi,
        })
    }

    /// True when no users are configured.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Current number of configured users (including any unclaimed
    /// `hash == "init"` placeholders).
    pub fn users_count(&self) -> usize {
        self.entries.len()
    }

    /// The secret store for one connection from `peer_ip`.
    pub fn peer_store(self: &Arc<Self>, peer_ip: Option<IpAddr>) -> PeerStore {
        PeerStore::new(Arc::clone(self), peer_ip)
    }

    /// The decoy key for unknown names.
    pub fn decoy(&self) -> &DecoyKey {
        &self.decoy
    }

    /// Пользовательский фильтр IP. `None` у пользователя не ограничивает;
    /// неизвестное или выключенное имя → `false` (клиент получает обычный
    /// отказ аутентификации). Анонимный клиент (без credentials) сюда не
    /// попадает и подчиняется только глобальному правилу.
    pub(crate) fn client_ip_allowed(&self, name: &str, ip: Option<IpAddr>) -> bool {
        let Some(ip) = ip else {
            // Адрес недоступен — fail-closed.
            return false;
        };
        self.entries
            .get(name)
            .is_some_and(|u| u.enabled && u.allowed.as_ref().is_none_or(|r| r.matches(ip)))
    }

    /// Returns `true` when the named user exists, is enabled, and has
    /// `direct == true`. Returns `false` for missing, disabled, or
    /// pool-routed users.
    pub fn is_direct(&self, name: &str) -> bool {
        self.entries
            .get(name)
            .map(|u| u.enabled && u.direct)
            .unwrap_or(false)
    }

    /// What is stored for `name`: its secret, `Init` while unclaimed, or
    /// `None` for an unknown or disabled user or an unusable stored value
    /// (answered with the decoy).
    pub(crate) fn lookup_secret(&self, name: &str) -> Option<StoredUser> {
        let entry = self.entries.get(name).filter(|u| u.enabled)?;
        let users = self.users.read().expect("users RwLock poisoned");
        let hash = &users[entry.index].hash;
        if hash == INIT_HASH {
            return Some(StoredUser::Init);
        }
        parse_secret(hash).ok().map(StoredUser::Secret)
    }
}

/// Startup notice for accounts no client can log in to: a stored value that
/// is not a usable secret, or one derived more cheaply than a default client
/// accepts. Names only, never the values.
fn warn_unusable_secrets(users: &[User], users_path: &str) {
    for user in users
        .iter()
        .filter(|u| u.is_enabled && u.hash != INIT_HASH && u.hash != gssapi::GSSAPI_HASH)
    {
        match parse_secret(&user.hash) {
            Err(e) => eprintln!(
                "{users_path}: user {:?}: stored hash unusable ({e}); \
                 reset it with `resocks5 user set-password`",
                user.name
            ),
            Ok(secret) if !secret.params.at_least(&KdfParams::DEFAULT) => eprintln!(
                "{users_path}: user {:?}: secret derived below the client default \
                 (m=19456,t=2,p=1); default clients refuse it — reset it with `resocks5 user set-password`",
                user.name
            ),
            Ok(_) => {}
        }
    }
}
