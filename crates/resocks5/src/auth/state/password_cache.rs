//! Verified-credential cache in front of the Argon2id derivation for the
//! clear-text login path (`PeerStore::check_password`).
//!
//! Only HMAC tags are stored — never the password, never the key `K`. The
//! cache key tags the (user, password) pair under a process-random master
//! key; the cached value tags the stored secret's key `K`, so any change to
//! the stored secret (set-password, disable, removal) invalidates the entry
//! even before the TTL does. The tags are useless without the master key,
//! which lives only in this process's memory.

use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;
use std::time::Duration;

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use tokio::time::Instant;
use zeroize::Zeroizing;

/// Maximum number of cached verified credentials.
pub(crate) const PASSWORD_CACHE_CAP: usize = 4096;
/// How long a verified credential stays valid.
pub(crate) const PASSWORD_CACHE_TTL: Duration = Duration::from_secs(300);

type HmacSha256 = Hmac<Sha256>;
type Tag = [u8; 32];

struct Entry {
    /// Tag of the stored secret's key this credential was verified against.
    k_tag: Tag,
    /// Async-side insert time plus the TTL.
    expires: Instant,
}

#[derive(Default)]
struct Inner {
    map: HashMap<Tag, Entry>,
    /// Insertion order for FIFO eviction; may briefly hold stale tags.
    order: VecDeque<Tag>,
}

/// Bounded TTL cache of verified clear-text credentials, keyed by
/// HMAC tags under a process-random master key.
pub(super) struct PasswordCache {
    master: Zeroizing<[u8; 32]>,
    inner: Mutex<Inner>,
}

impl PasswordCache {
    /// A cache with a fresh process-random master key.
    pub(super) fn generate() -> Result<Self, getrandom::Error> {
        let mut master = Zeroizing::new([0u8; 32]);
        getrandom::fill(master.as_mut_slice())?;
        Ok(Self {
            master,
            inner: Mutex::new(Inner::default()),
        })
    }

    fn mac(&self, message: &[u8]) -> Tag {
        let mut mac = HmacSha256::new_from_slice(self.master.as_slice())
            .expect("a 32-byte key is valid for HMAC-SHA256");
        mac.update(message);
        mac.finalize().into_bytes().into()
    }

    /// Cache key for a (user, password) pair: `HMAC(master, "pw" || user ||
    /// 0x00 || password)`.
    pub(super) fn tag(&self, user: &str, password: &str) -> Tag {
        let mut message = Vec::with_capacity(2 + user.len() + password.len());
        message.extend_from_slice(b"pw");
        message.extend_from_slice(user.as_bytes());
        message.push(0);
        message.extend_from_slice(password.as_bytes());
        self.mac(&message)
    }

    /// Validator for a stored secret's key: `HMAC(master, "K" || k)`. A hit
    /// requires this to match, so a changed stored secret invalidates.
    pub(super) fn tag_of(&self, k: &[u8]) -> Tag {
        let mut message = Vec::with_capacity(1 + k.len());
        message.push(b'K');
        message.extend_from_slice(k);
        self.mac(&message)
    }

    /// `true` when `tag` names a live entry whose stored-secret tag is
    /// `k_tag` (constant-time compare) and which has not expired. An expired
    /// match is dropped.
    pub(super) fn lookup(&self, tag: &Tag, k_tag: &Tag) -> bool {
        let mut inner = self.inner.lock().expect("password cache poisoned");
        let Some(entry) = inner.map.get(tag) else {
            return false;
        };
        if !bool::from(k_tag.ct_eq(&entry.k_tag)) {
            return false;
        }
        if entry.expires <= Instant::now() {
            inner.map.remove(tag);
            return false;
        }
        true
    }

    /// Cache a verified credential. When full: drop expired entries first,
    /// then evict the oldest until under the cap.
    pub(super) fn insert(&self, tag: Tag, k_tag: Tag) {
        let mut guard = self.inner.lock().expect("password cache poisoned");
        let Inner { map, order } = &mut *guard;
        order.push_back(tag);
        map.insert(
            tag,
            Entry {
                k_tag,
                expires: Instant::now() + PASSWORD_CACHE_TTL,
            },
        );
        if map.len() > PASSWORD_CACHE_CAP {
            let now = Instant::now();
            order.retain(|t| {
                let keep = map.get(t).is_some_and(|e| e.expires > now);
                if !keep {
                    map.remove(t);
                }
                keep
            });
            while map.len() > PASSWORD_CACHE_CAP {
                let Some(oldest) = order.pop_front() else {
                    break;
                };
                map.remove(&oldest);
            }
        }
    }

    /// Test-only: insert a dummy entry under `tag` through the real insert
    /// path (eviction included), without any derivation.
    #[cfg(test)]
    pub(super) fn insert_dummy(&self, tag: Tag) {
        self.insert(tag, [0; 32]);
    }

    /// Test-only inspector: current number of live entries.
    #[cfg(test)]
    pub(super) fn len(&self) -> usize {
        self.inner
            .lock()
            .expect("password cache poisoned")
            .map
            .len()
    }

    /// Test-only inspector: is `tag` present (live or not)?
    #[cfg(test)]
    pub(super) fn contains(&self, tag: &Tag) -> bool {
        self.inner
            .lock()
            .expect("password cache poisoned")
            .map
            .contains_key(tag)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn distinct_tag(seed: usize) -> Tag {
        let mut t = [0u8; 32];
        t[..8].copy_from_slice(&(seed as u64).to_le_bytes());
        t
    }

    /// Tags are deterministic for the same pair and distinct across users
    /// and passwords. Mutation: embedding the password in the tag directly
    /// (or dropping the separator) makes cross-user collisions possible and
    /// fails the distinctness assertions.
    #[test]
    fn tags_are_stable_and_distinct() {
        let cache = PasswordCache::generate().unwrap();
        let a1 = cache.tag("alice", "pw");
        assert_eq!(a1, cache.tag("alice", "pw"), "same pair, same tag");
        assert_ne!(a1, cache.tag("alice", "other"));
        assert_ne!(a1, cache.tag("bob", "pw"), "same password, other user");
        assert_ne!(
            cache.tag_of(b"k1"),
            cache.tag_of(b"k2"),
            "different keys tag differently"
        );
    }

    /// The cache never grows past the cap; the earliest-inserted tags are
    /// evicted first. Mutation: removing the eviction lets the map grow past
    /// `PASSWORD_CACHE_CAP`.
    #[test]
    fn the_cache_is_bounded_and_evicts_oldest() {
        let cache = PasswordCache::generate().unwrap();
        for i in 0..(PASSWORD_CACHE_CAP + 100) {
            cache.insert_dummy(distinct_tag(i));
        }
        assert!(cache.len() <= PASSWORD_CACHE_CAP);
        assert!(!cache.contains(&distinct_tag(0)), "oldest evicted");
        assert!(
            cache.contains(&distinct_tag(PASSWORD_CACHE_CAP + 99)),
            "newest kept"
        );
    }

    /// An expired entry is dropped on lookup. Mutation: removing the expiry
    /// check makes the lookup answer `true` after the TTL has passed.
    #[tokio::test(start_paused = true)]
    async fn an_expired_entry_is_not_a_hit() {
        let cache = PasswordCache::generate().unwrap();
        let tag = cache.tag("alice", "pw");
        let k_tag = cache.tag_of(b"key");
        cache.insert(tag, k_tag);
        assert!(cache.lookup(&tag, &k_tag), "live entry is a hit");
        tokio::time::advance(PASSWORD_CACHE_TTL + Duration::from_secs(1)).await;
        assert!(!cache.lookup(&tag, &k_tag), "expired entry is a miss");
    }
}
