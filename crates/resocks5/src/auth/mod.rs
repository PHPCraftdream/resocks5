//! Argon2id-based user authentication with an in-memory verify-cache.
//!
//! Hashes are stored as PHC strings, e.g.
//! `$argon2id$v=19$m=19456,t=2,p=1$<salt>$<hash>`. The per-user random
//! salt makes two users with the same password produce different hashes
//! and prevents any "swap user, reuse hash" attack — the global_salt of
//! the old SHA512 design is no longer needed.
//!
//! ## Why Argon2id with these params
//!
//! `m=19456` (19 MiB) per attempt is the dominant cost: a top-end GPU with
//! 16 GiB VRAM can fit only ~800 parallel attempts, vs ~100 billion for
//! SHA256 — memory hardness is what kills the GPU/ASIC parallelism that
//! made the previous SHA512 hash trivially brute-forceable. `t=2` then
//! gives ~50 ms wall time on modern CPU, an additional 2× cost factor
//! on the time dimension. This is the OWASP minimum for Argon2id; it
//! applies to NEW hashes (CLI and init-claims). Existing PHC strings
//! keep verifying with the parameters embedded in them — verification
//! reads m/t/p from the hash itself, so old hashes work unchanged and
//! there is no rehash-on-login migration.
//!
//! ## In-memory cache
//!
//! ~50 ms per auth would be lethal for browser traffic (Firefox opens
//! tens of TCP sessions per page). On every successful Argon2 verify
//! we cache `HMAC-SHA256(server_secret, name || 0x00 || password)` keyed
//! by username, so subsequent connections from the same client
//! validate in nanoseconds. A 32-byte `server_secret` is generated once
//! at startup and never persisted — a memory dump cannot be replayed
//! in a later run, and the plaintext password never sits in process
//! memory for longer than the verify call itself. Failed attempts are
//! not cached (caching them would speed up brute-force).

pub mod compute_hash;
mod params;
pub mod state;

pub use compute_hash::compute_hash;
pub use state::AuthState;
