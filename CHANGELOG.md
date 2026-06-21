# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-06-21

Initial public release. Workspace with two crates: `resocks5-net` (the
reusable networking toolkit) and `resocks5` (the CLI proxy server).

### Added

- **SOCKS5 + HTTP CONNECT** front end with auto-detection: a single listening
  port serves both protocols, distinguished by the first byte.
- **Upstream protocols:** SOCKS5 (RFC 1928), HTTP CONNECT, and HTTPS
  (TLS-wrapped CONNECT) proxies, with per-protocol IPv4/IPv6 lists.
- **Sand-rating soft-weight rotator:** every upstream has an exponentially
  decaying failure accumulator. Selection is weighted-random with
  `weight = exp(-K·sand)`, so failing upstreams are picked less often but
  never excluded, and recover automatically as their sand drains. When every
  upstream is bad the weights equalise into uniform round-robin.
- **Sticky cache:** per-target affinity to whichever upstream last succeeded
  for that target. On failure the cache entry is dropped and the next
  weighted draw picks fresh.
- **Gate chains:** a proxy entry prefixed `*` is a gate — `resocks5` tunnels
  through it before issuing the second handshake to the real upstream. The
  sticky cache stores `(gate, inner)` pairs.
- **Direct (bypass) users:** a `direct: true` flag in `users.ktav` makes the
  named user bypass the entire pool — traffic goes from the server's IP.
  Authenticated-only; capped by `max_concurrent_direct`.
- **Pre-warmed TCP pool:** background tasks keep a queue of TCP sockets to
  each unique upstream `(host, port)` so client requests skip the SYN
  round-trip. Stale entries (`max_session_age_sec`) are discarded.
- **Per-upstream concurrency cap:** `max_per_upstream` semaphore defends the
  provider's per-account/per-IP connection quota. Capacity-rejects are
  surfaced as a distinct `AtCapacity` error so the rotator can distinguish
  "our load" from real upstream failures and not sand healthy peers.
- **TLS ClientHello fragmentation:** optional splitting of the first TLS
  record across small TCP segments, defeating per-segment SNI-based DPI.
  `TCP_NODELAY` is enabled automatically when the feature is on.
- **Authentication:** Argon2id password hashing with PHC strings;
  init-on-first-login mode for placeholder accounts; in-memory HMAC verify
  cache for O(1) re-auth without re-running Argon2.
- **Safety nets:** connect/handshake/idle/lifetime timeouts, TCP keepalive,
  bounded log channel with non-blocking drops, max in-flight client cap,
  per-attempt upstream cap, slowloris-style protocol timeouts.
- **Banned patterns:** regex-list compiled into a single DFA, evaluated
  before any upstream attempt.
- **KTAV configuration:** three files (`resocks5.main.ktav`,
  `resocks5.proxy_list.ktav`, `resocks5.users.ktav`) auto-created on first
  run; `resocks5 config` prints the field reference.
- **CLI user management:** `resocks5 users add | add-init | set-password |
  enable | disable | remove | list | direct | pool`; passwords always read
  interactively from no-echo prompt, never via flags.
- **Configurable logging by category** with optional non-blocking file
  output (`file_log.enabled`, `file_log.also_console`).
- **Cross-platform:** Linux, Windows, macOS. Uses `ring` as the rustls
  crypto provider — no `cmake` or C toolchain required.
- **Library crate `resocks5-net`:** the networking core published separately
  so other projects can depend on the connectors, pool, rating model, and
  rotator without pulling in the CLI/config/auth layer. Public modules:
  `connect`, `pool`, `rating`, `rotator`, `types`. Example at
  `crates/resocks5-net/examples/connect_through_proxy.rs`.

### Security

- Argon2id PHC strings (per-user salt, configurable cost) for stored
  passwords.
- `RatingPolicy::default()` and `BreakerPolicy`-free design — no binary
  quarantines that could be weaponised against small pools.
- Direct-bypass users are documented as leaking the server's IP and DNS;
  opt-in only, never anonymous.

[Unreleased]: https://github.com/PHPCraftdream/resocks5/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/PHPCraftdream/resocks5/releases/tag/v0.1.0
