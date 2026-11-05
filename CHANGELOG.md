# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `resocks5-net`: secure auth (`secure_auth` module, feature `secure-auth`, on by
  default), SOCKS5 private method 0x80: the password never crosses the wire. The
  server stores a per-user Argon2id salt, parameters and the derived key `K`
  (`UserSecret`, behind the `SecretStore` trait); a login is a mutual HMAC-SHA256
  challenge-response over `K` with fresh nonces on both sides, so a recorded
  exchange cannot be replayed and a server without `K` cannot pass. Unknown users
  get a decoy (`DecoyKey`) indistinguishable from a wrong password; the client
  refuses server parameters below its floor (`KdfParams::DEFAULT`, 19 MiB / t=2 /
  p=1) and above hard limits.
- `resocks5-net`: init enrollment for `secure_auth`: a user stored as "waiting"
  (`StoredUser::Init`) is enrolled by its first client, which sends `K` sealed
  with X25519 + HKDF-SHA256 + ChaCha20-Poly1305 bound to both nonces;
  `SecretStore::claim` stores it atomically (one winner). A client enrolls only
  with `SecureCredentials::allow_enrollment(true)`.
- `resocks5-net`: `ProxyConfig::with_secure_auth(SecureCredentials)` — dial and
  chain hops authenticate to a SOCKS5 upstream with secure auth;
  `server::accept_secure(stream, options, store, decoy)` — inbound SOCKS5 with
  method 0x80 (or 0x00), never username/password; any HTTP `Proxy-Authorization`
  is answered 407.
- `resocks5-net`: `ProxyConfig::from_uri` / `from_uri_with(ProxyUriOptions)` parse
  `socks5://`, `http://`, `https://` URIs with percent-decoded credentials; the
  typed `ProxyUriError` never carries the input.
- `resocks5-net`: `ConnectError::suggested_reply()` maps a dial failure to the
  `server::Reply` to send the client (SOCKS5 REP 2/3/4/5/6, HTTP 403/502/503/504).
- `resocks5-net`: `connect::socks5_handshake_until` and
  `http_connect_handshake_until` run a handshake under an absolute deadline and
  fail with a typed `ConnectError::Timeout`.
- `resocks5-net`: `server::Credentials::basic_payload()` — the whole decoded HTTP
  Basic token, without splitting at `:`.
- `resocks5-net`: `DialOptions::with_nodelay` / `with_keepalive` (fields `nodelay`,
  `keepalive`) set `TCP_NODELAY` and TCP keepalive on the socket to the proxy
  (`dial`, `dial_chain`); by default the OS defaults stay. `connect::dial_tcp`
  returns the bare `TcpStream` of a SOCKS5 / HTTP CONNECT tunnel (HTTPS is refused
  before any connect).
- `resocks5-net`: `testing::MockUpstream` (feature `test-instrumentation`): a
  scripted SOCKS5 / HTTP CONNECT upstream on `127.0.0.1:0` for tests — `Script`
  (tunnel with echo, refuse with a REP/status, silent greeting, silent CONNECT,
  hang-up), `MockAuth` (none, clear-text, secure auth), and the recorded CONNECT
  targets.
- `resocks5-net`: `ProxyConfig::wipe_credentials()` (feature `zeroize`) overwrites
  and clears `user`/`password` at this node and every solely owned gate, and
  reports a shared gate it left untouched. Opt-in: `ProxyConfig` has no `Drop`.

### Changed

- `resocks5-net` (**breaking**): clear-text credentials are off by default. A
  client never sends a password in clear text (SOCKS5 username/password, HTTP
  Basic) unless feature `cleartext-client` is on — otherwise the dial fails with
  `ConnectError::CleartextCredentialsRefused` before any byte is sent; the server
  (`server::accept`) never offers or accepts them unless feature
  `cleartext-server` is on (SOCKS5 0x02 not chosen, HTTP Basic answered 407).
- `resocks5` (**breaking**): inbound users authenticate with secure auth only.
  SOCKS5 username/password and HTTP Basic are refused; standard clients
  (browsers, curl) can connect only anonymously, a password needs a
  `resocks5-net` client (`ProxyConfig::with_secure_auth`). HTTP CONNECT has no
  password authentication. Upstream proxy credentials work as before.
- `resocks5`: `users[].hash` keeps the Argon2id v19 PHC form; it is now read as
  the secure-auth key. Hashes written by earlier versions are exactly that, so
  existing accounts keep working with the same password. A stored value in
  another format, or derived below m=19456,t=2,p=1 (default clients refuse it),
  is reported at startup; reset it with `users set-password`.
- `resocks5`: `hash: init` accounts are claimed by the first enrolling client
  (only the sealed key travels); concurrent first logins have exactly one winner,
  the others are denied. A user filtered by `allowed_clients` is answered like a
  wrong password and cannot claim an init account.

### Removed

- `resocks5`: the server-side password verify path and its in-memory password
  cache: the server neither receives nor holds passwords and never runs Argon2
  for a login.

## [0.5.0] - 2026-11-05

### Added

- `resocks5-net`: `ProxyConfig::validate()`, `validate_node()` and
  `try_with_auth()` with the typed `ProxyConfigError`, `ChainConfigError` and
  `CredentialField`: host, port, gate flag, credential pairing, SOCKS5 1..=255 byte
  fields (RFC 1929) and HTTP Basic rules (no `:` in the username, no control
  characters, RFC 7617). No I/O, no values in error texts; the dial functions are
  unchanged.
- `resocks5-net`: `server::Reply::{ConnectionRefused, NetworkUnreachable, TimedOut}`
  (SOCKS5 REP 5 / 3 / 6, HTTP 502 / 502 / 504).
- `resocks5-net`: `server::Prefixed<S>` and `IncomingRequest::into_prefixed(stream)`
  serve the over-read request bytes before the stream.
- `resocks5-net`: `ServerOptions::retain_credentials`,
  `IncomingRequest::take_credentials` / `take_username` and
  `Credentials::into_parts`.
- `resocks5-net`: `ServerOptions::raw_credentials` with
  `Credentials::{username_bytes, password_bytes, is_utf8}` and
  `IncomingRequest::username_bytes`: SOCKS5 UNAME/PASSWD that are not valid UTF-8
  (a character split across the two fields at 255 bytes) are accepted as bytes.
- `resocks5-net`: `ServerOptions::strict_http`: opt-in RFC 9112 validation of the
  CONNECT request (bracketed IPv6, numeric port, HTTP/1.0 and 1.1 only with 505
  otherwise, a single `Host`, token header names, no obs-fold, one
  `Proxy-Authorization`); the default stays permissive.
- `resocks5-net`: optional feature `zeroize` wipes inbound credentials on drop.
- `resocks5-net`: `ProxyRotator::probe_due_with` and `probe_all_with` take a
  per-probe reservation hook (`Fn(&ProxyConfig) -> Option<guard>`): `None` defers
  the probe (no connection, no health change, no event), `Some(guard)` holds the
  guard for the probe. `probe_due` / `probe_all` are unchanged.
- `resocks5-net`: `chain::GateLevels::try_new` (duplicate ranks are an error in
  release builds too, `GateLevelsError`), `types::MAX_CHAIN_NODES` (64) with
  `ProxyConfigError::ChainTooLong`, `error::TimeoutKind::Socks5Greeting`, and
  `ProxyRotator::{take_probe_claims, record_success_for, record_hard_failure_for,
  quarantine_now_unless_tripped}` with `UpstreamProbeClaim`.
- `resocks5-net`: feature `test-instrumentation` adds `progress::ProgressScopeProbe`,
  an instance-scoped observer of confirmed write progress.
- CI: a `feature-unification` job builds the `tests/feature_unification` fixture,
  `release-behavior` runs a few release-mode suites on full runs, every job has a
  `timeout-minutes`, and `changed-areas.sh --self-test` pins the classifier.

### Changed

- `resocks5-net`: `ServerError::Authentication` texts no longer contain the
  submitted username, and `Debug` of `IncomingRequest` no longer prints the
  username or the pipeline bytes (`has_username`, `has_credentials` and
  `pipeline_len` instead).
- `resocks5-net`: `ProxyRotator` (and every constructor) now deduplicates identical
  upstreams (same endpoint, protocol, account and gate level) at construction,
  keeping the first occurrence; `len()` and `all_proxies()` describe unique
  upstreams. Before, events landed on the last duplicate while the first stayed
  selectable after a quarantine.
- `resocks5-net`: `connect_hedged` makes the TCP-ready to handshake step
  exclusive: a launched attempt that reaches its upstream while another one is
  handshaking waits and sends nothing, so the target never sees two CONNECTs;
  a `hedge_delay` too large for the monotonic clock means "never hedge".
- `resocks5-net`: `dial_chain` without a gate reports `ChainStage::Target` when the
  total timeout expires after the TCP connect (it said `Connect`).
- `resocks5`: `resocks5.health.ktav` records carry a `group` (`v6`, `v4`,
  `gate<rank>`); files from older builds still load and apply to every matching
  group.
- CI: a change under `crates/resocks5-net/src/session/chain/` runs the SDK `chain::`
  tests and the app `server::` tests instead of only building them.
- `resocks5-net`: strict HTTP validates the `Host` value as `uri-host [":" port]`
  (a path, userinfo or broken percent escape is rejected); the default stays
  permissive. A `Lost` hedge report carries `after_win == true` once a win is
  published.
- `resocks5`: direct probes and chain probes reserve a pool permit for the tested
  endpoint, so probes respect `max_per_upstream`; at capacity a probe is deferred,
  never counted as down. A chain probe runs under an absolute deadline from its
  claim, its result is discarded when it settles after its lease, and only an
  upstream's refusal of the final CONNECT quarantines the tested gate (prefix
  auth, TLS or greeting failures do not).
- `resocks5`: the health file is guarded by a cross-process lock
  (`resocks5.health.ktav.lock`, never deleted): a second instance in the same
  directory runs with health persistence disabled and one warning instead of
  deleting the running writer's temp; shutdown reports go through the log
  channel.
- `resocks5-net`: a SOCKS5 greeting that gets no reply within the handshake budget
  is `TimeoutKind::Socks5Greeting` and counts as upstream-down
  (`is_upstream_down`); a stalled CONNECT reply is still `Socks5Handshake`.
  `ProxyConfig` `Debug` renders the gate chain as a flat list (no recursion),
  and `ProxyConfig::validate` rejects chains over 64 nodes.
- `resocks5-net`: a chain probe outcome is bound to the claim that took the probe
  (generation token): a result for a slot that was reset, re-tripped or leased
  again meanwhile is dropped; only destination-unreachable replies (SOCKS5 REP
  3-6, HTTP 502-504) of the final CONNECT quarantine the tested gate.
- `resocks5`: new Argon2id hashes use m=19456 KiB, t=2, p=1 (OWASP minimum); stored
  hashes keep verifying with their own parameters. A stored hash that is not
  Argon2id v19 is rejected (it used to verify with the algorithm named in the
  string). `verify_async` runs the same single comparison (against a dummy)
  for unknown and disabled names, so the first step costs the same for every name.
- `resocks5`: cached chains honour the direct fallback reserve of
  `max_upstream_attempts` (a budget of 1 still serves the sticky cache first),
  and `network.*` time budgets above one day and limits above 2^30 are rejected
  at start-up.
- `resocks5`: strict HTTP `Host` follows RFC 9110 (empty port and any digits are
  valid, bracketed IPvFuture is accepted, no 1..65535 range); the app enables the
  `zeroize` feature of `resocks5-net`.

### Fixed

- `resocks5-net`: `ChainPlan` ends at once when every candidate of a layer is
  dead; it no longer walks the whole gate odometer (a product of the layer
  sizes, synchronously) after the only exit failed.
- `resocks5-net`: `connect_hedged` no longer panics on `Duration::MAX`-sized hedge
  delays (checked instant arithmetic, no timer for a single candidate).
- `resocks5-net`: quarantine back-off reaches the configured maximum for tiny
  initial values (the exponent was capped at 20 doublings).
- `resocks5-net`: `ProxyPool::forget` and `spawn_refill_for` are serialized under one
  lock, so a refill task can no longer be orphaned or detached by a racing
  `forget`.
- `resocks5-net`: strict HTTP validation rejects authorities with a path, userinfo,
  query, fragment or a broken percent escape, and control bytes in header
  values; with `zeroize`, `take_username` wipes the raw identity bytes before
  freeing them.
- `resocks5`: a cached chain whose gate is quarantined is no longer dialed, and
  queued sticky routes count against `max_upstream_attempts`.
- `resocks5`: probes of inner gates no longer blame the tested gate for prefix or
  capacity failures, run under a deadline shorter than their lease, and the
  lease covers the chain depth.
- `resocks5`: the health restore probes only directly dialed upstreams (outermost
  gate and exits), so a live inner gate is not re-quarantined by a direct
  connect; endpoints in different routing groups keep separate health.
- `resocks5`: the health file is written off the async workers, the shutdown stops
  the writer before the final snapshot (no racing second writer), and a stale
  `.tmp` from a crashed run no longer blocks every later save.
- Docs: `docs/ARCHITECTURE.md` describes the quarantine layer next to sand-rating and
  the startup snapshot of users; the `progress` rustdoc example returns
  `WriteZero` on `Ok(0)`, and the `dial_chain_over` example bounds its read.
- `resocks5`: a cached chain is resolved through the rotator that owns the cache, so
  an identical exit endpoint in another group (v6 vs v4) no longer drops a working
  route.
- `resocks5`: the health writer reclaims its own `.tmp` before every write (a kept
  Windows recovery temp no longer blocks later saves), and the saver baseline is
  taken before post-restore probes run.
- `resocks5-net`: a quarantine whose deadline is not representable as an `Instant`
  (huge configured maximum) stays quarantined instead of dropping to probation at
  once.
- `resocks5-net`: `connect_hedged` no longer launches a pending candidate on a hedge
  tick after a win was published, catches a callback panic inside the detached
  drain, and `HedgeError::source()` returns the last connection error.
  `http_error` falls back to a 500 head for an unknown status instead of panicking.
- `resocks5-net`: strict HTTP accepts an uppercase `V` in a bracketed IPvFuture
  `Host` (`[V1.example]`), as the RFC 3986 ABNF string is case-insensitive.
- `resocks5`: the verify-cache keeps the presented password in process memory
  (wiped on drop, never persisted) instead of an HMAC of it, so a repeated login is
  one constant-time comparison and nothing is recomputed; unknown and disabled
  names run the same single comparison against a dummy. Anyone who can read the
  process memory (dump, debugger) can read the cached passwords of users who
  logged in since the start.
- `resocks5`: the health writer compares quarantine deadlines with a two-second
  tolerance (the whole-second truncation jitter) instead of one save interval, so a
  re-trip with unchanged counters is saved whenever its expiry really moved.
- `resocks5-net`: a `Duration::MAX` handshake budget no longer panics the dial
  paths (SOCKS5 and TLS hops use a checked deadline); `same_upstream` documents
  that `gate_level` is part of an upstream's identity and the `gate` link is not.
- `resocks5-net`: SOCKS5 server credentials are not cloned in raw mode and a rejected
  buffer is wiped before it is freed (feature `zeroize`).
- `resocks5-net`: a probe lease too large for the `Instant` range still excludes a
  second probe, and `probe_all_with` trips an upstream atomically.
- `resocks5`: the health file lock now outlives a blocking write that the bounded
  shutdown stopped waiting for; a failed save clears the baseline so the next
  round rewrites; the quarantine deadline is part of the compared state;
  duplicated or ambiguous records (same label, different secret) are not
  restored and warn; the lock sentinel refuses symlinks and keeps one pid line.
- `resocks5`: the tunnel's fragmentation prelude renews its idle window from every
  accepted relay write, and a client that only half-closes after the early reply
  keeps its session (the IP fallback is dialed, the FIN is propagated and the
  greeting relayed).
- `resocks5`: the log drain reports a failed log file through a bounded, awaited
  stderr write instead of a blocking `eprintln!` on the worker.
- CI: `release.yml` grants `contents: write` only to the release job, and the crate
  is packaged and verified before the token-bearing step, which publishes with
  `--no-verify`.

## [0.4.1] - 2026-11-02

### Added

- `resocks5-net`: `connect::dial_chain_over` runs a proxy chain over an owning
  stream already connected to `ProxyConfig::outermost()`, without dialing or DNS;
  it uses a caller-supplied remaining total-timeout budget.
- `resocks5-net`: `ProxyConfig::outermost()` and `nodes()` expose the chain's
  outermost node and its nodes in outermost-first order.

### Changed

- `resocks5-net`: SOCKS5 rejects empty targets and zero ports before writing,
  and rejects nonzero reserved reply bytes and empty bound domains, including
  replies from upstream servers.
- Docs: `resocks5-net` README gains an "Over an existing stream" example for
  `dial_chain_over` (mirrored by a test and the `dial_chain_over` example), the
  new `ProtocolViolation` variants are listed, and `docs/ARCHITECTURE.md`
  describes the three chain entry points.

### Fixed

- README: the "Use as a library" example no longer uses the removed `IP` type
  and the old `parse_proxy_str` signature, so it compiles against 0.4.
- README and `docs/REFERENCE.md`: static Linux archives and arm64 builds ship
  from 0.4.0 (they said "after 0.3.0").

## [0.4.0] - 2026-11-02

### Added

- A tunnel that ended with an I/O error now says which end broke it — `failed
  on client side: …` or `failed on upstream side: …` in the `log.tunnels` line —
  so resets caused by the client (browser/Proxifier aborts) are told apart from
  resets by the upstream.
- The probe log lines carry the reason of the failed connect (`is unreachable at
  startup (connection refused…)`, `still unreachable (no answer within 3s)`);
  `ProbeEvent::{StillDown, QuarantinedAtStart}` got a `reason` field.
- The server remembers which upstreams are dead across restarts: the quarantine
  picture (state, time left, trips) is saved to `resocks5.health.ktav` every
  `network.health_save_sec` seconds (default 30, only when it changed) and on a
  clean shutdown, and read back at start. Dead upstreams return quarantined, or
  on probation when their time ran out meanwhile, so client requests do not
  rediscover them — the background probes decide. `0` disables it; passwords
  are never written; an unreadable file is ignored with a warning.
- SDK: `ProxyRotator::health` / `restore_health`, `UpstreamHealth`,
  `rating::{Health, UpstreamState}`, `Ratings::health` / `restore_health` — a
  wall-clock-free snapshot of the quarantine bookkeeping to save and put back.
- SDK: `connect::connect_hedged` (feature `pool`) with `HedgeOptions`,
  `AttemptReport`/`AttemptOutcome`, `Hedged`, `HedgeError` — the ordered hedged
  race over a candidate list (next attempt only while none is past TCP connect,
  late attempts stop before CONNECT, losers drain in the background and are
  reported through `on_attempt`). The server's direct race now uses it.
- Parallel fallback attempt (`network.hedge_delay_ms`, default 2000): an upstream
  attempt whose TCP connect is still pending after this delay no longer holds
  the request — the next candidate starts beside it and the first success wins.
  A dead upstream that nothing knows about yet (right after start) now costs a
  request about 2 s, not `connect_timeout_sec`. `0` restores strictly
  sequential attempts. Once an upstream is reached, no further attempt starts
  while it talks to the target, so the target never sees duplicate CONNECTs.
  Attempts that lose the race finish in the background and still feed the
  ratings and the quarantine, without touching the target's sticky link; one
  that reaches its upstream only after the win stops before CONNECT. A
  target's sticky-cache upstream now leads the race instead of being waited
  for on its own.
- At startup every upstream gets one TCP check in the background, after the
  listener is up; unreachable ones start quarantined (`Upstream … is
  unreachable at startup`). `resocks5-net`: `ProxyRotator::quarantine_now`,
  `Ratings::quarantine_now`, and `connect::connect_proxy_on` — the handshake
  half of `connect_proxy` over a socket already taken from the pool.
- `log.tunnels` (default off): one line per closed tunnel with target, how it
  ended, bytes sent and received and duration. A tunnel whose upstream sent
  nothing back is reported under `log.proxy_failures` regardless.

- Doctests are forbidden: rustdoc examples are `text` blocks, `resocks5-net`
  sets `doctest = false`, the examples run as ordinary tests in
  `tests/doc_examples.rs`, and the `structure` CI job enforces the rule
  (`.github/scripts/check-no-doctests.sh`).

- Dead upstreams now leave the rotation temporarily. After
  `network.quarantine_threshold` (default 3) consecutive hard failures — TCP
  connect refused or timed out, TLS to the proxy failed, credentials refused —
  an upstream is not tried at all for `network.quarantine_initial_sec` (default
  30 s) while another upstream is healthy; then a background TCP check (never a
  client request) probes it, success clears the quarantine, failure doubles it up to
  `network.quarantine_max_sec` (default 600 s). A stalled or refused CONNECT to
  one target does not count, and a quarantine never empties the rotation. The
  log shows `Upstream … is unreachable - quarantined for Ns` and `… is reachable
  again - back in rotation`. `0` for the
  threshold disables it. `resocks5-net`: `rating::QuarantinePolicy`,
  `Ratings::try_with_quarantine` / `on_hard_failure` / `is_quarantined` /
  `take_probes`, `ProxyRotator::try_with_quarantine` / `record_hard_failure` /
  `is_quarantined` / `take_probes`; the existing constructors are unchanged and keep the plain
  sand model.

- `resocks5-net`: the quarantine logic the app used now lives in the SDK.
  `ConnectError::is_upstream_down` / `counts_against_upstream` classify errors,
  `ProxyRotator::record_error` applies them (capacity errors are ignored, an
  upstream-down error counts towards the quarantine, the rest only lower the
  weight), and `ProxyRotator::probe_due` / `probe_all` with `ProbeEvent` run the
  background and startup TCP checks.
- Gate levels: the number of leading `*` on an upstream line is now its level
  (`ProxyConfig::gate_level`, `with_gate_level`; `parse_proxy_str` accepts up to
  255 stars, a second `*` is no longer an error). `is_gate` stays and equals
  `gate_level > 0`. A single `*` behaves as before.
- `resocks5-net`: a proxy chain as a value — `ProxyConfig::chain`, `chain_nodes`,
  `chain_len`, and `ChainKey`, a hashable identity of a whole chain.
- `resocks5-net`: `connect::connect_chain` — the pool-backed multi-hop dial
  (feature `pool`): the outermost node takes a pooled socket, every other node
  reserves its `max_per_upstream` permit for the life of the tunnel, each hop is
  bounded by the handshake timeout, failures carry the `ChainStage`.
- `resocks5-net`: `chain::GateLevels` and `chain::ChainPlan` (feature `rotator`)
  — the chain-selection engine. Gate levels are ranks (outermost first, gaps
  allowed); the plan lazily walks one node per level, the exit last, skips dead
  nodes with their whole subtree, excludes chains already tried, and attributes
  a failed `ChainError` by stage (`Connect` -> outermost node; `Hop(i)` -> node
  `i` if it is down, else a soft penalty on both neighbours; `Target` -> exit).
- Multi-level gate chains. The number of leading `*` on an upstream line is its
  level: a request goes through one gate of the highest level, then one of each
  lower level, then an ordinary proxy, then the target (`***a`, `**b`, `*c`, `d`
  gives `a -> b -> c -> d -> target`). Levels are ranks, gaps are fine; a single
  `*` behaves as before. Every node of a chain takes its `max_per_upstream`
  permit, the sticky cache stores whole chains, the pool pre-warm and the
  startup check cover only the outermost gate level and the exit proxies, and a
  quarantined inner gate is probed through a healthy outer prefix.

- `resocks5-net`: `connect::dial_chain` — a pool-free multi-hop dial that
  follows `ProxyConfig::gate` links (any depth, SOCKS5 / HTTP CONNECT / HTTPS
  at every hop, one TCP connection, per-hop handshake timeout, optional total
  timeout). Failures are a `ChainError` carrying the typed `ConnectError` and
  a `ChainStage` (`Connect`, `Hop(n)`, `Target`) so callers can tell which
  node to blame. Without a gate it behaves like `dial`.
- License compliance in CI: `cargo deny check licenses bans sources` now gates
  every push and PR (allow-list in `deny.toml`; `sources` is strict —
  crates.io only), with `cargo deny check advisories` reported alongside as a
  non-blocking job. Release archives now include `THIRD-PARTY-LICENSES.txt`
  (generated by `cargo about` from `.github/licenses/`), so the attribution
  that MIT / Apache-2.0 / ISC dependencies require ships with the binaries; a
  CI job checks the generation on every push.
- Release binaries that run on any machine: fully static Linux builds for
  `x86_64-unknown-linux-musl` and `aarch64-unknown-linux-musl` (no libc
  dependency; glibc, musl/Alpine, old and new distributions alike), and the
  Windows build now links the CRT statically (no Visual C++ Redistributable
  needed). The release job verifies the musl binaries are static and smoke-tests
  every built binary with `--help`; a new `portable-builds` CI job builds the
  same targets on every push. `install.sh` prefers the static archive on Linux
  (x86_64 and arm64) and falls back to the glibc archive for older releases.

- `resocks5`: client IP allow-list. A global `allowed_clients` in
  `resocks5.main.ktav` (default `"*"`) and an optional per-user
  `allowed_clients` in `resocks5.users.ktav` restrict which peer addresses may
  connect: exact IPs, `loopback`, and `*` masks (one IPv4 octet / one IPv6
  group each), comma-separated alternatives. The check uses the real TCP peer
  address before any protocol byte is read; both rules must pass; the per-user
  rule runs before password verification (no Argon2 work, no init-claim write
  for a rejected IP) and does not apply to anonymous clients. An invalid rule
  fails server start (fail-closed). Changes need a restart.
- Installers for the latest GitHub Release: `.github/scripts/install.sh`
  (Linux, macOS) and `install.ps1` (Windows, PowerShell 5.1+). They resolve the
  release tag once, download the archive and `sha256sums.txt` from that same
  release, verify the SHA-256 before installing, and never build from source.
  CI exercises both installers.
- `resocks5`: full built-in reference. `resocks5 --help` and the new
  `resocks5 config` print every command and every field of the three config
  files (types, defaults, special values, examples, diagnostics) without
  network access or reading configs; `resocks5 users <command> --help` documents
  each account command (including the `add-init` first-login-claim risks). The
  same text is published as `docs/REFERENCE.md`. Self-contained "direct" proxy
  mode (`users direct` / `users pool`) is documented and covered by tests.

### Changed

- With a saved health picture (`resocks5.health.ktav`) the start-up TCP check of
  all upstreams is skipped: the file already says who was dead, and a single
  connect at the very first instant after a restart can fail for reasons of the
  host (observed: every live upstream "unreachable" for 30 s). The check still
  runs on the first start, when no file exists.

- CI is segmented by diff: a push or PR runs only the segments its changed files
  need, on ubuntu only, and only the SDK/app tests of the touched modules (feature
  matrix, lean clippy/doc, lint, MSRV, docs, license checks, installers, portable
  builds are selected the same way). The full run, with every segment and the
  whole workspace on Linux, macOS and Windows, is explicit: `[ci: full]` in a
  commit message or PR title, a manual run from Actions, a `v*` tag, or a change
  to the CI definition. A single `ci result` check summarises the run for branch
  protection. See `CONTRIBUTING.md`.

- CI: the release workflow no longer publishes the `resocks5` binary crate to
  crates.io (the 0.3.0 note about `cargo install resocks5` was never realised:
  the crate was not published). Binaries ship only as GitHub Release archives and
  the container image; the crate is `publish = false`. `resocks5-net` is still
  published to crates.io. The `only_app` manual-run input is removed.

### Security

- Dependencies: `rustls` 0.23.45 → 0.23.46 (RUSTSEC-2026-0346 … 0349);
  `rustls-webpki` 0.103.16, `webpki-roots` 1.0.11 and `tokio` 1.54.1 in the
  lockfile (RUSTSEC-2026-0381, -0382, -0386). No `Cargo.toml` requirement
  changed.

## [0.3.0] - 2026-10-12

Adds the reusable inbound server API (`resocks5_net::server`) that the Tor-based
sibling project builds on, and makes every reply the proxy sends reach the client
reliably.

### Added

- `resocks5-net::server`: unconditional SOCKS5 / HTTP CONNECT detection and inbound
  framing with owned, Debug-redacted credentials and closure authentication (no
  public authentication trait). `accept` returns the unresolved target, the
  verified username and the owned pipeline bytes; errors are typed and
  `#[non_exhaustive]`, and replies are semantic (`Reply::Established` and the
  failure variants). One host-supplied absolute deadline bounds detection,
  authentication and framing, with a guard against an already-expired entry.
  `GeneralFailure` keeps SOCKS REP 1 for embedding hosts and sends HTTP 502.
  Usage and contracts: [`crates/resocks5-net/README.md`](crates/resocks5-net/README.md#inbound-server-api).
- Finite `serve_local` example: two clients share one listener, authenticate through
  the host callback and relay to an explicit, separately running local echo target
  over a real TCP connection. Success is sent after the dial; buffered payload is
  forwarded once.
- Code-structure rule in CI (`structure` job): at most 1000 lines per Rust file and
  at most 7 entries per directory (`.github/scripts/check-line-limit.sh`,
  `.github/scripts/check-dir-entries.sh`). Offenders are recorded as a ratchet that
  can only shrink; none are left.
- CI: the release workflow now publishes the `resocks5` binary crate
  (`cargo install resocks5`) after `resocks5-net`; a manual run with `only_app`
  publishes just the binary for a version whose SDK is already on crates.io.

### Changed

- **Every inbound reply is written and flushed.** SDK replies use `write_all`
  followed by `flush`: method selection, password success and failure, unsupported
  methods, HTTP failures, domain rejection and each public SOCKS5 / HTTP final
  outcome. A transport failure surfaces as `ServerError::Io` instead of being hidden
  by an authentication or protocol error. Handshake and error flushes stay within the
  original accept deadline; the final-reply write budget remains the host's. Error,
  timeout and cancellation are terminal: buffered wrappers are discarded and a
  partial reply is never replayed.
- Both application paths (SOCKS5 and HTTP CONNECT) call the shared library parser
  once at dispatch, and protocol replies use the request's encoder. Routing, gate
  accounting, recovery, logging and forwarding budgets stay in the application. The
  accept deadline is anchored when the listener accepts the connection, not when the
  spawned handler first runs.
- Handlers borrow the destination and authenticated identity of the parsed request
  instead of allocating duplicate strings on every connection.
- Source files and directories were regrouped to satisfy the new structure rule;
  modules keep their names and paths, behaviour is unchanged.
- Unchanged by design: the delimiter-inclusive 16 KiB HTTP header cap, unused
  obs-text, the existing Basic and SOCKS method policy, permissive legacy framing and
  the lossless binary pipeline. An anonymous identity is never replaced by an empty
  authenticated username for direct routing.

### Fixed

- Unsupported SOCKS5 commands, including BIND and UDP ASSOCIATE, now flush the
  canonical refusal `[5, 7, 0, 1, 0, 0, 0, 0, 0, 0]`, and an unknown address type
  flushes `[5, 8, 0, 1, 0, 0, 0, 0, 0, 0]` before the protocol error, with either
  authentication method. A wrong protocol version keeps its terminal no-response
  contract.
- A flaky macOS test of the delayed accept deadline: it waited on real loopback
  sockets under a paused clock, which auto-advances while the runtime is idle, so a
  late FIN could trip the timeout. It now resumes the clock after the deliberate
  advance and uses wall-clock timeouts.

## [0.2.0] - 2026-10-01

### Added

- `resocks5-net`: `tests/send_bounds.rs`, a compile-time guard that
  `dial`, `dial_plain`, `connect_proxy_once`, `connect_proxy` (with `pool`),
  the SOCKS5 handshake and `tunnel_with_timeouts` futures are `Send` (also
  inside a `tokio::spawn`-style `async move` block), `AnyUpstream` /
  `UpstreamStream` are `Send + Unpin`, and `ConnectError`, `ProxyConfig`,
  `DialOptions` are `Send + Sync`. A regression now fails this crate's
  tests instead of a consumer's build.
- `resocks5-net`: `socks5_rep_description(code)` — the RFC 1928 §6 meaning
  of a SOCKS5 reply code, for `ConnectError::ProxyRejected { code, .. }`
  (unknown codes give `"unassigned"`).
- `resocks5-net`: `connect::dial_plain(proxy, host, port, &DialOptions)` —
  a convenience entry point identical to
  `dial(proxy, host, port, opts, None)` for the common SOCKS5 / HTTP
  CONNECT case, so lean builds no longer write a `None` TLS placeholder.
  An HTTPS upstream yields the same typed error as `dial` without a
  connector (`TlsFeatureMissing` without the `tls` feature, a `Tls` error
  with it); use `dial` with a `TlsConnector` there.
- CI: `release.yml` gains a `publish-crates` job that publishes
  `resocks5-net` and then the `resocks5` binary (`cargo install
  resocks5`) to crates.io on every `v*` tag push; a manual run with
  `only_app` publishes just the binary (after a
  packaging/build dry-run that always runs regardless). Skips the actual
  upload cleanly, without failing the workflow, until a maintainer adds
  the `CARGO_REGISTRY_TOKEN` repo secret — previously there was no
  automated SDK publish step at all, only a manual `cargo publish` a
  maintainer would have had to remember to run. The job supports both API
  token (default) and crates.io Trusted Publishing (OIDC) authentication:
  setting the repo variable `CRATES_IO_AUTH` to `oidc` switches the upload
  to a short-lived token from `rust-lang/crates-io-auth-action`, with no
  stored secret (see CONTRIBUTING.md, "crates.io credentials").
- `resocks5-net`: **pool-free dial.** `connect::dial(proxy, host, port,
  &DialOptions, Option<&TlsConnector>)` connects and handshakes through one
  upstream with no `ProxyPool`, bounded by `connect_timeout`,
  `handshake_timeout` and an optional `total_timeout` (`ConnectError::Timeout`
  with `Stage::Connect` / `Handshake` / `Total`). The TLS slot is a normal
  parameter of one fixed type in every build (no `cfg` on a parameter).
  `connect_proxy_once` is now built on it. The SOCKS5 / HTTP CONNECT / HTTPS
  handshakes are exposed as pool-free cores (`socks5_handshake`,
  `http_connect_handshake`) shared by `dial` and the pool-taking
  connectors, with no duplicated protocol logic.
- `resocks5-net`: **`ConnectError`** — typed errors for every connect and
  pool call (`Timeout { stage, .. }`, `Io` with the `io::Error` in the
  `source()` chain, `ProxyRejected`, `AuthFailed`, `MethodUnsupported`,
  `Protocol`, `InvalidTarget`, `TlsFeatureMissing`, `Tls`, `AtCapacity`),
  `#[non_exhaustive]`. The hand-written `Display` keeps the previous message
  text and `[SOCKS5]` / `[HTTP]` / `[HTTPS]` prefixes, so logs are unchanged.
- `resocks5-net`: **`pool` cargo feature** (default on) gating `ProxyPool`,
  `PoolConfig`, `AtCapacity` and the pool-taking connectors; `dashmap` and
  `crossbeam-queue` are now optional. `--no-default-features` pulls in no
  `dashmap`, `crossbeam` or `rustls` (CI checks the dependency graph).
  `AnyUpstream`, `UpstreamStream`, `BoxedUpstream` and `AsyncReadWrite` moved
  to `connect` and are always available (still re-exported from `pool`).
  `UpstreamStream::from_tcp` wraps a plain socket without a cap permit.
- `resocks5-net`: **`ProxyConfig` constructors** — `new`, `socks5`, `http`,
  `https`, `with_auth`, `with_gate`, `as_gate`, and `from_addr` (parse a
  `[*]user:pass@host:port` line directly).
- `resocks5-net`: fallible `ProxyRotator::try_new` / `try_with_policy` /
  `try_with_cache_limits` and `Ratings::try_new` (`RotatorError`,
  `RatingError`): an empty upstream list or an invalid `RatingPolicy` is an
  error instead of a later panic or silent NaN weights.
- `resocks5-net`: `ProxyPool::forget` removes one endpoint (spares, cap, and
  refill task); `ProxyPool::checkout` now keeps the cap permit
  (`Option<UpstreamStream>`), the old bare-socket behaviour is the explicit
  `checkout_unguarded`.
- `resocks5-net`: `tunnel_with_timeouts` returns `TunnelOutcome { end:
  TunnelEnd, a_to_b, b_to_a }` (EOF / idle / lifetime plus forwarded bytes,
  also on timeout paths).
- `resocks5-net`: public custom progress instrumentation —
  `FlushProgress::record`, `FlushProgress::current()`,
  `FlushProgress::report_confirmed()` let a third-party buffering/TLS
  wrapper feed `send_possibly_fragmented` and `tunnel_with_timeouts`.


- New `resocks5-net` API: `connect::make_tls_connector_with_provider` — the
  provider-explicit twin of `make_tls_connector`. Where the convenience
  function defers to rustls' process-level/feature-based provider
  resolution (which panics in a build graph rustls cannot resolve — see
  below), this variant takes an explicit `Arc<rustls::crypto::CryptoProvider>`
  and never consults process-global state, so it works in every graph
  state including the ones that would otherwise panic.


- New `resocks5-net` API: `connect::connect_proxy_once` — a one-shot
  counterpart of `connect_proxy` for consumers that dial a single upstream
  proxy without rotation or warm-socket reuse, and so should not have to
  construct a `ProxyPool` at all. It is a thin wrapper: the per-protocol
  handshakes (SOCKS5, HTTP CONNECT, HTTPS), the returned `AnyUpstream`
  variants, and the error behaviour are identical to `connect_proxy`. The
  cost is per call — a fresh TCP handshake to the proxy every time, and no
  shared per-upstream concurrency cap, so callers that fan out concurrently
  against the same proxy must bound that themselves.
- `tls` Cargo feature on `resocks5-net` (on by default): the `rustls`,
  `tokio-rustls` and `webpki-roots` dependencies, the HTTPS upstream
  connector with `make_tls_connector`, and the `AnyUpstream::Tls` variant
  are now optional. Consumers that only dial SOCKS5 or HTTP CONNECT
  upstreams can build with `default-features = false` and skip the whole
  TLS stack. ClientHello fragmentation (`connect::tls_fragment`) stays
  available without the feature — it fragments raw bytes and never links
  the TLS stack.
- `serde` Cargo feature on `resocks5-net` (on by default): the `serde`
  dependency and the `Serialize`/`Deserialize` derives on `pool::PoolConfig`
  — the crate's only serde touchpoint — are now optional. Consumers that
  build their own config plumbing can build with `default-features = false`
  (plus the features they do want) and drop serde and its proc-macro
  compile chain from their build entirely. Without the feature the struct
  is unchanged apart from the derives: still `Debug`, `Clone` and
  `Default`, still constructible and mutable by hand, and the `Default`
  values match what serde's field defaults produce.
- `rating` and `rotator` Cargo features on `resocks5-net` (on by default;
  `rotator` implies `rating`): the sand-rating model and the weighted
  rotator built on it are now optional for consumers that want only the
  connectors and the pool. The honest limits, unlike `tls` and `serde`:
  this removes no dependency from the graph — both modules use only `std`
  and `anyhow`, which the crate needs anyway — so the win is a smaller
  public API surface and less to compile, nothing more. The
  `test-instrumentation` feature now implies `rotator` (its
  `pick_order_calls()` counter lives inside the rotator), and the
  README-mirrored example declares `required-features = ["rotator"]` so
  lean builds skip it instead of failing.

### Changed

- `resocks5`: handler errors that are only a peer dropping the connection
  (connection reset / aborted / broken pipe — Windows os error 10053/10054,
  Unix ECONNRESET/ECONNABORTED/EPIPE) are no longer logged by default; they
  made up almost all of a long-running log. The new `log.client_disconnects`
  flag (default `false`) brings them back for verbose diagnostics. Every
  other handler error is still governed by `log.connection_errors`.
- Dependency: `socket2` 0.5 → 0.6 (a non-optional `resocks5-net` dependency
  used by TCP keepalive). Current `tokio` releases already depend on
  `socket2` 0.6, so a consumer's build no longer carries two copies. The
  workspace `Cargo.lock` (and the feature-unification fixture's) moves
  `tokio` 1.43.1 → 1.53.1 with it, for the same single-copy result; the
  declared `tokio` requirement is unchanged.
- **Breaking** (`resocks5-net`, not yet published): `ConnectError::Protocol`
  now carries a structured `ProtocolViolation` (`Socks5BadVersion { got }`,
  `Socks5BadAuthVersion { got }`, `Socks5UnknownAddressType { got }`,
  `Socks5DomainTooLong { len }`,
  `Socks5CredentialsTooLong { username_len, password_len }`,
  `HttpInvalidConnectTarget`, `HttpResponseTooLarge`, `HttpClosedEarly`)
  exposing the offending byte or length; `Display` still prints the exact
  legacy message text. `ProtocolViolation` is re-exported from the crate
  root. A SOCKS5 greeting answered with a non-`0x05` version byte (or an
  RFC 1929 reply with a non-`0x01` version) is now reported as
  `Protocol(Socks5BadVersion / Socks5BadAuthVersion)` instead of being
  folded into `MethodUnsupported` / `AuthFailed`, so a non-SOCKS5 peer is
  distinguishable from a SOCKS5 proxy that refused the method; the log
  line for that case changes accordingly.
- **Breaking** (`resocks5-net`, not yet published): the address-family label
  `ip` is removed from the SDK. `ProxyConfig.ip`, `ProxyConfig::with_family`
  and the public `types::IP` enum are gone (dialing only ever used
  `host`/`port`), and `parse_proxy_str` lost its `ip` parameter — it is now
  `parse_proxy_str(conn_str, protocol)`. Applications that grouped or printed
  proxies by family derive the label from the host literal themselves (e.g.
  `host.parse::<Ipv6Addr>()`). Added `ProxyConfig::from_addr(protocol, addr)`
  as a convenience shorthand for `parse_proxy_str`.
- **Breaking** (`resocks5-net`, not yet published): `ProxyConfig` is
  `#[non_exhaustive]` — build it with the constructors above;
  `parse_proxy_str` returns `Result<ProxyConfig, ParseProxyError>` (`Empty`,
  `Comment`, `BadHostPort`, `BadGate`) instead of `Option`. The `gate` doc is
  corrected: `gate` is the outer gate node and is not interpreted by
  `connect_proxy` / `dial`.
- **Breaking** (`resocks5-net`): connect and pool entry points
  (`connect_proxy`, `connect_proxy_once`, `connect_http_proxy`,
  `connect_socks5_proxy`, `connect_https_proxy`, `http_connect_handshake`,
  `handshake_over_stream`, `ProxyPool::acquire` / `reserve_permit`) return
  `Result<_, ConnectError>`; `send_possibly_fragmented` returns
  `io::Result<SendProgress>`; `RatingPolicy::validate` returns
  `RatingError`. `anyhow` is no longer part of the library's public API and
  is a dev-dependency only. `handshake_over_stream` parses the target before
  writing the greeting, so an invalid target sends nothing.
- `ktav` 0.6.4 → 0.8.0 (`[workspace.dependencies]` requirement raised from
  `0.6.0` to `0.8.0`; `ktav` is used only by the `resocks5` binary, not
  `resocks5-net`). No source changes were needed; the full `resocks5` test
  suite (config load/init, users-file round-trips), `clippy -D warnings`
  and `cargo deny check advisories` pass unchanged.


- **Breaking:** `AnyUpstream` is now `#[non_exhaustive]` — a `match` over
  its variants in a downstream crate must carry a wildcard arm. Landed
  alongside earlier review fixes (before this bump), so a lean `0.1.1`
  consumer that matched exhaustively would already have been broken by it;
  the version number simply never caught up until now.
- **Breaking:** `send_possibly_fragmented` gained a fourth parameter
  (`idle: Duration`, the idle-timeout bound also used by the rest of the
  bounded-send/tunnel progress machinery) and its return type changed from
  `Result<()>` to `Result<SendProgress>`, so callers can observe a
  false-idle-protected stall instead of it being indistinguishable from
  success. Same situation as `AnyUpstream` above: shipped as part of the
  Pending-write-progress fix, ahead of the version bump that should have
  accompanied it.


- **Breaking:** `ProgressReportingWriter` and `FlushProgress` moved from
  `connect::tls_fragment` to a new top-level `progress` module. They are
  generic `AsyncWrite` instrumentation with no TLS-specific logic, and their
  old home made `pool` depend on `connect` (`AnyUpstream::Tls` is a
  `TlsStream<ProgressReportingWriter<UpstreamStream>>`) while `connect`
  already depended on `pool` — a module cycle that blocked gating either
  half behind a feature. `progress` has no outgoing crate-internal
  dependencies, so the graph is now acyclic: `pool → {progress, types}`,
  `connect → {pool, progress, types}`. No deprecated alias is kept at the
  old path; code naming it gets a compile error with a mechanical fix.
- `resocks5-net` no longer depends on tokio's `"full"` feature. Each crate now
  declares the tokio features it actually uses; the workspace entry carries
  only the version. The library asks for `net`, `io-util`, `time`, `sync`,
  `rt` and `macros` (plus `test-util` and `rt-multi-thread` as dev-only), so
  downstream consumers no longer have `fs`, `process`, `signal`, `io-std` and
  `rt-multi-thread` forced on them. The binary keeps what it genuinely needs —
  it builds its own multi-threaded runtime, handles Ctrl+C and writes log
  files — and drops only `process` and `parking_lot`. `Cargo.lock` loses the
  `parking_lot` node, which was reachable solely through `"full"`; no
  dependency version changed.
- **Breaking for feature-off builds only:** with `tls` disabled,
  `connect_proxy`/`connect_proxy_once` lose their trailing
  `tls_connector: Option<&TlsConnector>` argument, and an HTTPS upstream
  is rejected with an error naming the missing feature instead of
  silently falling back to plaintext. With the default features the
  signatures are unchanged; the `resocks5` binary now enables the feature
  explicitly (`resocks5-net = { ..., features = ["tls"] }`). The
  `ProxyProtocol::Https` enum variant itself stays ungated, so config
  parsing does not change shape with features.

### Fixed

- **`cargo package -p resocks5` failed outright (`does not specify a
  version`) because its path dependency on `resocks5-net` had no
  `version` requirement.** A registry consumer of `resocks5` has no
  `../resocks5-net` checkout on disk, so Cargo refuses to package a path
  dependency with no version to resolve it from instead. Added
  `version = "0.2.0"` alongside the existing `path = "../resocks5-net"`
  in `crates/resocks5/Cargo.toml` — `path` still wins for the local
  workspace build, `version` only matters when packaging for a registry.
  This clears the manifest-level blocker; `cargo package -p resocks5`
  still can't fully verify until `resocks5-net` is actually live on
  crates.io (expected publish-order dependency, not a defect), and
  `resocks5` itself still isn't published (that's a separate, undecided
  question — see `CONTRIBUTING.md`).


Version bump, not just a rollup: `cargo-semver-checks` against the `v0.1.1`
baseline confirms two breaking API changes already present in this release
(see `### Changed` below); several other entries in this section are
independently marked **Breaking**. `0.1.1` is already tagged and published
under the old, incompatible shape, so publishing under that same number
again is not an option either technically (registries reject re-publishing
a version) or honestly. No other manifest or dependency versions changed as
part of the bump itself.


- **A cancelled init-claim could let a same-account follower start a second
  concurrent blocking claim, weakening the "at most one claim attempt per
  account" guarantee.** The per-account claim gate's guard lived in
  `verify_async`'s own async stack frame; if the caller cancelled that
  future while the admitted `spawn_blocking` persistence closure was
  still running (`spawn_blocking` work is not itself cancelled when the
  awaiting future is dropped — the same tokio semantics the admission
  permit already relied on), the frame's drop released the gate
  immediately, even though the orphaned closure kept running. A
  same-account follower could then take the now-free gate, find no
  committed hash yet, and start its own blocking claim while the first
  one was still in flight. The overall admission cap still bounded total
  blocking-pool usage, so this did not reopen the P1-01 denial-of-service;
  it broke per-account deduplication specifically under cancellation. The
  gate guard is now an owned guard (`Mutex::lock_owned`) moved into the
  same blocking closure as the permit, so it lives exactly as long as the
  persistence work it protects. A deterministic test cancels a leader
  claim while its persistence is parked on a pinned file lock and asserts
  a same-account follower cannot enter the claim machinery a second time
  until the leader's orphaned closure actually finishes.
- **Docs and CLI help described the sand-rating model's zero-`fail_penalty`
  escape hatch as "round-robin", but the selection path it falls back to
  (`Ratings::pick_order`) is a weighted-random permutation that becomes
  uniform *random* selection at equal weights, not a deterministic
  round-robin rotation** — consecutive picks can repeat before every
  upstream has had a turn, unlike true round-robin. Corrected the wording
  in `RatingPolicy::fail_penalty`'s doc comment, `NetworkConfig`'s
  `sand_fail_penalty` doc comment, the CLI's `print-config-docs` output,
  `resocks5-net`'s README, and `docs/ARCHITECTURE.md`. No selection
  behavior changed — `ProxyRotator::get_next`'s own separate fetch-and-increment
  fallback genuinely is round-robin and was already described correctly.
- **The published SDK archive was missing `LICENSE-MIT`/`LICENSE-APACHE`
  despite declaring `license = "MIT OR Apache-2.0"`.** `cargo package`
  only includes files inside a crate's own directory; the workspace's
  license files live at the repo root, one level up from
  `crates/resocks5-net/`, so they were silently absent from every SDK
  package. Copied both license files into `crates/resocks5-net/` so they
  are included in the packaged archive going forward.
- **`cargo deny check licenses` had no project policy, so its default
  policy rejected the workspace's own MIT/Apache-2.0 dependencies outright**
  (`bans`/`sources` were unaffected and already passed). Added `deny.toml`
  with an explicit allow-list covering every license actually present in
  the locked dependency graph. Deliberately does not touch `advisories`
  policy — the currently-failing rustls advisory and yanked `ktav` pin are
  real, unresolved, version-bump decisions for the release owner, not
  something to silence here.
- **`handshake_over_stream`'s SOCKS5 handshake could hang forever over any
  buffered stream, with no timeout of its own.** Each of the four
  request/response steps (auth-method negotiation, username/password
  sub-negotiation, CONNECT request) called `write_all` immediately
  followed by `read_exact`, with no `flush` in between. `write_all` only
  guarantees the bytes reach the writer's own internal buffer, not the
  underlying transport; this happened to work only because the existing
  tests drove it over a raw, unbuffered `DuplexStream`. Any buffered
  wrapper — `tokio::io::BufStream`, and per the review also relevant to
  TLS/gate stacks under backpressure — could leave a request sitting in
  the buffer indefinitely while both sides waited on a read that would
  never be satisfied. Each write is now followed by an explicit `flush`
  before the matching read. Two new regression tests drive the handshake
  (no-auth and with username/password auth) through a real `BufStream`
  and prove it completes; run against the pre-fix code they reproduce the
  hang directly (`Elapsed` after 5s).
- **`make_tls_connector`'s crypto-provider prerequisite was undocumented,
  so a downstream application could hit an unexpected panic before any
  network I/O.** rustls requires a process-level `CryptoProvider`
  decision; `resocks5-net`'s own default build graph (only `ring`
  enabled) has always auto-resolved this transparently, so today's
  behaviour for ordinary consumers is unchanged and verified unchanged.
  But an application that links a second crypto backend alongside this
  SDK's `ring`, or enables rustls' `custom-provider` feature, takes that
  auto-resolution away — and without installing its own default
  provider, `make_tls_connector` then panics inside rustls with no
  warning that this prerequisite existed. `make_tls_connector` now
  documents the exact three-case resolution order, the exact panic
  message (verified byte-for-byte against rustls 0.23.40's source, both
  in the default graph and reproduced live in a real
  `ring`+`aws_lc_rs`-ambiguous build), and a working example of
  installing a provider once at startup. Not a regression from this
  release cycle, and not a rustls or cryptography defect — provider
  selection is explicitly the application's responsibility; the gap was
  purely that the SDK never said so.
- **Confirmed transport progress made DURING a `Pending` write attempt was
  never counted, so a bounded send or the tunnel's idle tracking could
  falsely declare a healthy, backpressured writer stalled.** Both
  `write_progress_bounded` (the client-dial bounded send) and
  `Tracked::poll_write` (the tunnel's idle-activity tracking) bounded or
  recorded activity only on the outer call's own `Ready`/timeout outcome.
  But tokio-rustls' `poll_write` can perform several real writes to the
  transport underneath — each one genuinely advancing
  `FlushProgress` — while still returning `Pending` overall, because the
  *new* plaintext this call is offering was not itself accepted (its
  internal ciphertext buffer was already full from an earlier call): the
  `(0, would_block)` branch verified directly against tokio-rustls
  0.26.4's vendored source. Both call sites now poll a single,
  never-restarted write future/poll and renew their idle window (or mark
  activity) whenever confirmed progress advances during the wait — never
  on a bare wakeup or a plain `Pending`, which still stall exactly as
  before. Mirrors the pattern the final flush already used.
- **HTTPS-through-gate never reported transport progress, so a
  slow-draining upstream behind any HTTPS gate hop could be killed as
  falsely idle.** The false-idle protection added for the direct HTTPS
  connector reports confirmed write progress from a `ProgressReportingWriter`
  wrapped around the raw transport, but the gate dialer never wrapped its
  raw transport this way — a gate chain's `FlushProgress` never advanced,
  so a bounded send through any HTTP→HTTPS, HTTPS→HTTP or HTTPS→HTTPS gate
  variant could stall and be torn down after one idle window even while
  the underlying TCP connection was actively moving bytes. Fixed by
  wrapping the gate chain's single raw transport (the one TCP connection
  every hop multiplexes over) below the first TLS hop, and by adding the
  missing `AsyncReadWrite` implementation for `ProgressReportingWriter` so
  socket reach-through (`as_tcp`/`set_nodelay`) still digs through it.
  Verified with byte-for-byte slow-drain tests through all three
  HTTPS-involving gate variants, a negative control built with the
  pre-fix construction (which must and does lose the resilience the fix
  provides), and a dead-transport control confirming the zero-progress
  timeout still fires promptly.

- **Breaking:** `ProxyConfig`'s `Debug` output no longer prints `user` or
  `password` in clear text. Both fields previously came from a plain
  `#[derive(Debug)]`, so any ordinary debug log, `dbg!`, tracing field, or
  panic diagnostic containing a `ProxyConfig` leaked proxy credentials —
  recursively through a nested `gate`, at any depth. The new hand-written
  `Debug` impl shows `protocol`/`ip`/`host`/`port`/`is_gate`/`gate` as
  before and renders `user`/`password` as `Some("<redacted>")` or `None`
  — presence is visible for diagnostics, values never are. Pre-existing
  defect, not a regression from this release cycle.

- **Breaking (fixes a worse break):** `connect_proxy` and `connect_proxy_once`
  now take a `tls_connector: Option<&TlsConnector>` argument under every
  build of `resocks5-net`, feature-gated or not. Previously that parameter
  was itself `#[cfg(feature = "tls")]`, which is incompatible with how
  Cargo unifies features across a dependency graph: a lean consumer
  (`default-features = false`) compiled standalone, but broke with
  `error[E0061]: this function takes 5 arguments but 4 arguments were
  supplied` the moment any OTHER crate in the same build enabled `tls` —
  a defect a lean consumer cannot detect or guard against from its own
  `cfg`. Without the `tls` feature, `TlsConnector` is a private
  zero-sized placeholder type that can only ever be constructed as
  `None`, so the call shape is identical either way. `ProxyProtocol::Https`
  requested without `tls` is still rejected with a clear error naming the
  missing feature, never a silent plaintext fallback — that part of the
  design is unchanged. A permanent, checked-in regression fixture at
  `tests/feature_unification/` builds two downstream crates together (one
  lean, one with `tls`) and proves the lean consumer's source needs no
  change either way.

- **The TLS build's `TlsConnector` name was private, so a lean consumer
  that named the type itself (not just passed `None`) broke under
  feature unification even after the arity fix above.**
  `connect::connect_proxy::TlsConnector` resolved to a private
  `use tokio_rustls::TlsConnector;` import whenever `tls` was enabled,
  while the lean build's placeholder of the same name was `pub`. A
  downstream crate built with `default-features = false` that wrote
  `use resocks5_net::connect::connect_proxy::TlsConnector;` to declare
  its own `Option<&'static TlsConnector>` compiled standalone, then
  failed with `error[E0603]: struct TlsConnector is private` the moment
  some other crate in the same build graph turned `tls` on — the same
  feature-unification hazard as the arity break above, surviving one
  round of fixes because that fix only closed the untyped `None` call
  shape. The import is now `pub use`, so the name is public and
  resolves to the same real type under every feature combination. The
  checked-in fixture at `tests/feature_unification/` now also names the
  type explicitly, not just infers it from `None`, so it catches this
  class of regression going forward.

- **Init-claim admission could exhaust the shared Tokio blocking pool
  (conditional denial of service).** Each concurrent init-on-first-login
  claim launched its own `spawn_blocking` for the persistence phase with
  no admission limit, and that closure could park its blocking-pool
  thread on the in-process claim mutex and then the cross-process
  users-file lock (up to 10 seconds) with no separate cap. On a runtime
  with a small blocking pool, a handful of concurrent claims against a
  delayed persist could occupy every blocking thread, starving ordinary
  cache-miss logins, DNS and file I/O sharing that executor; a client
  timeout freed the client's own permit but did not cancel work already
  running in `spawn_blocking`. Fixed with an independent admission
  semaphore acquired asynchronously before `spawn_blocking` (a queued
  claimant holds no thread) and moved into the blocking closure so it is
  held until the persistence work actually finishes, including after
  client cancellation; concurrent claims for the same account are also
  deduplicated behind a per-account async gate so at most one claim
  attempt per account occupies a blocking thread at a time. No
  password-verification behaviour changed.

### Security

- **`ktav` was pinned at the yanked 0.6.1** (yanked 2026-09-16, cause not
  disclosed upstream; no runtime vulnerability was claimed or found —
  `cargo deny check advisories` flags a yank on its own, independent of
  any CVE/RUSTSEC advisory). Moved to `0.6.4`, the latest release under
  the existing `ktav = "0.6.0"` manifest requirement (no manifest change
  needed, `cargo update -p ktav` was enough). `cargo deny check
  advisories` is now fully clean — this was the last of the two findings
  from this week's review rounds; the other (`rustls`) was fixed in the
  `[0.2.0]` release above. Config parsing exercises `ktav` on nearly every
  test in the `resocks5`
  binary; the full 192-test binary suite was re-run and passed unchanged.


- **`rustls` was pinned at 0.23.40, affected by
  [RUSTSEC-2026-0285](https://rustsec.org/advisories/RUSTSEC-2026-0285.html)
  / [GHSA-2mjx-qc3c-rqvc](https://github.com/rustls/rustls/security/advisories/GHSA-2mjx-qc3c-rqvc):**
  TLS 1.3 handshake messages sent at the wrong encryption level (e.g. a
  plaintext `EncryptedExtensions` packed into the same record as
  `ServerHello`) were incorrectly accepted instead of terminating the
  connection per RFC 8446 §5.1. The handshake transcript stays
  authenticated — this is not a MITM or certificate-bypass primitive — but
  rustls should reject such messages regardless. Raised the
  `[workspace.dependencies]` floor to `rustls = "0.23.45"` (the fixed
  version) so a future `cargo update` cannot resolve back down to a
  vulnerable patch, and updated `Cargo.lock` accordingly (also pulls in
  `rustls-webpki` 0.103.15). `cargo deny check advisories` no longer flags
  this advisory. The full TLS-facing test suite (fragmentation, tunnel,
  gate-progress, crypto-provider contract) was re-run against the new
  version, in both debug and release, with no change in behavior.

## [0.1.1] - 2026-06-23

### Added

- **Host recovery from client payload** (`network.recover_host_from_payload`,
  default `true`). When a SOCKS front-end resolves DNS locally and issues
  `CONNECT` to a bare IP literal, upstream proxies that refuse `CONNECT` to
  raw CDN IP ranges time out every request. resocks5 now recovers the
  intended hostname from the client's first record — TLS **SNI** (port 443)
  or the HTTP **`Host`** header (plain HTTP CONNECT) — and addresses the
  upstream by that domain instead of the IP. Falls back to the IP when no
  name can be recovered (non-TLS, no SNI, ESNI/ECH). Applies to pool-routed
  (non-direct) clients whose target is a bare IPv4 literal. Trade-off: the
  success reply is sent before the upstream is connected, and the first
  client record is inspected; set the flag to `false` for strict RFC 1928 /
  RFC 7231 reply ordering and zero payload inspection.
- New `resocks5-net` API: `connect::parse_sni` and `connect::parse_http_host`
  — strictly bounds-checked, allocation-light extractors that never panic on
  malformed input.

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
  upstream is bad the weights equalise into uniform random selection.
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

[Unreleased]: https://github.com/PHPCraftdream/resocks5/compare/v0.5.0...HEAD
[0.5.0]: https://github.com/PHPCraftdream/resocks5/compare/v0.4.1...v0.5.0
[0.4.1]: https://github.com/PHPCraftdream/resocks5/compare/v0.4.0...v0.4.1
[0.4.0]: https://github.com/PHPCraftdream/resocks5/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/PHPCraftdream/resocks5/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/PHPCraftdream/resocks5/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/PHPCraftdream/resocks5/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/PHPCraftdream/resocks5/releases/tag/v0.1.0
