# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- CI: `release.yml` gains a `publish-sdk` job that publishes
  `resocks5-net` to crates.io on every `v*` tag push (after a
  packaging/build dry-run that always runs regardless). Skips the actual
  upload cleanly, without failing the workflow, until a maintainer adds
  the `CARGO_REGISTRY_TOKEN` repo secret — previously there was no
  automated SDK publish step at all, only a manual `cargo publish` a
  maintainer would have had to remember to run.

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

## [0.2.0] - 2026-09-22

Version bump, not just a rollup: `cargo-semver-checks` against the `v0.1.1`
baseline confirms two breaking API changes already present in this release
(see `### Changed` below); several other entries in this section are
independently marked **Breaking**. `0.1.1` is already tagged and published
under the old, incompatible shape, so publishing under that same number
again is not an option either technically (registries reject re-publishing
a version) or honestly. No other manifest or dependency versions changed as
part of the bump itself.

### Changed

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

### Security

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

### Added

- New `resocks5-net` API: `connect::make_tls_connector_with_provider` — the
  provider-explicit twin of `make_tls_connector`. Where the convenience
  function defers to rustls' process-level/feature-based provider
  resolution (which panics in a build graph rustls cannot resolve — see
  below), this variant takes an explicit `Arc<rustls::crypto::CryptoProvider>`
  and never consults process-global state, so it works in every graph
  state including the ones that would otherwise panic.

### Fixed

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

### Added

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

[Unreleased]: https://github.com/PHPCraftdream/resocks5/compare/v0.1.1...HEAD
[0.1.1]: https://github.com/PHPCraftdream/resocks5/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/PHPCraftdream/resocks5/releases/tag/v0.1.0
