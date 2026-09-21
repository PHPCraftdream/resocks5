# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://github.com/PHPCraftdream/resocks5/compare/v0.1.1...HEAD
[0.1.1]: https://github.com/PHPCraftdream/resocks5/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/PHPCraftdream/resocks5/releases/tag/v0.1.0
