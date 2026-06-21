# Architecture

This document explains how `resocks5` is put together — the request-flow,
the upstream-selection model, the safety nets, and where each concern lives
in the codebase. Read it once and the `.rs` files map onto a coherent system
instead of looking like a pile of code.

## Repository layout

A Cargo workspace with two crates:

| Crate | Role |
|---|---|
| **`resocks5-net`** | Reusable proxy networking toolkit. Knows nothing about KTAV, logging, or authentication. Public modules: `connect`, `pool`, `rating`, `rotator`, `types`. |
| **`resocks5`** | The CLI binary. Wires `resocks5-net` together with config parsing, Argon2 auth, logging, and the SOCKS5/HTTP listener. |

The split is deliberate: anybody building a different proxy product can
depend on `resocks5-net` and bring their own application layer.

## Request flow

For every accepted client connection:

```
client TCP                                          target host
   │
   ▼
┌───────────────────────────────────────────────┐
│ 1. Protocol detect                            │   first byte: 0x05 → SOCKS5
│    (server/handle_client.rs)                  │   first byte: ASCII alpha → HTTP CONNECT
└────────────────────┬──────────────────────────┘
                     ▼
┌───────────────────────────────────────────────┐
│ 2. Authenticate                               │   Argon2id verify + verify-cache (HMAC of
│    (auth/state.rs, both handlers)             │   server_secret ⨁ name ⨁ password) for
│                                               │   O(1) re-auth without re-Argon2
└────────────────────┬──────────────────────────┘
                     │
              ┌──────┴──────┐
              ▼             ▼
       direct user?    pool user (default)
              │             │
              ▼             ▼
┌────────────────┐  ┌──────────────────────────────────────────────┐
│ establish_     │  │ 3. Pick an upstream                          │
│ direct         │  │    - if target was seen before:              │
│                │  │      sticky cache → that one upstream        │
│ TcpStream::    │  │    - else: rotator.pick_order() —            │
│ connect from   │  │      weighted-random permutation driven      │
│ server's IP    │  │      by sand-rating (see below)              │
└───────┬────────┘  │    IPv6 targets prefer the IPv6 upstream set │
        │          │                                              │
        │          │ 4. Connect through the upstream              │
        │          │    - optional pre-warmed TCP from the pool   │
        │          │    - optional gate-chain (proxy → proxy)     │
        │          │    - per-upstream semaphore caps concurrency │
        │          │    - real failure → rotator.record_failure() │
        │          │    - success → rotator.record_success()      │
        │          │    - AtCapacity → don't sand (our load)      │
        │          └──────────────────┬───────────────────────────┘
        │                             │
        └──────────────┬──────────────┘
                       ▼
┌───────────────────────────────────────────────┐
│ 5. Tunnel                                     │   tunnel_with_timeouts:
│    (connect/tunnel.rs)                        │     - bidirectional copy
│                                               │     - idle timeout
│                                               │     - hard lifetime cap
│   On the first write: if it looks like a TLS  │     - half-close aware
│   ClientHello and tls_fragment.enabled, split │
│   it across small TCP segments.               │
└────────────────────┬──────────────────────────┘
                     ▼
                target host
```

## Sand-rating: how an upstream is chosen

`resocks5` does **not** use a binary circuit breaker. Failed upstreams are
not quarantined — they are *demoted* via a soft-weight model called
sand-rating that converges back on its own as upstreams recover.

### State (per upstream)

```rust
struct Sand { level: f64, last: Instant }
```

Two scalars per upstream: how much sand is in the bucket, and when we last
touched it. Everything is computed lazily on read — no background tick is
ever needed.

### Transitions

| Event | Update |
|---|---|
| read | `level ← level · exp(−Δt / τ)` (exponential decay since `last`) |
| failure | read; then `level ← min(SAND_MAX, level + FAIL_PENALTY)` |
| success | read; then `level ← level · SUCCESS_FACTOR` |

Where `τ = HALF_LIFE / ln 2` so that level halves every `HALF_LIFE` seconds
of silence.

### Selection weight

```
weight = exp(−K · level)        with  K = ln(1/MIN_WEIGHT) / SAND_MAX
```

`weight ∈ [MIN_WEIGHT, 1]`. A fresh upstream gets weight 1; a fully-saturated
upstream gets weight `MIN_WEIGHT > 0` — never zero. The rotator draws
upstreams with probability proportional to weight; in one client request it
draws an entire weighted-random permutation (Efraimidis–Spirakis) so the
fallback walk never revisits the same upstream.

### Three desired properties — and how they fall out

| Property | Why it holds |
|---|---|
| "Out of the whole pool, always" | `weight > 0` always → no upstream is ever excluded. The MIN_WEIGHT floor is the built-in probe. |
| "All bad → all equal" | Equal `level` ⇒ equal weight ⇒ uniform probability. So a global outage degrades to uniform round-robin. |
| "Worse → less often, never zero" | Monotonicity of `exp(−K·level)` plus the floor. |

### Convergence — why state cannot run away

Four predicates protect the model:

1. **Hard clamp** at `SAND_MAX` after every failure — `level` cannot exceed
   the ceiling regardless of failure rate.
2. **Floor at `1e-6`** — sub-microsecond residuals snap to zero, killing
   float denormals and slow drift.
3. **Closed-form lazy decay** — `s · exp(−Δt / τ)` from a monotonic `Instant`.
   No accumulated discretization error; untouched cells decay to zero in
   bounded time.
4. **Bounded weights** — `weight ∈ [MIN_WEIGHT, 1]` ⇒ `Σweights ≥ N · MIN_WEIGHT > 0`,
   so division by zero in selection is structurally impossible.

Under a sustained failure rate `λ` (failures/sec), the steady-state level is

```
level* = min(SAND_MAX, λ · FAIL_PENALTY · τ)
```

i.e. clamped, bounded, and falling — the model is a damped feedback loop,
not an open one.

### Code map

| Concern | File |
|---|---|
| `Sand` cell state machine | `crates/resocks5-net/src/rating/sand.rs` |
| `RatingPolicy` (knobs + derived constants) | `crates/resocks5-net/src/rating/policy.rs` |
| Weighted index / weighted permutation | `crates/resocks5-net/src/rating/select.rs` |
| Deterministic small RNG (splitmix64) | `crates/resocks5-net/src/rating/rng.rs` |
| `Ratings` integrator (Mutex + cells + RNG) | `crates/resocks5-net/src/rating/mod.rs` |

## The TCP pool and `AtCapacity`

`crates/resocks5-net/src/pool/proxy_pool.rs` keeps two things per upstream
`(host, port)`:

1. A bounded queue of pre-warmed TCP sockets (master switch `pool.enabled`).
2. A per-upstream `Semaphore` capping in-flight connections.

When `pool.acquire(proxy)` cannot acquire a permit, it returns an
**`AtCapacity`** error — a distinct type so callers can downcast and
distinguish capacity-rejects from real connect/handshake failures.

This matters for sand: a capacity-reject is *our* load, not the upstream's
fault, so the rotator's `should_record_failure(err)` skips sanding when it
sees an `AtCapacity` downcast. Without that distinction, a busy server
would punish its own healthy upstreams during traffic spikes.

## Gate chains

A proxy entry with a leading `*` in `proxy_list.ktav` is a **gate** —
`resocks5` will tunnel through the gate first, then issue a second
SOCKS5/CONNECT handshake to the real upstream over that tunnel. The
combinatorics (`gates × inner`) are walked in `server/establish_connection.rs`,
and the sticky cache stores the `(target → (gate, inner))` pair so the
chain reuses on subsequent calls.

## Direct (bypass) users

A user with `direct: true` in `users.ktav` bypasses the entire pool: the
server itself opens a `TcpStream` straight to the target. This is meant for
trusted internal users or for emergency fallback when the pool is empty.
Anonymous clients never get the direct path — it requires authentication.

Direct traffic is capped by a separate semaphore (`max_concurrent_direct`)
so a burst of bypass requests cannot drown the global pool.

Security notes:

- Direct **leaks the server's real IP** to every target the bypass user
  connects to.
- DNS for the target is resolved by the server, not by an upstream — DNS
  queries leak through the server's configured resolver.

These are documented in `print_config_docs.rs` and the README so users
opt in knowingly.

## TLS ClientHello fragmentation

When `tls_fragment.enabled`, the server inspects the *first* outgoing
record on the upstream socket. If it looks like a TLS ClientHello, the
record is split into small TCP segments (`fragment_size` bytes each,
optional `delay_ms` between them). `TCP_NODELAY` is enabled on the socket
so the OS won't merge the fragments back via Nagle.

Effective against per-segment DPI scanners that try to read SNI from a
single packet. Not effective against stateful DPI with full-stream
reassembly — fragmentation alone is no silver bullet.

Implementation: `crates/resocks5-net/src/connect/tls_fragment.rs`.

## Safety nets — every place a tunnel can stall

| Defense | Knob | Lives in |
|---|---|---|
| Connect timeout to upstream | `network.connect_timeout_sec` | `pool/proxy_pool.rs` |
| SOCKS5 / CONNECT handshake timeout | `network.handshake_timeout_sec` | `establish_connection.rs` |
| Per-upstream concurrency cap | `network.max_per_upstream` | `pool/proxy_pool.rs` (Semaphore) |
| Tunnel idle timeout | `network.tunnel_idle_timeout_sec` | `connect/tunnel.rs` |
| Tunnel hard lifetime | `network.tunnel_max_lifetime_sec` | `connect/tunnel.rs` |
| TCP keepalive on both legs | `network.tcp_keepalive_sec` | `connect/tcp_keepalive.rs` |
| Client-side protocol budget | `network.client_protocol_timeout_sec` | both handlers |
| Max in-flight clients (global) | `network.max_concurrent_clients` | `server/run_server.rs` |
| Max in-flight direct (bypass) | `network.max_concurrent_direct` | `server/run_server.rs` |
| Max upstream attempts per request | `network.max_upstream_attempts` | `establish_connection.rs` |

Every one of these exists because of a real production failure mode.
Defaults are picked conservatively; `resocks5 config` documents each one.

## Concurrency model

- Single Tokio multi-thread runtime.
- One task per accepted client (`server/run_server.rs`), bounded by the
  `max_concurrent_clients` semaphore at accept-time.
- The log channel is a bounded `mpsc::channel<ELog>(2048)`. On overflow the
  hot path drops via `try_send` rather than blocking — the proxy never
  stalls because logs are slow.
- The pool refill tasks are one per unique `(host, port)`, spawned at
  startup. They use a `Notify` so they wake the instant a slot frees up.

## Auth and the verify-cache

`resocks5` uses Argon2id with per-user PHC strings. To avoid running Argon2
on every request:

- On the first successful verify, we compute `HMAC(server_secret, name ⨁ 0x00 ⨁ password)`
  and store that in a `DashMap`. The `server_secret` is fresh 32 bytes per
  process — no persistence.
- Subsequent verifies for the same name compare the stored HMAC in constant
  time. Hit → success without touching Argon2.
- On a password change, the new HMAC mismatches the cache → fallthrough to
  Argon2 → success → cache updated. Old passwords stop authenticating the
  moment the new one is recorded, including for in-flight sessions.

The `hash == "init"` sentinel implements claim-on-first-login: the first
authenticated connect for that username records the password and writes
the file under a write-lock. Concurrent claims with different passwords
serialize cleanly — exactly one winner.

## Config files

Three KTAV files in the working directory, all auto-created on first run
with sensible defaults:

- `resocks5.main.ktav` — server settings (port, auth, logging, pool,
  network/sand-rating, TLS fragmentation, banned patterns)
- `resocks5.proxy_list.ktav` — upstream proxy lists, grouped by transport
  and IP family
- `resocks5.users.ktav` — client users; managed by `resocks5 users …`,
  never edit by hand

`resocks5 config` prints the authoritative field reference. KTAV supports
`##`-prefixed comment lines, but `resocks5` itself never writes them — the
generated files are pure values.

## Testing strategy

- Unit tests inline (`#[cfg(test)] mod tests`) cover each module.
- Rating-model tests live in `crates/resocks5-net/src/rating/` and include
  property-style assertions: chi-square on uniform distribution, χ²-ish
  bounds on bad-upstream pick rate, simulated convergence over 100k iters.
- The `default_main_round_trips_through_ktav` and
  `default_main_has_no_type_tags` tests in `config/load_or_init.rs` catch
  KTAV serializer drift (e.g. a regression where integers get re-tagged).
- `examples/connect_through_proxy.rs` is the public-API smoke test for
  `resocks5-net` — the example compiles under `cargo clippy --all-targets`
  in CI, so a breaking change to the library shows up as a build failure
  here before users hit it.

## Where to start when reading the source

1. `crates/resocks5/src/main.rs` — wiring; reads the configs and assembles
   everything.
2. `crates/resocks5/src/server/run_server.rs` — accept loop, listener,
   permits.
3. `crates/resocks5/src/server/establish_connection.rs` — the heart of
   upstream selection (sticky cache, gates, sand-rated rotator,
   `should_record_failure`).
4. `crates/resocks5-net/src/rating/` — the math of sand-rating.
5. `crates/resocks5-net/src/pool/proxy_pool.rs` — the pool and
   `AtCapacity`.

Everything else hangs off these five.
