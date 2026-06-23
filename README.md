# resocks5

[![CI](https://github.com/PHPCraftdream/resocks5/actions/workflows/ci.yml/badge.svg)](https://github.com/PHPCraftdream/resocks5/actions/workflows/ci.yml)
[![MSRV: 1.88](https://img.shields.io/badge/MSRV-1.88-dea584.svg)](#install)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)

A SOCKS5 **and** HTTP-CONNECT proxy server that spreads incoming client
connections across a pool of upstream proxies — with per-client
authentication, per-target upstream stickiness, a self-recovering
sand-rating rotator that demotes failing upstreams without ever
excluding them, and TLS fragmentation for DPI evasion.

The listener auto-detects SOCKS5 vs HTTP CONNECT per connection, so a single
port serves both kinds of client.

> **Status:** working and in daily use by the author; pre-1.0. The CLI and
> config format are stable in practice; the [`resocks5-net`](crates/resocks5-net)
> library API may still change before a 1.0 release.

## Quick demo

```bash
# 1. first run — creates the three .ktav config files in the CWD, then exits
resocks5

# 2. add one upstream: edit resocks5.proxy_list.ktav and put it in the
#    socks5_v4 list (replace the empty `socks5_v4: []` line — don't add a
#    second one; ktav rejects duplicate keys):
#        socks5_v4: [ user:pass@198.51.100.7:1080 ]
# then add one client user (interactive, no-echo password prompt):
resocks5 users add alice

# 3. start the proxy (listens on 127.0.0.1:20082 by default)
resocks5

# 4. SOCKS5 and HTTP CONNECT share the same port — either works:
curl --socks5-hostname 127.0.0.1:20082 https://ifconfig.me   # → 198.51.100.7
curl -x http://127.0.0.1:20082           https://ifconfig.me   # → 198.51.100.7
```

The returned IP is the **upstream's**, not yours — that's the whole point. Add
more entries to `resocks5.proxy_list.ktav` and resocks5 rotates across them,
demoting any that fail via the sand-rating model instead of dropping them.

## Contents

- [Quick demo](#quick-demo)
- [Features](#features)
- [Why resocks5](#why-resocks5)
- [Install](#install)
- [Quick start](#quick-start)
- [How it works](#how-it-works)
- [Configuration](#configuration)
- [Use as a library](#use-as-a-library)
- [User management](#user-management)
- [Repository layout](#repository-layout)
- [License](#license)

## Features

- **SOCKS5 + HTTP CONNECT** front end, auto-detected per connection.
- **Upstream protocols:** SOCKS5, HTTP, and HTTPS (TLS-wrapped CONNECT) proxies.
- **Rotation + stickiness:** round-robin across the pool, with a per-target
  cache so a given destination keeps using the upstream that last worked.
- **Gates (proxy chaining):** route through a gate proxy to a second proxy
  before reaching the target.
- **Sand-rating soft-weight rotator:** each upstream has a per-failure
  sand accumulator that decays exponentially over time. Upstream selection
  is weighted-random with weight `exp(-k · sand)` — failing upstreams are
  picked less often but never excluded, and recover automatically as their
  sand drains. When every upstream is bad the weights equalise, so a
  full outage degrades to uniform round-robin instead of locking out.
- **Per-upstream concurrency cap** to respect a provider's per-account/per-IP
  connection quota.
- **Optional pre-warmed TCP pool** to cut connection latency.
- **TLS fragmentation:** splits the ClientHello across TCP segments to defeat
  SNI-based DPI blocking.
- **Authentication:** Argon2id password hashing, with an optional
  init-on-first-login mode.
- **Safety rails:** idle/lifetime tunnel timeouts, TCP keepalive, a
  max-concurrent-clients cap, and regex-based banned-target patterns.
- **Configurable logging** by category, with optional non-blocking file output.

## Why resocks5

resocks5 exists for one reason the established rotating-proxy tools don't
lean into: **graceful degradation under upstream churn**.

Most proxies either pin a single upstream (no rotation) or use a hard
circuit-breaker that quarantines a failed upstream for a fixed window. That's
fragile on small pools — one quarantine cascades into the next — and it's
weaponizable: an attacker who can trip failures can lock you out of your own
pool.

resocks5's **sand-rating** model takes the opposite stance. A failed upstream
is *demoted*, never excluded: its selection weight decays toward (but never
reaches) zero and recovers on its own as the sand drains. A full outage
degrades to uniform round-robin instead of a lockout, and a recovering
upstream is probed for free because its weight never hits zero.

### How it compares

| | resocks5 | 3proxy | gost | glider |
|---|---|---|---|---|
| Language | Rust (rustls / `ring`) | C | Go | Go |
| Front end | SOCKS5 + HTTP CONNECT (auto) | many | many | many |
| Rotation model | sand-rating soft-weight, self-recovering | round-robin / parent | chaining-first | failover |
| Per-target stickiness | yes | — | — | — |
| Auth | Argon2id + HMAC verify-cache | basic | basic | basic |
| TLS ClientHello fragmentation | yes | no | no | no |
| Single-port dual-protocol | yes | — | — | — |

**Where resocks5 wins**

- **Rotation that never locks you out** — the sand-rating model's whole
  reason to exist.
- **TLS fragmentation** for per-segment, SNI-based DPI, built in.
- **Rust + rustls** — memory-safe, no `cmake` / C toolchain to build.

**Where the others still win**

- **Protocol breadth** — gost in particular speaks far more wire protocols
  (shadowsocks, trojan, …) and is a better fit if you need those.
- **Footprint** — 3proxy is a hand-tuned C binary and uses less memory under
  extreme connection counts.
- **Operational maturity** — 3proxy has two decades of production use.

If you need a tunnelling swiss-army knife or a specific exotic protocol, reach
for gost. If you need the smallest possible binary on a constrained box, 3proxy.
If your problem is "I have a pool of flaky upstream proxies and I want traffic
to keep flowing when they misbehave," that's the case resocks5 is built for.

> The table characterises each project's *design focus*, not its absolute
> capabilities — verify against the current version before committing.

## Install

Requires a recent stable Rust toolchain. The dependency tree (rustls 0.23,
rpassword 7) sets the floor at **Rust 1.88+**, declared as `rust-version` in
every crate and enforced by the `msrv` job in CI. The crate uses the `ring`
crypto provider, so no C toolchain or `cmake` is needed to build.

```bash
# Build from a checkout:
cargo build --release
# → target/release/resocks5[.exe]

# …or install the binary onto your PATH:
cargo install --path crates/resocks5
# …or straight from git:
cargo install --git https://github.com/PHPCraftdream/resocks5 resocks5
```

### Run with Docker

A multi-arch image (`linux/amd64`, `linux/arm64`) is published to ghcr.io on
every release tag:

```bash
# latest release (auto-created configs land in the mounted volume)
docker run --rm -p 20082:20082 \
  -v "$PWD/resocks5-config:/etc/resocks5" \
  ghcr.io/phpcraftdream/resocks5:latest

# …or build it yourself
docker build -t resocks5 .
docker run --rm -p 20082:20082 -v "$PWD/resocks5-config:/etc/resocks5" resocks5
```

Mount your `resocks5.*.ktav` at `/etc/resocks5` (the image's working dir). The
process runs as a non-root user; the three config files are created there on
first run if they're missing. The image is distroless (~the binary + glibc),
so there's no shell inside it.

## Quick start

```bash
# 1. The first run creates the three config files in the working directory,
#    then exits telling you that no upstream proxies are configured yet.
resocks5

# 2. Add at least one upstream to resocks5.proxy_list.ktav by editing the
#    existing socks5_v4 line (replace `socks5_v4: []` in place — ktav rejects
#    duplicate keys, so don't append a second socks5_v4):
#       socks5_v4: [ user:pass@198.51.100.7:1080 ]

# 3. (Optional) add a client user. With no users configured the proxy
#    accepts anyone who can reach the listen address — see step 5.
resocks5 users add alice

# 4. Start the proxy. It listens on 127.0.0.1:20082 by default.
resocks5

# 5. Point your SOCKS5 / HTTP-proxy client at 127.0.0.1:20082.
```

To expose it beyond localhost, change `listen_host` in `resocks5.main.ktav`
— and configure users first, since a `0.0.0.0` listener with no auth is an
open proxy.

## How it works

For each accepted connection:

1. **Protocol detect** — the first bytes decide SOCKS5 vs HTTP CONNECT.
2. **Authenticate** — the client is checked against the user table (Argon2id);
   skipped when no users are configured.
3. **Pick an upstream** — if this target was reached before, reuse the sticky
   upstream that last worked; otherwise draw one with sand-rating's
   weighted-random order. IPv6 targets prefer the IPv6 upstream set.
4. **Connect** — open the tunnel through the upstream (optionally via a gate,
   optionally over a pre-warmed TCP socket). The per-upstream semaphore caps
   concurrent connections; real connect/handshake failures add sand to that
   upstream so subsequent draws prefer healthier peers (capacity-rejects
   don't count — that's our own load, not the upstream's fault).
5. **Tunnel** — forward bytes both ways until either side closes, with idle and
   lifetime timeouts. If the first client write is a TLS ClientHello and
   fragmentation is enabled, it is split across TCP segments.

## Configuration

Configuration lives in three [KTAV](https://github.com/ktav-lang/rust) files in
the working directory, all auto-created on first launch:

| File | Purpose |
|------|---------|
| `resocks5.main.ktav` | server settings: port, auth, logging, pool, network/sand-rating, TLS fragmentation, banned patterns |
| `resocks5.proxy_list.ktav` | upstream proxies, grouped by transport and IP family |
| `resocks5.users.ktav` | client users — managed by `resocks5 users …`, do not edit by hand |

Print the **full field reference** — every option, its default, and behaviour
notes — with:

```bash
resocks5 config
```

> **Security:** these files hold secrets — the auth salt, upstream proxy
> credentials, and Argon2 user hashes. They are git-ignored; never commit them.

### Upstream proxy list

In `resocks5.proxy_list.ktav`, list upstreams in arrays per transport and IP
family. Each entry is `[*]user:pass@host:port` (credentials optional); a
leading `*` marks a **gate**.

```text
socks5_v4: [
  alice:s3cret@198.51.100.7:1080
  *gateuser:gatepass@203.0.113.9:1080
]
http_v4:  [ user:pass@198.51.100.20:8080 ]
https_v4: [ user:pass@198.51.100.30:443 ]
## …and the corresponding *_v6 arrays for IPv6 upstreams.
```

## Use as a library

The networking core is published as a separate crate,
[`resocks5-net`](crates/resocks5-net) — upstream connectors, the TCP pool,
the sand-rating model, the weighted-random rotator, and TLS fragmentation,
with no application concerns (no config-file format, no logger, no auth).
Add it as a git dependency:

```toml
[dependencies]
resocks5-net = { git = "https://github.com/PHPCraftdream/resocks5" }
tokio = { version = "1", features = ["full"] }
anyhow = "1"
```

Connect to a target through an upstream proxy and drive any protocol over the
returned stream:

```rust
use std::time::Duration;

use resocks5_net::connect::{connect_proxy, parse_proxy_str};
use resocks5_net::pool::{PoolConfig, ProxyPool};
use resocks5_net::rotator::ProxyRotator;
use resocks5_net::types::{ProxyProtocol, IP};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Parse upstream lines: "[*]user:pass@host:port" (credentials optional).
    let proxies = ["user:pass@198.51.100.7:1080"]
        .into_iter()
        .filter_map(|s| parse_proxy_str(s, ProxyProtocol::Socks5, IP::V4))
        .collect::<Vec<_>>();

    // Weighted-random rotator (sand-rating uses defaults from RatingPolicy)
    // + a pre-connect TCP pool (left disabled here).
    let rotator = ProxyRotator::new(proxies);
    let pool = ProxyPool::new(
        PoolConfig::default(),
        Duration::from_secs(10), // upstream connect timeout
        8,                       // max concurrent connections per upstream
    );

    // Pick an upstream and tunnel to the target through it. The returned
    // stream is AsyncRead + AsyncWrite.
    let upstream = rotator.get_next();
    let mut stream = connect_proxy(
        "example.com:80",
        &upstream,
        &pool,
        Duration::from_secs(10), // handshake timeout
        None,                    // TLS connector — Some(..) only for HTTPS upstreams
    )
    .await?;

    stream
        .write_all(b"GET / HTTP/1.0\r\nHost: example.com\r\n\r\n")
        .await?;
    let mut body = Vec::new();
    stream.read_to_end(&mut body).await?;
    println!("received {} bytes", body.len());
    Ok(())
}
```

The library entry point is [`resocks5_net`](crates/resocks5-net/src/lib.rs);
the top-level modules are `connect`, `pool`, `rating`, `rotator`, and `types`.

## User management

```bash
resocks5 users add <name>            # add a user (interactive password)
resocks5 users add-init <name>       # claim-on-first-login placeholder
resocks5 users set-password <name>   # change a password
resocks5 users list                  # list users (never hashes)
resocks5 users enable  <name>
resocks5 users disable <name>
resocks5 users remove  <name> [--yes]
```

The server runs **without authentication** when no users are configured.
Passwords are only ever read from an interactive, no-echo prompt — never from
a command-line flag — so they don't leak into shell history.

## Repository layout

This is a Cargo workspace with two crates:

| Crate | Role |
|-------|------|
| [`resocks5-net`](crates/resocks5-net) | Reusable proxy networking toolkit — SOCKS5/HTTP/HTTPS upstream connectors, a pre-connect TCP pool, a sand-rating soft-weight rotator with exponential decay, and TLS ClientHello fragmentation. |
| [`resocks5`](crates/resocks5) | The CLI proxy server binary — wires `resocks5-net` together with KTAV configuration, Argon2 user auth, logging, and the SOCKS5/HTTP listener. |

```bash
cargo test --workspace      # run the test suite
cargo clippy --workspace --all-targets
```

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in the work by you, as defined in the Apache-2.0
license, shall be dual licensed as above, without any additional terms or
conditions.
