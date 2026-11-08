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
- [Standalone proxy without upstreams](#standalone-proxy-without-upstreams)
- [Detailed reference and all features](#detailed-reference-and-all-features)
- [Full reference of fields and commands](docs/REFERENCE.md)
- [How it works](#how-it-works)
- [Configuration](#configuration)
- [Authentication](#authentication)
- [Client IP allow-list (allowed_clients)](#client-ip-allow-list-allowed_clients)
- [Use as a library](#use-as-a-library)
- [User management](#user-management)
- [Repository layout](#repository-layout)
- [License](#license)

## Features

- **SOCKS5 + HTTP CONNECT** front end, auto-detected per connection.
- **Upstream protocols:** SOCKS5, HTTP, and HTTPS (TLS-wrapped CONNECT) proxies.
- **Rotation + stickiness:** weighted-random selection across the pool,
  with a per-target cache so a given destination keeps using the upstream
  that last worked.
- **Gates (proxy chaining):** route through one proxy at each configured
  gate level, highest to lowest, then one ordinary exit before the target.
- **Sand-rating soft-weight rotator:** each upstream has a per-failure
  sand accumulator that decays exponentially over time. Upstream selection
  is weighted-random with weight `exp(-k · sand)` — failing upstreams are
  picked less often but never excluded, and recover automatically as their
  sand drains. When every upstream is bad the weights equalise, so a
  full outage degrades to uniform random selection instead of locking out.
- **Per-upstream concurrency cap** to respect a provider's per-account/per-IP
  connection quota.
- **Optional pre-warmed TCP pool** to cut connection latency.
- **TLS fragmentation:** splits the ClientHello across TCP segments to defeat
  SNI-based DPI blocking.
- **Authentication:** one port, one account, three methods; the server picks
  the strongest the client offers. Our own **secure auth** (SOCKS5 method
  0x80, HTTP scheme `Resocks5-Secure`) never sends the password and never
  stores it (an Argon2id-derived key and a mutual HMAC challenge-response).
  Standard clients (browsers, curl) connect with the clear-text methods
  (SOCKS5 0x02, HTTP Basic), verified against the same stored secret, or
  anonymously where allowed. One secret per user works for every method and
  protocol, and a `hash: init` account is claimed by the first successful
  login by any of them. Two optional switches harden a deployment:
  `auth.secure_only` (inbound) and `upstream_auth.secure_only` (outbound)
  accept only our own method. Upstream `user:pass` entries upgrade
  automatically on SOCKS5.
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
degrades to uniform random selection instead of a lockout, and a recovering
upstream is probed for free because its weight never hits zero.

### How it compares

| | resocks5 | 3proxy | gost | glider |
|---|---|---|---|---|
| Language | Rust (rustls / `ring`) | C | Go | Go |
| Front end | SOCKS5 + HTTP CONNECT (auto) | many | many | many |
| Rotation model | sand-rating soft-weight, self-recovering | round-robin / parent | chaining-first | failover |
| Per-target stickiness | yes | — | — | — |
| Auth | secure auth (password never sent or stored) plus Basic / RFC 1929 | basic | basic | basic |
| TLS ClientHello fragmentation | yes | no | no | no |
| Single-port dual-protocol | yes | — | — | — |

**Where resocks5 wins**

- **Rotation that never locks you out** — the sand-rating model's whole
  reason to exist.
- **TLS fragmentation** for per-segment, SNI-based DPI, built in.
- **Rust + rustls** — memory-safe; no `cmake` needed (`ring` compiles
  bundled C sources, but the C compiler in any standard Rust build
  environment — MSVC Build Tools, gcc, or clang — covers it).

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

### Latest release: Linux, macOS and Windows

The installers download the **latest stable GitHub Release**; they do not
build the code from `main`. Neither Rust nor a C compiler is needed. The tag
is resolved once; the archive and `sha256sums.txt` are downloaded from the
same release, and the SHA-256 is verified before installing. The check
protects against a damaged download but does not replace trust in the
release publisher.

| OS | Architecture | Installer | Default directory |
|----|--------------|-----------|-------------------|
| Linux (any distribution, glibc and musl/Alpine) | x86_64, arm64 | `sh` | `~/.local/bin` |
| macOS | Intel x86_64, Apple Silicon arm64 | `sh` | `~/.local/bin` |
| Windows | x86_64 | PowerShell 5.1+ | `%LOCALAPPDATA%\resocks5\bin` |

The Linux archives are fully static (musl) and depend on no system
libraries; the Windows binary is built with a static CRT and does not need
the Visual C++ Redistributable. Static Linux archives and arm64 are
published starting with 0.4.0; 0.3.0 and earlier had only the glibc x86_64
archive (the installer picks the matching release archive by itself; an old
release is not supported on musl/Alpine).

For other platforms (Windows ARM64) native archives are not published yet:
the installer fails with an error and does not try to build the project.

**Linux / macOS** — needs `curl`, `tar` and `sha256sum` or `shasum`:

```sh
(
  set -eu
  installer_dir=$(mktemp -d)
  trap 'rm -rf -- "$installer_dir"' 0
  curl --proto '=https' --proto-redir '=https' --tlsv1.2 -fsSL \
    https://raw.githubusercontent.com/PHPCraftdream/resocks5/main/.github/scripts/install.sh \
    -o "$installer_dir/install.sh"
  sh "$installer_dir/install.sh"
)

# For the current terminal; for a permanent setup add it to ~/.profile
# or your shell's configuration file:
export PATH="$HOME/.local/bin:$PATH"
resocks5 --version
```

**Windows** — run in PowerShell; administrator rights are not needed:

```powershell
$installerDir = Join-Path ([IO.Path]::GetTempPath()) ("resocks5-script-" + [guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path $installerDir
try {
    $script = Join-Path $installerDir 'install.ps1'
    Invoke-WebRequest -UseBasicParsing -Uri 'https://raw.githubusercontent.com/PHPCraftdream/resocks5/main/.github/scripts/install.ps1' -OutFile $script -ErrorAction Stop
    powershell -NoProfile -ExecutionPolicy Bypass -File $script
    if ($LASTEXITCODE -ne 0) { throw 'Installation failed.' }
}
finally {
    Remove-Item -LiteralPath $installerDir -Recurse -Force
}

# For the current terminal:
$env:Path = "$env:LOCALAPPDATA\resocks5\bin;$env:Path"
resocks5 --version
```

For a permanent Windows setup add `%LOCALAPPDATA%\resocks5\bin` to the user
`Path` variable in the environment settings and open a new terminal.
`-ExecutionPolicy Bypass` applies only to the launched process; the system
policy is not changed. Both commands run the script from this repository;
you can inspect the downloaded file before running it.

Another directory can be passed as `sh install.sh /path/to/bin` or
`powershell -NoProfile -ExecutionPolicy Bypass -File install.ps1 -InstallDir 'D:\apps\resocks5'`.
The installers do not change `PATH`, do not start the server and do not
touch the configs. Running again updates only the binary, **a running
`resocks5` does not need to be stopped**. The installer does not restart the
process: an existing server keeps running the old version, new launches use
the new one.

- **Linux/macOS:** the new file is atomically renamed over the old one. The
  old inode stays available to the running process; the OS frees it when the
  process ends. No backup names are created.
- **Windows:** the old file is renamed to `.resocks5-old-<GUID>.exe`, then
  the new one gets the name `resocks5.exe`. If the second step fails, the
  installer tries to restore the previous name. Every successful install
  deletes unused old copies; files that are busy, locked or inaccessible are
  kept with a warning. After the old process ends its copy is deleted by the
  next successful install. Only this installer's backup names are deleted,
  never arbitrary `.exe` files. The `.resocks5-install.lock` file prevents
  several installers from changing the directory at once; the mere presence
  of the file does not mean an active lock.

### Where the settings come from after installing

`resocks5` reads and creates `resocks5.main.ktav`, `resocks5.proxy_list.ktav`
and `resocks5.users.ktav` **in the current working directory of the launch**,
not next to the installed binary. This applies to `resocks5 users …` as well.
The directory must be writable; installing into `PATH` does not change this
rule. For example, on Linux/macOS:

```sh
mkdir -p my-proxy
cd my-proxy
resocks5
```

On Windows in PowerShell:

```powershell
$null = New-Item -ItemType Directory -Path 'my-proxy' -Force
Set-Location 'my-proxy'
resocks5
```

Launches from different directories use independent sets of settings. The
first launch creates the missing files in the chosen directory; to get a
working proxy afterwards configure upstream proxies or direct users, as
described below.

### Build from source

Requires a recent stable Rust toolchain. The dependency tree (rustls 0.23,
rpassword 7) sets the floor at **Rust 1.88+**, declared as `rust-version` in
every crate and enforced by the `msrv` job in CI. The crate uses the `ring`
crypto provider, which compiles bundled C sources as part of the build, so
a C compiler must be available — as it already is on any system set up to
build Rust — but no `cmake` is needed.

```bash
# Build from a checkout:
cargo build --release
# → target/release/resocks5[.exe]

# …or install the binary onto your PATH from a checkout:
cargo install --path crates/resocks5
# …or straight from git:
cargo install --git https://github.com/PHPCraftdream/resocks5 resocks5
```

Prebuilt binaries are attached to each
[GitHub Release](https://github.com/PHPCraftdream/resocks5/releases); the
binary is not published on crates.io (only the `resocks5-net` library is).

### Run with Docker

A multi-arch image (`linux/amd64`, `linux/arm64`) is published to ghcr.io on
every release tag:

```bash
# Prepare a writable bind-mount directory on Linux; the image runs as UID 65532.
mkdir -p "$PWD/resocks5-config"
sudo chown 65532:65532 resocks5-config
# First run creates the three config files, then exits; it does NOT start a usable proxy.
docker run --rm \
  -v "$PWD/resocks5-config:/etc/resocks5" \
  ghcr.io/phpcraftdream/resocks5:latest

# Edit resocks5.main.ktav in the mounted host directory before starting:
# set listen_host: 0.0.0.0 and auth.allow_anonymous: false.
# Add at least one upstream to resocks5.proxy_list.ktav by replacing its
# existing `socks5_v4: []` line; do not add a duplicate key.
# Example: socks5_v4: [ user:pass@198.51.100.7:1080 ]
# The generated files are owned by UID 65532; on Linux use an elevated editor
# or choose host permissions that let your user edit them.
# Add a client user (interactive password prompt):
docker run --rm -it \
  -v "$PWD/resocks5-config:/etc/resocks5" \
  ghcr.io/phpcraftdream/resocks5:latest users add alice

# Start with host access restricted to localhost by default.
docker run --rm -p 127.0.0.1:20082:20082 \
  -v "$PWD/resocks5-config:/etc/resocks5" \
  ghcr.io/phpcraftdream/resocks5:latest

# …or build it yourself and use resocks5 instead of the image name above:
docker build -t resocks5 .
```

The mounted config directory must be writable by UID 65532. On Linux, prepare
it as shown above; permissions depend on the host platform (`chown` is
Linux-specific, and Docker Desktop bind mounts generally work). The generated
files are owned by UID 65532, so on Linux use an elevated editor or choose host
permissions that let your user edit them. The image is distroless, so it has no
shell; edit the bind-mounted config files on the host. Keep the host port bound
to `127.0.0.1` unless remote access is intended and secured.

## Quick start

```bash
# 1. The first run creates the three config files in the working directory,
#    then exits telling you that no upstream proxies are configured yet.
resocks5

# 2. Add at least one upstream to resocks5.proxy_list.ktav by editing the
#    existing socks5_v4 line (replace `socks5_v4: []` in place — ktav rejects
#    duplicate keys, so don't append a second socks5_v4):
#       socks5_v4: [ user:pass@198.51.100.7:1080 ]

# 3. (Optional) add a client user. Anonymous access is enabled by default;
#    see below for requiring credentials before exposing the listener.
resocks5 users add alice

# 4. Start the proxy. It listens on 127.0.0.1:20082 by default.
resocks5

# 5. Point your SOCKS5 / HTTP-proxy client at 127.0.0.1:20082.
```

Before exposing the listener beyond localhost, configure users and edit the
existing `auth` block in `resocks5.main.ktav`:

```text
auth: { allow_anonymous: false }
```

Restart the server after applying these settings. Adding users alone leaves
anonymous access enabled when `allow_anonymous` is `true`. Apply both settings
before changing `listen_host` to a public interface.

## Standalone proxy without upstreams

`resocks5` can serve SOCKS5 and HTTP CONNECT itself, connecting to the
target from the server's IP. This is the **`direct: true` account setting**,
not a global mode and not an automatic fallback when an upstream refuses.

In the instance's working directory create a user and enable direct:

```sh
resocks5 users add alice
resocks5 users direct alice
resocks5
```

Set `auth: { allow_anonymous: false }` in `resocks5.main.ktav` to require a
password. All six upstream arrays may stay empty: a single enabled direct
user is enough. After changing an account or the configs restart the server.
To return an account to upstream routing: `resocks5 users pool alice`.

An anonymous client gets no direct access. The target sees the server's IP,
DNS is resolved by the server; IP filters, banned_patterns, timeouts and
limits still apply. Details and client commands: the
[full reference](docs/REFERENCE.md).

## Detailed reference and all features

```sh
resocks5 -h                         # short help
resocks5 --help                     # the full embedded reference
resocks5 config                     # the same reference without starting the server
resocks5 users --help               # account management
resocks5 users add-init --help      # the first login sets the password: limits and risks
resocks5 users direct --help        # a standalone proxy per account
```

**[docs/REFERENCE.md](docs/REFERENCE.md)** is the single full reference
embedded in the binary: all commands, all fields of the three configs,
types, defaults, special values, examples, limits and diagnostics. `--help`
and `config` work without internet; `config` neither reads nor creates
configs.

| Capability | Setting / management |
|------------|----------------------|
| SOCKS5 and HTTP CONNECT on one port | `listen_host`, `port`; TCP CONNECT, no SOCKS5 UDP/BIND and no ordinary HTTP forward GET |
| Standalone proxy | `users direct/pool`, `users[].direct`; named enabled accounts only |
| Passwords, disabled accounts, first login | `users add/add-init/set-password/enable/disable/remove/list`, `auth.allow_anonymous` |
| Authentication methods | Secure auth (0x80 / `Resocks5-Secure`), clear text (0x02 / Basic) and anonymous; `auth.secure_only`, `upstream_auth.secure_only`, `;secure_only` per upstream entry |
| Client IP admission | `allowed_clients`, `users[].allowed_clients`: rule intersection, loopback and masks |
| Target bans | `banned_patterns`: a regex over `host:port`, not automatic filtering of DNS addresses |
| SOCKS5/HTTP/HTTPS upstreams | Six arrays in proxy_list, credentials, IPv6 and `*` gates |
| Rotation and target stickiness | Sand-rating and a bounded sticky cache, not a hard circuit breaker |
| Pre-opened TCP connections | `pool.enabled`, `spare_per_proxy`, `max_session_age_sec`; not to be confused with a pool account |
| Protection against hangs and overload | All `network.*`: connect/handshake/client/tunnel deadlines, idle, keepalive and limits |
| SNI / Host recovery | `network.recover_host_from_payload`: pool + a literal IPv4, an early CONNECT reply is possible |
| ClientHello fragmentation | `tls_fragment.*`: splitting the first recognized ClientHello, no promise of DPI bypass |
| Logging | All `log.*`, `file_log.*`; the file is append-only, no automatic rotation |
| Install and upgrade | Latest GitHub Release, SHA-256, Windows rename/cleanup and Unix atomic rename |
| Separate instances | Configs from the cwd, a snapshot at startup, a restart to apply changes |
| Container and shutdown | Docker amd64/arm64, UID 65532, a writable volume; Ctrl+C/SIGTERM and a bounded drain |
| Safety and diagnostics | Do not expose anonymous access; clear-text passwords cross the network and the tunnel is not encrypted — see [SECURITY.md](SECURITY.md) |

The settings, allowed values and practical limits of every row are covered
in the reference, and the implementation in
[ARCHITECTURE.md](docs/ARCHITECTURE.md).

## How it works

For each accepted connection:

1. **Protocol detect** — the first bytes decide SOCKS5 vs HTTP CONNECT.
2. **Authenticate** — the server picks the strongest method the client
   offers. Secure auth (SOCKS5 method 0x80, HTTP `Resocks5-Secure`) proves the
   password against the stored Argon2id key without sending it; standard
   clients (browsers, curl) use SOCKS5 username/password or HTTP Basic, which
   the server verifies against the same stored secret (unless
   `auth.secure_only` is on). Anonymous clients are accepted only when
   `auth.allow_anonymous` is `true`.
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
| `resocks5.main.ktav` | server settings: port, auth, logging, pool, network/sand-rating, TLS fragmentation, banned patterns, `allowed_clients` |
| `resocks5.proxy_list.ktav` | upstream proxies, grouped by transport and IP family |
| `resocks5.health.ktav` | written by the server, not by hand: which upstreams were dead, so a restart goes straight to background probes instead of rediscovering them (`network.health_save_sec`, `0` = off) |
| `resocks5.users.ktav` | users: passwords and flags go through `resocks5 users …`; `allowed_clients` is edited by hand while the server is stopped |

Print the **full field reference** — every option, its default, and behaviour
notes — with:

```bash
resocks5 config
```

> **Security:** these files hold secrets — upstream proxy credentials and
> the users' Argon2id keys (a key logs its user in, like a password). They
> are git-ignored; never commit them.

### Upstream proxy list

In `resocks5.proxy_list.ktav`, list upstreams in arrays per transport and IP
family. Each entry is `user:pass@host:port` (credentials optional), prefixed
by zero to 255 stars; more than 255 are invalid. Zero is an ordinary exit;
positive counts are gate levels.

```text
socks5_v4: [
  alice:s3cret@198.51.100.7:1080
  *gateuser:gatepass@203.0.113.9:1080
]
http_v4:  [ 198.51.100.20:8080 ]
https_v4: [ user:pass@198.51.100.30:443 ]
## …and the corresponding *_v6 arrays for IPv6 upstreams.
```

Credentials stay in this file. A SOCKS5 upstream with `user:pass` upgrades
automatically: secure auth (0x80) is offered first and clear text (0x02)
after it, and the upstream picks. An HTTP or HTTPS upstream gets Basic in the
first CONNECT, as in 0.4.x (many upstreams, 3proxy among them, close the
connection after a `407`, so the client does not probe first; Basic inside
TLS is not clear text on the wire). To use only our own secure method for
one upstream append `;secure_only` to its entry, or set
`upstream_auth: { secure_only: true }` in `resocks5.main.ktav` for all of
them: an upstream that offers nothing but a clear-text password is then
refused before the password is sent.

One node at each rank contributes one gate, ordered from highest to lowest,
then one ordinary exit and the target. Missing ranks are allowed. One star
retains the original gate meaning; gates without an ordinary exit cannot
form a route. The complete chain is sticky per target. Ordinary-route
fallback bypasses gates and selects only ordinary exits; it does not connect
directly to the target. All attempts share `network.max_upstream_attempts`,
with at least one attempt reserved for fallback; cached chains are admitted
under the same reserve, except that a budget of 1 still serves the sticky
cache first. `network.max_per_upstream`
limits each node's permits for the whole tunnel lifetime. Startup probes
and the pre-connect pool cover only the outermost gate level and exits;
probes for inner quarantined gates traverse the healthy outer prefix.
Independent rotators keep sand, quarantine, and sticky-cache state per
proxy/rank; whole-chain stickiness uses the complete chain identity.

For example, this skips rank 2 and uses one gate from each present rank:

```text
***user:pass@h1:1080
*h3:1080
h4:1080
```

The route is server -> h1 -> h3 -> h4 -> target.

## Authentication

One dual-protocol port serves SOCKS5 and HTTP CONNECT, and the client picks
the method: the server takes the **strongest one the client offers**.

| Order | Method | SOCKS5 | HTTP | Needs |
|-------|--------|--------|------|-------|
| 1 | Our secure auth: the password never crosses the network | method `0x80` | scheme `Resocks5-Secure` over `407` rounds | a client that speaks it (`resocks5-net`, another resocks5) |
| 2 | Clear-text password | `0x02` (RFC 1929) | `Basic` | any standard client (browsers, curl); off with `auth.secure_only` |
| 3 | Anonymous | `0x00` | no credentials | `auth.allow_anonymous: true` (the default) |

**One secret per user, for every method and protocol.** `users.ktav` stores
an Argon2id key (salt, parameters and key in a PHC string). Secure auth
proves knowledge of it with a mutual HMAC (the client does the Argon2 work);
a clear-text password is verified by deriving the same key on the server and
comparing in constant time. So an account that enrolled over SOCKS5 secure
auth logs in later over HTTP Basic, and the other way round — switching
protocol or method never breaks an account.

**`hash: init` registration** works over every protocol and method: the
first successful login claims the account atomically (one winner), either by
secure enrollment or by a clear-text login (the server derives the secret
from the presented password). Guard that first window, for example with
`allowed_clients`, because whoever knows the name can claim it first.

**Two optional switches** (both default to `false`; a config without them
loads silently, and a freshly generated config writes them explicitly with
comments):

```text
auth: { allow_anonymous: true, secure_only: false }
upstream_auth: { secure_only: false }
```

- `auth.secure_only: true` — inbound accepts only our own method; clear text
  and anonymous access are refused (standard clients can no longer log in).
- `upstream_auth.secure_only: true` — outbound uses only our own method for
  every upstream with credentials; one entry can opt in with a `;secure_only`
  suffix in `resocks5.proxy_list.ktav`. An upstream that offers nothing else
  is refused before the password is sent.

Old configs behave exactly as before: `allow_anonymous` still defaults to
`true` and clear text is accepted. For an untrusted network turn
`auth.secure_only` on or wrap the port in a protected transport.

**Cost trade-off and flood protection.** New secrets use Argon2id with
4 MiB, 1 pass, 1 lane — deliberately below the OWASP minimum (19 MiB,
2 passes). Guessing a password from a stolen users file or a captured secure
exchange is therefore roughly 10 times cheaper, and this gives no ASIC/GPU
resistance: use random passwords of 22+ characters. Floods of false logins
cannot take the server down: secure auth costs the server one HMAC;
clear-text checks share a limit on concurrent derivations (half of the
cores) and are refused rather than queued; unknown names derive nothing; and
successful logins are cached (HMAC tags only, 4096 entries, 300 s), so
clients that send Basic on every request do not re-derive. See
[SECURITY.md](SECURITY.md) and [docs/REFERENCE.md](docs/REFERENCE.md).

## Client IP allow-list (allowed_clients)

The global `allowed_clients` string in `resocks5.main.ktav` (default `"*"`,
everyone) restricts which client IPs may connect at all. The check uses the
**real TCP address of the peer**, before any protocol byte is read; a
rejected peer's connection is closed without a reply. An invalid rule fails
the server start (fail-closed), including rules attached to disabled and
duplicate users. Changes need a restart: the rule is compiled once into a
snapshot at startup.

Every user in `resocks5.users.ktav` can carry an optional `allowed_clients`
string. The final check is the **AND of the global rule and the user's
rule** (the user's field adds a restriction only when set); the elements
inside one list are **OR** alternatives. The user's filter is applied when
the secret is looked up, so a rejected IP gets the same refusal as a wrong
password (secure auth `Denied`, or the clear-text refusal) and cannot claim
an init account. It does not apply to anonymous clients at all (they obey
only the global rule); direct users obey it like everyone else.

Supported forms (comma-separated; elements are trimmed of spaces):

- an exact IP: `127.0.0.1`, `::1`, `2001:db8::1` — standard std syntax
  only;
- `loopback` — `127.0.0.0/8` and `::1` (not any interface address and not a
  replacement for authentication);
- wildcard `*` — the whole list (`*`) or exactly one octet of an IPv4 mask
  (exactly 4 octets): `192.168.*.*`, or exactly one hex group of an IPv6
  mask (exactly 8 groups): `2001:db8:*:*:*:*:*:*`. `::` may appear once and
  means **only** zero groups: `2001:db8::*` is `2001:db8:0:0:0:0:0:*`, not
  a /64.

When checked against an IPv6 mask an IPv4 address is treated as
`::ffff:a.b.c.d`; IPv4-compatible addresses (`::a.b.c.d` without ffff) are
not expanded. Example: the mask `::ffff:7f00:*` matches `127.0.0.1` and
`127.0.255.255`, but NOT `127.1.0.1`. The rejected forms — host names, CIDR,
ports, partial stars (`1*.2.3.4`), empty elements (`a,,b`) — make the whole
string invalid.

Alternative KTAV values — pick one, replacing the existing key. Strings are
written without quotes: quotes become part of the value and are not
stripped.

```text
allowed_clients: *
allowed_clients: 127.0.0.1,::1
allowed_clients: loopback
allowed_clients: 192.168.*.*
allowed_clients: 2001:db8:*:*:*:*:*:*
```

The peer is the actual TCP source address as the server sees it: behind NAT
or a reverse proxy the peer is the proxy's address — `X-Forwarded-For` is
NOT consulted.

## Use as a library

The networking core is published as a separate crate,
[`resocks5-net`](crates/resocks5-net) — inbound smart-port framing, upstream
connectors, the TCP pool, sand-rating, rotation and TLS fragmentation. Credential
storage, logging and routing policy stay in the host application.
Add it from crates.io (the inbound `server` module needs 0.3 or newer, chain dialing over an
existing stream, `dial_chain_over`, needs 0.4.1; `ProxyConfig::validate`, the
opt-in inbound options, secure auth and method negotiation need 0.5.0),
or as a git dependency to follow `main`:

```toml
[dependencies]
resocks5-net = "0.5"
# resocks5-net = { git = "https://github.com/PHPCraftdream/resocks5" }
tokio = { version = "1", features = ["full"] }
anyhow = "1"
```

Connect to a target through an upstream proxy and drive any protocol over the
returned stream:

```text
use std::time::Duration;

use resocks5_net::connect::{connect_proxy, parse_proxy_str};
use resocks5_net::pool::{PoolConfig, ProxyPool};
use resocks5_net::rotator::ProxyRotator;
use resocks5_net::types::ProxyProtocol;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Parse upstream lines: "user:pass@host:port" (credentials optional).
    let proxies = ["user:pass@198.51.100.7:1080"]
        .into_iter()
        .filter_map(|s| parse_proxy_str(s, ProxyProtocol::Socks5).ok())
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

Multi-hop chains (`ProxyConfig::gate`) are dialed with `dial_chain` (own TCP),
`connect_chain` (pooled) or `dial_chain_over` (a stream you already own, for
example from Tor), all with per-hop `ChainStage` error attribution; see the
[SDK README](crates/resocks5-net/README.md).

The library entry point is [`resocks5_net`](crates/resocks5-net/src/lib.rs);
the top-level modules include `server`, `connect`, `error`, `progress`, `pool`,
`rating`, `rotator`, and `types`.

### Embed a SOCKS5 + HTTP CONNECT listener

The `resocks5_net::server` module is available without default features; with
the default `secure-auth` feature it also authenticates users against a
store you provide (our secure method, plus clear-text SOCKS5 0x02 / HTTP
Basic verified against the same stored secret):

```text
let options = resocks5_net::server::ServerOptions::new(accept_deadline)
    .allow_anonymous(false); // clear text stays on; `.secure_only()` turns it off too
let decoy = resocks5_net::secure_auth::DecoyKey::generate()?;
let methods = resocks5_net::server::AuthMethods::secure(&store, &decoy);
let mut req = resocks5_net::server::accept_with(&mut client, &options, &methods).await?;
// Host-owned destination policy and real egress connection happen here.
// Only after egress is ready:
req.reply(&mut client, resocks5_net::server::Reply::Established).await?;
let prefix = req.take_pipeline(); // send exactly once before relaying unread bytes
```

The snippet's stream, deadline, user store (`store`, a `SecretStore`) and
egress are supplied by the host, not fabricated by the parser. See the
[complete API contracts and usage](crates/resocks5-net/README.md#inbound-server-api).

`accept_with` returns an unresolved destination, the verified username
(`None` for anonymous), the method that authenticated it and owned pipeline
bytes. It bounds detection/auth/framing with one absolute Tokio deadline;
the application anchors this at listener acceptance before task spawning.
HTTP headers are byte-parsed, accept unused obs-text, and have a
delimiter-inclusive 16KiB cap independent of tunneled payload size. On
cancellation/error discard the stream; admitted authentication persistence
can still finish. Routing, gates, SNI/Host recovery, logs and egress/tunnel
budgets remain host-owned. After early recovery success, failure closes the
tunnel instead of sending a second reply. A host with its own user database
implements `SecretStore` (the default clear-text check derives under a
process-wide limiter; override `check_password` to add a verified-credential
cache); the Tor proxy
[tor-socks5](https://github.com/PHPCraftdream/tor-socks5) embeds its
listener through the same module.

## User management

```bash
resocks5 users add <name>            # add a user (interactive password; one secret for every method)
resocks5 users add-init <name>       # claim-on-first-login placeholder
resocks5 users set-password <name>   # change a password
resocks5 users list                  # list users (never hashes)
resocks5 users enable  <name>
resocks5 users disable <name>
resocks5 users remove  <name> [--yes]
resocks5 users direct  <name>       # bypass upstream pool
resocks5 users pool    <name>       # route through upstream pool (default)
```

Anonymous access defaults to `auth.allow_anonymous: true`, including when users
are configured. Set it to `false` to require credentials. Restart the server
after changing users or authentication settings to apply the new snapshot.
Passwords are only ever read from an interactive, no-echo prompt — never from
a command-line flag — so they don't leak into shell history.

## Repository layout

This is a Cargo workspace with two crates:

| Crate | Role |
|-------|------|
| [`resocks5-net`](crates/resocks5-net) | Reusable proxy networking toolkit — SOCKS5/HTTP/HTTPS upstream connectors, a pre-connect TCP pool, a sand-rating soft-weight rotator with exponential decay, and TLS ClientHello fragmentation. |
| [`resocks5`](crates/resocks5) | The CLI proxy server binary — wires `resocks5-net` together with KTAV configuration, secure-auth users, logging, and the SOCKS5/HTTP listener. |

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
