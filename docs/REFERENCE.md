# resocks5 — full reference

This reference is embedded in the binary: `resocks5 --help` and
`resocks5 config` print it without internet access. `resocks5 -h` is the
short help. The document describes the version in the current sources; the
installed GitHub latest release may be older than `main`. Binary version:
`resocks5 --version`.

## 1. Capabilities and limits

- One TCP port accepts SOCKS5 and HTTP CONNECT with automatic protocol
  detection. SOCKS5 supports CONNECT, not BIND/UDP ASSOCIATE.
- The HTTP interface is meant for CONNECT tunnels, not for ordinary HTTP
  forward-proxy requests such as `GET http://…`. A TCP tunnel can carry
  HTTPS, SSH, WebSocket and other protocols; once the tunnel is established
  the content usually passes unchanged in both directions.
- A named account with `direct: true` uses the server as a standalone proxy:
  the server connects to the target itself, no upstream proxies are needed.
- All other accounts and anonymous clients use upstream proxies: SOCKS5,
  HTTP CONNECT or HTTPS CONNECT; IPv4/IPv6 groups, chains through gates,
  a per-target sticky cache and sand-rating for route selection.
- There is name/password authentication (our own secure method, where the
  password is never sent, and the standard SOCKS5 username/password and HTTP
  Basic, allowed by default), client IP allow-lists, regex target bans,
  connection limits, timeouts, TCP keepalive, pre-opened TCP connections and
  logging.
- One port serves SOCKS5 and HTTP CONNECT, and the client picks the method:
  the server takes the strongest one the client offers — our secure method
  (SOCKS5 method 0x80, HTTP scheme `Resocks5-Secure`), then a clear-text
  password (SOCKS5 0x02, HTTP Basic), then anonymous access (if enabled).
  Standard clients (browsers, curl) do not know our method and connect with
  Basic or 0x02. The "Authentication" section below describes the methods,
  the single per-user secret and `init` registration.
- The inbound client TCP transport is not wrapped in TLS. The secure method
  never sends the password, but a clear-text password (0x02, Basic) crosses
  the network as is: on an untrusted network set `auth.secure_only: true` or
  use a protected transport (VPN, SSH tunnel). The tunnel traffic itself is
  not encrypted.
- An HTTP authentication failure is `407 Proxy Authentication Required` with
  `Proxy-Authenticate: Resocks5-Secure` and (while clear text is allowed)
  `Basic realm="resocks5"`; the connection stays open so that the client
  retries with credentials, and is closed after a refusal. Status 403 means
  access denied, 407 asks for authentication (RFC 9110 §15.5.8).
- An HTTPS upstream means TLS to the upstream proxy, not an HTTPS listener.
  A private certificate authority, inbound TLS, UDP, automatic system-service
  creation and automatic config reloading are not provided by this binary.

## 2. Commands and account management

| Command | Action and details |
|---------|--------------------|
| `resocks5` | Load the configs from the cwd and start the listener; exit with an error if there is no usable route. |
| `resocks5 -h` | Short help. |
| `resocks5 --help` | Commands and the full embedded reference. |
| `resocks5 --version` | Binary version; the short form is `-V`. |
| `resocks5 help` | Standard CLI help; for example `resocks5 help users`. |
| `resocks5 config` | Print this reference without starting the listener and without loading configs. |
| `resocks5 users` | Account management command group; a subcommand is required. |
| `resocks5 users add <name>` | Create an enabled pool account; the password is read without a CLI flag and an Argon2id key (a PHC string), not the password, is stored. This one secret verifies a login by any method and over any protocol. Use a random password of 22+ characters (see "Authentication"). |
| `resocks5 users add-init <name>` | Create an account with `hash: init`; the first successful login by any method (secure registration or a clear-text password over 0x02/Basic) binds that client's password to the account. Use only when you control the first connection. |
| `resocks5 users set-password <name>` | Set a new password for an existing account. |
| `resocks5 users remove <name>` | Delete an account. A TTY asks for confirmation; `--yes` skips it. With non-interactive stdin no confirmation is requested. |
| `resocks5 users list` | Show names, enabled/disabled and direct/pool; hashes are not printed. |
| `resocks5 users enable <name>` | Allow the account to authenticate. |
| `resocks5 users disable <name>` | Forbid authentication; the external refusal does not reveal whether the account is unknown or disabled. |
| `resocks5 users direct <name>` | Enable a direct connection from the server IP for this account. |
| `resocks5 users pool <name>` | Return the account to upstream routing. |

Every command has `--help`, for example `resocks5 users direct --help`.
A name at creation: 1–255 bytes, no `:`; names are compared case-sensitively.
A password: 1–255 bytes, not characters. A TTY prompts for the password and
its confirmation with echo off; with redirected stdin one password is read
without confirmation. Do not put secrets into arguments, shell history or
logs.

The `users` commands work only with `resocks5.users.ktav` in the cwd,
creating it when needed: a broken main/proxy_list does not prevent account
management. Changes are written atomically under an inter-process lock. A
running server needs a restart to apply them: it holds a snapshot of the
accounts, policies and configuration taken at startup, not a hot reload. The
exception is the password written by an init claim inside the current
process.

### Standalone proxy without upstreams

In the directory of the chosen instance:

```sh
resocks5 users add alice
resocks5 users direct alice
resocks5
```

The server creates the missing configs. Set
`auth: { allow_anonymous: false }` in `resocks5.main.ktav` to require a
password. If the server was already running, restart it after changing the
account or the settings. `socks5_v4`, `socks5_v6`, `http_v4`, `http_v6`,
`https_v4`, `https_v6` may stay empty: a single enabled direct user is
enough. Without upstreams and without such a user the start fails; gates
alone are not enough either. Do not enable direct for everyone by default.

`direct` is a permission of an account, not a global fallback when the
upstream refuses. An anonymous client gets no direct access. The direct
target sees the server IP; a domain name is resolved by the server's DNS
resolver. `banned_patterns`, `allowed_clients`, timeouts and limits still
apply.

curl client examples (the password is prompted for and not part of the
example):

```sh
curl --proxy socks5h://127.0.0.1:20082 --proxy-user alice https://example.com/
curl --proxy http://127.0.0.1:20082 --proxytunnel --proxy-user alice https://example.com/
```

For SOCKS5 use remote DNS resolution (`socks5h` in curl) when the target
name must be sent to the server instead of being resolved by the client.

## 3. Settings directory and the KTAV format

All config paths are relative to the current working directory of the launch
(cwd), not to the directory of the installed binary. Different cwds give
independent instances. This holds both for a launch through PATH and for the
`users` commands. The directory must allow the writes the server needs; on a
permission error the server does not silently switch to another directory.

| File | Contents |
|------|----------|
| `resocks5.main.ktav` | Listener, client admission, auth, network, pool, fragmentation and logs. |
| `resocks5.proxy_list.ktav` | Six arrays of upstream proxies. |
| `resocks5.users.ktav` | Accounts and their policies. |
| `resocks5.health.ktav` | Memory of dead upstreams between runs; written by the server itself, do not edit by hand (see "Memory of dead upstreams"). |

Without a subcommand missing files are created with default values. A first
run without upstreams and without a direct user creates the configs and then
exits with a message about missing routes. KTAV objects are written as
`{ ... }`, arrays as `[ ... ]`, comments as `## ...` lines. Do not use YAML
indentation instead of objects. KTAV string values are written without
quotes, including masks, commas and IPv6. The parser does not strip quotes:
they become part of the value — this is not JSON/YAML. When editing, replace
the existing key; do not add a second key with the same name.

An example of part of the main file (the other sections take defaults):

```text
port: 20082
listen_host: 127.0.0.1
allowed_clients: loopback
auth: { allow_anonymous: false }
```

The "Default" values below refer to a created config or to fields with a
serde default. Quotes in the Default column only denote the String type;
they are not KTAV value syntax. `port` and `auth` are mandatory in main when
the file is created by hand. If the `tls_fragment` section is given
explicitly, give all three of its fields; omitting the whole section selects
its Default.

### All fields of resocks5.main.ktav

| Field | Type | Default | Meaning |
|-------|------|---------|---------|
| `port` | u16 | 20082 | TCP port of both inbound protocols. `0` lets the OS pick a free port. |
| `listen_host` | String | `"127.0.0.1"` | Bind address; `"0.0.0.0"` opens all IPv4 interfaces. The behaviour of `"::"` for IPv4 depends on the OS and is not guaranteed to be dual-stack everywhere. |
| `banned_patterns` | [String] | [] | Regular expressions over the target string `host:port`, checked before connecting. This is not the automatically resolved IP of a domain and not a CIDR filter. |
| `allowed_clients` | String | `"*"` | Global TCP peer allow-list, syntax below. |
| `auth` | object | see below | Authentication policy; the section is mandatory. |
| `upstream_auth` | object | see below | Authentication policy towards upstream proxies; optional. |
| `log` | object | see below | Event category flags. |
| `file_log` | object | see below | File log destination. |
| `pool` | object | see below | Pre-opened TCP connections to upstreams. |
| `tls_fragment` | object | see below | Splitting the first TLS ClientHello in forwarded traffic. |
| `network` | object | see below | Timeouts, limits and sand-rating. |

An invalid regular expression prevents the server from starting. A rule such
as `^10\.` filters target strings that begin with `10.`, but does not forbid
a domain that DNS later resolves to `10.x.x.x`. For network isolation also
use the firewall/network policies of the OS.

### Authentication

| Field | Type | Default | Meaning |
|-------|------|---------|---------|
| `auth.allow_anonymous` | bool | true | Allow SOCKS5 without a name/password and HTTP CONNECT without Proxy-Authorization. The presence of users does not by itself disable anonymous access. |
| `auth.secure_only` | bool | false | Accept only our own secure method (SOCKS5 0x80, HTTP `Resocks5-Secure`): clear-text passwords (0x02, Basic) and anonymous access are disabled and `auth.allow_anonymous` is ignored. An optional field: when absent it is `false`, so old configs behave as before. |
| `upstream_auth.secure_only` | bool | false | For every upstream with `user:password` use only our own method: an upstream that offers nothing but a clear-text password is refused before the password is sent. The `upstream_auth` section is optional; a single list entry can be restricted with the `;secure_only` suffix (see section 4). |

- Empty users + `true`: anonymous access is possible, but an upstream route
  is needed.
- Empty users + `false`: all clients are rejected; the server refuses to
  start and tells how to add an account.
- Non-empty users + `true`: anonymous access stays available, named login is
  possible; presented credentials are still verified.
- Non-empty users + `false`: a successful named login is required.
- `auth.secure_only: true` together with `auth.allow_anonymous: true`:
  anonymous clients are not accepted and a warning is printed at startup;
  such a server does not start without users.

Both new flags are optional: when they are absent from the file the server
neither fails nor warns, and the value is `false`. They are written
explicitly, with comments, into a freshly created `resocks5.main.ktav`.

**Methods and how one is chosen.** The server picks the strongest method
that both the client offered and the server has enabled:

1. our own secure method: SOCKS5 method 0x80, HTTP scheme `Resocks5-Secure`
   (the same messages, one per 407 round, base64-encoded; the server's last
   token rides in the `Proxy-Authenticate` header of the `200` reply so that
   the client completes the mutual check). The password never crosses the
   network. This is our own protocol: standard clients do not offer it;
2. a clear-text password: SOCKS5 0x02 (RFC 1929), HTTP Basic (RFC 7617).
   This is how browsers, curl and other standard clients connect. Disabled
   by `auth.secure_only: true`;
3. anonymous: SOCKS5 0x00, HTTP without Proxy-Authorization — with
   `auth.allow_anonymous: true`.

A client without an acceptable method gets `[5, 0xFF]` (SOCKS5) or a `407`
listing the enabled schemes (HTTP). The HTTP `407` keeps the connection
open, and a standard client repeats the request with credentials on the same
connection; after four rounds or on a refusal (`Connection: close`) the
connection is closed.

**One secret for all methods and protocols.** For every user the PHC string
holds the Argon2id v19 salt, parameters and the derived key K. The secure
method verifies a mutual HMAC over K: the client computes Argon2, the server
only an HMAC. A clear-text password is verified by the server itself: it
derives Argon2id(password, salt, parameters) and compares it with K in
constant time. So an account created through the secure method also logs in
over Basic and 0x02, and the other way round: switching the protocol or the
method breaks nothing. The key K grants access just like the password: guard
the users file. An unknown, disabled and filtered name get the same refusal.

**`init` registration.** An account with `hash: init` is bound by the first
successful login by any method and over any protocol: either by secure
registration (the client sends its key encrypted with an ephemeral X25519
key) or by a clear-text login (the server derives the secret from the
presented password). The server records the secret atomically (also across
processes); concurrent attempts are refused; an empty password never claims
an account. An outsider who knows the name can claim an init account first —
protect the window of the first login, for example with `allowed_clients`:
the filter applies before the claim, and a filtered peer gets the same
refusal as for a wrong password.

**Argon2id cost and flood protection.** New secrets are derived with
m=4096 KiB (4 MiB), t=1, p=1. This is deliberately below the OWASP minimum
(19 MiB, 2 passes): guessing a password from a stolen users file or from a
captured secure-method exchange is noticeably faster (roughly 10 times).
This cost gives no ASIC or GPU resistance: use random passwords of 22+
characters (128 bits), for which the cost hardly matters. Hashes that are
already stored keep their parameters; a 0.4.x hash (m=5120, t=2, p=1) is
accepted without a warning. The load on the server is bounded as follows:
the secure method costs the server one HMAC; clear-text verification goes
through a shared limit on concurrent derivations (half of the cores, at
least one) — the excess waits at most a second and is then refused; an
unknown or filtered name does not compute Argon2 at all (only a short
pause); successful logins are cached (HMAC tags only, up to 4096 entries for
300 s, dropped when the secret changes), so clients that send Basic with
every request do not trigger a derivation again. `auth.secure_only: true`
switches the clear-text path off completely.

**What was removed.** GSSAPI/Kerberos is removed entirely. The keys
`auth.gssapi_service` and `auth.gssapi_protection` are ignored with a
warning, the `;gssapi=` suffix in upstream lists skips the entry with a
warning, and `hash: gssapi` accounts are flagged as unusable at startup (set
a password with `resocks5 users set-password`).

### Client IP allow-list

Example: `allowed_clients: loopback,192.168.*.*,2001:db8:*:*:*:*:*:*`.

- Elements are comma-separated, surrounding spaces are trimmed; within the
  list the elements are OR-ed.
- The global and the per-user rules are combined with AND. A missing user
  field means no extra restriction.
- `*` admits any IP; exact IPv4/IPv6 addresses are compared numerically.
- `loopback` (case-insensitive) is `127.0.0.0/8` and `::1`, not the addresses
  of all interfaces of this machine and not a replacement for
  authentication.
- An IPv4 mask has four octets, `*` replaces a whole octet. An IPv6 mask has
  eight hextet groups after `::` expansion, `*` replaces one group; `::`
  means only zeros. `2001:db8::*` is `2001:db8:0:0:0:0:0:*`, not the whole
  /64.
- IPv4-mapped IPv6 is normalized to IPv4. When compared with an IPv6 mask an
  IPv4 address is represented as `::ffff:a.b.c.d`: `::ffff:7f00:*` covers
  `127.0.0.1` and `127.0.255.255` but not `127.1.0.1`. IPv4-compatible IPv6
  without `ffff` is not turned into IPv4 automatically.
- Host names, ports, CIDR, `%zone`, brackets, partial `*`, leading zeros in
  IPv4, empty strings and empty elements are not supported. An error in any
  element stops the start even when `*` is present; disabled users and
  duplicate names are checked too.
- The source is the real TCP peer, not X-Forwarded-For. NAT or a reverse
  proxy changes the visible peer. A global refusal closes the TCP connection
  before the handshake; a per-user refusal gives the same refusal as a wrong
  password and does not let the peer reach an init claim.

### Network, timeouts and limits

| Field | Type | Default | Meaning |
|-------|------|---------|---------|
| `network.connect_timeout_sec` | u64 | 10 | Budget for connecting to an upstream or a direct target. |
| `network.handshake_timeout_sec` | u64 | 10 | Budget of the protocol handshake with an upstream; direct performs no upstream handshake. |
| `network.tunnel_max_lifetime_sec` | u64 | 1800 | Maximum tunnel lifetime; `0` disables the limit. |
| `network.tcp_keepalive_sec` | u64 | 60 | TCP keepalive idle on active sockets; `0` disables it. Does not replace application timeouts. |
| `network.client_protocol_timeout_sec` | u64 | 30 | Total deadline of the client phases counted from accept: protocol detection, handshake and the recovery peek share the remainder of one budget. |
| `network.max_concurrent_clients` | usize | 1024 | Total limit of client connections. When full, a new TCP connection is closed at once; `0` does not mean unlimited. |
| `network.max_upstream_attempts` | usize | 10 | Total limit of upstream route attempts of one request, fallback included; `0` does not mean unlimited. |
| `network.max_per_upstream` | usize | 8 | Limit of connections to `(host, port)`, busy and spare ones included; the value `0` is normalized to `1`. When full, the candidate is skipped without waiting and without a sand penalty. |
| `network.tunnel_idle_timeout_sec` | u64 | 30 | No confirmed data transfer in both directions ends the tunnel; `0` disables the idle limit. |
| `network.max_concurrent_direct` | usize | 256 | Total limit of direct tunnels after auth. SOCKS5 gets a refusal, HTTP gets 503; `0` forbids direct tunnels. Direct also occupies a total client slot. |
| `network.sand_half_life_sec` | f64 | 30.0 | Time for sand to halve; a finite positive value. |
| `network.sand_fail_penalty` | f64 | 1.0 | Sand increment per failure; a finite value >= 0; `0` disables the penalty model. |
| `network.sand_max` | f64 | 8.0 | Upper bound of sand; a finite positive value. |
| `network.sand_min_weight` | f64 | 0.05 | Weight of a saturated candidate relative to a fresh one; a finite normal number in (0, 1]. This is not a guaranteed traffic percentage. |
| `network.sand_success_factor` | f64 | 0.5 | Sand multiplier on success; a finite number in [0, 1]. |
| `network.quarantine_threshold` | u32 | 3 | How many consecutive failures that mean "the upstream is dead" (TCP connect refused or timed out, TLS failed, credentials rejected) take the upstream out of rotation. A refused or hung CONNECT to a single target does not count. While a live upstream exists, a quarantined one is not tried at all; if none is alive, the quarantine is ignored. `0` disables quarantine. |
| `network.quarantine_initial_sec` | u64 | 30 | Length of the first quarantine. After it ends the upstream is checked in the background with one TCP connection (client requests do not wait for it): reachable — it returns to rotation, not — the next quarantine is twice as long. >= 1 while quarantine is enabled. |
| `network.hedge_delay_ms` | u64 | 2000 | How many milliseconds an attempt may wait for the TCP connection to an upstream before the next candidate is started next to it: the first success wins. While the connected upstream talks to the target no new attempts are started (the target sees no duplicate CONNECT). An unknown dead upstream (for example right after startup) costs the request this delay, not `connect_timeout_sec`. `0` disables it (strictly one after another). Applies to direct upstream routes, not to chains through a gate. |
| `network.quarantine_max_sec` | u64 | 600 | Cap of the growing quarantine length; not less than `quarantine_initial_sec`. |
| `network.health_save_sec` | u64 | 30 | How often (seconds) to save into `resocks5.health.ktav` which upstreams are in quarantine, and to read that file at startup; it is saved only on changes and on a clean stop. `0` disables both writing and reading. Has no effect with `quarantine_threshold: 0`. |
| `network.recover_host_from_payload` | bool | true | For a pool request to a literal IPv4, try to recover the domain from the SNI/HTTP Host; direct and literal IPv6 do not use this path. |

The total client deadline does not become a new full timer at every stage.
Connecting to an upstream has separate connect/handshake budgets; once the
tunnel is established the idle and lifetime limits apply. Do not treat these
settings as a single global end-to-end timeout of all fallbacks. The sand
policy and its derived coefficients are validated when the rotator is
created; in direct-only mode the rotator may not be created at all.

Recovery can send a SOCKS5/HTTP CONNECT success before the upstream is ready
in order to read the client's first payload. A late error is then visible as
the tunnel closing, not as an ordinary CONNECT refusal. A bounded first
payload is read within the remainder of the client deadline; when there is
no suitable SNI/Host the original IP is used. This is not TLS decryption and
not recovery of a hidden ECH name. For a strict order of the reply after
connecting, and without this inspection, set
`recover_host_from_payload: false`.

### Memory of dead upstreams

Quarantine lives in process memory, so after a restart the server would not
know that some upstreams are dead and client requests would spend time on
them again. To avoid that, the server keeps the file `resocks5.health.ktav`
in the current directory: every `network.health_save_sec` seconds (if the
picture changed) and on a clean stop it writes the state of every upstream.
At startup the file is read before clients are accepted:

- `quarantined` with remaining time — returns to quarantine for the
  remainder, reduced by the server's downtime;
- `quarantined` whose time has run out, and `probation` — go on probation:
  they are not given to clients, and a background check (one TCP connect)
  decides whether the upstream is alive; a live one returns to rotation, a
  dead one gets the next, twice as long quarantine;
- `alive` and unknown upstreams (the proxy list changed) are skipped.

If the file was read, the startup check "one TCP connect to all upstreams"
is skipped: the file already knows who was dead, and a single connect in the
first second after a restart may fail by mistake because of the host state
(the network has not settled yet). Without the file (a first run) the check
runs as before. The reason a check failed is written to the log:
`is unreachable at startup (…)`.

The quarantine counter (`trips`) is kept, so the backoff keeps growing
instead of starting from zero. Passwords do not get into the file; an
upstream is identified by `protocol://user@host:port` and the gate level. The
file is not configuration: the server creates and rewrites it, delete it to
start from a clean slate. A corrupted file is ignored with a warning. On
kill -9 or a power failure the changes of the last `health_save_sec` seconds
are lost.

An example of the file (upstream records in the order: gate levels, then v6
and v4):

```ktav
saved_at: 1793000000
upstreams: [
    {
        upstream: socks5://alice@203.0.113.7:1080
        gate: 0
        state: alive
        remaining_sec: 0
        trips: 0
        failures: 0
    }
    {
        upstream: socks5://198.51.100.9:1080
        gate: 0
        state: quarantined
        remaining_sec: 240
        trips: 3
        failures: 3
    }
]
```

### Pre-opened TCP connections

| Field | Type | Default | Meaning |
|-------|------|---------|---------|
| `pool.enabled` | bool | false | Enable pre-connect spare sockets; this is not the direct/pool account switch. |
| `pool.spare_per_proxy` | usize | 1 | Target number of spare sockets per upstream; the effective value is bounded below by 1 and above by max_per_upstream. |
| `pool.max_session_age_sec` | u64 | 30 | Age of a spare socket after which it is replaced. |

An empty spare pool is not the same as no upstream: a new connection is
created when needed. The max_per_upstream limit applies even with the
pre-connect pool disabled. This pool is not used for direct targets.

### ClientHello fragmentation

| Field | Type | Default | Meaning |
|-------|------|---------|---------|
| `tls_fragment.enabled` | bool | false | Enable splitting of the first recognized TLS ClientHello when forwarding. |
| `tls_fragment.fragment_size` | usize | 40 | Part size; `0` is normalized to `1`. Smaller means more operations and overhead. |
| `tls_fragment.delay_ms` | u64 | 0 | Delay after the parts; `0` means no extra delay. |

Applies to the client's TLS ClientHello inside the tunnel and does not make
the server a TLS MITM. TCP_NODELAY reduces coalescing, but the application
cannot guarantee TCP packet boundaries. This is not a guarantee of bypassing
DPI: an analyzer that reassembles the whole stream still sees the
ClientHello. For an unsuitable payload the transfer stays ordinary. Large
delays are bounded by the timeouts.

### Log categories

| Field | Type | Default | Meaning |
|-------|------|---------|---------|
| `log.lifecycle` | bool | true | Start, listener, auth mode, stop. |
| `log.cache_attempts` | bool | false | Attempts to use a sticky route. |
| `log.cache_hits` | bool | false | Successful use of a sticky route. |
| `log.cache_writes` | bool | false | Update of a target-to-upstream binding. |
| `log.proxy_failures` | bool | true | Upstream errors. |
| `log.banned_targets` | bool | true | Banned targets. |
| `log.connection_errors` | bool | true | Client handling errors, including auth/protocol. |
| `log.client_disconnects` | bool | false | Reset/abort/closed peer; does not clutter the log by default. |
| `log.attempts` | bool | false | Attempt diagnostics: outcome, time, target and path. |
| `log.tunnels` | bool | false | One line per closed tunnel: target, how it ended, how many bytes were sent and received, duration. A tunnel on which the upstream returned no byte at all is written to `proxy_failures` regardless of this flag. A tunnel torn down by an I/O error names the side: `failed on client side` (the client reset it) or `failed on upstream side` (the upstream reset it). |
| `file_log.enabled` | bool | false | Additionally route events to a file. |
| `file_log.path` | String | `"resocks5.log"` | Append/create; a relative path is taken from the cwd. |
| `file_log.also_console` | bool | true | Also write to the console while file_log is enabled. |

A disabled category does not build the message. The log channel is bounded
to 2048 events; under overload some messages may be lost, so this is not
guaranteed audit delivery. Some startup messages are printed separately from
the categories. There is no automatic rotation/reopen: after moving the file
restart the process to open a new one.

## 4. All fields of resocks5.proxy_list.ktav

| Field | Type | Default | Meaning |
|-------|------|---------|---------|
| `socks5_v4` | [String] | [] | SOCKS5 upstreams, IPv4 group. |
| `socks5_v6` | [String] | [] | SOCKS5 upstreams, IPv6 group. |
| `http_v4` | [String] | [] | HTTP CONNECT upstreams, IPv4 group. |
| `http_v6` | [String] | [] | HTTP CONNECT upstreams, IPv6 group. |
| `https_v4` | [String] | [] | TLS to an HTTP CONNECT upstream, IPv4 group. |
| `https_v6` | [String] | [] | TLS to an HTTP CONNECT upstream, IPv6 group. |

An element: `[*][user:password@]host:port`. KTAV examples:

```text
socks5_v4: [
    alice:secret@192.0.2.10:1080
    *192.0.2.20:1080
]
socks5_v6: [
    alice:secret@[2001:db8::10]:1080
]
http_v4: [ 192.0.2.30:8080 ]
https_v4: [ user:secret@proxy.example.com:443 ]
```

Credentials are stored in the file as written. How they are used depends on
the protocol:

- A SOCKS5 entry with `user:password` upgrades automatically: the greeting
  offers our secure method (0x80) first and clear text (0x02) after it, and
  the upstream picks. The password stays in the process when the secure
  method is chosen.
- An HTTP or HTTPS entry sends `Basic` in its first CONNECT, exactly as
  0.4.x did. Many upstreams (3proxy among them) answer an unauthenticated
  CONNECT with `407` and close the connection, so the client does not probe
  first. Basic inside TLS (`https_*`) is not clear text on the wire.

A single entry can end with `;secure_only` (a line suffix without a value,
for example `192.0.2.10:1080;secure_only`), and the global
`upstream_auth: { secure_only: true }` does the same for every entry. Such
an entry offers only our own method (SOCKS5 0x80, or an HTTP probe that
requires `Resocks5-Secure`): an upstream that offers nothing but a
clear-text password is refused before the password is sent. This requires
the upstream to be another resocks5 or a client built on `resocks5-net`. A
malformed `;secure_only` option, or a leftover 0.4.x `;gssapi=` suffix,
skips the entry with a warning (the entry text is never printed).

IPv6 with a port is written in square brackets. The protocol scheme is given
by the array name, not by a mandatory URL prefix of the element. Invalid
elements are skipped with a warning that does not publish credentials.
Inside arrays old lines with a leading `#` are supported as comments; for an
ordinary KTAV comment use `##`.

An HTTPS upstream verifies the certificate and the proxy name against the
built-in Mozilla `webpki-roots` set, not automatically against the OS CA
store. The TLS handshake and the following CONNECT share one upstream
handshake deadline. There is no CLI flag to disable certificate verification
and no private-CA setting.

Stars set the gate rank: zero stars is an ordinary exit, one to 255 are gate
levels 1..255; more than 255 stars are invalid. For every level present
exactly one gate is chosen, the levels go in descending order; after them
comes exactly one ordinary exit, then the target. Gaps between levels are
allowed. One star keeps the previous gate value. Gates alone do not form a
route.

For example, here exactly one node is given on levels 3, 2 and 1, then one
ordinary exit:

```text
***user:pass@h1:1080
**h2:1080
*h3:1080
h4:1080
```

The result: server -> h1 -> h2 -> h3 -> h4 -> target. Gaps in ranks are
allowed: for example `***user:pass@h1:1080`, `*h3:1080` and `h4:1080` define
two gates (levels 3 and 1) and an exit. In chain mode the attempts of chains
and the fallback share the `network.max_upstream_attempts` budget, with at
least one attempt reserved for the fallback. The fallback bypasses gates and
chooses only an ordinary exit; it never connects to the target directly.

Every gate level has its own rotator; ordinary exits are also spread across
independent rotators. Nodes keep their own sand/quarantine and sticky state.
A successful chain is pinned to the target as a whole in the sticky cache.
The `network.max_per_upstream` permits are held for every node for the whole
tunnel lifetime. Startup probes and the pre-connect pool apply only to the
outer gate level and the ordinary exits. A quarantined inner-level gate is
checked through a healthy outer prefix. On a failure that marks a node dead
the plan skips its subtree without trying the combinations of descendants.

The sticky cache prefers a previously successful route for the same target
string; the cache is bounded to 4096 entries per rotator and a TTL of 600
seconds, not unbounded. These SDK limits are not fields of the binary's main
config. Sand-rating lowers the weight of a failing upstream and gradually
restores it without hard exclusion; an error of our own capacity does not
penalize the upstream.

## 5. All fields of resocks5.users.ktav

| Field | Type | Default | Meaning |
|-------|------|---------|---------|
| `users` | [object] | [] | Array of accounts. The CLI does not create identical names; with manual duplicates the runtime uses the first record. |
| `users[].name` | String | required | Account name. |
| `users[].hash` | String | required | Argon2id v19 PHC (salt, parameters, key) or the special string `init`; never a clear-text password. |
| `users[].is_enabled` | bool | true | Allow login. |
| `users[].direct` | bool | false | Standalone proxy from the server IP, without upstreams. |
| `users[].allowed_clients` | optional String | absent | Additional IP restriction; None is not serialized and does not widen the global policy. |

Create and change passwords/modes through `users`. The per-user
`allowed_clients` is edited by hand on a stopped instance: there is no
separate CLI command for this field. Do not edit the users file at the same
time as an init claim or another writer: a third-party editor is not obliged
to honour the application's lock. Do not publish the users file, a proxy list
with credentials and configs in logs or repositories.

## 6. Installation, upgrade and operation

- Official archives: Linux x86_64 and arm64 (static musl — runs on any
  distribution, Alpine included), macOS Intel/Apple Silicon, Windows x86_64
  (static CRT, no VC++ Redistributable). There is no native Windows ARM64
  archive yet. Static Linux archives appeared in 0.4.0; 0.3.0 and earlier
  have only the glibc archive `x86_64-unknown-linux-gnu`, which does not
  promise compatibility with all old glibc versions. The container image
  remains an alternative.
- `.github/scripts/install.sh` and `install.ps1` download the latest stable
  release, pin the tag and verify the SHA-256 from sha256sums.txt. Checksums
  protect the download but do not replace trust in the publisher.
- Without administrator rights: `~/.local/bin` or
  `%LOCALAPPDATA%\resocks5\bin`. Alternative: `sh install.sh /path/to/bin` or
  PowerShell `-InstallDir`. PATH is not changed automatically; the commands
  to add it are in the README.
- An upgrade does not stop the server. Unix renames atomically; the old inode
  stays with the process. Windows renames the old exe to its own
  `.resocks5-old-<GUID>.exe`, publishes the new one and on error tries to
  restore the previous name. Free backups are deleted on a successful
  install, busy ones stay until the next installer run after the process
  ends. `.resocks5-install.lock` is a permanent name for a temporary handle
  lock, not a sign of an installer hung forever.
- A running process keeps using the old version and the old settings; a new
  launch uses the new binary and the configs of the chosen cwd.
- Docker: `ghcr.io/phpcraftdream/resocks5:latest`, Linux amd64/arm64; the
  container cwd is `/etc/resocks5`, the process UID is 65532. The mounted
  directory must be writable for this UID. The distroless image has no shell:
  edit the configs from the host. Publish the port as
  `127.0.0.1:20082:20082` until auth/firewall are configured.
- Ctrl+C, and on Unix also SIGTERM, close the listener and give active
  tunnels up to 30 seconds to finish. Forced process termination is not a
  graceful shutdown. SIGHUP/hot reload and daemon/service commands are not
  provided; supervision is configured separately by OS means.
- Legacy: when the new files are absent, `resocks5.conf` and the old SOCKS
  lists `socks5_ipv4_list.txt`/`socks5_ipv6_list.txt` are migrated. The old
  files stay in place; delete them after checking the result, not in
  advance.

## 7. Diagnostics and safe settings

- "no upstream proxies": fill an ordinary upstream array or enable an
  existing direct user. Anonymous access alone does not create a route.
- Auth refusal: check the cwd, enabled, the password, auth.allow_anonymous,
  auth.secure_only (a standard client cannot log in when it is on),
  allowed_clients and whether a restart is needed. `users list` does not
  describe the auth policy of the main file; empty users does not mean
  anonymous when it is false.
- TCP is closed without a reply: check the global allowed_clients,
  max_concurrent_clients, the client deadline and the error log.
- HTTP 407 / SOCKS5 auth failure: wrong credentials or a per-user IP filter;
  disabled/unknown are deliberately not distinguished externally.
- HTTP 403 / SOCKS5 Forbidden (REP 2): banned_patterns.
- HTTP 502 / SOCKS5 host unreachable (REP 4): an unreachable upstream route
  or a direct-connect error. HTTP 503 / SOCKS5 general failure (REP 1): an
  exhausted direct limit.
- If you need exactly the upstream's error reply after CONNECT: turn
  recovery off. For minimal diagnostics use log.attempts, proxy_failures and
  connection_errors; enable the noisy cache categories only when needed.
- Before opening the listener to the outside, disable anonymous access,
  create accounts, restrict client IPs, configure the firewall and a
  protected transport (or `auth.secure_only`). Do not treat a loopback bind
  or banned_patterns as a full network ACL.

The README has installation commands and quick scenarios.
docs/ARCHITECTURE.md describes the implementation and algorithms;
SECURITY.md covers vulnerability reports.
