# Security Policy

`resocks5` is a proxy server that handles untrusted network input, performs
authentication, and forwards traffic to upstream proxies on behalf of clients.
Security-relevant bugs are taken seriously and handled fast.

## Reporting a vulnerability

**Do not open a public GitHub issue** for anything you suspect is a security
problem.

Please report privately, in order of preference:

1. **GitHub Private Vulnerability Reporting** — go to the
   [Security tab](https://github.com/PHPCraftdream/resocks5/security/advisories/new)
   of `PHPCraftdream/resocks5` and choose *Report a vulnerability*. This is the
   preferred channel: it keeps the report between you and the maintainer and
   lets us publish a GitHub Security Advisory + patched release together.
2. **Email** — `<phpcraftdream@gmail.com>`, with `[resocks5 security]` in the
   subject. If the report contains sensitive material, attach an
   [age](https://github.com/str4d/rage) payload encrypted to this public key
   (request the key in a heads-up email first so we can send it to you
   out-of-band).

Include, where relevant:

- resocks5 version (`resocks5 --version`) and the `resocks5-net` version it
  was built against.
- The OS and Rust toolchain used to build.
- A minimal `resocks5.proxy_list.ktav` / `resocks5.main.ktav` reproduction, or
  the smallest client script that triggers the bug. **Redact real credentials
  and upstream proxy addresses** before sending.
- Observed vs. expected behaviour.
- Whether the issue is reachable from an unauthenticated client, an
  authenticated client, or only the operator.

You should receive an acknowledgement within **72 hours**. If you have not
heard back in that window, follow up — email can silently disappear.

We credit reporters in the release notes and the corresponding GitHub Security
Advisory unless you ask to remain anonymous.

## Scope

**In scope:**

- The `resocks5` binary and the `resocks5-net` library, from a checkout of this
  repository or a release artifact we ship.
- Anything in the request path: protocol detection (SOCKS5 / HTTP CONNECT),
  authentication (secure auth over SOCKS5 0x80 and HTTP `Resocks5-Secure`, clear-text 0x02 / Basic against the same stored secret, init claims), upstream selection,
  the TCP pool, tunnel forwarding, TLS ClientHello fragmentation.
- Bypass of the safety rails: `max_concurrent_clients`, `max_per_upstream`,
  the protocol timeouts, or the banned-pattern filter.
- Privilege issues: an authenticated pool-user reaching the `direct: true`
  bypass path, or an unauthenticated client being routed to it.
- Resource-exhaustion / DoS from a single connection (unbounded buffer growth,
  log-channel stall, slowloris that defeats `client_protocol_timeout_sec`).
- Crashes, panics on untrusted input, or memory-safety issues reachable from
  the network.

**Out of scope** (but still welcome as a regular issue):

- The behaviour, security, or availability of any **upstream proxy** you point
  `resocks5` at — we forward to it, we don't control it.
- Misconfiguration by the operator (an open listener with no users, weak
  passwords, committed secrets in `resocks5.*.ktav`). The defaults are safe;
  the operator's responsibility begins where the docs say "change this if you
  …".
- DPI-evasion strength of TLS fragmentation. It is a best-effort defence
  against per-segment scanners and is documented as such in
  [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md); a DPI box that reassembles
  the stream defeats it by design.
- Issues only reproducible against an end-of-life or otherwise unsupported
  `resocks5` version.

## Disclosure

- We work on the fix in a private fork and coordinate a release with you.
- A GitHub Security Advisory is published together with (or shortly after) the
  patched release, including affected versions, a CVSS score, and credit.
- We support the latest minor release line. Please pin to a tagged release,
  not `main`, in production.

## Hardening notes for operators

These aren't vulnerabilities, they're defaults worth knowing about:

- A publicly reachable listener with `auth.allow_anonymous: true` is an open
  proxy, even when users are configured. Before exposing the port, add users
  (`resocks5 users add …`), set `allow_anonymous: false` inside the main config's
  existing `auth` block, and restart the server. User and authentication changes
  require a restart.
- `direct: true` users leak the **server's real IP** and the server's DNS
  resolver to every target they contact. Reserve it for trusted internal use.
- `resocks5.*.ktav` files contain upstream credentials and the users'
  Argon2id keys; a stored key logs its user in like the password does. They
  are git-ignored; never commit them, never world-read them.

## Authentication model and its limits

One port serves SOCKS5 and HTTP CONNECT and the server picks the strongest
method the client offers: our secure auth (SOCKS5 0x80, HTTP `Resocks5-Secure`),
then a clear-text password (SOCKS5 0x02, HTTP Basic), then anonymous access.
All of them verify against **one Argon2id secret per user**, so switching
protocol or method never breaks an account, and a `hash: init` account is
claimed by the first successful login by any of them. What this does and does
not protect:

- **Secure auth** never sends the password and the server never stores it; the
  stored key `K` is a credential, though (it logs its user in, and it is what
  an offline guess is checked against). Guard `resocks5.users.ktav`.
- **Clear text** (0x02, Basic) puts the password on the wire as is. There is no
  TLS on the listener. On an untrusted network set `auth.secure_only: true`
  (inbound: only our own method; standard clients can no longer log in) or put
  the port behind a protected transport such as a VPN or an SSH tunnel.
  `upstream_auth.secure_only: true`, or a `;secure_only` suffix on one list
  entry, does the same for upstream hops. Both flags are optional and default
  to `false`, so existing configs behave exactly as before.
- **Argon2id cost is deliberately low**: new secrets use 4 MiB, 1 pass,
  1 lane (`KdfParams::DEFAULT`), below the OWASP minimum of 19 MiB and 2
  passes, to keep clear-text checks cheap. The trade-off is explicit: guessing
  a password from a stolen users file, or from a captured secure-auth exchange
  (the exchange is an offline-guessing oracle at the cost of one derivation),
  is roughly 10 times cheaper than at the OWASP cost, and at this size the
  memory-hardness gives no ASIC or GPU resistance. **Use random passwords of at
  least 22 characters (128 bits)**: for those the cost is irrelevant. Secrets
  stored by earlier versions keep their parameters. A PAKE (OPAQUE, SRP) would
  remove the offline-guessing oracle; it is not part of this release.
- **Flood protection**: a flood of false logins cannot take the server down.
  Secure auth costs the server HMACs only; clear-text checks share a
  process-wide limit on concurrent derivations (half of the cores, at least
  one), wait at most a second for a slot and are refused rather than queued;
  an unknown, disabled or filtered name derives nothing (a short fixed pause
  keeps its timing close to a real check); successful logins are cached
  (HMAC tags only, never the password or the key; 4096 entries, 300 s, dropped
  when the stored secret changes), so clients that send Basic with every
  request do not re-derive. A sustained flood can still make clear-text
  logins of new clients fail while it lasts; `auth.secure_only` removes that
  surface completely.
- **First-login claim**: whoever knows an `init` account's name and reaches the
  port first claims it. Restrict that window with `allowed_clients`; a filtered
  peer is answered like a wrong password and can never claim.
