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
  authentication (Argon2id verify + the HMAC verify-cache), upstream selection,
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

- A listener bound to `0.0.0.0` **with no users configured is an open proxy.**
  Add users (`resocks5 users add …`) before exposing the port.
- `direct: true` users leak the **server's real IP** and the server's DNS
  resolver to every target they contact. Reserve it for trusted internal use.
- `resocks5.*.ktav` files contain the auth salt, upstream credentials, and
  Argon2 hashes. They are git-ignored; never commit them, never world-read
  them.
