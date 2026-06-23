/// Dump human-readable documentation for the three config files to
/// stdout. Invoked from the `resocks5 config` subcommand.
///
/// The text is hardcoded rather than generated from struct docstrings —
/// keep it in sync by hand when adding fields. The
/// `default_main_serializes_every_field` test in
/// `config::load_or_init` will catch missing serialised fields, but
/// only this function is the user-facing reference for what each
/// field actually means.
pub fn print_config_docs() {
    print!("{}", DOCS);
}

const DOCS: &str = r#"resocks5 — configuration reference
====================================

Three files live in the working directory, all auto-created on first
launch with sensible defaults. KTAV supports comment lines that start
with `##` — but this document is the authoritative reference for what
each field does.

resocks5.main.ktav  — server settings
-------------------------------------

port: u16                       (default 20082)
    Local TCP port the server binds on. Both SOCKS5 and HTTP CONNECT
    clients connect to this single port; the server auto-detects the
    protocol from the first byte.

listen_host: String             (default "127.0.0.1")
    Host (interface) the listener binds on. Defaults to localhost so
    a fresh install never accidentally exposes the proxy to the
    network. Flip to "0.0.0.0" (IPv4 LAN), "::" (dual-stack IPv6+v4)
    or a specific interface address only when auth, banned_patterns
    and the firewall in front of you are all set up for that.

banned_patterns: [String]       (default [])
    List of regex patterns. A target host:port matching any pattern
    is rejected before any upstream attempt. Compiled once at startup
    into a single DFA, so the per-connection cost is constant in the
    number of patterns. Example:
        banned_patterns: [
            \.example\.com:
            ^10\.
        ]

auth: { ... }                   (always present)

    auth.allow_anonymous: bool  (default true)
        When true, the server advertises SOCKS5 method 0x00
        (no-auth) alongside any user/password method, and accepts
        HTTP CONNECT without Proxy-Authorization. When false, only
        authenticated clients are accepted.

        Behaviour matrix:
          users.ktav | allow_anonymous | client experience
          -----------|-----------------|--------------------------
          empty      | true (default)  | anonymous (legacy)
          empty      | false           | every client rejected
          non-empty  | true            | client may auth or skip
          non-empty  | false           | client MUST auth

log: { ... }                    (per-event flags; defaults shown below)
    Each flag, when false, makes the corresponding log line a no-op
    (no allocation, no channel send) so leaving noisy categories off
    is essentially free.

    log.lifecycle: bool           (default true)
        Server start, bind address, auth-mode summary.
    log.cache_attempts: bool      (default false)
        "Attempting to use cached proxy for <addr>" — every cache
        lookup. High volume; debug only.
    log.cache_hits: bool          (default false)
        "Cache used for <addr>" — every successful cache hit.
        Highest-volume event on a healthy server.
    log.cache_writes: bool        (default false)
        "Cache written for <addr>" — once per first-seen target.
    log.proxy_failures: bool      (default true)
        Per-attempt connect/handshake failures. Useful to see which
        upstreams are dying.
    log.banned_targets: bool      (default true)
        Connections to banned addresses. Security-relevant.
    log.connection_errors: bool   (default true)
        Errors from per-client handlers — auth failures, malformed
        clients, half-broken handshakes.
    log.attempts: bool            (default false)
        One structured line per upstream connect+handshake attempt,
        with outcome (ok/fail), duration in ms, target, proxy, gate,
        and path (cache/gate/direct). High volume; enable temporarily
        to diagnose which upstreams are slow or dead.

file_log: { ... }              (optional file destination for logs)

    file_log.enabled: bool                (default false)
        Master switch. When false, the drain task writes to
        stdout/stderr only — behaviour is identical to pre-file-log
        builds. When true, log lines are written to `path` (and
        optionally also to the console, see `also_console`).

    file_log.path: String                 (default "resocks5.log")
        File path opened with O_APPEND | O_CREATE at startup. Each
        log line — both info and error — is written in the format
        "YYYY-MM-DD HH:MM:SS: <message>". No rotation; rotate
        externally (logrotate, etc.) via rename + signal.

    file_log.also_console: bool           (default true)
        When true, log lines are written to BOTH the file AND
        stdout/stderr as usual. When false, only the file receives
        log lines — console output is suppressed.

pool: { ... }                   (pre-connect TCP pool to upstreams)

    pool.enabled: bool                      (default false)
        Master switch. When false, no background tasks run and every
        upstream connect is a fresh TcpStream::connect — same as
        before the pool existed. Old configs are unaffected.

    pool.spare_per_proxy: usize             (default 1)
        Target number of pre-warmed sockets per upstream (host, port).
        One always-fresh spare ready, the moment it's taken the
        refill task kicks off another connect.

    pool.max_session_age_sec: u64           (default 30)
        After this many seconds, a pre-warmed socket is discarded
        and reconnected. Defends against the common pattern of
        upstream proxies silently dropping idle TCP after 30-60 s.

tls_fragment: { ... }           (TLS ClientHello fragmentation)
    Splits the first outgoing TLS ClientHello into small TCP segments
    so that stateless DPI cannot extract the SNI hostname from a single
    packet. Effective only against per-segment inspection; stateful DPI
    with full-stream reassembly is not defeated by fragmentation alone.
    TCP_NODELAY is enabled automatically on the upstream socket when
    tls_fragment.enabled is true, so the OS does not merge fragments
    via Nagle's algorithm.

    tls_fragment.enabled: bool              (default false)
        Master switch. When false all traffic is forwarded as-is and
        no additional reads or socket options are applied. Old configs
        without this section are unaffected.

    tls_fragment.fragment_size: usize       (default 40)
        Bytes per TCP segment. The TLS ClientHello SNI field is
        typically at offset 45–80 bytes into the record; a fragment
        size of 40 bytes puts it in a later segment, making the
        hostname invisible to per-segment scanners.
        Set to 1 for maximum splitting (slowest), 100–200 if only
        lightweight DPI needs to be bypassed.

    tls_fragment.delay_ms: u64              (default 0)
        Milliseconds to wait between consecutive fragments. Zero sends
        all fragments back-to-back. A small value (1–5 ms) can help
        against stateful DPI that reassembles only within a short time
        window. Raises per-connection latency by delay_ms × (record
        size / fragment_size), so keep it low.

network: { ... }                (timeouts and TCP keepalive)
    Safety net against dead upstreams and half-closed tunnels. Without
    these caps a misbehaving proxy can stall callers for tens of
    seconds per connect, leave sockets in CLOSE_WAIT forever, and burn
    through the per-account connection quota at the upstream provider.

    network.connect_timeout_sec: u64        (default 10)
        Maximum time to wait for a TCP `connect()` to an upstream
        proxy. Without this cap a dead proxy blocks for the full
        kernel SYN timeout (~21 s on Windows, ~127 s on Linux),
        multiplied by every fallback attempt.

    network.handshake_timeout_sec: u64      (default 10)
        Maximum time for one SOCKS5 handshake exchange with an
        upstream (greeting + auth + CONNECT). A proxy that accepts
        our TCP but stalls in the middle of the protocol is treated
        as dead and the next candidate is tried.

    network.tunnel_max_lifetime_sec: u64    (default 1800)
        Hard cap on total lifetime of a forwarded tunnel, from the
        moment SOCKS5/CONNECT setup completes. Defends against tunnels
        that are kept alive forever by a misbehaving peer (no FIN, no
        RST). Half an hour is generous enough for typical browsing and
        long-poll HTTP; set higher for long-lived sessions like SSH or
        websockets. `0` disables the cap (not recommended).

    network.tcp_keepalive_sec: u64          (default 60)
        TCP keepalive idle interval. After this many seconds of
        silence the kernel starts probing the peer; non-responsive
        peers get the socket closed by the OS, which propagates back
        to us as an I/O error and tears the tunnel down. This is the
        primary defense against half-open zombie connections on the
        upstream proxy's side. `0` disables keepalive entirely.

    network.client_protocol_timeout_sec: u64 (default 30)
        Time budget for the client-side protocol phase — from the
        moment a client connects until SOCKS5/CONNECT setup is done
        and forwarding starts. Defends against slowloris-style clients
        that open TCP but never finish the handshake. Does not bound
        the subsequent upstream chain (which has its own timeouts).

    network.max_concurrent_clients: usize   (default 1024)
        Maximum number of in-flight client tunnels. New connections
        that would exceed this are dropped immediately (TCP close, no
        protocol reply). Caps worst-case resource usage under attack
        or runaway load.

    network.max_upstream_attempts: usize    (default 10)
        Hard cap on connect+handshake attempts per one client request
        across all configured proxies. Prevents a 100-proxy fleet
        with 10 s timeouts from translating into ~15 min of upstream
        retries for a single client.

    network.tunnel_idle_timeout_sec: u64    (default 30)
        Idle timeout on a forwarded tunnel: if no bytes flow in
        either direction for this many seconds, both halves get an
        explicit `shutdown()` (FIN) and the connection is torn down.
        Releases the per-upstream connection slot promptly instead
        of waiting for the TCP keepalive cycle or
        `tunnel_max_lifetime_sec` to expire.
        `0` disables the idle check (only keepalive + lifetime apply).

    network.max_per_upstream: usize         (default 8)
        Maximum simultaneous TCP connections to any single upstream
        proxy (host, port). Permits are held for the lifetime of each
        tunnel and released on drop. When the cap is hit, `acquire`
        fails fast — `establish_connection` skips this proxy and
        tries the next one instead of waiting.

        This is what defends the *upstream* provider's per-account /
        per-IP connection quota. Without it a burst of client
        requests opens hundreds of sockets in parallel, the provider
        flat-out stops responding (or saturates the proxy process's
        FD table), and every direct attempt 10-s-times-out until the
        provider's cool-down expires. Through Tor the symptom is
        masked because each circuit sources from a different exit IP.

        Tune to the provider's published limit. The default of 8 was
        empirically chosen against residential SOCKS5 providers that
        start refusing handshakes when hammered with 10+ concurrent
        from a single account. Bump higher only if you know your
        provider can take it:
          dirt-cheap shared:    3–5
          residential (default 8 is safe for most)
          premium dedicated:    100+

    network.sand_half_life_sec: f64         (default 30.0)
        Sand model: time in seconds for accumulated failure sand to
        decay by half. Shorter values make the model forget failures
        faster; longer values make it hold a grudge.

    network.sand_fail_penalty: f64         (default 1.0)
        Sand added to the upstream's accumulator on each failure.
        Higher values make a single failure weigh more heavily.

        Setting sand_fail_penalty: 0.0 disables the sand model
        entirely and gives pure round-robin selection (escape hatch).

    network.sand_max: f64                  (default 8.0)
        Hard ceiling on accumulated sand per upstream. Prevents any
        single upstream from being penalised beyond this level.

    network.sand_min_weight: f64           (default 0.05)
        Weight of a fully-saturated upstream (sand == sand_max).
        Even the worst upstream is never excluded — it is still
        selected with at least this probability share.

    network.sand_success_factor: f64       (default 0.5)
        Multiplicative factor applied to current sand on each
        success. Values below 1.0 reduce sand (restore weight);
        0.5 means each success halves the accumulated penalty.

        Note: cap-hit (max_per_upstream semaphore full) does NOT
        count as an upstream failure — it is our own load, not an
        upstream fault.

    network.max_concurrent_direct: usize   (default 256)
        Maximum number of simultaneous bypass (direct) tunnels across
        all direct-enabled users. New direct connections that would
        exceed this cap are rejected after authentication — SOCKS5
        gets a general-failure reply, HTTP CONNECT gets 503. This
        limit is independent of max_concurrent_clients: the client
        slot is acquired first (at accept), the direct slot is
        acquired later (after auth confirms the user is direct).
        Tune to the outbound bandwidth / FD budget you are willing
        to dedicate to direct traffic. 256 is generous for a personal
        server; lower it on shared hosts or raise it on a dedicated
        box with plenty of headroom.

    network.recover_host_from_payload: bool (default true)
        When the CONNECT target is a bare IP literal, recover the
        original hostname from the client's first record — TLS SNI on
        port 443, or the HTTP `Host` header for plain HTTP — and
        address the upstream by that domain instead of the IP.

        Why: some SOCKS front-ends (e.g. Proxifier with local DNS)
        resolve the destination on the client and send an IP. Upstream
        proxies that refuse CONNECT to raw CDN IPs then time out every
        such request, while the same host succeeds by name. This
        recovers the name the client already stated in its own payload.

        Trade-off: the SOCKS5 success reply is sent BEFORE the upstream
        is connected (a later upstream failure surfaces as a dropped
        tunnel, not a SOCKS error), and the first client record is
        inspected to read SNI/Host. Set to false for strict RFC 1928
        reply ordering and zero payload inspection. Falls back to the
        IP when no name can be recovered (non-TLS, no SNI, ESNI/ECH).

resocks5.proxy_list.ktav  — upstream proxies
--------------------------------------------

Six arrays, each a list of `[*]user:pass@host:port` strings.
The leading `*` marks a gate (chained proxy). For KTAV-level comment
lines anywhere in the file, use `##` (e.g. `## backup pool`). The
parser also tolerates legacy single-`#` lines inside the proxy arrays
themselves and skips them — kept for backwards compatibility with
older proxy lists.

socks5_v4: [String]             (default [])
socks5_v6: [String]             (default [])
http_v4: [String]               (default [])
http_v6: [String]               (default [])
https_v4: [String]              (default [])
https_v6: [String]              (default [])

SOCKS5 upstreams use the SOCKS5 protocol (RFC 1928).
HTTP upstreams use HTTP CONNECT (plain TCP to the proxy).
HTTPS upstreams use TLS-wrapped HTTP CONNECT — the connection to
the upstream proxy is encrypted with TLS before sending CONNECT.
This is what commercial providers like Bright Data and Oxylabs use.

Example:
    socks5_v4: [
        alice:s3cret@1.2.3.4:1080
        *gate.example.com:1080
        2.3.4.5:1080
    ]
    https_v4: [
        user:pass@proxy.example.com:443
    ]

resocks5.users.ktav  — client users
-----------------------------------

Managed primarily by `resocks5 users <add|set-password|remove|list|
enable|disable|direct|pool>`. Each entry stores an Argon2id PHC
string for the password, plus an `is_enabled` flag — disabled users
are rejected without the client being able to tell disabled from
unknown.

Per-user "direct" flag (bool, default false):
    When true, traffic for this user bypasses the upstream proxy pool
    and connects straight from the server's own IP to the target.

    Security notes:
    - Bypass leaks the server's real IP address to every target the
      direct user connects to.
    - DNS resolution for the target is performed by the server itself
      (not by any upstream proxy), which leaks queries to the
      server's configured resolver.
    - Only authenticated users may be marked direct — anonymous
      clients are never eligible for the direct path.

    Manage with CLI commands:
        resocks5 users direct <name>   — enable direct bypass
        resocks5 users pool <name>     — disable direct (use pool)

DO NOT edit this file by hand, with one explicit exception:

Init-on-first-login: setting a user's `hash` field to the literal
string `init` marks the account as unclaimed. The first client that
connects with that username submits a password which the server
hashes (Argon2id), writes back into this file, and from that point on
the account behaves as a normally-managed user. Concurrent first
attempts are serialised internally — exactly one winner records the
password, others either match (same password → accepted) or get the
standard rejection.

Warning: the window between marking a user `init` and the first
legitimate login is wide open to whoever knows the username. Use this
mode only when you control both ends of that timing.

Migration from the legacy layout
--------------------------------

If `resocks5.conf` and/or `socks5_ipv4_list.txt` /
`socks5_ipv6_list.txt` exist on first launch, they are migrated into
the new `.ktav` files. The old files are left in place untouched —
delete them once you've confirmed the new ones look right.

See `resocks5 --help` for CLI options and `resocks5 users --help`
for user management.
"#;
