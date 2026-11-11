# resocks5-net

Reusable proxy networking toolkit in Rust: the engine the
[`resocks5`](https://github.com/PHPCraftdream/resocks5) proxy server is
built on, factored out as a self-contained library.

What's inside:

- **Inbound smart-port framing** (`server`, always available): SOCKS5/HTTP
  CONNECT detection, closure authentication, unresolved requests and replies.
- **Upstream connectors** for SOCKS5, HTTP CONNECT, and HTTPS (TLS-wrapped
  CONNECT) proxies.
- **Pre-connect TCP pool** (`pool` feature) that keeps warm sockets to each upstream, plus a
  per-upstream concurrency cap that respects provider-side per-account
  connection quotas.
- **Sand-rating model** — each upstream has a failure accumulator that
  decays exponentially over time. Upstream selection is weighted-random
  with weight `exp(-k · sand)`: failing upstreams are picked less often
  but never excluded, and recover automatically as their sand drains.
  When every upstream is bad the weights equalise, so a full outage
  degrades to uniform random selection instead of locking out.
- **Quarantine** (opt-in, `ProxyRotator::try_with_quarantine`) — after
  repeated *hard* failures (`record_hard_failure`) an upstream leaves
  `pick_order` and the sticky cache for a doubling backoff while healthy
  upstreams exist; then `take_probes` hands it out for an out-of-band check
  (`record_success` / `record_hard_failure`). Client orders never wait on it. Without it the sand weights alone apply.
  `ProxyRotator::health` / `restore_health` export and re-create the
  quarantine picture (`UpstreamHealth`, `rating::{Health, UpstreamState}`) so a
  restart need not rediscover dead upstreams; it holds durations only — the
  caller saves it and subtracts the downtime.
- **TLS ClientHello fragmentation** for SNI-based DPI evasion.
- **Strong authentication** — one dual port serves SOCKS5 and HTTP CONNECT,
  and the server always picks the strongest method the client supports:
  secure auth (private method 0x80 / HTTP `Resocks5-Secure`, feature
  `secure-auth`), clear text (SOCKS5 0x02 / HTTP `Basic`, switchable off),
  or anonymous (off by default) — one stored secret per user verifies all
  of them. Upstream dials upgrade a plain user/password pair to secure
  auth automatically.

No application concerns leak in: no config-file format, logger, credential
storage, or egress policy. Inbound authentication is supplied by a
`SecretStore` with the strong acceptors (`accept_secure`, `accept_with`),
or by the host's admission policy through the anonymous-only `accept`.

## Features

- `pool` (**enabled by default**): the pre-connect TCP pool (`ProxyPool`,
  `PoolConfig`, `AtCapacity`, `ConnectError::AtCapacity`) and the
  pool-taking connectors (`connect_proxy`, `connect_http_proxy`,
  `connect_socks5_proxy`, and with `tls` also `connect_https_proxy`); it is
  the only user of `dashmap` and `crossbeam-queue`. Without it you still
  get the pool-free `dial` / `connect_proxy_once`, the protocol cores,
  `AnyUpstream` / `UpstreamStream`, the tunnel, ClientHello fragmentation
  and the rating / rotator modules, with neither dependency in the graph.
  `AnyUpstream`, `UpstreamStream`, `BoxedUpstream` and `AsyncReadWrite`
  live in `connect` and are also re-exported from `pool`.
- `tls` (**enabled by default**): HTTPS (TLS-wrapped CONNECT) upstreams,
  the Mozilla-root-store default connector (`connect::make_tls_connector`),
  and the `AnyUpstream::Tls` variant, backed by `rustls`, `tokio-rustls`
  and `webpki-roots`. The default connector relies on rustls'
  process-level crypto-provider resolution: install a provider once at
  process startup
  (`rustls::crypto::ring::default_provider().install_default()`) or hand
  one in via `connect::make_tls_connector_with_provider` / your own
  `TlsConnector`. A build that links both `ring` and `aws-lc-rs` (or
  enables rustls' `custom-provider` feature) makes `connect::make_tls_connector`
  panic unless such an install happened first — see its `# Panics`
  documentation. Lean SOCKS5/HTTP-only builds opt out with
  `default-features = false`; a config that then still names an HTTPS
  upstream fails fast with an error naming the missing feature — never a
  silent plaintext fallback. TLS ClientHello fragmentation stays available
  without the feature: it fragments raw bytes and links none of the TLS
  stack. The trailing `tls_connector` argument of `connect_proxy` (needs `pool`)/
  `connect_proxy_once` is present in every build — lean builds included —
  and takes `None` for SOCKS5/HTTP upstreams, so one call site compiles no
  matter which features other crates in the same build enable; in a
  `default-features = false` build its type is an unconstructible
  placeholder, making `None` the only possible value. For the common
  SOCKS5/HTTP case the slot-free `dial_plain` exists in every build.
- `serde` (**enabled by default**): the `Serialize`/`Deserialize` derives on
  `pool::PoolConfig`, the crate's only serde touchpoint (a no-op without
  `pool`). Consumers that
  build their own config plumbing opt out with `default-features = false`
  and drop serde and its proc-macro compile chain; the struct itself —
  `Debug`, `Clone`, `Default`, hand-construction — is unchanged.
- `rating` / `rotator` (**enabled by default**; `rotator` implies
  `rating`): the sand-rating model and the weighted rotator that drives
  upstream selection. Connector/pool-only consumers can opt out for a
  smaller public API and less to compile. Unlike `tls` and `serde` this
  removes no dependency — both modules are `std` only.
- `secure-auth` (**enabled by default**): password authentication for SOCKS5
  that never puts the password on the wire. Private-use method 0x80
  (`secure_auth::METHOD`); the server stores per user only a `UserSecret` —
  random salt, `KdfParams`, and the Argon2id key
  `K = Argon2id(password, salt, params)` (`KEY_LEN` = 32) — never the
  password. A login is a mutual HMAC-SHA256 challenge-response over `K`
  with fresh 32-byte nonces on both sides: a recorded exchange cannot be
  replayed, and a peer not holding `K` cannot pose as the server (the
  client checks the server proof in constant time). Unknown users are
  answered with a decoy derived from a `DecoyKey` (process-local random
  key; the same name always gets the same decoy salt), indistinguishable
  from a wrong password, so user names are not enumerable. A client
  refuses server KDF parameters below its floor
  (`SecureCredentials::with_min_kdf` / `ProxyConfig::with_min_kdf`; by default
  only `KdfParams::MIN` is required, so no cost is refused) and above the hard limits
  (256 MiB, 16 passes, 16 lanes; `KdfParams::is_in_range`), so a man in the
  middle cannot downgrade the KDF. One secret per user, any protocol, any
  method: the stored `UserSecret` verifies both the strong exchange and the
  clear-text methods through the default `SecretStore::check_password`
  (`Argon2id(password, stored salt + params)` compared to the stored key in
  constant time), so switching between SOCKS5 0x80/0x02 and HTTP
  `Resocks5-Secure`/`Basic` never breaks the account. Clear-text derivations
  run under a `DerivationLimiter` — by default the process-wide
  `secure_auth::derivation_limiter()` (half the CPU count in flight, a
  bounded 1 s wait, saturation rejects without queueing), replaceable per
  store through `SecretStore::derivation_limiter` — so the server is not
  taken down by a couple of hundred false authorizations; the client side
  has its own limiter, so inbound floods never starve outbound derivations.
  Unknown users cost no server-side derivation (a cheap fixed sleep keeps
  timing in the same order) and hosts SHOULD override `check_password` with
  a verified-credential cache. First-login enrollment works for every protocol
  and method: a user stored as `StoredUser::Init` is claimed by its first
  client — either by sending `K` sealed with X25519 + HKDF-SHA256 +
  ChaCha20-Poly1305 bound to both nonces over method 0x80, or by a
  clear-text login that stores `UserSecret::from_password` at the store's
  `enrollment_floor()` (`PasswordCheck::Claimed`); of two concurrent first
  logins exactly one wins. Limits, stated plainly: this is not a
  PAKE — a passive observer can still try passwords offline (the Argon2id
  cost slows that; use strong passwords), and only the authentication is
  protected: the SOCKS5 request that follows travels plain, and tunnel
  data is never protected. Pulls argon2, hmac/hkdf/sha2, subtle,
  getrandom, zeroize, x25519-dalek and chacha20poly1305.
- `test-instrumentation` (off by default; implies `rotator`): test-only
  cross-crate instrumentation — `testing::MockUpstream` (a scripted
  SOCKS5/HTTP CONNECT upstream on 127.0.0.1:0, see the `testing` module
  below, with `MockAuth::{None, Cleartext, Secure, SecureDenied,
  AuthStatus, NoAcceptableMethod}`), and the rotator's
  `pick_order_calls()` diagnostic counter. Dependents enable it from
  `[dev-dependencies]`; it is not default, so release builds compile it to
  nothing.
- `zeroize` (off by default): wipes the retained user name of
  `server::IncomingRequest` when it is dropped, and the secure-auth password when
  the last copy of its credentials goes (the `zeroize` crate, already part of the
  TLS dependency tree). Outbound `ProxyConfig` credentials are plain public
  `String` fields and are not wiped.
  With the feature, `ProxyConfig::wipe_credentials()` also overwrites and
  clears `user`/`password` at this node and every gate it solely owns, drops
  the secure-auth credentials, and returns `false` when a shared gate was
  left untouched — `ProxyConfig` has no `Drop`, so clones keep their values.

## Authentication

Inbound (one dual port, SOCKS5 + HTTP CONNECT; the server always picks the
strongest method the client supports):

- **Secure auth** — SOCKS5 method 0x80, HTTP scheme `Resocks5-Secure` (the
  same secure_auth messages, one per 407 round, base64); the server's last
  token rides on the `200` as `Proxy-Authenticate: Resocks5-Secure <b64>`,
  completing mutual auth. Feature `secure-auth`.
- **Clear text** — SOCKS5 0x02 (RFC 1929) and HTTP `Basic`, verified
  against the same store via the default `SecretStore::check_password`.
  Allowed unless `ServerOptions::allow_cleartext(false)`.
- **Anonymous** — SOCKS5 0x00 / HTTP without credentials, only when
  `ServerOptions::allow_anonymous(true)` (default off).

With no acceptable method, SOCKS5 answers `[5, 0xFF]`; HTTP answers a
keep-alive `407` listing the enabled schemes (`Proxy-Authenticate:
Resocks5-Secure`, then `Proxy-Authenticate: Basic realm="resocks5"` while
clear text is on) so standard clients retry on the same connection. After
`MAX_ROUNDS`, on an unsupported scheme or any refusal the 407 closes
(`Connection: close`).

One secret per user, any protocol, any method: the stored `UserSecret`
(Argon2id salt + params + key; a PHC string in the host app) verifies both
secure auth and clear text, so switching protocol or method never breaks
the account. Init registration works for every protocol and method:
enrollment sealed-K over 0x80, or a clear-text login claiming the user
with `UserSecret::from_password` at the store's `enrollment_floor()`; of
two concurrent first logins exactly one wins.

Outbound, `with_auth(u, p)` is all a caller needs. A SOCKS5 upstream
upgrades automatically — the SDK derives secure-auth credentials from the
same password and the greeting offers 0x80 plus (while `allow_cleartext`,
default true) 0x02; the upstream picks. An HTTP/HTTPS upstream gets `Basic`
in the first CONNECT, as 0.4.x did (see "Authenticating to an upstream").
`ProxyConfig::secure_only()` never offers or accepts anything weaker:
an upstream without our method fails with
`ConnectError::SecureAuthUnsupported` before any credential byte.

```text
use resocks5_net::connect::{dial_plain, DialOptions};
use resocks5_net::server::{accept_with, AuthMethods, ServerOptions};
use resocks5_net::types::ProxyConfig;

// Inbound: strong methods plus clear text, anonymous refused.
let options = ServerOptions::new(deadline)
    .allow_cleartext(true);      // or .secure_only(): 0x80 / Resocks5-Secure only
let req = accept_with(&mut client, &options, &AuthMethods::secure(&store, &decoy)).await?;

// Outbound: one call, upgraded to secure auth when the upstream has it.
let proxy = ProxyConfig::socks5("198.51.100.7", 1080).with_auth("alice", "correct horse");
let stream = dial_plain(&proxy, "example.com", 80, &DialOptions::new()).await?;
```

## Inbound server API

`server` is unconditional, including `default-features = false`; it requires no
pool, TLS, serde, rating, or rotator feature. `accept` borrows any
`AsyncRead + AsyncWrite + Unpin` stream and serves only when anonymous access
is allowed (`allow_anonymous`, default off); users authenticate through
`accept_secure` / `accept_with` (feature `secure-auth`, below), which run
the full negotiation: strong, clear text, and anonymous per the options.

```text
use std::time::Duration;
use resocks5_net::server::{accept, Reply, ServerOptions};
use tokio::{io::AsyncWriteExt, net::TcpStream, time::{timeout, Instant}};

async fn serve(mut client: TcpStream) -> anyhow::Result<()> {
    let deadline = Instant::now() + Duration::from_secs(5); // anchor at accept in the host
    let options = ServerOptions::new(deadline).allow_anonymous(true);
    let mut req = accept(&mut client, &options).await?;
    // Apply destination policy before dialing: this sample permits one local target.
    if req.target() != "127.0.0.1:20084" {
        req.reply(&mut client, Reply::Forbidden).await?;
        return Ok(());
    }
    let mut egress = match timeout(Duration::from_secs(5), TcpStream::connect(req.target())).await {
        Ok(Ok(stream)) => stream,
        _ => { req.reply(&mut client, Reply::UpstreamUnavailable).await?; return Ok(()); }
    };
    req.reply(&mut client, Reply::Established).await?; // only after a real dial
    timeout(Duration::from_secs(5), egress.write_all(&req.take_pipeline())).await??;
    resocks5_net::connect::tunnel::tunnel_with_timeouts(
        client, egress, Duration::from_secs(5), Duration::from_secs(15),
    ).await?;
    Ok(())
}
```

The host must additionally bound response writes/admission, and perform a real
TCP dial: the parser never manufactures egress.

Contracts:
- One supplied absolute Tokio deadline covers detection, framing, authentication,
  and flushing every handshake/error reply; expired entry is rejected before polling.
  No DNS or egress occurs in `accept`. The deadline never renews on read/write progress.
- `target()` stays unresolved. HTTP authority spelling is preserved; SOCKS IPs are
  canonical. Validation reuses `HostPort` (including legacy bare IPv6 and port zero).
- `username()` is `Some` after secure auth or clear text (verified against
  the store); anonymous admission is `None`. Routing privileges are
  exclusively host policy.
- SOCKS selects the strongest method offered and enabled: secure auth
  (0x80), then clear text (0x02, while `allow_cleartext`), then anonymous
  (0x00, while `allow_anonymous`); nothing acceptable answers `[5, 255]`.
  HTTP serves a request without `Proxy-Authorization` when anonymous access
  is allowed; otherwise a keep-alive 407 lists the enabled schemes
  (`Resocks5-Secure`, then `Basic realm="resocks5"` while clear text is on)
  so standard clients retry with credentials on the same connection.
- HTTP request line and headers are limited to 16KiB **including** `\r\n\r\n`.
  Unused headers remain bytes and accept obs-text; only the first auth header is
  looked at. By default the parser stays permissive (any `HTTP/…` version, no
  `Host` requirement, bare IPv6 authority, ignored SOCKS RSV in requests);
  `ServerOptions::strict_http(true)` opts in to RFC 9112 validation.
- `take_pipeline()` transfers exact owned HTTP over-read bytes once; remaining bytes
  stay on the stream. SOCKS consumes exactly its frame. Forward the prefix before
  reading/relaying further data. Failure or cancellation during a partial write is
  terminal, never a reason to replay the prefix.
- `reply` maps Established/Forbidden/UpstreamUnavailable/ConnectionRefused/
  NetworkUnreachable/TimedOut/GeneralFailure/Overloaded to protocol-specific
  outcomes: SOCKS REP 0/2/4/5/3/6/1/1 and HTTP 200/403/502/502/502/504/502/503.
  The host picks the variant (it knows whether the dial was refused or timed out).
  GeneralFailure uses SOCKS REP 1 / HTTP 502, distinct from admission overload
  (HTTP 503). Parsing never sends tunnel success.
  Hosts doing early-success recovery must not send another protocol reply afterward.
  Every completed protocol response uses `write_all` followed by `flush`, including
  method selection, refusals and public final replies.
  Buffered streams therefore need no extra host write, manual flush or shutdown to
  expose a completed reply. Flush/write errors propagate as `ServerError::Io`.
  Final `reply` writes and flushes have no implicit SDK timeout: the host owns their
  response budget, separately from the absolute `accept` deadline.
- After method selection, unsupported commands (including BIND and UDP ASSOCIATE)
  receive exactly `[5, 7, 0, 1, 0, 0, 0, 0, 0, 0]`; unknown ATYP receives exactly
  `[5, 8, 0, 1, 0, 0, 0, 0, 0, 0]`. Both are flushed before a terminal protocol
  error. Wrong request versions retain the terminal no-failure-response contract.
- On error, timeout, or cancellation discard the stream and any buffered wrapper;
  never retry parsing or replay a partial reply, even if a write completed but its
  flush did not. Successful flushing is not a peer acknowledgement.
  `Debug` of `IncomingRequest` is redacted (no username or pipeline bytes), and
  `ServerError::Authentication` texts never contain submitted credentials;
  transport encryption is not supplied here.

### Inbound options

All options are opt-in builders on `ServerOptions`; the defaults keep the
behaviour described above.

- `strict_http(true)`: RFC 9112 validation of the CONNECT request before any
  authentication decision: exactly `method SP target SP HTTP/d.d`, versions other
  than 1.0/1.1 answer 505, authority-form with bracketed IPv6 and a 1..=65535
  numeric port, exactly one non-empty `Host` for HTTP/1.1, header names that are
  tokens with no whitespace before the colon, no obs-fold, and at most one
  `Proxy-Authorization`. Violations answer 400/505 and return
  `ServerError::Protocol` with a fixed reason. Many real clients omit `Host` or
  send HTTP/1.0, so it is off by default.
- `IncomingRequest::into_prefixed(stream)` wraps the stream in
  `server::Prefixed<S>`, which serves the over-read pipeline bytes before the
  stream itself (writes pass through), instead of forwarding `take_pipeline()` by
  hand. `take_username()` moves the authenticated user name out of the request.

```text
use resocks5_net::server::{accept, ServerOptions};
use resocks5_net::types::ProxyConfig;

// Check an entry before storing or dialing it.
let proxy = ProxyConfig::socks5("198.51.100.7", 1080).try_with_auth("user", "pass")?;
proxy.validate()?;

let options = ServerOptions::new(deadline).allow_anonymous(true).strict_http(true);
let req = accept(&mut client, &options).await?;
let mut stream = req.into_prefixed(client); // pipelined bytes first, then the socket
```

### Strong inbound authentication (feature `secure-auth`)

`server::accept_secure(stream, options, store, decoy)` is a shorthand for
`accept_with(stream, options, &AuthMethods::secure(store, decoy))`.
`accept_with` runs the full negotiation, strongest first: the SOCKS5 side
offers secure auth (0x80), then clear text (0x02, while
`options.allow_cleartext`), then anonymous (0x00, while
`options.allow_anonymous`); a client offering none of them gets
`[5, 0xFF]` and `ServerError::Authentication`. The HTTP side serves a
request without `Proxy-Authorization` when anonymous access is allowed;
otherwise it answers a keep-alive `407` listing the enabled schemes
(`Proxy-Authenticate: Resocks5-Secure`, then
`Proxy-Authenticate: Basic realm="resocks5"` while clear text is on), so a
standard client retries with credentials on the same connection. The
`Resocks5-Secure` exchange runs one message per 407 round (base64), and
the server's last token rides on the final `200` as
`Proxy-Authenticate: Resocks5-Secure <b64>`, which a mutually
authenticating client checks. After `MAX_ROUNDS`, an unsupported scheme
or a failed check the answer is a 407 with `Connection: close`. `decoy`
(a `DecoyKey`) answers unknown user names, indistinguishable from a wrong
password.

`IncomingRequest::auth_method()` returns `server::AuthMethod` —
`Anonymous`, `Cleartext` (SOCKS5 0x02 / HTTP `Basic`), `Secure` (method
0x80 / HTTP `Resocks5-Secure`); the enum is `#[non_exhaustive]`, and the
last two variants need the feature. `username()` is the verified user
(`None` only for anonymous admission); `set_identity(name)` replaces the
identity everything downstream sees (`auth_method()` is unchanged);
`take_username()` moves it out. When a request completed a
`Resocks5-Secure` exchange over HTTP, the `reply()` final answer carries
that last authentication token on the `200` as `Proxy-Authenticate`.

The `SecretStore` trait is the host's half: async
`lookup(user) -> Option<StoredUser>`, atomic
`claim(user, secret) -> bool`, `enrollment_floor()` defaulting to
`KdfParams::DEFAULT`, and — for the clear-text methods — the default
`check_password(user, password)`, returning a `PasswordCheck` verdict:
`Accepted`, `Claimed` (this login set an init user's secret) or
`Rejected`. `None` from `lookup` is answered with the decoy / a fixed
sleep, so the store never reveals which names exist.
`StoredUser::Secret(UserSecret)` authenticates normally;
`StoredUser::Init` enrolls on the first login (see the `secure-auth`
feature above). `NoSecrets` is a store with no users, for hosts that only
want the policy plumbing.

A host that verifies passwords itself (its own hashes, its own first-use
rules) overrides `check_password` and builds the methods with
`AuthMethods::cleartext_only(&store)` instead of `AuthMethods::secure`: the
strong method is not offered, so a client that lists 0x80 with 0x02 is served
with 0x02 (and the HTTP `407` names only `Basic`) rather than being refused by
a decoy for a user the store holds no `UserSecret` for. `lookup` and `claim`
can then be stubs (`None`, `false`). Run slow hashing inside
`tokio::task::spawn_blocking` within the returned future, and, to tie
per-login state (an admission proof, say) to the exact check that passed,
give each accepted connection its own small store value that records the
verdict in `check_password`. `allow_cleartext(false)` with `cleartext_only`
leaves nothing acceptable. Fields that are not UTF-8 are refused before
`check_password` runs.

```text
use resocks5_net::server::{accept_with, AuthMethod, AuthMethods};

let decoy = resocks5_net::secure_auth::DecoyKey::generate()?;
let methods = AuthMethods::secure(&store, &decoy);
let mut req = accept_with(&mut client, &options, &methods).await?;
if req.auth_method() == AuthMethod::Cleartext {
    // RFC 1929 / HTTP Basic, verified via SecretStore::check_password
}
```


## Usage

Upstream lines encode rank with their leading-star count: zero stars is an
ordinary exit, and levels 1..255 are gates. More than 255 stars are invalid;
one star retains the original gate syntax. A chain uses one node from each
present level, descending, then one ordinary exit and the target. Rank gaps
are allowed. `ProxyConfig::gate_level` stores the rank, `with_gate_level`
sets it, and `as_gate` promotes zero to level 1 without lowering a higher
rank. `chain` links nodes outermost-first; `chain_nodes` returns that order
and `chain_len` its count. `ChainKey` identity includes node order, length,
and every node's protocol, host, port, username, password and gate level.
Parse a proxy entry with `parse_proxy_str(line, protocol)` or use
`ProxyConfig::from_addr(protocol, addr)`; host accepts domains, IPv4 and
bracketed or bare IPv6, and password may contain `:`. A URI form exists
too: `ProxyConfig::from_uri(uri)` / `from_uri_with(uri, &ProxyUriOptions)`
parse `scheme://[user:password@]host:port` with schemes `socks5`, `socks5h`,
`http`, `https` — percent-decoded credentials, a required port, no path,
query or fragment; the typed `ProxyUriError` never carries the input text.
`ProxyUriOptions::new().validate_auth(true)` also checks the credentials for
the scheme's protocol (as `try_with_auth` does), so a URI that could never
authenticate fails at parse time with `ProxyUriError::InvalidCredentials`.

```toml
[dependencies]
resocks5-net = "0.5"
# resocks5-net = { git = "https://github.com/PHPCraftdream/resocks5" }
tokio = { version = "1", features = ["full"] }
anyhow = "1"
```

```text
use std::time::Duration;

use resocks5_net::connect::{connect_proxy, parse_proxy_str};
use resocks5_net::pool::{PoolConfig, ProxyPool};
use resocks5_net::rotator::ProxyRotator;
use resocks5_net::types::ProxyProtocol;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let proxies = ["user:pass@198.51.100.7:1080"]
        .into_iter()
        .filter_map(|s| parse_proxy_str(s, ProxyProtocol::Socks5).ok())
        .collect::<Vec<_>>();

    let rotator = ProxyRotator::new(proxies);
    let pool = ProxyPool::new(
        PoolConfig::default(),
        Duration::from_secs(10),
        8,
    );

    let upstream = rotator.get_next();
    let mut stream = connect_proxy(
        "example.com:80",
        &upstream,
        &pool,
        Duration::from_secs(10),
        None,
    )
    .await?;

    stream.write_all(b"GET / HTTP/1.0\r\nHost: example.com\r\n\r\n").await?;
    let mut body = Vec::new();
    // Bound the response: at most 64 KiB within five seconds.
    tokio::time::timeout(Duration::from_secs(5), async {
        stream.take(64 * 1024).read_to_end(&mut body).await
    })
    .await
    .map_err(|_| anyhow::anyhow!("peer kept sending for over 5 s"))??;
    println!("received {} bytes", body.len());
    Ok(())
}
```

### Without a pool

`dial` connects through one upstream with no `ProxyPool` (this is what
`default-features = false` leaves you with). For SOCKS5 and HTTP
CONNECT upstreams `dial_plain` is the simpler entry point; `dial`
returns an `AnyUpstream` through an extra `tls_connector` argument and
is the one to use when the upstream is HTTPS (pass a `TlsConnector`).
Cap accounting is then up to the caller. `DialOptions::with_nodelay(bool)` / `with_keepalive(Duration)` set
`TCP_NODELAY` and TCP keepalive on the socket to the proxy (fields `nodelay`,
`keepalive`; by default the OS defaults stay).
`with_keepalive_interval(Duration)` sets the probe interval only when
`with_keepalive(idle)` is also configured; it is best-effort and ignored on
platforms where `socket2` lacks `with_interval`.
`connect::dial_tcp(proxy, host, port, opts)` returns the bare `TcpStream` of
a SOCKS5 / HTTP CONNECT tunnel (no wrapper, no permit) and
refuses an HTTPS upstream before any connect.

```text
use std::time::Duration;

use resocks5_net::connect::{dial_plain, DialOptions};
use resocks5_net::types::ProxyConfig;

# async fn run() -> Result<(), resocks5_net::ConnectError> {
let proxy = ProxyConfig::socks5("198.51.100.7", 1080); // anonymous upstream
let opts = DialOptions::new().with_total_timeout(Duration::from_secs(20));
let stream = dial_plain(&proxy, "example.com", 80, &opts).await?;
# drop(stream);
# Ok(())
# }
```

### Over an existing stream

`dial_chain_over` runs the hops of a chain over a stream you already own, for
example one returned by Tor. The stream must be connected to the chain's
outermost node (`proxy.outermost()`); nothing is dialed and no DNS lookup
happens. `total_timeout` is the remaining budget of your own deadline.

```text
use std::time::Duration;

use resocks5_net::connect::{dial_chain_over, DialOptions};
use resocks5_net::types::ProxyConfig;
use tokio::net::TcpStream;

# async fn run(deadline: tokio::time::Instant) -> Result<(), Box<dyn std::error::Error>> {
let proxy = ProxyConfig::socks5("exit.example", 1080)
    .with_gate(ProxyConfig::socks5("198.51.100.7", 1080));
// Stand-in for a Tor stream: any owned AsyncRead + AsyncWrite works.
let outer = proxy.outermost();
let base = TcpStream::connect((outer.host.as_str(), outer.port)).await?;

let opts = DialOptions::new()
    .with_handshake_timeout(Duration::from_secs(10))
    .with_total_timeout(deadline.saturating_duration_since(tokio::time::Instant::now()));
let stream = dial_chain_over(base, &proxy, "example.com", 80, &opts, None).await?;
# drop(stream);
# Ok(())
# }
```

### Errors

Connect and pool calls return `resocks5_net::ConnectError`
(`#[non_exhaustive]`): match on `Timeout { stage, .. }`, `ProxyRejected`,
`MethodUnsupported`, `AuthFailed { status }` (the upstream rejected the
RFC 1929 username/password sub-negotiation), `SecureAuthUnsupported`
(a `secure_only` upstream that did not offer our method),
`Protocol(ProtocolViolation)`,
`InvalidTarget`, `SecureAuth(SecureAuthError)`
(this carries the typed exchange error, re-exported from the crate root),
`TlsFeatureMissing`, `Io` (the `io::Error` is reachable via `source()`)
and, with `pool`, `AtCapacity` — no message parsing needed.
`Protocol` carries a structured `ProtocolViolation` (e.g.
`Socks5BadVersion { got }`, `Socks5UnknownAddressType { got }`,
`Socks5DomainTooLong { len }`,
`Socks5BadReserved { got }`, `Socks5EmptyBoundDomain`,
`HttpInvalidConnectTarget`, `HttpResponseTooLarge`, `HttpClosedEarly`)
with the offending byte or length; its `Display` still prints the
legacy message text. A peer that answers the greeting with a
non-SOCKS5 version byte is `Protocol(Socks5BadVersion { got })`, not
`MethodUnsupported`. For `ProxyRejected { code, .. }` on SOCKS5,
`resocks5_net::socks5_rep_description(code)` gives the RFC 1928 reply
meaning. `ConnectError::suggested_reply()` maps an error to the reply a
gateway should send its own client: TCP-connect, SOCKS5-greeting and HTTPS-TLS-handshake
timeouts → `UpstreamUnavailable`; SOCKS5/HTTP/HTTPS CONNECT-handshake and total
timeouts → `TimedOut`; I/O timeouts → `TimedOut` regardless of stage; other
connect-stage I/O → `UpstreamUnavailable`, other I/O → `GeneralFailure`; TLS
failures → `UpstreamUnavailable`. SOCKS5 `ProxyRejected` REP 2/3/4/5/6 →
`Forbidden`/`NetworkUnreachable`/`UpstreamUnavailable`/`ConnectionRefused`/
`TimedOut`; HTTP(S) 403/504/502+503 →
`Forbidden`/`TimedOut`/`UpstreamUnavailable`; other refusals, auth/method
failures (`AuthFailed` and `SecureAuthUnsupported` included — both count
as upstream-down like the other auth refusals), `Protocol`,
`InvalidTarget`, `CleartextCredentialsRefused`,
secure-auth exchange errors and a missing TLS feature →
`GeneralFailure`; with `pool`, `AtCapacity` → `Overloaded`. Only the
destination's own verdict selects a specific reply; hop failures never
answer "connection refused".

`ProxyConfig` builders include `socks5/http/https(..)`, `with_auth` and
`with_gate`. `dial_chain` follows explicit `gate` links without a pool;
`connect_chain` requires the `pool` feature and holds every node’s permit
for the tunnel lifetime. `dial`, `connect_proxy` and `connect_proxy_once`
do **not** follow gate links (`connect_proxy` requires `pool`). None of
these dial/connect functions derives a route from `gate_level`; use
`GateLevels`/`ChainPlan` for ranked selection and `ProxyConfig::chain`
to build explicit links. `ChainError` provides the underlying `ConnectError` and `ChainStage`:
`Connect` is outer TCP, `Hop(i)` is node i tunnelling to node i+1, and
`Target` is the exit.

`ProxyConfig::validate()` checks a whole chain (outermost first) and
`validate_node()` one entry, without any I/O: non-empty host, port 1..=65535,
`is_gate` consistent with `gate_level`, credentials set as a pair, SOCKS5
username/password 1..=255 bytes each (RFC 1929), and for HTTP/HTTPS no `:` in
the username and no control characters (RFC 7617). `try_with_auth` is the
fallible `with_auth`. Errors (`ProxyConfigError`, `ChainConfigError` with the
failing node index) name the rule only, never a host or a credential value. The
dial and connect functions do not call it: a half-set pair is still sent
anonymously, so validate when you build or load a config.

`dial_chain_over` runs that chain on a caller-supplied owning stream (for
example, a Tor stream) already connected to `proxy.outermost()`; it performs
no TCP dial or DNS lookup and returns `AnyUpstream::Gate`. Supply `total_timeout`
as the relative remaining budget (`deadline.saturating_duration_since(now)`);
each hop uses `handshake_timeout`, and `connect_timeout` is ignored. `ChainError`
attributes TLS preflight errors to `Connect`, intermediate tunnels to `Hop(i)`,
and the exit tunnel to `Target`. It is not cancel-safe: on error or cancellation
the owning stream is dropped, though dropping a shared/cloned handle may not
close the underlying transport. `ProxyConfig::outermost()` returns the first
node; `nodes()` lists nodes outermost first and `self` last. SOCKS5 rejects an
empty target host or zero port before writing, and rejects a nonzero reserved
reply byte or empty bound domain; SOCKS5 upstreams used by the `resocks5`
server are checked too.

`connect_hedged` (feature `pool`) races a candidate list: attempts launch in
order, and the next one starts beside a slow one after
`HedgeOptions::hedge_delay` only while no running attempt is past its TCP
connect, so the target never sees duplicate CONNECTs: an attempt that reaches
its upstream while another one is handshaking waits and sends nothing, and is
reported `Lost` if that one succeeds. A delay too large for the monotonic clock
means never hedge. The first success is returned as `Hedged { stream, winner }`; the rest finish in the background
and every launched attempt is reported exactly once through `on_attempt`
(`AttemptReport` with `AttemptOutcome::{Won, LateSuccess, Lost, Failed}` and
`after_win`), so the caller can feed ratings and quarantine. A zero delay
means strictly sequential; `HedgeError` carries the attempt count and the
last error.

`ConnectError::is_upstream_down` treats TCP-connect failures, HTTPS TLS
handshake failures, auth/method refusal (secure-auth exchange failures,
`AuthFailed` and `SecureAuthUnsupported` included), bad SOCKS5 response
versions, and
TLS errors as hard upstream failures. It excludes destination-dependent
CONNECT failures and ambiguous handshakes. `counts_against_upstream` is
false for local `AtCapacity` errors when `pool` is enabled. The chain
selection module (`rotator`, which implies `rating`) provides `GateLevels`,
`ChainPlan`, `ChainPick`, `Hop` and `Quarantined`. The plan traverses
weighted ranked candidates; application code owns sticky-route storage.

`ProxyRotator::record_error` classifies an error, updates rating/quarantine,
and returns the new quarantine duration when hard-failure threshold trips.
`probe_all` probes every configured proxy; a failed connect carries its
`reason` (the I/O error or the timeout) in `QuarantinedAtStart` and `StillDown`.
It reports
`ProbeEvent::QuarantinedAtStart` only for newly quarantined failures when
quarantine is enabled; `probe_due` reports recovered or still-down due
proxies. Both return `ProbeEvent` lists. `probe_due_with` and `probe_all_with`
take a reservation hook (`Fn(&ProxyConfig) -> Option<guard>`) that lets the
host bound probes by its own capacity: `None` defers the probe without a
connection or a health change, `Some(guard)` holds the guard (for example a
pool permit) while the probe runs.

Three no-copy helpers on the dial path: `ChainKey::singleton(&Arc<ProxyConfig>)`
keys one node without its gate link — a gate-less node is shared by
refcount, a gated node is copied once with the link dropped.
`ChainPick::config_arc()` returns the pick's linked configuration as a
shared `Arc` (a refcount bump; `config()` still returns an owned copy).
`ProxyRotator::link_proxy(addr, proxy)` inserts or replaces the sticky-cache
entry for `addr` (`impl AsRef<str>`: nothing is allocated for the address
when the entry already exists; it takes the `Arc<ProxyConfig>` so the
caller can hand off its only clone), with `unlink_proxy(addr)` and
`get_linked(addr)` — an expired entry is a miss, and an entry whose
upstream is quarantined is not returned (the entry itself stays until it
expires or is replaced). A full cache reclaims an expired entry first,
otherwise it evicts the least-recently-used one.

Top-level modules: `connect` (dial, connectors, tunnel, fragmentation),
`error`, `server`, `progress`, `pool` (`pool` feature), `rating` (`rating`
feature), `rotator` (`rotator` feature), `types`, `chain` (`rotator`
feature), `secure_auth` (`secure-auth` feature), and `testing`
(`test-instrumentation` feature).

`testing::MockUpstream` (feature `test-instrumentation`) is a scripted
SOCKS5/HTTP CONNECT proxy for tests. `.auth(MockAuth)` defaults to `None`;
`Cleartext { user, password }` speaks clear text only (SOCKS5 method 0x02,
HTTP Basic); `Secure { user, secret }` stores one secret for one user and,
because that same secret verifies clear text too, accepts RFC 1929 / Basic
against it; `SecureDenied` selects secure auth and always denies via the
store; `AuthStatus(byte)` answers the first secure-auth message with
`[VERSION, byte]` (`0xFF` refused, `0x01` enrollment, other non-zero bad
version); `NoAcceptableMethod` forces SOCKS5
`[5, 255]`. The HTTP side runs the real 407 dance: a keep-alive challenge
listing the enabled schemes, then the `Resocks5-Secure` token rounds,
ending in a `200` that carries the final `Proxy-Authenticate` token;
`Basic` is verified against the store, and `AuthStatus(byte)` answers the
first `Resocks5-Secure` round with `[VERSION, byte]` on a closing 407.
Every non-None auth mode answers HTTP 407. `.script(Script)`
defaults to `Tunnel`; it also supports `Refuse(code)`, `SilentGreeting`,
`SilentConnect`, and `Hangup`. `.spawn()` binds `127.0.0.1:0`; `addr()`,
`proxy()`, `targets()`, and `connections()` report activity.
`connect_in_memory()` returns a socket-free `DuplexStream` served by the same
handler and sharing auth, targets, and counts. `.spawn()` still binds the TCP
listener; dropping the mock aborts in-memory tasks. `.reply_delay(Duration)`
(default zero) and `.drip(true)` affect method selections and CONNECT/HTTP
responses. In-memory clients observe these precisely; TCP timing and
fragmentation are best-effort and subject to kernel scheduling/coalescing.
Secure-auth exchange messages are not delayed or dripped.

A working version of the pooled example lives at
[`examples/connect_through_proxy.rs`](examples/connect_through_proxy.rs).
CI compiles that file, so it tracks the API; the Markdown blocks above are
not extracted.

## Authenticating to an upstream

`ProxyConfig::with_auth(u, p)` is all a caller needs. With feature
`secure-auth` the SDK also derives secure-auth credentials from the same
password, so a **SOCKS5** upstream upgrades automatically: the greeting
offers method 0x80 and (while `allow_cleartext`, default true) RFC 1929, and
the upstream picks. An entry built only with `with_secure_auth` offers the
strong greeting (plus 0x02 only when a clear-text pair also exists and is
allowed).

**HTTP/HTTPS upstreams send `Basic` in the first CONNECT**, exactly as 0.4.x
did: many proxies (3proxy among them) answer an unauthenticated CONNECT with
`407` + `Connection: close`, so probing first would never reach them. HTTPS
Basic travels inside the TLS connection — not clear text on the wire — and is
allowed regardless of `allow_cleartext`; plain-HTTP Basic requires
`allow_cleartext`. The credential-less probe (CONNECT without credentials,
then the scheme the `407` names) runs only when Basic cannot or must not be
sent first: `secure_only` entries, plain-HTTP entries with clear text
disallowed, and entries with secure credentials but no user/password pair. On
the probe path `Resocks5-Secure` is used when the proxy offers it; if clear
text is the only method on offer and it is disallowed, the dial fails with
`ConnectError::CleartextCredentialsRefused` before the password is sent.

`ProxyConfig::secure_only()` (builder + field) offers ONLY method 0x80 and
uses ONLY `Resocks5-Secure` over HTTP(S) — even Basic inside TLS is
refused — and an upstream without our method fails with
`ConnectError::SecureAuthUnsupported` before any password byte.
`ProxyConfig::allow_cleartext(bool)` sets the field (default true).
Empty user names or passwords are refused by
`validate`/`try_with_auth` and by `SecureCredentials::try_new` (`new`,
like the server, rejects them at use time).

`ProxyConfig::with_secure_auth(SecureCredentials)` (feature `secure-auth`):
dial and chain hops authenticate with secure auth; over HTTP(S) the
`Resocks5-Secure` scheme. The
user name is kept in `ProxyConfig::user` (it is the upstream's identity);
the password stays inside the credentials — never on the wire, never a
plain `ProxyConfig::password` field. `SecureCredentials::new(user,
password)`; `.allow_enrollment(true)` opts in to first-login enrollment
(off by default: a man in the middle could claim "init" to an already
enrolled client; `SecureAuthError::EnrollmentNotAllowed` otherwise);
`.with_enrollment_kdf(params)` sets the enrollment cost; `.with_min_kdf(floor)`
refuses a server whose KDF is cheaper than the floor (default
`KdfParams::MIN`: nothing is refused; `ProxyConfig::with_min_kdf` sets it for
the credentials a `with_auth` entry derives). `KdfParams::DEFAULT` (19 MiB, 2
passes, 1 lane) is the cost new secrets and enrollments use; `DecoyKey::
generate_with(params)` makes unknown names advertise the cost a host stores
its real secrets at. The derived key is cached
after the first exchange
(per salt and parameters), so the Argon2id cost is paid once per process
and server, not per connection. Client derivations run under their own
process-wide limiter (separate from the server's, so a flood of inbound
clear-text checks cannot starve outbound derivations); a saturated limiter
fails the exchange with `SecureAuthError::Kdf` instead of queueing.

```text
use resocks5_net::connect::{dial_plain, DialOptions};
use resocks5_net::secure_auth::SecureCredentials;
use resocks5_net::types::ProxyConfig;

let proxy = ProxyConfig::socks5("198.51.100.7", 1080)
    .with_secure_auth(SecureCredentials::new("alice", "correct horse"));
let stream = dial_plain(&proxy, "example.com", 443, &DialOptions::new()).await?;
```

Only SOCKS5 upstreams get the strong SOCKS greeting. An HTTP CONNECT upstream
uses `Resocks5-Secure` only on the probe path above (`secure_only`, or secure
credentials without a user/password pair); a plain `with_auth` entry sends
Basic first.

## Status

Pre-1.0. The API may still change before a 1.0 release. For project
context, full architecture, and the consuming binary see the main
[`resocks5`](https://github.com/PHPCraftdream/resocks5) repository.

## License

Dual-licensed under MIT OR Apache-2.0, at your option.
