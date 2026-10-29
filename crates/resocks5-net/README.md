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
- **TLS ClientHello fragmentation** for SNI-based DPI evasion.

No application concerns leak in: no config-file format, logger, credential
storage, or egress policy. Inbound authentication is supplied by the host closure.

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

## Inbound server API

`server` is unconditional, including `default-features = false`; it requires no
pool, TLS, serde, rating, or rotator feature. `accept` borrows any
`AsyncRead + AsyncWrite + Unpin` stream and invokes an owned-credentials
`FnOnce(Credentials) -> Future<Output = bool>` at most once. No public auth trait.

```rust
use std::time::Duration;
use resocks5_net::server::{accept, Reply, ServerOptions};
use tokio::{io::AsyncWriteExt, net::TcpStream, time::{timeout, Instant}};

async fn serve(mut client: TcpStream) -> anyhow::Result<()> {
    let deadline = Instant::now() + Duration::from_secs(5); // anchor at accept in the host
    let options = ServerOptions::new(deadline, false, true);
    let mut req = accept(&mut client, &options, |credentials| async move {
        // Demo only: substitute the host's bounded credential verifier.
        credentials.username() == "demo" && credentials.password() == "demo"
    }).await?;
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

The host must additionally bound response writes/admission; the finite
[`serve_local` example](examples/serve_local.rs) bounds the whole client operation,
requires explicit loopback listener/echo-target arguments, and serves exactly two
clients on one port. The echo service is separate: the example performs a real TCP
dial, never manufactures egress or substitutes an echo stream.

Contracts:
- One supplied absolute Tokio deadline covers detection, framing, authentication,
  and flushing every handshake/error reply; expired entry is rejected before polling.
  No DNS or egress occurs in `accept`. The deadline never renews on read/write progress.
- `target()` stays unresolved. HTTP authority spelling is preserved; SOCKS IPs are
  canonical. Validation reuses `HostPort` (including legacy bare IPv6 and port zero).
- `username()` is `Some` only after verification; anonymous is `None`. Verified empty
  HTTP usernames stay `Some("")`; routing privileges are exclusively host policy.
- SOCKS prefers username/password if offered and enabled, otherwise anonymous when
  offered and enabled. HTTP verifies supplied Basic credentials even if anonymous
  access is allowed; supplied credentials fail when no password capability exists.
- HTTP request line and headers are limited to 16KiB **including** `\r\n\r\n`.
  Unused headers remain bytes and accept obs-text. Basic credentials require UTF-8;
  only the first auth header is used. Existing permissive `HTTP/` version parsing and
  ignored SOCKS RSV are retained, not advertised as strict RFC validation.
- `take_pipeline()` transfers exact owned HTTP over-read bytes once; remaining bytes
  stay on the stream. SOCKS consumes exactly its frame. Forward the prefix before
  reading/relaying further data. Failure or cancellation during a partial write is
  terminal, never a reason to replay the prefix.
- `reply` maps Established/Forbidden/UpstreamUnavailable/GeneralFailure/Overloaded
  to protocol-specific outcomes. GeneralFailure uses SOCKS REP 1 / HTTP 502,
  distinct from admission overload (HTTP 503). Parsing never sends tunnel success.
  Hosts doing early-success recovery must not send another protocol reply afterward.
  Every completed protocol response uses `write_all` followed by `flush`, including
  method selection, password success/failure, refusals and public final replies.
  Buffered streams therefore need no extra host write, manual flush or shutdown to
  expose a completed reply. Flush/write errors propagate as `ServerError::Io`.
  Final `reply` writes and flushes have no implicit SDK timeout: the host owns their
  response budget, separately from the absolute `accept` deadline.
- After method selection and any successful password authentication, unsupported
  commands (including BIND and UDP ASSOCIATE) receive exactly
  `[5, 7, 0, 1, 0, 0, 0, 0, 0, 0]`; unknown ATYP receives exactly
  `[5, 8, 0, 1, 0, 0, 0, 0, 0, 0]`. Both are flushed before a terminal protocol
  error. Wrong request/auth versions retain the terminal no-failure-response contract.
- On error, timeout, or cancellation discard the stream and any buffered wrapper;
  never retry parsing or replay a partial reply, even if a write completed but its
  flush did not. Successful flushing is not a peer acknowledgement.
  Authentication side effects (such as admitted blocking password persistence) may
  finish after cancellation; the host retains its own admission permits accordingly.
  Credentials' Debug is redacted; transport encryption is not supplied here.


## Usage

Upstream lines are `[*]user:pass@host:port` — credentials optional, a
leading `*` marks a gate node. Parse one with
`parse_proxy_str(line, protocol)` or the
`ProxyConfig::from_addr(protocol, addr)` shorthand; `host` may be a
domain, an IPv4 literal, or a bracketed (or bare) IPv6 literal, and the
password may contain `:`.

```toml
[dependencies]
resocks5-net = "0.3"
# resocks5-net = { git = "https://github.com/PHPCraftdream/resocks5" }
tokio = { version = "1", features = ["full"] }
anyhow = "1"
```

```rust
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
    stream.read_to_end(&mut body).await?;
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
Cap accounting is then up to the caller.

```rust,no_run
use std::time::Duration;

use resocks5_net::connect::{dial_plain, DialOptions};
use resocks5_net::types::ProxyConfig;

# async fn run() -> Result<(), resocks5_net::ConnectError> {
let proxy = ProxyConfig::socks5("198.51.100.7", 1080).with_auth("user", "pass");
let opts = DialOptions::new().with_total_timeout(Duration::from_secs(20));
let stream = dial_plain(&proxy, "example.com", 80, &opts).await?;
# drop(stream);
# Ok(())
# }
```

### Errors

Connect and pool calls return `resocks5_net::ConnectError`
(`#[non_exhaustive]`): match on `Timeout { stage, .. }`, `ProxyRejected`,
`AuthFailed`, `MethodUnsupported`, `Protocol(ProtocolViolation)`,
`InvalidTarget`,
`TlsFeatureMissing`, `Io` (the `io::Error` is reachable via `source()`)
and, with `pool`, `AtCapacity` — no message parsing needed.
`Protocol` carries a structured `ProtocolViolation` (e.g.
`Socks5BadVersion { got }`, `Socks5UnknownAddressType { got }`,
`Socks5DomainTooLong { len }`, `Socks5CredentialsTooLong`,
`HttpInvalidConnectTarget`, `HttpResponseTooLarge`, `HttpClosedEarly`)
with the offending byte or length; its `Display` still prints the
legacy message text. A peer that answers the greeting with a
non-SOCKS5 version byte is `Protocol(Socks5BadVersion { got })`, not
`MethodUnsupported`. For `ProxyRejected { code, .. }` on SOCKS5,
`resocks5_net::socks5_rep_description(code)` gives the RFC 1928 reply
meaning.

`ProxyConfig` is built with `ProxyConfig::socks5/http/https(..)` plus
`with_auth` / `with_gate`. Its `gate` field is the outer node dialed first.
`dial_chain(&proxy, host, port, &opts, tls)` follows those links to any
depth, tunnelling hop by hop over one TCP connection (SOCKS5, HTTP CONNECT
or HTTPS at every hop) and returning `AnyUpstream::Gate`; its
`ChainError::stage()` says which step failed (`Connect`, `Hop(n)`,
`Target`). `dial`, `connect_proxy` and `connect_proxy_once` do **not**
interpret `gate`.

Top-level modules: `connect` (dial, connectors, tunnel, fragmentation),
`error`, `server`, `progress`, `pool` (`pool` feature), `rating` (`rating`
feature), `rotator` (`rotator` feature), `types`.

A working version of the pooled example lives at
[`examples/connect_through_proxy.rs`](examples/connect_through_proxy.rs).
CI compiles that file, so it tracks the API; the Markdown blocks above are
not extracted.

## Status

Pre-1.0. The API may still change before a 1.0 release. For project
context, full architecture, and the consuming binary see the main
[`resocks5`](https://github.com/PHPCraftdream/resocks5) repository.

## License

Dual-licensed under MIT OR Apache-2.0, at your option.
