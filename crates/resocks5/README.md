# resocks5

A SOCKS5 **and** HTTP-CONNECT proxy server in Rust that spreads incoming
client connections across a pool of upstream proxies — with per-client
authentication, per-target upstream stickiness, a self-recovering
sand-rating rotator that demotes failing upstreams without ever excluding
them, and TLS fragmentation for DPI evasion.

The listener auto-detects SOCKS5 vs HTTP CONNECT per connection, so a
single port serves both kinds of client.

## Install

```bash
# From a checkout:
cargo install --path .

# …or straight from git:
cargo install --git https://github.com/PHPCraftdream/resocks5 resocks5
```

Requires Rust 1.88+ (enforced by CI). Uses the pure-Rust `ring` crypto
provider — no `cmake` or C toolchain needed.

## Quick start

```bash
# 1. The first run creates three config files in the working directory,
#    then exits saying no upstream proxies are configured yet.
resocks5

# 2. Add at least one upstream to resocks5.proxy_list.ktav, e.g.:
#       socks5_v4: [ user:pass@198.51.100.7:1080 ]

# 3. (Optional) add a client user.
resocks5 users add alice

# 4. Start the proxy — listens on 127.0.0.1:20082 by default.
resocks5
```

Print the full configuration reference with `resocks5 config`.

## More

This crate is the CLI proxy server. It builds on top of the
[`resocks5-net`](https://crates.io/crates/resocks5-net) library, which
is also published separately and can be used as a reusable proxy
networking toolkit.

For full architecture, README, examples, and contributing guidelines see
the project repository:
**[github.com/PHPCraftdream/resocks5](https://github.com/PHPCraftdream/resocks5)**.

## License

Dual-licensed under MIT OR Apache-2.0, at your option.
