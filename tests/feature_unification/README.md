# Feature-unification fixture (dev-only, review P2-01 regression gate)

Two downstream crates share one cargo graph and depend on this repo's
`resocks5-net` by path:

- `lean-consumer` — `default-features = false`; calls `connect_proxy` and
  `connect_proxy_once` with the universal call shape (trailing `None`), and
  additionally names the parameter type itself
  (`use resocks5_net::connect::connect_proxy::TlsConnector;` +
  `Option<&'static TlsConnector>`).
- `tls-consumer` — default features (`tls` on); passes a real connector
  from `make_tls_connector` for an HTTPS upstream.

Cargo unifies features per build graph, so the single workspace build
below compiles `resocks5-net` ONCE with `tls` on — and `lean-consumer`'s
source must still compile against it unchanged. That is exactly the
failure mode from review P2-01, where `#[cfg(feature = "tls")]` on the
`tls_connector` parameter changed the entry points' arity and broke lean
consumers under unification (`error[E0061]: this function takes 5
arguments but 4 arguments were supplied`); the named-type check above is
the counterpart regression gate for review R2-P2-01, where the TLS build
kept the arity but made the type private (`error[E0603]: struct
TlsConnector is private`) because `tokio_rustls::TlsConnector` was only
imported, not re-exported.

This directory is not part of the root workspace (`exclude`d in the root
`Cargo.toml`) and is never published; it is a compile-time gate, the
crates' `main` functions never dial anything.

## Commands (from this directory)

    cargo build --workspace          # both consumers TOGETHER — unification bites here
    cargo build -p lean-consumer     # lean consumer alone (no tls in graph)
    cargo build -p tls-consumer     # tls consumer alone

All three must succeed with zero changes to `lean-consumer/src/main.rs`.
Add `--locked` once `Cargo.lock` is present.

## Sensitivity check (performed once, manually, by the orchestrator)

A fixture that always passes proves nothing by itself — it has to be shown
to fail on the actual regression it claims to catch. This was done once by
hand and is recorded here rather than left as an unverified claim:

1. Reverted `crates/resocks5-net/src/connect/proxy_connect/connect_proxy.rs`
   to its pre-fix form (`#[cfg(feature = "tls")]` on the `tls_connector`
   parameter).
2. Rewrote `lean-consumer/src/main.rs` to call `connect_proxy`/
   `connect_proxy_once` with NO trailing argument — exactly how a real
   lean caller would have written it against that pre-fix API.
3. `cargo build --workspace` from this directory then failed with the
   exact error from the review: `error[E0061]: this function takes 5
   arguments but 4 arguments were supplied`, at the `connect_proxy` call
   site, because `tls-consumer` unified `tls` on for the whole graph.
4. Restored both files to the fixed state; `cargo build --workspace`
   succeeded again.

Note step 2 matters: reverting only the library and leaving
`lean-consumer`'s CURRENT (post-fix) source in place does NOT reproduce
the bug — that source already calls with 5 arguments, which happens to
satisfy the old cfg'd-on signature too once `tls` is unified on. The
fixture demonstrates the fix; catching a future regression the same way
would require rewriting the lean consumer back to the old call shape, as
above.

The named-type half of the fixture got the same treatment when R2-P2-01
was fixed: with `pub use tokio_rustls::TlsConnector;` in
`connect_proxy.rs` temporarily reverted to the private
`use tokio_rustls::TlsConnector;`, `cargo check --workspace` from this
directory failed with `error[E0603]: struct TlsConnector is private` on
lean-consumer's named-type use (tls-consumer had unified `tls` on), while
`cargo check -p lean-consumer` alone still passed against the lean
placeholder. Restoring the `pub use` made both green again. Note the
pre-fix source of this file (untyped `None` only) did NOT trip that
variant — the named-type use above is what makes the fixture catch it.
