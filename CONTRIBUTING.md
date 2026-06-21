# Contributing to resocks5

Thanks for considering a contribution. This document is short on purpose —
the rules are mostly the rules of any small Rust project.

## Before you open a PR

1. **Open an issue first** for anything bigger than a typo or a one-file
   bugfix. It's much cheaper to align on the design before the diff
   exists. Bug reports and feature requests both have templates under
   [`.github/ISSUE_TEMPLATE`](.github/ISSUE_TEMPLATE).
2. **Security issues:** do **NOT** open a public issue.
   See [`SECURITY.md`](SECURITY.md) for the private reporting channel.

## Development setup

You need a recent stable Rust toolchain. The repository declares MSRV
`1.88` (enforced by the `msrv` job in CI on ubuntu + windows), set as
`rust-version` in every crate manifest.

```bash
git clone https://github.com/PHPCraftdream/resocks5
cd resocks5
cargo build --workspace
```

## The checks your PR must pass

CI runs exactly these four — match them locally and your PR turns green
on the first push:

```bash
cargo build --workspace
cargo test  --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
```

Notes:

- `clippy -D warnings` means `unwrap()` in a hot path, `dbg!`, or a stray
  `TODO` will fail CI. That's intentional.
- `fmt --check` means run `cargo fmt --all` before committing. If it's
  already clean, the CI step is a no-op.

## Repository layout

A Cargo workspace with two crates:

| Crate | What goes there |
|---|---|
| [`crates/resocks5-net`](crates/resocks5-net) | The reusable library: connectors, TCP pool, sand-rating model, rotator, TLS fragmentation, low-level types. **Must not** depend on the binary's config format, logging sink, or auth. |
| [`crates/resocks5`](crates/resocks5) | The CLI binary: KTAV config, Argon2 auth, logging, the SOCKS5/HTTP listener, the CLI itself. |

When in doubt about where a change belongs, ask in the issue. A good
heuristic: if it could be useful to a *different* proxy product, it
probably belongs in `resocks5-net`.

For the system overview (request flow, sand-rating math, gate chains,
TLS-fragmentation, safety nets), see [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

## Commit style

- One logical change per commit. Mixed-purpose commits (refactor + fix +
  unrelated rename) are hard to review and to revert.
- Subject line in imperative mood, no trailing period, ≤ 72 chars.
- If the change touches the public API of `resocks5-net`, mention it in
  the commit body and add a note in `CHANGELOG.md` under `## [Unreleased]`.

## PR description

Use the [PR template](.github/pull_request_template.md). The reviewers
need to see what changed, why, and how you verified it.

## License

Contributions are dual-licensed under MIT or Apache-2.0, matching the
project (see [`LICENSE-MIT`](LICENSE-MIT) and
[`LICENSE-APACHE`](LICENSE-APACHE)). By submitting a PR you agree to that
licensing — no separate CLA is required.

## Conduct

Civil and constructive. See [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md).
