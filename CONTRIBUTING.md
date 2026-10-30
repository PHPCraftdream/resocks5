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

CI's core local checks are:

```bash
cargo build --workspace --all-targets
cargo test  --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
```

CI also runs structure, MSRV, documentation, feature-matrix, and lean-library
checks. The workflow's `RUSTFLAGS=-D warnings` treats compiler warnings as
errors; this does not prohibit particular constructs such as `unwrap()`,
`dbg!`, or `TODO` by itself.

### Segmented CI: targeted runs and the full run

A push or PR does not run everything. The `changes` job
(`.github/scripts/changed-areas.sh`) maps the **diff** to what is needed and CI
runs only that, on ubuntu. Nothing needs to be written in the commit message.

| Changed files | What runs |
|---------------|-----------|
| SDK core: `crates/resocks5-net/src/{lib.rs,connect,error,types}`, `session/{pool,progress.rs}`, `tests/` | all SDK tests in every feature-matrix row, lean clippy/doc, and all app tests |
| `crates/resocks5-net/src/session/rating`, `rotator` | SDK tests of `rating::` / `rotator::` in every matrix row; app `server::` tests |
| `crates/resocks5-net/src/server` | SDK `server::` tests; app `server::` and `http_proxy::` tests |
| SDK examples, fixtures | test builds of every matrix row (`--no-run`) |
| `crates/resocks5/src/{main.rs,config}` | all app tests |
| `crates/resocks5/src/{auth,cli,server,http_proxy,logger}` | app tests of that module (`auth` also `server::`, `http_proxy::`) |
| `README.md`, `docs/REFERENCE.md`, `docs/ARCHITECTURE.md` (embedded and tested by the app) | app `print_config_docs` tests |
| any Rust file | fmt + clippy, MSRV, docs, portable builds |
| `Cargo.toml`, `Cargo.lock`, `.cargo/**` | everything above for both crates, plus the license/supply-chain jobs |
| `deny.toml`, `.github/licenses/**` | license/supply-chain jobs, portable builds |
| `.github/workflows/release.yml` | portable builds |
| `.github/scripts/install.*`, `test_installers.py` | installer tests on Linux, macOS and Windows |
| anything else (changelog, other docs) | only the `structure` job |

Tests are chosen by module: a libtest filter such as `server::` selects every
unit test and doctest under that module. Limits of this mapping: a change is
tested in its own module (and the modules known to depend on it), so
cross-module behaviour changes and Windows/macOS-only breakage can slip past a
targeted run. The full run exists for exactly that.

**The full run** (every segment, the whole workspace, Linux, macOS and
Windows, no filters) is started explicitly, at the end of a sprint and before a
release:

- put `[ci: full]` (or `[full-ci]`) in the text of a commit message of the push
  or PR, or in the PR title:

  ```text
  chore: sprint close [ci: full]
  ```

  Write that marker only when you want the full run: it is matched anywhere in
  the commit messages of the range;
- or start it by hand: **Actions → CI → Run workflow**, branch `main`
  (`workflow_dispatch`, always a full run);
- it also runs for every `v*` tag, and when `.github/workflows/ci.yml` or the
  classifier script changes (to prove the change).

Require the single **`ci result`** check in branch protection: segments that
were skipped count as passing, a failed or cancelled one fails it.

### Code structure (the `structure` CI job)

- A Rust file has at most **1000 lines**
  (`sh .github/scripts/check-line-limit.sh`).
- A directory has at most **7 entries**, files and sub-directories together
  (`sh .github/scripts/check-dir-entries.sh`; counts what git tracks).

Files and directories that were already over the limit when the rule was
introduced are listed in the scripts' `BASELINE` with their current size. They
may not grow, no new ones may appear, and an entry is lowered or deleted as the
file or directory is split.

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

## Releasing (maintainers)

1. Bump `[workspace.package].version` in the root `Cargo.toml` — both
   crates share one version. Roll `CHANGELOG.md`'s `## [Unreleased]`
   section into a dated `## [X.Y.Z] - YYYY-MM-DD` section, and add a
   fresh empty `## [Unreleased]` above it. If `resocks5-net`'s public API
   changed at all this cycle, this must be at least a minor bump (0.x
   SemVer treats a minor bump as the breaking-change boundary) —
   `cargo semver-checks -p resocks5-net --baseline-rev <previous tag>`
   catches what plain review misses.
2. Also bump the `version = "..."` on the `resocks5-net` path dependency
   in `crates/resocks5/Cargo.toml` to match — it's a separate field from
   `version.workspace`, not auto-derived, since it's declaring a registry
   version requirement for a *sibling* crate, not this crate's own version.
3. Commit, push, then push a `v<version>` tag. That single tag push
   triggers `.github/workflows/release.yml`: native archives + a GitHub
   Release, a multi-arch Docker image to `ghcr.io`, and — once crates.io
   credentials are configured (see below) — a `cargo publish` of
   `resocks5-net` (the SDK) to crates.io. The `resocks5` binary crate is
   `publish = false`: binaries are distributed only through the GitHub
   Release and the container image.

### crates.io credentials

The `publish-crates` job in `release.yml` (`resocks5-net` only) always runs
a packaging dry-run and uploads only when credentials exist. The mode is
chosen by the repository variable `CRATES_IO_AUTH`:

- **API token (default; unset variable).** Create a token at
  <https://crates.io/settings/tokens> scoped to `publish-new` +
  `publish-update`, store it as the `CARGO_REGISTRY_TOKEN` Actions secret,
  push the tag. Required for the **first** release: a trusted publisher can
  only be configured for a crate that already exists on crates.io.
- **Trusted Publishing (OIDC).** After the first release, open the crate's
  settings on crates.io → Trusted Publishing (`resocks5-net`), add repository
  `PHPCraftdream/resocks5`, workflow `release.yml`; leave "Environment
  name" empty (the job declares no `environment:`). Then set the Actions
  variable `CRATES_IO_AUTH` to `oidc` and delete the `CARGO_REGISTRY_TOKEN`
  secret. The job exchanges its GitHub identity for a short-lived token; no
  long-lived secret remains.

Without either, the tag still produces archives and the Docker image; the
crates.io step logs a notice and is skipped.

## License

Contributions are dual-licensed under MIT or Apache-2.0, matching the
project (see [`LICENSE-MIT`](LICENSE-MIT) and
[`LICENSE-APACHE`](LICENSE-APACHE)). By submitting a PR you agree to that
licensing — no separate CLA is required.

## Conduct

Civil and constructive. See [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md).
