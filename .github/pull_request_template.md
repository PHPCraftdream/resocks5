<!--
Fill in the sections that apply. Delete the rest. See
crates/ktav/CONTRIBUTING.md for the full rules.
-->

## Summary

<!-- One sentence on what and why. -->

## Bug fix? → Regression test

<!--
If this PR fixes a bug, include a test that fails on main and passes
with this change. Link it here, e.g.:

    tests/edge_cases/paren_literals.rs::single_open_paren_round_trips
-->

## Perf-sensitive? → before/after benchmarks

<!--
If this PR touches any of:
  - src/parser/            src/thin/parser.rs
  - src/ser/text_serializer.rs  src/render/
  - src/thin/deserializer.rs    src/de/
  - src/value/

Paste criterion numbers for the affected scenarios:

    parse_to_struct/100_upstreams_typed
      before: 275 µs
      after:  198 µs
      change: -28%

Use `./crates/ktav/bench.sh` to produce them.
-->

## API compatibility

<!--
- [ ] semver-compatible (additions, doc changes)
- [ ] semver-breaking — MINOR bump while pre-1.0 (state why)
- [ ] no public API change
-->

## Checklist

- [ ] Tests added / updated
- [ ] `cargo test -p ktav` passes
- [ ] `cargo clippy --all-features -- -D warnings` clean
- [ ] `cargo fmt --check` clean
- [ ] `CHANGELOG.md` updated (if user-visible)
