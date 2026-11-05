#!/bin/sh
# Workflow hygiene gate, run by the `structure` job:
#
#   workflow-hygiene.sh [DIR]        check DIR (default .github/workflows)
#   workflow-hygiene.sh --self-test  prove the checks fail on broken copies
#
# Pins what a workflow reader cannot see from behaviour:
#   - every job of ci.yml and release.yml has `timeout-minutes`;
#   - every ci.yml job is aggregated by `ci-result` (`needs`);
#   - release.yml: workflow-level `contents: read`, `contents: write` only in
#     the `release` job;
#   - release.yml `publish-crates`: package first, upload with `--no-verify`
#     only (nothing compiles while the registry token is set).
set -eu

check() {
  dir=$1
  failures=0
  fail() {
    printf 'workflow-hygiene: %s\n' "$1"
    failures=$((failures + 1))
  }

  for file in ci.yml release.yml; do
    missing=$(awk '
      /^jobs:/ { j = 1; next }
      j && /^[^ #]/ { j = 0 }
      j && /^  [A-Za-z0-9_-]+:[[:space:]]*$/ {
        if (name != "" && !has) print name
        name = $1; sub(":", "", name); has = 0
      }
      j && /^    timeout-minutes:/ { has = 1 }
      END { if (name != "" && !has) print name }
    ' "$dir/$file")
    for job in $missing; do
      fail "$file: job '$job' has no timeout-minutes"
    done
  done

  jobs=$(awk '
    /^jobs:/ { j = 1; next }
    j && /^[^ #]/ { j = 0 }
    j && /^  [A-Za-z0-9_-]+:[[:space:]]*$/ { n = $1; sub(":", "", n); print n }
  ' "$dir/ci.yml")
  needed=$(awk '
    /^  ci-result:/ { r = 1; next }
    r && /^  [A-Za-z0-9_-]+:/ { r = 0 }
    r && /^    needs:/ { n = 1; next }
    r && n && /^      - / { print $2; next }
    r && n && !/^      - / { n = 0 }
  ' "$dir/ci.yml")
  for job in $jobs; do
    [ "$job" = ci-result ] && continue
    printf '%s\n' "$needed" | grep -qx "$job" ||
      fail "ci.yml: job '$job' is not in ci-result needs"
  done

  top=$(awk '
    /^permissions:/ { p = 1; next }
    p && /^[^ #]/ { p = 0 }
    p && /^  contents:/ { print $2 }
  ' "$dir/release.yml")
  [ "$top" = read ] ||
    fail "release.yml: workflow-level permissions must be 'contents: read' (got '$top')"
  writers=$(awk '
    /^jobs:/ { j = 1; next }
    j && /^  [A-Za-z0-9_-]+:[[:space:]]*$/ { n = $1; sub(":", "", n) }
    j && /^      contents: write/ { print n }
  ' "$dir/release.yml")
  [ "$writers" = release ] ||
    fail "release.yml: only the 'release' job may have contents: write (got '$writers')"

  publish=$(awk '
    /^  publish-crates:/ { p = 1; next }
    p && /^  [A-Za-z0-9_-]+:/ { p = 0 }
    p { print }
  ' "$dir/release.yml")
  printf '%s\n' "$publish" | grep -q 'cargo package' ||
    fail "release.yml: publish-crates must package before uploading"
  if printf '%s\n' "$publish" | grep 'cargo publish' | grep -qv -e '--no-verify'; then
    fail "release.yml: every 'cargo publish' must use --no-verify"
  fi

  if [ "$failures" -ne 0 ]; then
    printf 'workflow-hygiene: %d problem(s)\n' "$failures"
    return 1
  fi
  printf 'workflow-hygiene: ok\n'
}

self_test() {
  tmp=$(mktemp -d)
  trap 'rm -rf "$tmp"' EXIT
  base=.github/workflows
  check "$base" >/dev/null || {
    echo 'self-test: the real workflows must pass first'
    exit 1
  }
  # Each mutation must make the check fail.
  mutate() {
    name=$1
    shift
    rm -rf "$tmp/w"
    mkdir "$tmp/w"
    cp "$base/ci.yml" "$base/release.yml" "$tmp/w/"
    "$@"
    if check "$tmp/w" >/dev/null 2>&1; then
      printf 'self-test: mutation "%s" was not caught\n' "$name"
      exit 1
    fi
  }
  drop_timeout() { sed '0,/^    timeout-minutes:/{/^    timeout-minutes:/d}' "$tmp/w/ci.yml" >"$tmp/w/x" && mv "$tmp/w/x" "$tmp/w/ci.yml"; }
  top_write() { sed '0,/^  contents: read/s//  contents: write/' "$tmp/w/release.yml" >"$tmp/w/x" && mv "$tmp/w/x" "$tmp/w/release.yml"; }
  verify_back() { sed 's/ --no-verify//' "$tmp/w/release.yml" >"$tmp/w/x" && mv "$tmp/w/x" "$tmp/w/release.yml"; }
  unaggregated() { sed '/^      - deny-advisories$/d' "$tmp/w/ci.yml" >"$tmp/w/x" && mv "$tmp/w/x" "$tmp/w/ci.yml"; }
  mutate 'a job loses its timeout' drop_timeout
  mutate 'workflow-level write permission' top_write
  mutate 'publish verifies again' verify_back
  mutate 'a job leaves ci-result' unaggregated
  echo 'workflow-hygiene self-test: ok'
}

case "${1:-}" in
  --self-test) self_test ;;
  '') check .github/workflows ;;
  *) check "$1" ;;
esac
