#!/bin/sh
# Pick the CI segments and the tests a change needs, from its diff.
#
#   changed-areas.sh EVENT BASE HEAD [MARKER]
#
# Writes `key=value` lines to stdout (append them to $GITHUB_OUTPUT); the
# human-readable summary goes to stderr.
#
# The diff BASE..HEAD is mapped to
#   - segments (lint, MSRV, docs, license checks, installers, portable builds),
#   - the SDK feature-matrix rows and WHICH SDK tests they run,
#   - WHICH app tests the app job runs.
# Tests are chosen by module: libtest filters such as `server::` select every
# unit test and doctest under that top-level module. Where modules depend on
# each other too tightly to separate (SDK core, app config), the whole crate's
# tests run. Dependencies are followed one way: an SDK core change also runs
# all app tests; an SDK `server` change runs the app's `server::` and
# `http_proxy::` tests, and so on.
#
# A FULL run (every segment, workspace tests, every OS, no filters) is chosen
# for manual / tag events, when the diff base is unknown, when the
# message carries `[full-ci]`, and when this script or ci.yml changes.
# `structure` always runs. Cross-crate and Windows/macOS-only breakage that a
# targeted run cannot see is caught by the full run.
set -eu

event=${1:?event}
base=${2:-}
head=${3:?head}
marker=${4:-}

ALL_ROWS="lean pool tls pool-tls serde rating rotator test-instrumentation default all"

row_args() {
  case "$1" in
    lean) echo "--no-default-features" ;;
    pool) echo "--no-default-features --features pool" ;;
    tls) echo "--no-default-features --features tls" ;;
    pool-tls) echo "--no-default-features --features pool,tls" ;;
    serde) echo "--no-default-features --features serde" ;;
    rating) echo "--no-default-features --features rating" ;;
    rotator) echo "--no-default-features --features rotator" ;;
    test-instrumentation) echo "--no-default-features --features test-instrumentation" ;;
    default) echo "" ;;
    all) echo "--all-features" ;;
    *) return 1 ;;
  esac
}

rows_json() {
  out=""
  for n in $1; do
    a=$(row_args "$n")
    out="${out:+$out,}{\"name\":\"$n\",\"args\":\"$a\"}"
  done
  printf '{"include":[%s]}' "$out"
}

uniq_words() {
  printf '%s\n' "$*" | tr ' ' '\n' | sed '/^$/d' | sort -u | tr '\n' ' ' | sed 's/ $//'
}

full=false
case "$event" in
  push | pull_request) ;;
  *) full=true ;;
esac
case "$marker" in
  *"[full-ci]"* | *"[ci: full]"*) full=true ;;
esac

files=""
if [ "$full" = false ]; then
  case "$base" in
    "" | 0000000000000000000000000000000000000000) full=true ;;
    *)
      if git cat-file -e "$base^{commit}" 2>/dev/null; then
        files=$(git diff --name-only "$base" "$head")
        # Messages of the range may ask for a full run too.
        if git log --format=%B "$base..$head" | grep -qE '\[(full-ci|ci: full)\]'; then
          full=true
        fi
      else
        full=true
      fi
      ;;
  esac
fi

rust=false
deps=false
installers=false
release_wf=false
net_all=false
net_touched=false
net_f=""
app_all=false
app_touched=false
app_f=""

if [ "$full" = false ]; then
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    case "$f" in
      .github/workflows/ci.yml | .github/scripts/changed-areas.sh)
        full=true
        ;;
      Cargo.lock | Cargo.toml | rust-toolchain* | .cargo/*)
        rust=true
        deps=true
        net_all=true
        app_all=true
        ;;
      deny.toml | .github/licenses/*)
        deps=true
        ;;
      crates/resocks5-net/Cargo.toml)
        rust=true
        deps=true
        net_all=true
        ;;
      crates/resocks5/Cargo.toml)
        rust=true
        deps=true
        app_all=true
        ;;
      # SDK core: modules that depend on each other too tightly to separate.
      crates/resocks5-net/src/lib.rs | crates/resocks5-net/src/error/* | \
        crates/resocks5-net/src/types/* | crates/resocks5-net/src/connect/* | \
        crates/resocks5-net/src/session/pool/* | crates/resocks5-net/src/session/progress.rs | \
        crates/resocks5-net/tests/*)
        rust=true
        net_all=true
        ;;
      crates/resocks5-net/src/session/rating/*)
        rust=true
        net_f="$net_f rating:: rotator::"
        app_f="$app_f server::"
        ;;
      crates/resocks5-net/src/session/rotator/*)
        rust=true
        net_f="$net_f rotator::"
        app_f="$app_f server::"
        ;;
      crates/resocks5-net/src/server/*)
        rust=true
        net_f="$net_f server::"
        app_f="$app_f server:: http_proxy::"
        ;;
      crates/*/README.md)
        ;;
      crates/resocks5-net/* | tests/feature_unification/*)
        rust=true
        net_touched=true
        ;;
      crates/resocks5/src/main.rs | crates/resocks5/src/config/*)
        rust=true
        app_all=true
        ;;
      crates/resocks5/src/auth/*)
        rust=true
        app_f="$app_f auth:: server:: http_proxy::"
        ;;
      crates/resocks5/src/cli/*)
        rust=true
        app_f="$app_f cli::"
        ;;
      crates/resocks5/src/server/*)
        rust=true
        app_f="$app_f server::"
        ;;
      crates/resocks5/src/http_proxy/*)
        rust=true
        app_f="$app_f http_proxy::"
        ;;
      crates/resocks5/src/logger/*)
        rust=true
        app_f="$app_f logger::"
        ;;
      crates/resocks5/*)
        rust=true
        app_touched=true
        ;;
      # The app embeds these files (include_str!) and tests that they agree.
      README.md | docs/REFERENCE.md | docs/ARCHITECTURE.md)
        app_f="$app_f print_config_docs"
        ;;
      .github/workflows/release.yml)
        release_wf=true
        ;;
      .github/scripts/install.sh | .github/scripts/install.ps1 | .github/scripts/test_installers.py)
        installers=true
        ;;
    esac
  done <<EOF
$files
EOF
fi

# An SDK core change can break any app test; the app job covers it.
if [ "$net_all" = true ]; then
  app_all=true
fi

run_test=false
run_net=false
run_clippy_net=false
run_doc_net=false
run_lint=$rust
run_msrv=$rust
run_doc=$rust
run_portable=false
run_deny=$deps
run_licenses=$deps
run_installers=$installers
net_rows=""
net_test_args=""
test_scope="-p resocks5"
test_filter=""
test_os='["ubuntu-latest"]'
msrv_os='["ubuntu-latest"]'

net_f=$(uniq_words "$net_f")
app_f=$(uniq_words "$app_f")

if [ "$net_all" = true ] || [ -n "$net_f" ] || [ "$net_touched" = true ]; then
  run_net=true
  run_clippy_net=true
  run_doc_net=true
  net_rows="$ALL_ROWS"
  if [ "$net_all" = true ]; then
    net_test_args=""
  elif [ -n "$net_f" ]; then
    # `cargo test` takes ONE filter before `--`; several go after it.
    net_test_args="-- $net_f"
  else
    # Only examples / README / fixtures changed: prove the test builds compile.
    net_test_args="--no-run"
  fi
fi

if [ "$app_all" = true ] || [ -n "$app_f" ]; then
  run_test=true
  if [ "$app_all" = false ]; then
    test_filter="-- $app_f"
  fi
fi

if [ "$rust" = true ] || [ "$release_wf" = true ]; then
  run_portable=true
fi
if [ "$deps" = true ]; then
  run_portable=true
fi

if [ "$full" = true ]; then
  run_test=true
  run_net=true
  run_clippy_net=true
  run_doc_net=true
  run_lint=true
  run_msrv=true
  run_doc=true
  run_portable=true
  run_deny=true
  run_licenses=true
  run_installers=true
  net_rows="$ALL_ROWS"
  net_test_args=""
  test_scope="--workspace"
  test_filter=""
  test_os='["ubuntu-latest","windows-latest","macos-latest"]'
  msrv_os='["ubuntu-latest","windows-latest"]'
fi

net_matrix=$(rows_json "$net_rows")

{
  echo "full=$full"
  echo "run_test=$run_test"
  echo "run_lint=$run_lint"
  echo "run_msrv=$run_msrv"
  echo "run_doc=$run_doc"
  echo "run_net=$run_net"
  echo "net_matrix=$net_matrix"
  echo "net_test_args=$net_test_args"
  echo "run_clippy_net=$run_clippy_net"
  echo "run_doc_net=$run_doc_net"
  echo "run_portable=$run_portable"
  echo "run_deny=$run_deny"
  echo "run_licenses=$run_licenses"
  echo "run_installers=$run_installers"
  echo "test_os=$test_os"
  echo "msrv_os=$msrv_os"
  echo "test_scope=$test_scope"
  echo "test_filter=$test_filter"
}

{
  echo "event=$event full=$full"
  echo "app tests: run=$run_test scope='$test_scope' filter='${test_filter:-<all>}'"
  echo "sdk tests: run=$run_net args='${net_test_args:-<all>}'"
  echo "lint=$run_lint msrv=$run_msrv doc=$run_doc portable=$run_portable deny=$run_deny licenses=$run_licenses installers=$run_installers"
  if [ -n "$files" ]; then
    echo "changed files:"
    echo "$files" | sed 's/^/  /'
  fi
} >&2
