#!/bin/sh
# Pick the CI segments and the tests a change needs, from its diff.
#
#   changed-areas.sh EVENT BASE HEAD [MARKER]
#   changed-areas.sh --self-test
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
#
# CHANGED_FILES (newline-separated paths) replaces the `git diff` file list;
# the self-test uses it to feed cases without a git history.
set -eu

ALL_ROWS="lean pool tls pool-tls serde rating rotator zeroize test-instrumentation secure-auth default all"

row_args() {
  case "$1" in
    lean) echo "--no-default-features" ;;
    pool) echo "--no-default-features --features pool" ;;
    tls) echo "--no-default-features --features tls" ;;
    pool-tls) echo "--no-default-features --features pool,tls" ;;
    serde) echo "--no-default-features --features serde" ;;
    rating) echo "--no-default-features --features rating" ;;
    rotator) echo "--no-default-features --features rotator" ;;
    zeroize) echo "--no-default-features --features zeroize" ;;
    secure-auth) echo "--no-default-features --features secure-auth" ;;
    test-instrumentation) echo "--no-default-features --features test-instrumentation" ;;
    default) echo "" ;;
    all) echo "--features pool,tls,serde,rating,rotator,zeroize,test-instrumentation,secure-auth" ;;
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

# ---- self-test ----
# `changed-areas.sh --self-test` feeds the case table below through the
# classifier itself (CHANGED_FILES injects the file list, no git history
# needed) and pins the outputs. The `structure` job runs it: deleting or
# breaking a mapping case here fails CI — e.g. dropping the session/chain
# case would classify those files as generic net changes (`--no-run`, no
# app tests) and the chain assertions below would fail.
self_test() {
  failures=0
  cases=0
  name=
  files=
  marker=
  out=

  # expect KEY=VALUE: the value may be empty or contain spaces.
  expect() {
    key=${1%%=*}
    want=${1#*=}
    actual=$(printf '%s\n' "$out" | sed -n "s/^$key=//p")
    if [ "$want" != "$actual" ]; then
      printf 'changed-areas self-test: FAIL %s: expected %s=[%s], got [%s]\n' \
        "$name" "$key" "$want" "$actual"
      failures=$((failures + 1))
    fi
  }

  while IFS= read -r line; do
    case "$line" in
      '' | '#'*) continue ;;
      files*)
        files=${line#files }
        marker=
        ;;
      marker*)
        marker=${line#marker }
        ;;
      case*)
        name=${line#case }
        cases=$((cases + 1))
        if ! out=$(CHANGED_FILES="$files" sh "$0" push base head "$marker" 2>/dev/null); then
          printf 'changed-areas self-test: FAIL %s: classifier exited non-zero\n' "$name"
          failures=$((failures + 1))
          out=
        fi
        ;;
      expect*)
        expect "${line#expect }"
        ;;
      *)
        printf 'changed-areas self-test: bad table line: %s\n' "$line"
        failures=$((failures + 1))
        ;;
    esac
  done <<'EOF'
# session/chain -> SDK chain:: tests in every matrix row + app server:: tests
files crates/resocks5-net/src/session/chain/mod.rs
case chain
expect full=false
expect run_net=true
expect net_test_args=-- chain::
expect run_clippy_net=true
expect run_test=true
expect test_filter=-- server::
expect run_lint=true
expect run_deny=false
expect run_portable=true
expect run_unification=false

# session/rating -> rating:: + rotator:: SDK tests (rotator implies rating)
files crates/resocks5-net/src/session/rating/sand.rs
case rating
expect net_test_args=-- rating:: rotator::
expect test_filter=-- server::

# session/rotator -> rotator:: SDK tests + app server:: tests
files crates/resocks5-net/src/session/rotator/mod.rs
case rotator
expect net_test_args=-- rotator::
expect test_filter=-- server::

# SDK server -> server:: SDK tests + app server::/http_proxy:: tests
files crates/resocks5-net/src/server/conn.rs
case net-server
expect run_net=true
expect net_test_args=-- server::
expect run_test=true
expect test_filter=-- http_proxy:: server::

# generic net path (examples, ...): builds every row, runs no tests
files crates/resocks5-net/examples/demo.rs
case net-generic
expect run_net=true
expect net_test_args=--no-run
expect run_test=false
expect run_unification=false

# session/testing (mock upstream, perf counters) -> testing:: SDK tests, not a bare build
files crates/resocks5-net/src/session/testing/mod.rs
case testing
expect run_net=true
expect net_test_args=-- testing::
expect run_unification=false

# other session modules (auth, health, ...) -> whole session:: SDK test tree
files crates/resocks5-net/src/session/auth/secure_auth/server.rs
case session-rest
expect run_net=true
expect net_test_args=-- session::
expect run_unification=false

# the fixture workspace itself: only the feature-unification job
files tests/feature_unification/lean-consumer/src/main.rs
case fixture
expect run_unification=true
expect run_net=false
expect run_test=false
expect run_lint=false

# SDK core -> all matrix rows, all app tests, and the fixture job
files crates/resocks5-net/src/connect/proxy_connect/connect_proxy.rs
case sdk-core
expect run_unification=true
expect net_test_args=
expect run_test=true
expect test_filter=
expect run_deny=false

# app server -> app server:: tests only (no SDK matrix, no fixture job)
files crates/resocks5/src/server/accept.rs
case app-server
expect run_test=true
expect test_filter=-- server::
expect run_net=false
expect run_unification=false

# dependency manifests: both crates, license jobs, fixture job
files Cargo.lock
case manifests
expect run_deny=true
expect run_licenses=true
expect run_net=true
expect net_test_args=
expect run_test=true
expect run_unification=true

# [ci: full] in the message -> the full run incl. fixture job + release lane
files docs/RELEASE_CHECKLIST.md
marker [ci: full]
case full-marker
expect full=true
expect run_test=true
expect test_scope=--workspace
expect run_installers=true
expect run_unification=true
expect run_release_lane=true

# docs-only -> nothing but the always-on structure job
files CHANGELOG.md
case docs-only
expect full=false
expect run_test=false
expect run_net=false
expect run_lint=false
expect run_msrv=false
expect run_doc=false
expect run_portable=false
expect run_deny=false
expect run_unification=false
expect run_release_lane=false
EOF

  if [ "$failures" -ne 0 ]; then
    printf 'changed-areas self-test: %d case(s), %d failed assertion(s)\n' "$cases" "$failures"
    exit 1
  fi
  printf 'changed-areas self-test: %d case(s) ok\n' "$cases"
}

if [ "${1:-}" = "--self-test" ]; then
  self_test
  exit
fi

event=${1:?event}
base=${2:-}
head=${3:?head}
marker=${4:-}

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
      if [ -n "${CHANGED_FILES:-}" ]; then
        # Test seam: the self-test injects the file list, no git needed.
        files=$CHANGED_FILES
      elif git cat-file -e "$base^{commit}" 2>/dev/null; then
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
uni_touched=false
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
      crates/resocks5-net/src/session/chain/*)
        rust=true
        net_f="$net_f chain::"
        app_f="$app_f server::"
        ;;
      crates/resocks5-net/src/server/*)
        rust=true
        net_f="$net_f server::"
        app_f="$app_f server:: http_proxy::"
        ;;
      crates/resocks5-net/src/session/testing/*)
        rust=true
        net_f="$net_f testing::"
        ;;
      # Remaining session modules (auth, health, ...): the whole session tree.
      crates/resocks5-net/src/session/*)
        rust=true
        net_f="$net_f session::"
        ;;
      crates/*/README.md)
        ;;
      # The fixture workspace is not a member of the root workspace: its
      # gate is the feature-unification job alone.
      tests/feature_unification/*)
        uni_touched=true
        ;;
      crates/resocks5-net/*)
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
# The fixture workspace is the unification gate: SDK core changes and the
# fixture itself run it.
run_unification=false
if [ "$net_all" = true ] || [ "$uni_touched" = true ]; then
  run_unification=true
fi
run_lint=$rust
run_msrv=$rust
run_doc=$rust
run_portable=false
run_deny=$deps
run_licenses=$deps
run_installers=$installers
run_release_lane=false
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
  run_unification=true
  run_lint=true
  run_msrv=true
  run_doc=true
  run_portable=true
  run_deny=true
  run_licenses=true
  run_installers=true
  run_release_lane=true
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
  echo "run_unification=$run_unification"
  echo "run_portable=$run_portable"
  echo "run_deny=$run_deny"
  echo "run_licenses=$run_licenses"
  echo "run_installers=$run_installers"
  echo "run_release_lane=$run_release_lane"
  echo "test_os=$test_os"
  echo "msrv_os=$msrv_os"
  echo "test_scope=$test_scope"
  echo "test_filter=$test_filter"
}

{
  echo "event=$event full=$full"
  echo "app tests: run=$run_test scope='$test_scope' filter='${test_filter:-<all>}'"
  echo "sdk tests: run=$run_net args='${net_test_args:-<all>}'"
  echo "lint=$run_lint msrv=$run_msrv doc=$run_doc portable=$run_portable deny=$run_deny licenses=$run_licenses installers=$run_installers unification=$run_unification lane=$run_release_lane"
  if [ -n "$files" ]; then
    echo "changed files:"
    echo "$files" | sed 's/^/  /'
  fi
} >&2
