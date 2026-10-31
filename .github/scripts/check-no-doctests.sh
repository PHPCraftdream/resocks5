#!/bin/sh
# Doctests are forbidden: examples in rustdoc are `text` blocks and real
# behaviour is covered by ordinary tests. Fails when
#   - a library crate does not set `doctest = false` in its [lib] section, or
#   - a rustdoc code block (/// or //!) opens with anything but ```text.
set -eu

status=0

for manifest in crates/*/Cargo.toml; do
  dir=$(dirname "$manifest")
  [ -f "$dir/src/lib.rs" ] || continue
  if ! awk '/^\[lib\]/{lib=1; next} /^\[/{lib=0} lib && /^doctest[[:space:]]*=[[:space:]]*false/{ok=1} END{exit !ok}' "$manifest"; then
    echo "no-doctests: $manifest: [lib] must set doctest = false" >&2
    status=1
  fi
done

# Only opening fences matter; a closing fence is a bare ``` and toggles.
bad=$(git ls-files 'crates/*.rs' | while IFS= read -r f; do
  awk -v f="$f" '
    /^[[:space:]]*\/\/[\/!][[:space:]]?```/ {
      line = $0
      sub(/^[[:space:]]*\/\/[\/!][[:space:]]?```/, "", line)
      if (!open) {
        if (line != "text") print f ":" NR ": rustdoc code block must be ```text"
        open = 1
      } else {
        open = 0
      }
    }' "$f"
done)
if [ -n "$bad" ]; then
  echo "$bad" >&2
  status=1
fi

if [ "$status" -eq 0 ]; then
  echo "no-doctests: ok"
fi
exit "$status"
