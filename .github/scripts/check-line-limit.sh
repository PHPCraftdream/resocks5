#!/bin/sh
# Fail if a Rust file exceeds MAX_LINES physical lines. Enforced by CI
# (.github/workflows/ci.yml, line-limit job); together with
# check-dir-entries.sh (at most 7 entries per directory) it is the project's
# code-structure rule: small files, small folders.
#
# BASELINE lists files that were already over the limit when this check was
# introduced, as "<lines> <path>". It is a ratchet: a file outside the baseline
# going over the limit, or a baseline file growing past its recorded size,
# fails the check, so the baseline can only shrink. Split a file, then lower or
# delete its entry.

set -u

MAX_LINES=1000

BASELINE="
2191 crates/resocks5/src/auth/state/tests.rs
1188 crates/resocks5-net/src/server_tests.rs
1143 crates/resocks5-net/src/connect/tunnel.rs
1060 crates/resocks5-net/src/connect/tls/tls_fragment/tests.rs
1035 crates/resocks5-net/src/error.rs
"

status=0

# Tracked plus untracked-but-not-ignored files, so brand-new oversized
# files are caught before they are ever committed.
files=$(git ls-files --cached --others --exclude-standard -- '*.rs')

while IFS= read -r file; do
    [ -n "$file" ] || continue
    lines=$(wc -l < "$file" | tr -d ' ')
    [ "$lines" -gt "$MAX_LINES" ] || continue
    allowed=$(printf '%s\n' "$BASELINE" | awk -v f="$file" '$2 == f { print $1 }')
    if [ -z "$allowed" ]; then
        printf 'line-limit: ERROR: %s: %d lines exceeds the %d-line limit\n' "$file" "$lines" "$MAX_LINES"
        status=1
    elif [ "$lines" -gt "$allowed" ]; then
        printf 'line-limit: ERROR: %s: %d lines, baseline allows %d (split it; the baseline only shrinks)\n' "$file" "$lines" "$allowed"
        status=1
    else
        printf 'line-limit: %s: %d lines (over %d; baseline %d, split pending)\n' "$file" "$lines" "$MAX_LINES" "$allowed"
    fi
done <<EOF
$files
EOF

# Baseline hygiene: entries that no longer need the exemption or can be tightened.
while read -r allowed entry; do
    [ -n "$entry" ] || continue
    if [ ! -f "$entry" ]; then
        printf 'line-limit: NOTE: baseline entry %s no longer exists; remove it\n' "$entry"
        continue
    fi
    lines=$(wc -l < "$entry" | tr -d ' ')
    if [ "$lines" -le "$MAX_LINES" ]; then
        printf 'line-limit: NOTE: baseline entry %s is now %d lines; remove it from the baseline\n' "$entry" "$lines"
    elif [ "$lines" -lt "$allowed" ]; then
        printf 'line-limit: NOTE: baseline entry %s shrank to %d lines; lower it from %d\n' "$entry" "$lines" "$allowed"
    fi
done <<EOF
$BASELINE
EOF

exit $status
