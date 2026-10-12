#!/bin/sh
# Fail if a directory holds more than MAX_ENTRIES direct entries (files plus
# sub-directories). Enforced by CI (.github/workflows/ci.yml, dir-entries job);
# together with check-line-limit.sh (at most 1000 lines per Rust file) it is
# the project's code-structure rule: small folders, small files.
#
# Counts what git tracks, so the result is the same locally and in CI. A new
# folder is checked as soon as its files are added.
#
# BASELINE lists directories that were already over the limit when this check
# was introduced, as "<entries> <path>" (the repository root is "."). It is a
# ratchet: a directory outside the baseline going over the limit, or a
# baseline directory growing past its recorded size, fails the check, so the
# baseline can only shrink. Split a directory, then lower or delete its entry.

set -u

MAX_ENTRIES=7

BASELINE="
19 .
13 docs
10 crates/resocks5-net/src/connect
10 crates/resocks5-net/src
"

status=0

# "<entries> <dir>" for every directory, from the tracked file list: each path
# registers itself once as a child of every ancestor directory.
counts=$(git ls-files | awk -F/ '
    {
        dir = "."
        for (i = 1; i <= NF; i++) {
            key = dir SUBSEP $i
            if (!(key in seen)) { seen[key] = 1; count[dir]++ }
            dir = (dir == "." ? $i : dir "/" $i)
        }
    }
    END { for (dir in count) print count[dir], dir }
')

while read -r entries dir; do
    [ -n "$dir" ] || continue
    [ "$entries" -gt "$MAX_ENTRIES" ] || continue
    allowed=$(printf '%s\n' "$BASELINE" | awk -v d="$dir" '$2 == d { print $1 }')
    if [ -z "$allowed" ]; then
        printf 'dir-entries: ERROR: %s: %d entries exceeds the %d-entry limit\n' "$dir" "$entries" "$MAX_ENTRIES"
        status=1
    elif [ "$entries" -gt "$allowed" ]; then
        printf 'dir-entries: ERROR: %s: %d entries, baseline allows %d (split it; the baseline only shrinks)\n' "$dir" "$entries" "$allowed"
        status=1
    else
        printf 'dir-entries: %s: %d entries (over %d; baseline %d, split pending)\n' "$dir" "$entries" "$MAX_ENTRIES" "$allowed"
    fi
done <<EOF
$counts
EOF

# Baseline hygiene: entries that no longer need the exemption or can be tightened.
while read -r allowed dir; do
    [ -n "$dir" ] || continue
    current=$(printf '%s\n' "$counts" | awk -v d="$dir" '$2 == d { print $1 }')
    current=${current:-0}
    if [ "$current" -le "$MAX_ENTRIES" ]; then
        printf 'dir-entries: NOTE: baseline entry %s is now %d entries; remove it from the baseline\n' "$dir" "$current"
    elif [ "$current" -lt "$allowed" ]; then
        printf 'dir-entries: NOTE: baseline entry %s shrank to %d entries; lower it from %d\n' "$dir" "$current" "$allowed"
    fi
done <<EOF
$BASELINE
EOF

exit $status
