#!/usr/bin/env bash
# Build a release binary and copy it to a date-stamped sibling for
# archival / "what version is this binary?" purposes. Works on Windows
# (Git Bash) and Unix — handles the `.exe` suffix conditionally.
#
# Usage:
#     ./release.sh
#
# Output:
#     target/release/resocks5.exe                    (cargo's own output)
#     target/release/resocks5-YYYY-MM-DD_HH-MM.exe   (dated copy)
set -euo pipefail

cargo build --release

DATE=$(date +%Y-%m-%d_%H-%M)

# Cargo names the binary with or without `.exe` based on host OS.
if [ -f "target/release/resocks5.exe" ]; then
    SRC="target/release/resocks5.exe"
    DST="target/release/resocks5-${DATE}.exe"
else
    SRC="target/release/resocks5"
    DST="target/release/resocks5-${DATE}"
fi
# Format chosen so the timestamp is filename-safe everywhere:
#   - ':' breaks Windows paths, so we use '-' inside the time
#   - '_' between date and time keeps date and time visually separate
#     while still letting `ls -1 | sort` order builds chronologically

cp -f "$SRC" "$DST"
echo "→ $DST"
ls -lh "$DST"
