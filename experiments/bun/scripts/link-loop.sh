#!/usr/bin/env bash
# link-loop.sh <cargo bsan test args...> — build test binaries (--no-run), stubbing undefined
# symbols and rebuilding the native archive until everything links. Inside the bsan container.
set -uo pipefail
LOG=$(mktemp)
for i in 1 2 3 4 5 6; do
  /workspaces/bsan-bun/scripts/bsan-test.sh --no-run "$@" >"$LOG" 2>&1 && { echo "linked"; exit 0; }
  if ! grep -q "undefined symbol:" "$LOG"; then grep -E "^error|error\[" -A12 "$LOG" | head -60; exit 1; fi
  /workspaces/bsan-bun/native/gen-stubs.sh "$LOG"
  /workspaces/bsan-bun/native/build-cdeps.sh >/dev/null 2>&1 || { echo "cdeps build failed"; exit 1; }
done
echo "still failing after retries"; tail -30 "$LOG"; exit 1
