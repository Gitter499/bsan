#!/usr/bin/env bash
# run-crates.sh <crate>...  — link (auto-stubbing) and run each crate's tests under BSan,
# one log per crate in logs/, one summary line per crate. Inside the bsan container.
set -uo pipefail
cd /workspaces/bun
L=/workspaces/bsan-bun/logs; mkdir -p $L
for c in "$@"; do
  if ! /workspaces/bsan-bun/scripts/link-loop.sh -p "$c" > $L/$c.link.log 2>&1; then
    echo "$c: LINK/BUILD FAILED (see logs/$c.link.log)"; continue
  fi
  timeout ${CRATE_TIMEOUT:-3600} /workspaces/bsan-bun/scripts/bsan-test.sh -p "$c" --no-fail-fast > $L/$c.log 2>&1; rc=$?
  res=$(grep -h "^test result" $L/$c.log | tr '\n' ' ')
  ub=$(grep -cE "Undefined Behavior|ERROR: |SEGV|bsan-bun: test reached|signal: " $L/$c.log)
  echo "$c: rc=$rc reports=$ub $res"
done
