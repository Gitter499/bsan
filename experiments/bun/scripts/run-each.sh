#!/usr/bin/env bash
# run-each.sh <test binary> [log dir] — run every test of a built test binary in its own
# process (a BSan report aborts the process), one log per test, one summary line per test.
set -uo pipefail
bin=$1; L=${2:-/workspaces/bsan-bun/logs/each}; mkdir -p "$L"
name=$(basename "$bin" | sed 's/-[0-9a-f]*$//')
for t in $("$bin" --list --format terse 2>/dev/null | sed -n 's/: test$//p'); do
  log="$L/$name.$t.log"
  BSAN_SYMBOLIZER=${BSAN_SYMBOLIZER:-/opt/llvm23/bin/llvm-symbolizer} BSAN_OPTIONS=${BSAN_OPTIONS:-$( [ "${BSAN_WILDCARD:-0}" = 0 ] && echo "wildcard=0:" )stacktrace_max_len=40} timeout ${TEST_TIMEOUT:-1800} "$bin" --exact "$t" --test-threads=1 >"$log" 2>&1; rc=$?
  ub=$(grep -m1 -oE "error: Undefined Behavior.*|ERROR: .*|bsan-bun: test reached.*" "$log" | cut -c1-160)
  printf '%-60s rc=%-3s %s\n' "$t" "$rc" "$ub"
done
