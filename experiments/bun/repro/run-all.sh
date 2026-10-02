#!/usr/bin/env bash
# Runs every repro under BSan: the code as in Bun (expects a report) and, where a fix
# exists, with fix.diff applied (expects a clean run). Logs: <repro>/*.bsan.log.
# Inside the container: /workspaces/bsan-bun/repro/run-all.sh
# zlib-backpointer links the instrumented zlib-ng from native/build-clibs.sh
# (override the directory with BSAN_CLIBS).
set -u
cd "$(dirname "$0")"
export BSAN_OPTIONS="${BSAN_OPTIONS:-stacktrace_max_len=10}"
status=0

expect() { # expect <report|clean> <dir> <log> <cargo run args...>
  local want=$1 dir=$2 log=$3; shift 3
  (cd "$dir" && cargo +bsan bsan build -q "$@" >/dev/null 2>&1; cargo +bsan bsan run -q "$@" >"$log" 2>&1)
  local rc=$? got=clean
  grep -q "error: Undefined Behavior" "$dir/$log" && got=report
  [ $rc -ne 0 ] && [ $got = clean ] && got="failed(rc=$rc)"
  local mark=ok; [ "$got" = "$want" ] || { mark=UNEXPECTED; status=1; }
  printf '%-20s %-48s want=%-6s got=%-6s %s\n' "$dir" "$log ($*)" "$want" "$got" "$mark"
}

with_fix() { # with_fix <dir> <cmd...>: run with fix.diff applied, then revert
  local dir=$1; shift
  (cd "$dir" && patch -p1 -s --no-backup-if-mismatch <fix.diff) || return 1
  "$@"
  (cd "$dir" && patch -p1 -R -s --no-backup-if-mismatch <fix.diff)
}

expect report zlib-backpointer   bsan.log
with_fix zlib-backpointer   expect clean zlib-backpointer   fixed.bsan.log
expect report ast-store-current  bsan.log
with_fix ast-store-current  expect clean ast-store-current  fixed.bsan.log
expect report ast-alloc-reborrow bsan.log
with_fix ast-alloc-reborrow expect clean ast-alloc-reborrow fixed.bsan.log
expect report vm-eventloop ensure_waker.bsan.log --bin ensure_waker
expect clean  vm-eventloop ensure_waker.fixed.bsan.log --bin ensure_waker --features ensure-waker-fix
expect report vm-eventloop run_start.bsan.log --bin run_start --features ensure-waker-fix
expect report dec2flt-protector  bsan.log   # BSan false positive (no unsafe code)
exit $status
