#!/usr/bin/env bash
# run-drivers.sh [crate...] — build each crate's tests/bsan_drivers.rs (auto-stubbing, linked
# against the instrumented C libraries) and run every test in its own process. Inside the
# container, cwd-independent. Logs: logs/each-<crate>/, summary: logs/drivers-summary.txt.
set -uo pipefail
cd /workspaces/bun
H=/workspaces/bsan-bun; L=$H/logs; mkdir -p $L
export EXTRA_RUSTFLAGS="-Clink-arg=@$H/native/out/clibs.rsp ${EXTRA_RUSTFLAGS:-}"
crates=${*:-bun_zlib bun_zstd bun_brotli bun_libdeflate_sys bun_picohttp bun_libarchive}
for c in $crates; do
  if ! $H/scripts/link-loop.sh -p "$c" --test bsan_drivers > $L/$c.drivers.link.log 2>&1; then
    echo "$c: LINK/BUILD FAILED (logs/$c.drivers.link.log)" | tee -a $L/drivers-summary.txt; continue
  fi
  bin=$($H/scripts/bsan-test.sh -p "$c" --test bsan_drivers --no-run 2>&1 | grep -oE '\([^)]*bsan_drivers-[0-9a-f]+\)' | tr -d '()' | tail -1)
  echo "== $c" | tee -a $L/drivers-summary.txt
  $H/scripts/run-each.sh "/workspaces/bun/$bin" $L/each-$c | tee -a $L/drivers-summary.txt
done
