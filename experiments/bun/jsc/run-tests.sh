#!/usr/bin/env bash
# run-tests.sh <listfile> <outdir> [timeout_s]   (inside bsan-jsc container)
# Runs each test file with the BSan bun-debug, one process per file; saves output and extracts BSan reports.
source /workspaces/bsan-bun/jsc/env.sh
list=$1 out=$2 to=${3:-300}
mkdir -p "$out"
cd /workspaces/bun/test
while read -r t; do
  [ -z "$t" ] && continue
  case "$t" in \#*) continue;; esac
  name=$(echo "$t" | tr '/' '_')
  start=$(date +%s)
  BSAN_OPTIONS="stacktrace_max_len=40:wildcard=0:log_path=$out/$name.bsan" timeout -k 10 "$to" ../build/debug/bun-debug test "./$t" > "$out/$name.log" 2>&1
  rc=$?
  dur=$(( $(date +%s) - start ))
  if cat "$out/$name.log" "$out/$name".bsan.* 2>/dev/null | grep -q "Undefined Behavior"; then
    loc=$(cat "$out/$name".bsan.* "$out/$name.log" 2>/dev/null | grep -m1 -A1 "Undefined Behavior" | tail -1 | sed 's/^ *--> *//')
    echo "UB   $t rc=$rc ${dur}s $loc" | tee -a "$out/summary.txt"
  else
    pass=$(grep -Eo "^ *[0-9]+ pass" "$out/$name.log" | tail -1); fail=$(grep -Eo "^ *[0-9]+ fail" "$out/$name.log" | tail -1)
    echo "OK   $t rc=$rc ${dur}s pass=${pass// /} fail=${fail// /}" | tee -a "$out/summary.txt"
  fi
done < "$list"
