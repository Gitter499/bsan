#!/usr/bin/env bash
# Reproduces the findings on Bun's own code, inside the container (hpc/run.sh) after `hpc/setup.sh build`.
# For each case: run the test as Bun ships it (expect a BSan report), then with the fix (expect a pass).
set -u
H=/workspaces/bsan-bun
P=$H/bun-patches
cd /workspaces/bun
[ -f src/zlib/tests/bsan_repro.rs ] || git apply "$P/0004-bsan-repro-tests.patch"
export RUST_MIN_STACK=67108864
mkdir -p "$H/logs/repro"
CLIBS="-Clink-arg=@$H/native/out/clibs.rsp"
status=0

# case <name> <want: report|pass> <fix patch or -> <bsan-test.sh args...>
case_() {
  local name=$1 want=$2 fix=$3; shift 3
  local log="$H/logs/repro/$name.log"
  [ "$fix" != - ] && git apply "$fix"
  EXTRA_RUSTFLAGS="$CLIBS" "$H/scripts/bsan-test.sh" "$@" >"$log" 2>&1
  [ "$fix" != - ] && git apply -R "$fix"
  local got=pass
  grep -q "^error: Undefined Behavior" "$log" && got=report
  grep -q "test result: ok" "$log" || [ $got = report ] || got=failed
  local mark=ok; [ $got = $want ] || { mark=UNEXPECTED; status=1; }
  printf '%-28s want=%-6s got=%-6s %s  (logs/repro/%s.log)\n' "$name" "$want" "$got" "$mark" "$name"
}

ZLIB=(-p bun_zlib --test bsan_repro)
ALLOC=(-p bun_alloc --test bsan_repro)
STORE=(-p bun_parsers --lib -- json::tests::env_json --exact)
FLOAT=(-p bun_parsers --lib -- json::tests::lenient_numbers --exact)

case_ 1-zlib            report -                                       "${ZLIB[@]}"
case_ 1-zlib-fixed      pass   "$P/fix-zlib-deflate-backpointer.patch" "${ZLIB[@]}"
case_ 2-ast-store       report -                                       "${STORE[@]}"
case_ 2-ast-store-fixed pass   "$P/fix-ast-store-current.patch"        "${STORE[@]}"
case_ 3-ast-alloc       report -                                       "${ALLOC[@]}"
case_ 3-ast-alloc-fixed pass   "$P/fix-ast-alloc.patch"                "${ALLOC[@]}"
# BSan false positive in safe float parsing; needs bug 2's fix to get past it.
case_ fp-float-parse    report "$P/fix-ast-store-current.patch"        "${FLOAT[@]}"
exit $status
