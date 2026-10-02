#!/usr/bin/env bash
# bsan-test.sh <cargo bsan test args...>   (run inside the bsan container, cwd = Bun checkout)
# `cargo bsan test` for Bun crates, linked against the instrumented native-deps archive.
set -euo pipefail
NATIVE=/workspaces/bsan-bun/native/out/libbsan_bun_cdeps.a
[ -f "$NATIVE" ] || { echo "missing $NATIVE: run native/build-cdeps.sh" >&2; exit 1; }
# RUSTFLAGS replaces the [target] rustflags from Bun's .cargo/config.toml, so repeat them.
FLAGS=(-Clink-arg=-fuse-ld=lld -Clink-arg=-Qunused-arguments -Alinker_messages)
# Bun's sanitizer configuration: system allocator instead of mimalloc, so BSan sees every
# allocation (ASan/LSan hooks it enables are stubbed in the archive).
FLAGS+=(--cfg=bun_asan)
FLAGS+=(-Clink-arg=-Wl,--whole-archive -Clink-arg=$NATIVE -Clink-arg=-Wl,--no-whole-archive -Clink-arg=-lstdc++)
export RUSTFLAGS="${FLAGS[*]} ${EXTRA_RUSTFLAGS:-}"
export CARGO_BUILD_JOBS=${CARGO_BUILD_JOBS:-2}
# Fast mode (default): BSAN_OPTIONS=wildcard=0. BSan exposes provenance on every ptrtoint
# (including `ptr.addr()` in core's debug UB checks), and each expose walks every location of
# the allocation, which makes e.g. `iter_mut()` over a few-KB array quadratic and GB-sized.
# With wildcard=0, int->ptr-derived accesses go unchecked (possible misses, never extra
# reports). Confirm findings with BSAN_WILDCARD=1 (BSan's default semantics).
if [ "${BSAN_WILDCARD:-0}" = 0 ]; then export BSAN_OPTIONS="wildcard=0${BSAN_OPTIONS:+:$BSAN_OPTIONS}"; fi
exec cargo +bsan bsan test "$@"
