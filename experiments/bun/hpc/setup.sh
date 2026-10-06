#!/usr/bin/env bash
# hpc/setup.sh fetch   — everything that needs the network (run on a login node). Idempotent.
# hpc/setup.sh build   — compile BSan, its sysroot and the native libraries; no network needed
#                        (run on a compute node: `srun ... hpc/setup.sh build`).
# hpc/setup.sh check   — smoke test: Bun's bun_ptr tests under BSan.
# Uses hpc/run.sh, so STATE (and optionally SIF, BSAN_DIR, BUN_DIR, RUNTIME) must be set.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
R="$here/run.sh"
BUN_COMMIT=${BUN_COMMIT:-bc7a813b10b6ef8accc00c931b9a501331ac8c5c}
TC='$HOME/.rustup/toolchains/bsan'

shims='T='"$TC"'/bin; S=$HOME/.local/llvm23/bin; rm -rf $S; mkdir -p $S
  for t in $T/clang* $T/llvm-* $T/lld $T/opt $T/llc; do ln -sf $t $S/; done
  ln -sf $T/llvm-ar $S/llvm-ranlib; ln -sf $T/lld $S/ld.lld; ln -sf $T/llvm-objcopy $S/llvm-strip'

fetch() {
  echo "== rustup + nightly (bootstraps BSan's xb)"
  "$R" 'command -v rustup >/dev/null || curl -fsSL https://sh.rustup.rs | sh -s -- -y --no-modify-path --profile minimal --default-toolchain nightly'
  echo "== BSan toolchain, its clang and LLVM sources (xb setup)"
  "$R" 'cd /workspaces/bsan && ./xb --skip setup && rustup default bsan'
  echo "== crates for BSan and for its instrumented sysroot"
  "$R" 'cd /workspaces/bsan && cargo +bsan fetch -q && cargo +bsan fetch -q --manifest-path '"$TC"'/lib/rustlib/src/rust/library/Cargo.toml'
  "$R" "$shims"
  echo "== bun binary (for Bun's configure step)"
  "$R" 'command -v bun >/dev/null || curl -fsSL https://bun.sh/install | bash >/dev/null'
  echo "== Bun checkout at $BUN_COMMIT + harness patches"
  "$R" 'cd /workspaces/bun && if [ ! -d .git ]; then git init -q . && git remote add origin https://github.com/oven-sh/bun.git && git fetch -q --depth=1 origin '"$BUN_COMMIT"' && git checkout -q FETCH_HEAD; fi
        for p in '"${BUN_PATCHES:-0001-toolchain-compat 0002-bsan-drivers 0003-test-shim-asan-headroom}"'; do
          f=/workspaces/bsan-bun/bun-patches/$p.patch
          git apply --check -R $f 2>/dev/null && continue
          git apply $f && echo "applied $p"
        done'
  echo "== Bun configure (codegen) and vendored Rust deps"
  # RUSTUP_TOOLCHAIN=bsan: don't let Bun's rust-toolchain.toml pull its own 3 GB nightly.
  "$R" 'cd /workspaces/bun && RUSTUP_TOOLCHAIN=bsan bun run build --configure-only 2>&1 | tail -3
        pin() { grep -oE "_COMMIT = \"[0-9a-f]+\"" scripts/build/deps/$1.ts | head -1 | cut -d\" -f2; }
        F=/workspaces/bsan-bun/scripts/fetch-dep.sh
        [ -f vendor/lolhtml/Cargo.toml ] || $F vendor/lolhtml oven-sh/lol-html $(pin lolhtml)
        [ -f vendor/rust-argon2/Cargo.toml ] || $F vendor/rust-argon2 sru-systems/rust-argon2 $(pin rust-argon2) $PWD/patches/rust-argon2/legacy-low-memory.patch
        cargo +bsan fetch -q'
  echo "== native library sources at Bun's pins"
  "$R" '[ -f /workspaces/bsan-bun/native/src/SIMDUTF_VERSION ] || /workspaces/bsan-bun/native/fetch-sources.sh'
  echo "fetch done"
}

build() {
  export CARGO_NET_OFFLINE=true
  echo "== BSan (pass, runtimes, cargo-bsan)"
  "$R" 'cd /workspaces/bsan && ./xb --skip install 2>&1 | tail -2'
  "$R" "$shims"
  echo "== instrumented sysroot"
  "$R" 'cargo +bsan bsan setup 2>&1 | tail -2'
  echo "== native libraries (instrumented)"
  "$R" '/workspaces/bsan-bun/native/build-cdeps.sh | tail -1 && /workspaces/bsan-bun/native/build-clibs.sh | tail -1'
  echo "build done"
}

check() {
  export CARGO_NET_OFFLINE=true
  "$R" 'cd /workspaces/bun && /workspaces/bsan-bun/scripts/run-crates.sh bun_ptr'
}

case "${1:-}" in
  fetch) fetch ;; build) build ;; check) check ;;
  *) echo "usage: $0 fetch|build|check" >&2; exit 2 ;;
esac
