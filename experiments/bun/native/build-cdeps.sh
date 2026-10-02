#!/usr/bin/env bash
# Build the native code Bun's Rust crates call into, as one static archive that test binaries
# link against. Run inside the bsan container. Mirrors Bun's scripts/bench-json-rust.sh, but
# compiles with the same flags cargo-bsan's CC wrapper uses so the C/C++ side is instrumented.
#   INSTRUMENT=0 ./build-cdeps.sh   -> plain -O0 -g build (for differential runs)
set -euo pipefail
cd "$(dirname "$0")"
BUN=${BUN:-/workspaces/bun}
OUT=${OUT:-$PWD/out}
TC=/root/.rustup/toolchains/bsan
CC=$TC/bin/clang CXX=$TC/bin/clang++
FLAGS=(-g -O0 -fno-omit-frame-pointer -mno-omit-leaf-frame-pointer -fPIC)
[ "${INSTRUMENT:-1}" = 1 ] && FLAGS+=(-fpass-plugin=$TC/lib/libbsan_plugin.so)
mkdir -p "$OUT/obj"
cc()  { echo "  CC  $2"; $CC  "${FLAGS[@]}" "${@:3}" -c "$2" -o "$OUT/obj/$1.o"; }
cxx() { echo "  CXX $2"; $CXX "${FLAGS[@]}" "${@:3}" -c "$2" -o "$OUT/obj/$1.o"; }
pids=(); job() { "$@" & pids+=($!); if [ ${#pids[@]} -ge ${JOBS:-2} ]; then wait "${pids[0]}"; pids=("${pids[@]:1}"); fi; }

cc asan_stubs shim/asan_stubs.c
[ -f shim/ffi_stubs.c ] && cc ffi_stubs shim/ffi_stubs.c
cc mimalloc_shim shim/mimalloc_shim.c

# highway runtime + Bun's highway kernels (src/jsc/bindings/highway_*.cpp)
HWY=(-std=c++23 -I$OUT/hwy-src -Isrc/highway -Ishim -I$BUN/build/debug/codegen)
for f in abort targets per_target print timer nanobenchmark aligned_allocator; do job cxx hwy_$f src/highway/hwy/$f.cc "${HWY[@]}"; done
# Compile copies: a quoted #include "root.h" resolves next to the source first, which would pick
# up JSC's real root.h instead of the shim.
mkdir -p "$OUT/hwy-src"
cp $BUN/src/jsc/bindings/{highway_dispatch.h,BufferStringSearch.h} "$OUT/hwy-src/"
for k in strings json xml sourcemap; do
  cp $BUN/src/jsc/bindings/highway_$k.cpp "$OUT/hwy-src/"
  job cxx highway_$k "$OUT/hwy-src/highway_$k.cpp" "${HWY[@]}"
done

# simdutf amalgamation + Bun's C shim (src/simdutf_sys/bun-simdutf.cpp)
job cxx simdutf src/simdutf.cpp -std=c++20 -Isrc
job cxx bun_simdutf $BUN/src/simdutf_sys/bun-simdutf.cpp -std=c++20 -Isrc -Ishim

wait
# Weaken everything: some crates define their own versions of these symbols under cfg(test)
# (e.g. bun_paths' highway_* fallbacks written for Miri), and those must win.
for o in "$OUT"/obj/*.o; do $TC/bin/llvm-objcopy --weaken "$o"; done
# Atomic replace: concurrent cargo links may be reading the archive.
rm -f "$OUT/libbsan_bun_cdeps.a.tmp"
$TC/bin/llvm-ar rcs "$OUT/libbsan_bun_cdeps.a.tmp" "$OUT"/obj/*.o
mv -f "$OUT/libbsan_bun_cdeps.a.tmp" "$OUT/libbsan_bun_cdeps.a"
echo "built $OUT/libbsan_bun_cdeps.a"
