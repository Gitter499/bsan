#!/usr/bin/env bash
# Build the vendored C libraries Bun's *_sys crates bind (at Bun's pinned commits, fetched into
# src/ by fetch-sources.sh) with BSan instrumentation, as static libs under out/clibs/.
set -euo pipefail
cd "$(dirname "$0")"
N=$PWD; OUT=$N/out/clibs; mkdir -p $OUT $N/out/build
TC=${BSAN_TC:-${RUSTUP_HOME:-$HOME/.rustup}/toolchains/bsan}
# ONLY="zlib libarchive" builds a subset.
want() { [ -z "${ONLY:-}" ] || [[ " $ONLY " == *" $1 "* ]]; }
cm() { # cm <name> <srcdir> [cmake args...]
  want $1 || return 0
  local b=$N/out/build/$1; rm -rf $b
  cmake -S "$2" -B $b -G Ninja -DCMAKE_BUILD_TYPE=Debug -DBUILD_SHARED_LIBS=OFF \
    -DCMAKE_C_COMPILER=$N/bsan-cc -DCMAKE_CXX_COMPILER=$N/bsan-c++ \
    -DCMAKE_POSITION_INDEPENDENT_CODE=ON "${@:3}" >$b.cmake.log 2>&1 || { tail -30 $b.cmake.log; exit 1; }
  ninja -C $b -j${JOBS:-2} >$b.ninja.log 2>&1 || { tail -30 $b.ninja.log; exit 1; }
  find $b -name '*.a' -exec cp {} $OUT/ \;
  echo "built $1: $(cd $b && find . -name '*.a' | tr '\n' ' ')"
}
cm zlib src/zlib -DZLIB_COMPAT=ON -DZLIB_ENABLE_TESTS=OFF -DWITH_GTEST=OFF -DZLIBNG_ENABLE_TESTS=OFF -DWITH_FUZZERS=OFF -DWITH_BENCHMARKS=OFF
cm zstd src/zstd/build/cmake -DZSTD_BUILD_PROGRAMS=OFF -DZSTD_BUILD_TESTS=OFF -DZSTD_BUILD_SHARED=OFF -DZSTD_BUILD_STATIC=ON -DZSTD_MULTITHREAD_SUPPORT=OFF
cm brotli src/brotli -DBROTLI_DISABLE_TESTS=ON -DBROTLI_BUILD_TOOLS=OFF
cm libdeflate src/libdeflate -DLIBDEFLATE_BUILD_SHARED_LIB=OFF -DLIBDEFLATE_BUILD_GZIP=OFF
want picohttpparser && $N/bsan-cc -fPIC -c src/picohttpparser/picohttpparser.c -o $N/out/build/picohttpparser.o
want picohttpparser && $TC/bin/llvm-ar rcs $OUT/libpicohttpparser.a $N/out/build/picohttpparser.o
ls -la $OUT
# libarchive (bun install / Bun.Archive tarballs): zlib only, like Bun's build.
if [ -d src/libarchive ]; then
  ZB=$N/out/build/zlib
  cm libarchive src/libarchive -DENABLE_TEST=OFF -DENABLE_TAR=OFF -DENABLE_CPIO=OFF -DENABLE_CAT=OFF -DENABLE_UNZIP=OFF \
    -DENABLE_OPENSSL=OFF -DENABLE_MBEDTLS=OFF -DENABLE_NETTLE=OFF -DENABLE_LZMA=OFF -DENABLE_ZSTD=OFF -DENABLE_LZ4=OFF \
    -DENABLE_BZip2=OFF -DENABLE_LIBB2=OFF -DENABLE_LIBXML2=OFF -DENABLE_EXPAT=OFF -DENABLE_PCREPOSIX=OFF -DENABLE_PCRE2POSIX=OFF \
    -DENABLE_ICONV=OFF -DENABLE_ACL=OFF -DENABLE_XATTR=OFF -DENABLE_CNG=OFF -DENABLE_WERROR=OFF \
    -DZLIB_INCLUDE_DIR=$ZB -DZLIB_LIBRARY=$OUT/libz.a
fi
# Linker response file for test binaries that reach these libraries; pass it with
#   EXTRA_RUSTFLAGS="-Clink-arg=@/workspaces/bsan-bun/native/out/clibs.rsp"
# Order matters for static archives: libarchive needs zlib.
for a in libarchive libz libzstd libbrotlienc libbrotlidec libbrotlicommon libdeflate libpicohttpparser; do
  [ -f $OUT/$a.a ] && echo $OUT/$a.a
done > $N/out/clibs.rsp
echo "wrote $N/out/clibs.rsp"
