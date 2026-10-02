#!/usr/bin/env bash
# Fetch the native libraries Bun's *_sys crates bind, at the commits Bun pins in
# scripts/build/deps/*.ts (with Bun's patches), into native/src/. Run inside the container.
# Uses git (GitHub archive tarballs may be blocked by egress proxies); simdutf comes from its
# release assets, matching the version Bun's WebKit ships closely enough for the C shim.
set -euo pipefail
cd "$(dirname "$0")"
BUN=${BUN:-/workspaces/bun}; P=$BUN/patches; F=../scripts/fetch-dep.sh
pin() { grep -oE "_COMMIT = \"[0-9a-f]+\"" "$BUN/scripts/build/deps/$1.ts" | head -1 | cut -d'"' -f2; }
mkdir -p src && cd src
$F highway        google/highway           "$(pin highway)"
$F zlib           zlib-ng/zlib-ng          "$(pin zlib)"           $P/zlib/clang-cl-arm64.patch
$F zstd           facebook/zstd            "$(pin zstd)"           $P/zstd/bmi2-probe-once.patch
$F brotli         google/brotli            "$(pin brotli)"
$F libdeflate     ebiggers/libdeflate      "$(pin libdeflate)"
$F picohttpparser h2o/picohttpparser       "$(pin picohttpparser)" $P/picohttpparser/chunked-decoder.patch
$F libarchive     libarchive/libarchive    "$(pin libarchive)"     $P/libarchive/archive_write_add_filter_gzip.c.patch \
  $P/libarchive/select-registered-only.patch $P/libarchive/nonblocking-read.patch $P/libarchive/archive_string-codepage-cache.patch
SIMDUTF=${SIMDUTF:-v9.2.1}
for f in simdutf.cpp simdutf.h; do curl -fsSL -o $f "https://github.com/simdutf/simdutf/releases/download/$SIMDUTF/$f"; done
echo "$SIMDUTF" > SIMDUTF_VERSION
