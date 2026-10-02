#!/usr/bin/env bash
# Run inside the container (Docker: bsan-dev/image-dev as root; Singularity: hpc/ image as
# yourself). Installs bsan from /workspaces/bsan plus the extra tools Bun's configure step needs.
set -euo pipefail
if [ "$(id -u)" = 0 ] && command -v apt-get >/dev/null; then
  # The devcontainer image lacks a few tools; the hpc/ image already has them.
  [ -n "${HTTPS_PROXY:-}" ] && echo "Acquire::https::Proxy \"$HTTPS_PROXY\";" > /etc/apt/apt.conf.d/99proxy
  apt-get update -qq && apt-get install -y -qq unzip nasm golang-go perl xz-utils >/dev/null
fi
# Bun's build looks for llvm-ranlib / ld.lld by name; the bsan toolchain ships
# multi-call llvm-ar / lld, so expose the whole toolchain bin dir plus aliases.
T=${RUSTUP_HOME:-$HOME/.rustup}/toolchains/bsan/bin
S=$HOME/.local/llvm23/bin   # must be on PATH (start-container.sh / hpc/run.sh put it there)
rm -rf "$S" && mkdir -p "$S"
# LLVM tools only: the Rust binaries must keep resolving to rustup's proxies.
for t in "$T"/clang* "$T"/llvm-* "$T"/lld "$T"/opt "$T"/llc; do ln -sf "$t" "$S"/; done
ln -sf "$T/llvm-ar" "$S/llvm-ranlib"
ln -sf "$T/lld" "$S/ld.lld"
ln -sf "$T/llvm-objcopy" "$S/llvm-strip"
rustup default bsan
cd /workspaces/bsan && ./xb --skip install
cargo bsan --version
