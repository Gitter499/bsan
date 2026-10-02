#!/usr/bin/env bash
# Run inside the bsan-dev (devcontainer image-dev) container.
# Installs bsan from /workspaces/bsan plus the extra tools Bun's configure step needs.
set -euo pipefail
# The session proxy port can change across reboots; point apt at the current one.
[ -n "${HTTPS_PROXY:-}" ] && echo "Acquire::https::Proxy \"$HTTPS_PROXY\";" > /etc/apt/apt.conf.d/99proxy
apt-get update -qq && apt-get install -y -qq unzip nasm golang-go perl xz-utils >/dev/null
# Bun's build looks for llvm-ranlib / ld.lld by name; the bsan toolchain ships
# multi-call llvm-ar / lld, so expose the whole toolchain bin dir plus aliases.
T=/root/.rustup/toolchains/bsan/bin
rm -rf /opt/llvm23 && mkdir -p /opt/llvm23/bin
# LLVM tools only: the Rust binaries must keep resolving to rustup's proxies.
for t in "$T"/clang* "$T"/llvm-* "$T"/lld "$T"/opt "$T"/llc; do ln -sf "$t" /opt/llvm23/bin/; done
ln -sf "$T/llvm-ar" /opt/llvm23/bin/llvm-ranlib
ln -sf "$T/lld" /opt/llvm23/bin/ld.lld
ln -sf "$T/llvm-objcopy" /opt/llvm23/bin/llvm-strip
rustup default bsan
cd /workspaces/bsan && ./xb --skip install
cargo bsan --version
