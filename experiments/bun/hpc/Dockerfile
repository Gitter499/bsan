# OS packages only. Everything mutable (rustup, the bsan toolchain, cargo registry, bun, caches)
# lives in $STATE/home on the host, so the image works read-only under Singularity/Apptainer as
# an unprivileged user. Build with Docker anywhere, then convert (see RUNBOOK.md), or use bsan.def.
FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
      build-essential cmake clang clang-tidy ninja-build curl ca-certificates git \
      python3 pkg-config libssl-dev libunwind-dev unzip xz-utils nasm golang-go perl gdb \
    && rm -rf /var/lib/apt/lists/* \
    && update-alternatives --install /usr/bin/cc cc /usr/bin/clang 100 \
    && update-alternatives --install /usr/bin/c++ c++ /usr/bin/clang++ 100 \
    && mkdir -p /workspaces/bsan /workspaces/bun /workspaces/bsan-bun
