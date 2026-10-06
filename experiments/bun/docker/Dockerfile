# Bun (oven-sh/bun@bc7a813b10) ready to run its Rust tests under BorrowSanitizer.
#   docker build -t bun-bsan <this directory's parent, experiments/bun>  -f docker/Dockerfile
#   docker run --rm -v $PWD/repro.rs:/workspaces/bun/src/<crate>/tests/repro.rs bun-bsan -p <pkg> --test repro
ARG BASE=ghcr.io/borrowsanitizer/bsan@sha256:088df2384cf88949dfb630d45b62cc1b84f92c465b7408298124a2d132ddaa21
FROM $BASE
ARG BUN_COMMIT=bc7a813b10b6ef8accc00c931b9a501331ac8c5c
ARG MACOS_TEMPLATE=https://github.com/oven-sh/bun/releases/download/bun-v1.4.2/bun-darwin-x64.zip

RUN apt-get update && apt-get install -y --no-install-recommends unzip && rm -rf /var/lib/apt/lists/*

# Bun's configure step looks for the LLVM tools by name; point them at BSan's toolchain.
RUN T=/root/.rustup/toolchains/bsan/bin S=/root/.local/llvm23/bin && mkdir -p $S \
 && for t in $T/clang* $T/llvm-* $T/lld $T/opt $T/llc; do ln -sf $t $S/; done \
 && ln -sf $T/llvm-ar $S/llvm-ranlib && ln -sf $T/lld $S/ld.lld && ln -sf $T/llvm-objcopy $S/llvm-strip
ENV PATH=/root/.bun/bin:/root/.local/llvm23/bin:$PATH
RUN curl -fsSL https://bun.sh/install | bash >/dev/null

# Bun, unmodified, at the pinned commit; then Bun's own configure step (codegen) and its
# vendored Rust dependencies.
WORKDIR /workspaces/bun
RUN git init -q . && git remote add origin https://github.com/oven-sh/bun.git \
 && git fetch -q --depth=1 origin $BUN_COMMIT && git checkout -q FETCH_HEAD
COPY scripts /workspaces/bsan-bun/scripts
RUN RUSTUP_TOOLCHAIN=bsan bun run build --configure-only 2>&1 | tail -3 \
 && pin() { grep -oE "_COMMIT = \"[0-9a-f]+\"" scripts/build/deps/$1.ts | head -1 | cut -d'"' -f2; } \
 && F=/workspaces/bsan-bun/scripts/fetch-dep.sh \
 && $F vendor/lolhtml oven-sh/lol-html $(pin lolhtml) \
 && $F vendor/rust-argon2 sru-systems/rust-argon2 $(pin rust-argon2) $PWD/patches/rust-argon2/legacy-low-memory.patch \
 && cargo +bsan fetch -q

# BSan's instrumented standard library.
RUN cargo bsan setup 2>&1 | tail -1

# Bun's native dependencies at Bun's pinned commits, compiled with BSan instrumentation.
COPY native /workspaces/bsan-bun/native
RUN /workspaces/bsan-bun/native/fetch-sources.sh >/dev/null \
 && /workspaces/bsan-bun/native/build-cdeps.sh | tail -1 \
 && /workspaces/bsan-bun/native/build-clibs.sh | tail -1

# A macOS Bun binary: the template `bun build --compile --target=bun-darwin-x64` patches.
RUN mkdir -p /templates && cd /templates && curl -fsSLO $MACOS_TEMPLATE && unzip -q bun-darwin-x64.zip && rm bun-darwin-x64.zip

COPY docker/bsan-test /usr/local/bin/bsan-test
ENTRYPOINT ["bsan-test"]
