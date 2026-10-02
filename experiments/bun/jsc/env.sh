# Source inside the bsan-jsc container: environment for the BSan-instrumented bun build.
export BUN_BSAN=1
export BUN_TOOLCHAIN_RUST=/root/.rustup/toolchains/bsan
export BUN_TOOLCHAIN_LLVM=/opt/llvm23
export RUSTUP_TOOLCHAIN=bsan
export CARGO_BUILD_JOBS=2
export BUN_BUILD_CACHE_DIR=/workspaces/bun/build/cache
export BSAN_RUST_DEBUGINFO=line-tables-only
export BSAN_SKIP_CRATES=bun_css
export BSAN_SYMBOLIZER=/root/.rustup/toolchains/bsan/bin/llvm-symbolizer
export BSAN_OPTIONS=stacktrace_max_len=40:wildcard=0
export BUN_DEBUG_QUIET_LOGS=1
export BSAN_NORETAG_CRATES=bun_jsc,bun_runtime
export BSAN_INSTRUMENT_CXX=1
