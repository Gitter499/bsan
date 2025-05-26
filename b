#!/usr/bin/env bash
set -e
# We want to call the binary directly, so we need to know where it ends up.
ROOT_DIR="$(dirname "$0")"
BSAN_SCRIPT_TARGET_DIR="$ROOT_DIR"/bsan-script/target
# We need a nightly toolchain, for `-Zroot-dir`.
cargo build $CARGO_EXTRA_FLAGS --manifest-path "$ROOT_DIR"/bsan-script/Cargo.toml \
  -Zroot-dir="$ROOT_DIR" \
  -q --target-dir "$BSAN_SCRIPT_TARGET_DIR" $MESSAGE_FORMAT || \
  ( echo "Failed to build bsan-script."; exit 1 )
# Instead of doing just `cargo run --manifest-path .. $@`, we invoke bsan-script binary directly. 
# Invoking `cargo run` goes through rustup (that sets it's own environmental variables), which is undesirable.
"$BSAN_SCRIPT_TARGET_DIR"/debug/bsan-script "$@"