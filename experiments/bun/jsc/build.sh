#!/usr/bin/env bash
# Run inside bsan-jsc container: build.sh [extra build.ts args...]
# e.g. build.sh --target=bun-rust   |   build.sh   (full bun-debug)
source /workspaces/bsan-bun/jsc/env.sh
cd /workspaces/bun
exec bun run build --asan=off -j2 "$@"
