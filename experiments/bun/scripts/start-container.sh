#!/usr/bin/env bash
# start-container.sh <name> <image> <bun checkout> [extra docker args...]
# (Re)starts dockerd if needed and launches a long-lived dev container with this BSan checkout
# at /workspaces/bsan, this harness (experiments/bun) at /workspaces/bsan-bun and the Bun
# checkout at /workspaces/bun. Passes the host's HTTPS proxy through when one is set.
set -euo pipefail
name=$1 image=$2 bun=$(realpath "$3"); shift 3
bsan=$(realpath "$(dirname "$0")/../../..")
if ! docker info >/dev/null 2>&1; then
  nohup dockerd >/tmp/dockerd.log 2>&1 &
  until docker info >/dev/null 2>&1; do sleep 1; done
fi
docker rm -f "$name" >/dev/null 2>&1 || true
docker run -d --name "$name" --network=host \
  -e HTTPS_PROXY="${HTTPS_PROXY:-}" -e https_proxy="${HTTPS_PROXY:-}" -e NO_PROXY="${NO_PROXY:-}" -e no_proxy="${NO_PROXY:-}" \
  -e PATH=/root/.bun/bin:/opt/llvm23/bin:/root/.cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
  -v "$bsan":/workspaces/bsan -v "$bsan/experiments/bun":/workspaces/bsan-bun -v "$bun":/workspaces/bun "$@" \
  -w /workspaces "$image" sleep infinity
