#!/usr/bin/env bash
# hpc/run.sh <command...> — run a shell command inside the image, like `docker exec bsan ...`.
#
#   STATE     (required) directory for all mutable state; $STATE/home is the container's $HOME
#   SIF       Singularity/Apptainer image (default: $STATE/bsan.sif)
#   BSAN_DIR  BSan checkout (default: this repo)     -> /workspaces/bsan
#             its experiments/bun                    -> /workspaces/bsan-bun
#   BUN_DIR   Bun checkout (default: $STATE/bun)     -> /workspaces/bun
#   RUNTIME   singularity | apptainer | docker (auto-detected; docker is for testing off-cluster
#             with the image built from hpc/Dockerfile, IMAGE=bsan-hpc)
set -euo pipefail
: "${STATE:?set STATE to a directory on scratch}"
here=$(cd "$(dirname "$0")" && pwd)
BSAN_DIR=${BSAN_DIR:-$(cd "$here/../../.." && pwd)}
BUN_DIR=${BUN_DIR:-$STATE/bun}
SIF=${SIF:-$STATE/bsan.sif}
H=$STATE/home
mkdir -p "$H" "$BUN_DIR"
if [ -z "${RUNTIME:-}" ]; then
  if command -v apptainer >/dev/null; then RUNTIME=apptainer
  elif command -v singularity >/dev/null; then RUNTIME=singularity
  else RUNTIME=docker; fi
fi
export RUSTUP_HOME=$H/.rustup CARGO_HOME=$H/.cargo
P=$H/.cargo/bin:$H/.bun/bin:$H/.local/llvm23/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
# Variables forwarded into the container (both runtimes start from a clean environment).
PASS="RUSTUP_HOME CARGO_HOME HTTPS_PROXY https_proxy NO_PROXY no_proxy SSL_CERT_FILE CURL_CA_BUNDLE CARGO_HTTP_CAINFO
      GIT_SSL_CAINFO CARGO_BUILD_JOBS CARGO_NET_OFFLINE BSAN_OPTIONS BSAN_WILDCARD BSAN_SYMBOLIZER
      EXTRA_RUSTFLAGS RUST_MIN_STACK CRATE_TIMEOUT TEST_TIMEOUT JOBS ONLY RUSTUP_TOOLCHAIN"
case "$RUNTIME" in
  singularity|apptainer)
    pre=$(echo "$RUNTIME" | tr a-z A-Z)ENV_
    export "${pre}PATH=$P"
    for v in $PASS; do [ -n "${!v:-}" ] && export "$pre$v=${!v}"; done
    exec "$RUNTIME" exec --cleanenv --home "$H" \
      --bind "$BSAN_DIR:/workspaces/bsan,$BSAN_DIR/experiments/bun:/workspaces/bsan-bun,$BUN_DIR:/workspaces/bun" \
      --pwd /workspaces "$SIF" bash -c "$*" ;;
  docker)
    env=(-e HOME="$H" -e PATH="$P")
    for v in $PASS; do [ -n "${!v:-}" ] && env+=(-e "$v=${!v}"); done
    exec docker run --rm -i --read-only --tmpfs /tmp:exec --user "${DOCKER_USER:-$(id -u):$(id -g)}" \
      --network "${DOCKER_NETWORK:-host}" "${env[@]}" ${DOCKER_EXTRA:-} \
      -v "$H:$H" -v "$BSAN_DIR:/workspaces/bsan" -v "$BSAN_DIR/experiments/bun:/workspaces/bsan-bun" \
      -v "$BUN_DIR:/workspaces/bun" -w /workspaces "${IMAGE:-bsan-hpc}" bash -c "$*" ;;
  *) echo "unknown RUNTIME=$RUNTIME" >&2; exit 2 ;;
esac
