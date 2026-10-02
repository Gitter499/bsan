#!/bin/bash
# sbatch hpc/job.slurm   — one batch run on a compute node (no network needed after setup fetch).
#   MODE=build    compile BSan, sysroot, native libs   (once, after `hpc/setup.sh fetch`)
#   MODE=crates   Bun's own tests:   CRATES="bun_ptr bun_sys ..." (default: all that ran here)
#   MODE=drivers  driver tests:      DRIVERS="bun_zlib ..."       (default: all)
# Pass settings with: sbatch --export=ALL,STATE=$SCRATCH/bsan-state,MODE=crates hpc/job.slurm
#SBATCH --job-name=bsan-bun
#SBATCH --nodes=1
#SBATCH --ntasks=1
#SBATCH --cpus-per-task=32
#SBATCH --mem=128G
#SBATCH --time=08:00:00
#SBATCH --output=bsan-bun-%j.out
##SBATCH --account=<your ACES/ACCESS account>     # uncomment and fill in
##SBATCH --partition=<cpu partition>              # see ACES docs / `sinfo`
set -euo pipefail
: "${STATE:?export STATE (e.g. \$SCRATCH/bsan-state)}"
here=${SLURM_SUBMIT_DIR:-$(pwd)}
cd "$here"   # submit from the BSan checkout's experiments/bun directory
module load ${SING_MODULE:-} 2>/dev/null || true   # if Singularity is a module on your cluster
export CARGO_NET_OFFLINE=true CARGO_BUILD_JOBS=${SLURM_CPUS_PER_TASK:-8} JOBS=${SLURM_CPUS_PER_TASK:-8}
export RUST_MIN_STACK=${RUST_MIN_STACK:-67108864}   # bun_parsers' stack guard (see README)
CRATES=${CRATES:-"bun_ptr bun_collections bun_ast bun_paths bun_hash bun_base64 bun_clap bun_dispatch bun_errno bun_http_types bun_md bun_resolve_builtins bun_shell_parser bun_threading bun_url bun_wyhash bun_sys bun_core bun_parsers bun_io bun_semver bun_react_compiler bun_uws_sys bun_boringssl bun_router bun_resolver bun_bundler"}
case "${MODE:-crates}" in
  build)   hpc/setup.sh build ;;
  crates)  hpc/run.sh "cd /workspaces/bun && /workspaces/bsan-bun/scripts/run-crates.sh $CRATES" ;;
  drivers) hpc/run.sh "/workspaces/bsan-bun/scripts/run-drivers.sh ${DRIVERS:-}" ;;
  *) echo "MODE must be build|crates|drivers" >&2; exit 2 ;;
esac
echo "logs: $here/logs/"
