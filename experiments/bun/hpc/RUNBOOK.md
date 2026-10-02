# Running the Bun × BSan harness on an HPC cluster (ACES)

Built for a cluster with Slurm and Singularity/Apptainer, no Docker and no root. All
mutable state (rustup, the BSan toolchain, the cargo registry, `bun`, caches, the Bun
checkout) lives in one directory, `$STATE`. The image only provides OS packages.

Two stages:
- `fetch` needs internet and runs on a **login node**.
- `build` and the test runs need **no network** and run on **compute nodes**.

This was tested off-cluster with Docker emulating Singularity: read-only image, `$HOME` on
a bind mount, and the build and test stages run with networking disabled.

Placeholders like `<...>` are yours to fill in: your account, partitions and scratch path.

## 0. One-time: the image

Pick one:

```sh
# a) On any machine with Docker, then copy the tar to ACES:
docker build -t bsan-hpc experiments/bun/hpc
docker save bsan-hpc -o bsan-hpc.tar
scp bsan-hpc.tar aces:<scratch>/
# then, on ACES:
singularity build $STATE/bsan.sif docker-archive://<scratch>/bsan-hpc.tar

# b) Directly on ACES, if fakeroot builds are enabled for you:
singularity build --fakeroot $STATE/bsan.sif experiments/bun/hpc/bsan.def
```

The `.sif` is about 1 GB.

## 1. One-time: the checkout and state (login node)

```sh
export STATE=<scratch>/bsan-state          # needs ~15 GB, plus ~5 GB per crate build tree
git clone -b claude/adoring-meitner-qt7qch https://github.com/Gitter499/bsan.git <scratch>/bsan
cd <scratch>/bsan/experiments/bun
hpc/setup.sh fetch      # ~15–20 min: rustup, BSan toolchain, crates, bun, Bun checkout + patches,
                        # Bun's configure step, native library sources. Safe to re-run.
```

`fetch` clones Bun at the pinned commit into `$STATE/bun` and applies the harness patches.
It is light on CPU; the only compile is BSan's small `xb` helper.

## 2. Build (compute node, offline)

```sh
sbatch --export=ALL,STATE=$STATE,MODE=build hpc/job.slurm       # or interactively:
srun -c 32 --mem=128G -t 2:00:00 --pty bash -c "STATE=$STATE hpc/setup.sh build && STATE=$STATE hpc/setup.sh check"
```

`build` compiles the BSan pass and runtimes, the instrumented sysroot, and the instrumented
C/C++ libraries. `check` runs Bun's `bun_ptr` tests under BSan as a smoke test.

## 3. Runs (compute node, offline)

```sh
sbatch --export=ALL,STATE=$STATE,MODE=crates hpc/job.slurm                       # Bun's own tests
sbatch --export=ALL,STATE=$STATE,MODE=crates,CRATES="bun_sys bun_core" hpc/job.slurm
sbatch --export=ALL,STATE=$STATE,MODE=drivers hpc/job.slurm                      # driver tests
```

Edit the `#SBATCH --account/--partition` lines in `hpc/job.slurm` first.

Results:
- `experiments/bun/logs/summary*.txt` (per crate)
- `logs/<crate>.log`
- `logs/each-<crate>/` (one log per driver test)
- `logs/drivers-summary.txt`

Any line with `reports=N>0` or `error: Undefined Behavior` needs triage: see
`../README.md` and `../REPRO.md`.

`job.slurm` sets `CARGO_BUILD_JOBS` to the CPU count. The default 128 GB is enough for
`bun_css`/`bun_bundler`, which need over 10 GB per rustc process.

## 4. Driving it from a local agent over SSH + tmux

Nothing Claude-related runs on the cluster. Your local agent only sends shell commands.

On your machine, in `~/.ssh/config`:

```
Host aces
  HostName <a specific ACES login node>
  User <user>
  ControlMaster auto
  ControlPath ~/.ssh/cm-%r@%h:%p
  ControlPersist 12h
  ServerAliveInterval 60
```

Then log in once by hand (`ssh aces`) to get through MFA. The agent's later
`ssh aces '…'` calls reuse that connection with no prompt.

Start a persistent session, holding a compute-node allocation:

```sh
ssh aces 'tmux new -d -s bsan'
ssh aces 'tmux send-keys -t bsan "cd <scratch>/bsan/experiments/bun && export STATE=<scratch>/bsan-state" Enter'
ssh aces 'tmux send-keys -t bsan "srun -c 32 --mem=128G -t 8:00:00 --pty bash" Enter'
```

How the agent drives it — write output to files and read the files rather than
scraping the screen:

```sh
ssh aces 'tmux send-keys -t bsan "hpc/run.sh \"cd /workspaces/bun && /workspaces/bsan-bun/scripts/run-crates.sh bun_sys\" > run1.log 2>&1; echo EXIT:\$?" Enter'
ssh aces 'tail -5 <scratch>/bsan/experiments/bun/run1.log; cat <scratch>/bsan/experiments/bun/logs/summary*.txt'
ssh aces 'tmux capture-pane -p -t bsan -S -50'      # quick look at the pane
```

When the `srun` time limit ends, re-run the `srun` line. All state is on scratch, so work
picks up where it left off.

## 5. Watching files in a browser

Use the HPRC Open OnDemand portal: its **Files** app, or the **VS Code / code-server**
interactive app, pointed at `<scratch>/bsan`. It is sanctioned by the center and needs no
install.

Alternatives:
- VS Code Remote-SSH over the same `aces` host entry;
- `sshfs aces:<scratch>/bsan ~/aces-bsan` to view with a local editor.

## Notes

- **rustup message:** inside the container rustup may print
  `$HOME differs from euid-obtained home directory`. It's harmless, because `run.sh` sets
  `RUSTUP_HOME` and `CARGO_HOME` explicitly.
- **Fast mode:** runs default to `BSAN_OPTIONS=wildcard=0` (see `../README.md`, BSan issue 1).
  Use `BSAN_WILDCARD=1` to confirm a finding under BSan's default semantics.
- **Cargo lock:** every run shares the Bun target directory, so concurrent jobs on the same
  `$STATE` serialize on cargo's lock. For parallel jobs, use separate `STATE` directories
  (one per job) or run test binaries in parallel after a single build.
- **Proxies and CA bundles:** if your cluster requires them, `run.sh` forwards
  `HTTPS_PROXY`, `SSL_CERT_FILE` and similar into the container.
