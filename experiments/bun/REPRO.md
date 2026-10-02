# Repros

Each crate in [`repro/`](repro) is Bun's own code, cut down to the buggy path.
They run under BSan.

## Run all

In the container:

```sh
/workspaces/bsan-bun/repro/run-all.sh
```

This runs each crate as-is (expect a BSan report) and with its `fix.diff`
applied (expect a clean run). The last result is in [`repro/run-all.txt`](repro/run-all.txt).

## Run one

```sh
cd repro/<crate>
cargo +bsan bsan run                           # reports
patch -p1 < fix.diff && cargo +bsan bsan run   # clean
patch -p1 -R < fix.diff                        # undo
```

`vm-eventloop` has two binaries:

- `--bin ensure_waker`. Its fix is `--features ensure-waker-fix`.
- `--bin run_start --features ensure-waker-fix`. It has no fix.

## Crates

| Crate | Bug | Log |
|---|---|---|
| `zlib-backpointer` | zlib writes through its saved stream pointer while Rust holds `&mut` | `bsan.log` |
| `ast-store-current` | pointer taken from a `Box`, then the `Box` is moved | `bsan.log` |
| `ast-alloc-reborrow` | each allocation reborrows the whole arena, invalidating earlier pointers | `bsan.log` |
| `vm-eventloop` | VM ↔ event loop self-pointers vs. live `&mut` | `ensure_waker.bsan.log`, `run_start.bsan.log` |
| `dec2flt-protector` | **BSan false positive** (no `unsafe` code) | `bsan.log` |
| `adler-hang` | **BSan slowdown**: hangs by default, 3 s with `BSAN_OPTIONS=wildcard=0` | — |

`zlib-backpointer` needs the instrumented C libraries from `native/build-clibs.sh`.

Logs from the original runs on full Bun are in [`results/`](results) and [`jsc/repro/`](jsc/repro).
