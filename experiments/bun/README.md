# BorrowSanitizer × Bun

BorrowSanitizer (BSan) run on [Bun](https://github.com/oven-sh/bun) at `bc7a813b10`. Repros re-checked on BSan from upstream main `0302f58`.

## Bun bugs found: 6

| # | Where | Bug | Fix |
|---|---|---|---|
| 1 | `bun_zlib` (gzip/deflate, WebSocket compression) | zlib writes through its saved stream pointer while Rust holds `&mut` to the stream | [patch](bun-patches/fix-zlib-deflate-backpointer.patch) |
| 2 | `bun_ast` node store (every parse) | pointer taken from a `Box`, then the `Box` is moved | [patch](bun-patches/fix-ast-store-current.patch) |
| 3 | `bun_alloc` AST allocator (every parse) | each allocation reborrows the whole arena, invalidating earlier pointers | [patch](bun-patches/fix-ast-alloc.patch) |
| 4 | `bun_jsc` VM / event loop (every run) | VM ↔ event-loop self-pointers used while `&mut` is live | partial ([patch](jsc/fix-03-ensure_waker-partial.patch)); a full fix needs a refactor |
| 5 | `bun_alloc` `BSSList` (resolver's directory-entry cache, past ~8.4k entries) | each append reborrows a whole overflow block, and chaining a new block re-`Box`es the old one; both invalidate earlier entry pointers, then `Entry::kind` writes through one | [patch](bun-patches/fix-bss-list-append.patch) |
| 6 | `bun_exe_format` Mach-O writer (`bun build --compile` for macOS) | `update_load_command_offsets` writes load commands through a pointer derived from `&self.data` (a shared reference) | [patch](bun-patches/fix-macho-load-command-writes.patch) |

All six are aliasing UB (Tree Borrows). None is known to crash today, but the
compiler is allowed to miscompile them.

**Each bug, in plain terms, with a 3-step repro anyone can run: [`bugs/`](bugs/).** Bugs 1–3, 5 and 6
reproduce with one small test on unmodified Bun, and their fixes make that test pass.

## BSan issues found: 6

1. **Slowdown:** quadratic time and GBs of memory on ordinary loops. Workaround: `BSAN_OPTIONS=wildcard=0`. Still present on upstream main `0302f58` (Bun's Adler-32 test: 1 s fast mode, out of memory after 333 s default mode).
2. **Missing line numbers:** some locations print as line 0.
3. **Proc-macro doctests:** `cargo bsan test` fails on them.
4. **Runtime bundling:** the BSan runtime is copied into every rlib.
5. **False positive:** float parsing (`str::parse::<f64>`) in safe code. **Fixed on upstream main** (`0302f58`).
6. **Aborts on first report:** it can't continue past one.

## What ran

- **Bun's own tests:** 25 crates. Only `bun_parsers` reported (bug 2).
- **New driver tests for C-library wrappers:** zlib, zstd, brotli, libdeflate, picohttpparser, libarchive. Only zlib reported (bug 1).
- **A BSan-instrumented `bun-debug`:** bugs 2–4 ([jsc/REPORT.md](jsc/REPORT.md)).
- **Second round of drivers** ([`0005`](bun-patches/0005-bsan-drivers-2.patch), [`results/drivers-2/`](results/drivers-2)): `bun_alloc` 38 tests (bug 5), `bun_core` 45 (clean), `bun_sys` 38 (clean), `bun_exe_format` 9 (bug 6), `bun_sourcemap` 15 (5 clean; 7 need a C++ stack-check symbol, 3 failed their assertions). `bun_io` (16) does not build yet.
- **Not run:** `bun_css` and `bun_bundler` (compiler out of memory), `bun_router`.

## Running it

To run on a cluster, see [hpc/RUNBOOK.md](hpc/RUNBOOK.md). Locally, use the same scripts with `RUNTIME=docker`:

```sh
docker build -t bsan-hpc hpc
export STATE=<dir> RUNTIME=docker
hpc/setup.sh fetch && hpc/setup.sh build             # toolchain, Bun checkout, native libs
hpc/run.sh "cd /workspaces/bun && /workspaces/bsan-bun/scripts/run-crates.sh bun_parsers"
```

Full details (setup, coverage tables, BSan issue analysis): [DETAILS.md](DETAILS.md).
