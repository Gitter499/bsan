# BorrowSanitizer × Bun

BorrowSanitizer (BSan) run on [Bun](https://github.com/oven-sh/bun) at `bc7a813b10`.

## Bun bugs found: 4

| # | Where | Bug | Fix |
|---|---|---|---|
| 1 | `bun_zlib` (gzip/deflate, WebSocket compression) | zlib writes through its saved stream pointer while Rust holds `&mut` to the stream | [patch](bun-patches/fix-zlib-deflate-backpointer.patch) |
| 2 | `bun_ast` node store (every parse) | pointer taken from a `Box`, then the `Box` is moved | [patch](bun-patches/fix-ast-store-current.patch) |
| 3 | `bun_alloc` AST allocator (every parse) | each allocation reborrows the whole arena, invalidating earlier pointers | [patch](jsc/fix-02-ast_alloc.patch) |
| 4 | `bun_jsc` VM / event loop (every run) | VM ↔ event-loop self-pointers used while `&mut` is live | partial ([patch](jsc/fix-03-ensure_waker-partial.patch)); a full fix needs a refactor |

All four are aliasing UB (Tree Borrows). None is known to crash today, but the
compiler is allowed to miscompile them. With its fix applied, each one runs
clean under BSan.

Repros: [REPRO.md](REPRO.md).

## BSan issues found: 6

1. **Slowdown:** quadratic time and GBs of memory on ordinary loops. Workaround: `BSAN_OPTIONS=wildcard=0`.
2. **Missing line numbers:** some locations print as line 0.
3. **Proc-macro doctests:** `cargo bsan test` fails on them.
4. **Runtime bundling:** the BSan runtime is copied into every rlib.
5. **False positive:** float parsing (`str::parse::<f64>`) in safe code.
6. **Aborts on first report:** it can't continue past one.

## What ran

- **Bun's own tests:** 25 crates. Only `bun_parsers` reported (bug 2).
- **New driver tests for C-library wrappers:** zlib, zstd, brotli, libdeflate, picohttpparser, libarchive. Only zlib reported (bug 1).
- **A BSan-instrumented `bun-debug`:** bugs 2–4 ([jsc/REPORT.md](jsc/REPORT.md)).
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
