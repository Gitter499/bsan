# Repros

All repros run on Bun's own code. We ship no reduced copies. Bugs 1 and 3 use a
~10-line test added to the affected Bun crate
([`0004-bsan-repro-tests.patch`](bun-patches/0004-bsan-repro-tests.patch)).
Bug 2 is hit by one of Bun's existing tests.

## Run

Set up once (Bun checkout, BSan toolchain, instrumented C libraries):

```sh
hpc/setup.sh fetch && hpc/setup.sh build
```

Then run the repros:

```sh
hpc/run.sh /workspaces/bsan-bun/repro/run.sh
```

Each case runs the test as Bun ships it (expect a BSan report), then with the
fix applied (expect a pass). Logs go to `logs/repro/`.

Last result, on BSan built from upstream main `0302f58` ([`results/repro/`](results/repro)):

```
1-zlib                  want=report got=report ok
1-zlib-fixed            want=pass   got=pass   ok
2-ast-store             want=report got=report ok
2-ast-store-fixed       want=pass   got=pass   ok
3-ast-alloc             want=report got=report ok
3-ast-alloc-fixed       want=pass   got=pass   ok
fp-float-parse          want=pass   got=pass   ok   (BSan false positive, fixed upstream)
```

## Cases

| Case | Bun test | Fix |
|---|---|---|
| 1 zlib | `bun_zlib` `tests/bsan_repro.rs` (added) | `fix-zlib-deflate-backpointer.patch` |
| 2 AST store | `bun_parsers` `json::tests::env_json` (Bun's) | `fix-ast-store-current.patch` |
| 3 AST allocator | `bun_alloc` `tests/bsan_repro.rs` (added) | `fix-ast-alloc.patch` |
| BSan false positive (fixed on upstream main `0302f58`) | `bun_parsers` `json::tests::lenient_numbers` (Bun's) | — (BSan bug) |

**Bug 4 (VM / event loop)** can't be hit from a unit test, because the VM needs
JSC. It reproduces only in the BSan-instrumented `bun-debug` build: see
[`jsc/REPORT.md`](jsc/REPORT.md). The logs are in `jsc/repro/F2*.bsan.txt`.
