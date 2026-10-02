# Reproducing the findings

Two levels per finding:

- **Quick (Miri, ~1 min, no Bun build):** a standalone crate that copies the
  shape of Bun's code. This shows the Tree Borrows violation exists.
- **Full (BSan on Bun's real code):** needs the container setup in
  [README.md § Running it](README.md#running-it). The real BSan output is
  saved in the log files listed for each finding.

Every Miri crate also contains the fixed shape, and it passes.

## 1. bun_zlib: zlib-ng `z_stream` back-pointer

Quick:

```sh
cd experiments/bun/repro/zlib-backpointer
MIRIFLAGS=-Zmiri-tree-borrows cargo +bsan miri test   # bun_structure fails, fixed_structure passes
```

Full, in the container under `/workspaces/bun`, after applying
`bun-patches/0001` and `0002` and running `native/fetch-sources.sh`,
`build-cdeps.sh` and `build-clibs.sh`:

```sh
EXTRA_RUSTFLAGS="-Clink-arg=@/workspaces/bsan-bun/native/out/clibs.rsp" \
  /workspaces/bsan-bun/scripts/link-loop.sh -p bun_zlib --test bsan_drivers
/workspaces/bsan-bun/scripts/run-each.sh <printed test binary>
# fails: http_body_*, gzip_multi_member_body, websocket_*, reader_truncated_and_corrupt, bun_sync_apis_roundtrip
# passes: inflate_*, crc32_*
git apply /workspaces/bsan-bun/bun-patches/fix-zlib-deflate-backpointer.patch   # rebuild + rerun: all 11 pass
```

BSan logs:

- `results/zlib-deflate-encoder.bsan.log` (`DeflateEncoder`/`step`)
- `results/zlib-compressor-arraylist.bsan.log` (`ZlibCompressorArrayList`)
- with the fix: `results/zlib-fixed-fast-mode.txt` and `results/zlib-fixed-default-mode.log`

## 2. bun_ast `new_store!`: `current` taken before the Box moves

Quick:

```sh
cd experiments/bun/repro/ast-store-current
MIRIFLAGS=-Zmiri-tree-borrows cargo +bsan miri test   # bun_shape_* fails, fixed_shape_* passes
```

Full: this uses Bun's own unit tests, with no driver patch needed. Apply
`0001` and `0003`, then:

```sh
RUST_MIN_STACK=67108864 /workspaces/bsan-bun/scripts/run-crates.sh bun_parsers
```

BSan logs:

- `results/ast-store-bun_parsers-env_json.bsan.log`
- per-test results: `results/bun_parsers-unpatched-per-test.txt` (21 tests report it)
- with `bun-patches/fix-ast-store-current.patch`: `results/bun_parsers-with-ast-store-fix.txt`
  (35 pass, 1 = BSan float false positive, 2 large-document tests unfinished)
- the same bug seen in the runtime run: `jsc/repro/F1-new_store.bsan.txt`
- independent Miri crate: `jsc/repro/newstore` (`cargo +bsan miri run`)

## 3. bun_alloc ast_alloc: whole-state reborrow per allocation

Quick:

```sh
cd experiments/bun/jsc/repro/astalloc
MIRIFLAGS=-Zmiri-tree-borrows cargo +bsan miri run   # expected output: miri-output.txt
```

Full: needs the BSan-instrumented `bun-debug` (`jsc/build.sh`, `jsc/bun-bsan-build.patch`; see
`jsc/REPORT.md`), then `bun-debug -e 'console.log(1+1)'`.

BSan log: `jsc/repro/F3-ast_alloc.bsan.txt`. Fix: `jsc/fix-02-ast_alloc.patch`.

## 4. bun_jsc VirtualMachine / EventLoop

Quick:

```sh
cd experiments/bun/jsc/repro/vm_backref && MIRIFLAGS=-Zmiri-tree-borrows cargo +bsan miri run   # sites (a), (b)
cd ../vm_selfptr                        && MIRIFLAGS=-Zmiri-tree-borrows cargo +bsan miri run   # site (c)
```

Full: same `bun-debug` as finding 3; it fires on every run.

BSan logs:

- `jsc/repro/F2-eventloop-vm_ref.bsan.txt`
- `jsc/repro/F2b-ensure_waker-gc-init.bsan.txt`
- `jsc/repro/F2c-run-start-event_loop.bsan.txt`

Partial fix: `jsc/fix-03-ensure_waker-partial.patch`.

## BSan issues

| Issue | Repro | Log |
|---|---|---|
| Quadratic exposure / GBs of memory | `repro/adler-hang`: `cargo +bsan bsan test` (hangs), then the same with `BSAN_OPTIONS=wildcard=0` (3 s) | `results/notes.txt` |
| Float-parse false positive | `repro/dec2flt-protector`: `cargo +bsan bsan test` (BSan reports), `cargo +bsan miri test` (passes) | `results/false-positive-dec2flt-bun_parsers-lenient_numbers.bsan.log` |
| Stale shadow from uninstrumented code | runtime only | `jsc/repro/FP1-*`, `FP2-*`, `FP3-*` |
