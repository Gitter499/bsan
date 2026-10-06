# BorrowSanitizer × Bun: detailed notes

Running BorrowSanitizer on [Bun](https://github.com/oven-sh/bun) at
`bc7a813b10` (2026-10-02), now that Bun is written entirely in Rust, to find
aliasing/memory bugs that Miri cannot reach.

| | |
|---|---|
| Bun | `oven-sh/bun@bc7a813b10` — ~1,540 `.rs` files, 103 workspace crates, 0 `.zig` |
| BSan | `main@b1c71a3`, toolchain = upstream nightly `75a75c3e0` (2026-09-26), LLVM 23.1.1 |
| Environment | the repo's devcontainer image (`.devcontainer/Dockerfile`, target `image-dev`) |

## Findings

| # | Bun bug | Found by | Repro ([bugs/](bugs/)) | Fix |
|---|---|---|---|---|
| 1 | `bun_zlib`: zlib-ng's stored `z_stream` back-pointer vs. protected `&mut` (HTTP/WebSocket compression, `Bun.deflateSync`/`gzipSync`) | BSan, driver tests | `bun_zlib` test `bsan_repro`; passes with fix | `bun-patches/fix-zlib-deflate-backpointer.patch` |
| 2 | `bun_ast` `new_store!`: `current` taken from a `Box` before it is moved (every parse) | BSan, Bun's `bun_parsers` tests + runtime run | Bun's test `json::tests::env_json`; passes with fix | `bun-patches/fix-ast-store-current.patch` |
| 3 | `bun_alloc::ast_alloc`: each allocation reborrows the whole state, freezing earlier bump allocations (every parse) | BSan, runtime run | `bun_alloc` test `bsan_repro`; passes with fix | `bun-patches/fix-ast-alloc.patch` |
| 4 | `bun_jsc` VirtualMachine/EventLoop: `&VirtualMachine` / self-pointer writes while a protected `&mut` to an embedded part is live (3 sites observed; ~28 more match the pattern, unconfirmed) | BSan, runtime run | instrumented `bun-debug` only (`jsc/`) | partial: `jsc/fix-03-ensure_waker-partial.patch` |

Bugs 1–3 reproduce on Bun's own code: a Bun test, or a ~10-line test added by
[`bun-patches/0004-bsan-repro-tests.patch`](bun-patches/0004-bsan-repro-tests.patch).
[`repro/run.sh`](repro/run.sh) runs each before and after its fix. See [bugs/](bugs/).

Findings 3–4 come from the runtime run (a BSan-instrumented `bun-debug` built
with Bun's own build system); details and reports are in
[`jsc/REPORT.md`](jsc/REPORT.md). That run only exercised startup: every JS
test aborts at the first module load on a BSan false positive (stale shadow
provenance for pointers written by uninstrumented C++), see the report.

### Bun bug: zlib-ng's stored `z_stream` back-pointer vs. protected `&mut` (Tree Borrows UB)

**Status: confirmed** by BSan on Bun's real code against instrumented zlib-ng,
and by the test `bun_zlib/tests/bsan_repro.rs`. The proposed fix makes both clean.

zlib-ng's `deflateInit2_` stores the `z_stream*` it is given in its internal
state (`s->strm = strm`), and `deflate()` later reads and writes the stream
*through that stored pointer* (`fill_window` → `read_buf(s->strm, …)`:
`strm->avail_in -= len; strm->next_in += len; strm->total_in += len`, also
`deflate_stored.c`, `trees.c`). `bun_zlib` takes that pointer from one borrow
at init time and then, on every call, hands zlib a pointer derived from a
*different, protected* `&mut`:

1. **`DeflateEncoder` / `step`** (`src/zlib/lib.rs`): `new()` passes
   `&raw mut *this.strm` (the `Box`) to `deflateInit2_`. Each `step()` calls the
   shared helper `fn step(strm: &mut zStream_struct, …)`, writes
   `strm.next_in/avail_in/…` and calls `deflate(&raw mut *strm, …)`. `strm` is a
   function-argument reference, so it is protected for the whole call; when
   `deflate` accesses the stream through `s->strm` (the init-time pointer, not
   derived from `strm`), that is a foreign access to a protected tag.
   Reached from production by:
   - HTTP response/request compression — `http/compress_body.rs`
     `compress_zlib_streaming` (gzip/deflate `Content-Encoding`);
   - WebSocket permessage-deflate — `http_jsc/websocket_client/WebSocketDeflate.rs`.
2. **`ZlibCompressorArrayList::read_all`** (`Bun.deflateSync` / `Bun.gzipSync`,
   `runtime/api/BunObject.rs`): the `z_stream` is stored inline in the boxed
   struct; `init` passes `&raw mut zlib_reader.zlib` to `deflateInit2_`, and
   `read_all(&mut self)` — a protected reborrow covering the inline stream —
   calls `deflate`, which writes through the stored pointer.

The inflate side (`InflateDecoder`, `ZlibReaderArrayList`) has the same shape
but zlib-ng's inflate only *compares* `state->strm` (`inflateStateCheck`) and
never dereferences it, so it does not access memory through the stale pointer;
BSan reports nothing there.

Besides being Tree Borrows UB, this is an LLVM `noalias` violation for `step`'s
`&mut zStream_struct` parameter (memory it covers is accessed during the call
through a pointer not based on it). Bun's release build uses cross-language
ThinLTO (`-Clinker-plugin-lto`, C objects built for LTO), so `deflate` can be
inlined into `step`, where LLVM is entitled to exploit that `noalias`.

BSan report (Bun's code, real zlib-ng, `tests/bsan_drivers.rs::http_body_deflate_roundtrip`):

```
error: Undefined Behavior: read access through <1500900>(unprotected) at alloc95322[0x8] is forbidden
    --> native/src/zlib/deflate.c:1203:22
1203 | if (s->strm->avail_in == 0)
     = help: the accessed tag <1500900>(unprotected) is foreign to the protected tag <1500936>(StrongProtector) (i.e., it is not a child)
     = help: this foreign read access would cause the protected tag <1500936>(StrongProtector) (currently Unique) to become Disabled
     = help: protected tags must never be Disabled
help: the protected tag <1500936>(StrongProtector) later transitioned to Unique due to a child write access at offsets [0x8..0xc]
     = help: this transition corresponds to the first write to a 2-phase borrowed mutable reference
stack backtrace:
0: fill_window       at native/src/zlib/deflate.c:1203:22
1: deflate_quick     at native/src/zlib/deflate_quick.c:74:20
2: deflate           at native/src/zlib/deflate.c:977:18
3: bun_zlib::step
4: <bun_zlib::DeflateEncoder>::step
5: bsan_drivers::http_compress
```

and for `ZlibCompressorArrayList` (`bun_sync_apis_roundtrip`):

```
error: Undefined Behavior: write access through <985908>(unprotected) at alloc70181[0x10] is forbidden
    --> native/src/zlib/deflate_p.h:164:20
 164 | strm->avail_in -= len;
     = help: this foreign write access would cause the protected tag <986033>(StrongProtector) (currently Reserved (conflicted)) to become Disabled
help: the protected tag <986033>(StrongProtector) later transitioned to Reserved (conflicted) due to a foreign read access at offsets [0x10..0x14]
    --> native/src/zlib/deflate.c:1203:22
stack backtrace:
0: read_buf          at native/src/zlib/deflate_p.h:164:20
1: deflate_medium    at native/src/zlib/deflate_medium.c:182:20
2: deflate           at native/src/zlib/deflate.c:977:18
3: <bun_zlib::ZlibCompressorArrayList>::read_all::{closure#0}   at src/zlib/lib.rs:824:35
```

(Offsets: `next_in` is at 0x0 and `avail_in` at 0x8 of `z_stream`; in
`ZlibCompressorArrayList` the stream starts at 0x8, after `list_ptr`.)

**Repro.** `src/zlib/tests/bsan_repro.rs` (patch 0004) makes the same calls as
`compress_zlib_streaming`: `DeflateEncoder::new` + `step`. BSan reports the
read in `fill_window` (`deflate.c:1203`); with the fix the test passes.

**Fix.** [`bun-patches/fix-zlib-deflate-backpointer.patch`](bun-patches/fix-zlib-deflate-backpointer.patch):
keep each `z_stream` in its own heap allocation behind a raw pointer
(`ZStreamBox`), pass zlib that pointer, and access the stream's fields only
through it — never through a `&mut zStream_struct` or an inline field of a
struct accessed via `&mut self`. With the patch, all 11 zlib drivers pass under
BSan with no reports in fast mode (both the `DeflateEncoder` paths and
`ZlibCompressorArrayList`) and round-trips still match; under BSan's default
options the WebSocket permessage-deflate driver, which reports on unpatched
code, passes too. `cargo clippy -p bun_zlib --no-deps` (Bun's lint config,
including `undocumented_unsafe_blocks`) is clean.

### Bun bug: `bun_ast` `new_store!` caches `current` from a `Box` before moving it (Tree Borrows UB)

**Status: confirmed** — found independently by the runtime run
([`jsc/`](jsc/REPORT.md), on every `bun-debug` startup) and by Bun's own
`bun_parsers` unit tests under BSan (21 of 38 tests report it). The fix makes them pass.

`Store::allocate` (`src/ast/new_store.rs`, the arena behind every
`Expr`/`Stmt` store) does

```rust
let mut first = Block::new_boxed();
store.current = &raw mut *first;   // raw pointer from the Box's current tag
store.head = Some(first);          // moving the Box retags it
```

and the overflow path does the same with `*slot = Some(new_block)`. Every
payload is then written through `current` (a pointer derived *before* the
move), which is a foreign write for the moved `Box` and disables it; the next
`reset()` — at the end of every parse — reborrows it with
`store.head.as_deref_mut()` (line 254 in all builds; line 236 under
`debug_assertions`), which is UB.

BSan report (`bun_parsers` `json::tests::env_json`, Bun's code unchanged):

```
error: Undefined Behavior: reborrow through <303424>(unprotected) at alloc50857[0x0] is forbidden
    --> src/ast/new_store.rs:236:69
 236 | let mut it: Option<&mut Block> = store.head.as_deref_mut();
     = help: the accessed tag <303424>(unprotected) has state Disabled which forbids this reborrow (acting as a child read access)
help: the accessed tag <303424>(unprotected) later transitioned to Disabled due to a foreign write access at offsets [0x0..0x28]
    --> library/core/src/ptr/mod.rs:1966:41   (intrinsics::write_via_move)
stack backtrace:
4: <bun_ast::expr::expr_store::Store>::reset      at src/ast/new_store.rs:236:69
5: bun_ast::expr::data::Store::reset               at src/ast/new_store.rs:433:17
6: <bun_ast::StoreResetGuard as Drop>::drop        at src/ast/lib.rs:3230:9
9: bun_parsers::json::tests::env_json              at src/parsers/json.rs:2137:9
```

Bun's Miri CI cannot run this test (`can't call foreign function mi_heap_new`,
because the arena allocates through mimalloc), which is how the bug got past
it. Repro: Bun's own `json::tests::env_json`.
**Fix:** [`bun-patches/fix-ast-store-current.patch`](bun-patches/fix-ast-store-current.patch)
— derive `current` from the Box after it is stored (`Option::insert`).

### Other code exercised under BSan with no reports

See [Coverage](#coverage). Notable clean results for code Miri cannot run:
zlib-ng inflate paths (HTTP, WebSocket, sync APIs, multi-member gzip,
truncated/corrupt input), zstd, brotli, libdeflate, picohttpparser (incremental
response parsing, in-place chunked decoding), libarchive (`bun install` npm and
GitHub extraction, `bun create` overwrite scan, `bun publish`/`pm diff`
iteration, hostile tarballs).

## BorrowSanitizer issues found along the way

1. **Exposure bookkeeping makes ordinary loops quadratic and GB-sized.**
   A loop like `for (i, b) in [0u8; 6000].iter_mut().enumerate() { *b = i as u8 }`
   finishes natively in microseconds, but under BSan
   (default options) runs >20 s and grows past 1.5 GB (Bun's own
   `bun_hash::adler32::tests::very_long_with_variation` reached 5.7 GB; the
   `bun_paths` test binary was OOM-killed at 6 GB). With
   `BSAN_OPTIONS=wildcard=0` it finishes in 3 s / 30 MB. Cause: the pass emits
   `__bsan_expose_prov` for **every** `ptrtoint` (`visitPtrToIntInst`),
   including `ptr.addr()` in core's debug UB checks, which do not expose in
   Rust's semantics; and `EagerTree::expose_tag` then walks *every location
   range* of the allocation to update the wildcard cache. Each element touched
   adds a range, so each new exposure is O(n).
   `node_debug_info=0` cuts memory roughly 4× but not time.
2. **Some locations come out as line 0.** "Created here" notes for some
   retags carry no line — e.g. `new_store.rs:0:21` for the tag of the `Box`
   moved by `store.head = Some(first)` (a `Box` moved into a field) — and in the zlib
   driver binaries several Rust frames resolve to `<cgu-name>:0:0` while C and
   std frames are fine. Ruled out: Bun's `split-debuginfo = "unpacked"` (same
   with it off), the working directory, edition 2024, local vs. dependency
   crate. A pass-side fallback (give line-0 function-entry retags the
   function's line) left the UI suites green but did not fix the zlib case —
   there the addresses of the whole function lack line info — so it was not
   kept.
3. **`cargo bsan test` fails on proc-macro doctests**: `bun_dispatch`'s
   doctest fails with "can't find crate for `quote`/`syn`" in the rustdoc
   phase (its unit tests pass).
4. **Every instrumented rlib bundles the BSan runtime.** `-lstatic=clang_rt.bsan-…`
   in `bsan_rustflags` makes rustc copy the runtime's 176 objects (~3 MB) into
   each crate's rlib, which adds up on a 100-crate workspace.
5. **False positive: float parsing leaves a protector alive.**
   Bun's `parse_number_text` (`json_stage2.rs`, safe code): collect the digits
   into a `Vec`, `str::from_utf8(&v)?.parse::<f64>()`, drop the `Vec`. Safe
   code cannot have UB, so the report is a BSan false positive. BSan reports "deallocation through <tag> (root of the
   allocation) … would cause the protected tag <tag>(StrongProtector)
   (currently Frozen) to become Disabled", with the protected tag created in
   `core::num::dec2flt::parse.rs` (line 0). In Bun it fires in `bun_parsers`
   `json::tests::lenient_numbers`. The sysroot is built with
   `-Zmir-opt-level=0`, and the `dec2flt` functions are not
   `#[inline(always)]`. Root cause not identified.
6. No way to continue after the first report (each report aborts the process),
   which forces one-test-per-process runs to see past a known issue.

## How Bun was made to run under BSan

Bun's build system was not used. Each crate's tests (and the drivers below) are
built with `cargo bsan test`:

- **Toolchain drift**: BSan's nightly (09-26) is newer than Bun's pin (09-15);
  `allocator_api` was split into `allocator_ext` in between and Bun denies
  warnings. [`0001-toolchain-compat.patch`](bun-patches/0001-toolchain-compat.patch)
  adds `#![feature(allocator_ext)]` + `#![allow(stable_features, unused_features)]`
  (11 crates, no code changes).
- **Configure step**: `bun run build --configure-only` (generates
  `build/debug/codegen/build_options.rs` and byte-class tables) runs in the
  container with the toolchain's clang-23; vendored `lol_html`/`rust-argon2`
  are fetched with `git` (`scripts/fetch-dep.sh`).
- **Link-time dispatch**: Bun's low-tier crates call
  `__bun_dispatch__<Iface>__<Variant>__<method>` symbols that higher-tier crates
  define, so test binaries don't link standalone (Bun only runs Miri, which
  never links). `scripts/link-loop.sh` + `native/gen-stubs.sh` generate weak,
  aborting stubs for whatever is still undefined (a test that reaches one dies
  naming it — Miri's "can't call foreign function").
- **Native code**: `native/build-cdeps.sh` builds what the Rust crates call into
  — highway + Bun's `highway_*.cpp` kernels, simdutf + Bun's C shim — and
  `native/build-clibs.sh` builds zlib-ng, zstd, brotli, libdeflate,
  picohttpparser and libarchive at Bun's pinned commits with Bun's patches.
  Everything is compiled with the same flags cargo-bsan's CC wrapper uses
  (`native/bsan-cc`), i.e. **instrumented**, so pointers stored and used by C
  are tracked.
- **Allocator**: `--cfg=bun_asan` (Bun's sanitizer mode: system allocator
  instead of mimalloc). Its ASan/LSan hooks are no-op stubs
  (`native/shim/asan_stubs.c`), and the mimalloc API that arenas still call
  directly is implemented on top of libc (`native/shim/mimalloc_shim.c`) so
  BSan sees every block.
- **Drivers**: Bun's unsafe FFI wrappers mostly have no tests.
  [`0002-bsan-drivers.patch`](bun-patches/0002-bsan-drivers.patch) adds
  `tests/bsan_drivers.rs` to `bun_zlib`, `bun_zstd`, `bun_brotli`,
  `bun_libdeflate_sys`, `bun_picohttp`, `bun_libarchive` and `bun_css`; each
  test mirrors a named production call site (same parameters and call
  sequence).

## Coverage

`bun_parsers` runs used [`0003-test-shim-asan-headroom.patch`](bun-patches/0003-test-shim-asan-headroom.patch):
its test-only `Bun__StackCheck__getMaxStack` shim leaves 512 KB of fake stack,
which is exactly `StackCheck`'s headroom under `bun_asan`, so every guarded
parse failed with "too deeply nested" (harness artifact, not a Bun bug).

Bun's own `#[test]`s, built and run under BSan (Rust and the native code they
reach instrumented). "Miri" marks crates Bun already runs under Miri.

| Crate | Miri | Result |
|---|---|---|
| bun_ast | yes | 20 passed, no reports |
| bun_base64 | yes | 3 passed, no reports |
| bun_clap | yes | 9 passed, no reports |
| bun_dispatch | yes | unit test passed; doctest hits BSan issue 3 |
| bun_errno | yes | 6 passed, no reports |
| bun_http_types | yes | 1 passed, no reports |
| bun_md | yes | 14 passed, no reports |
| bun_ptr | yes | 21 passed, no reports |
| bun_resolve_builtins | yes | 1 passed, no reports |
| bun_shell_parser | yes | 1 passed, no reports |
| bun_threading | yes | 7 passed, no reports (21 min: native-size stress tests) |
| bun_url | yes | 8 passed, no reports |
| bun_wyhash | yes | 8 passed, no reports |
| bun_sys | no | 15 passed, no reports |
| bun_collections | yes | 37 passed, no reports (`static_hash_map_put_get_delete_grow` skipped: 128 seeds natively vs. 2 under `cfg(miri)`, >35 min) |
| bun_hash | yes | 10 passed, no reports |
| bun_paths | yes | 29 passed, no reports |
| bun_core | no | 39 passed (1 ignored), no reports |
| bun_parsers | no | **reports the `bun_ast` Store finding** (21 of the tests that ran, all at `new_store.rs:236`); 9 passed |
| bun_io | no | 3 passed, no reports |
| bun_semver | no | 2 passed, no reports |
| bun_react_compiler | no | 6 passed, no reports |
| bun_uws_sys | no | 2 passed, no reports |
| bun_boringssl | no | 2 passed, no reports |
| bun_resolver | no | 3 passed, no reports |
| bun_router | no | not run (build stopped by the disk watchdog) |
| bun_bundler, bun_css | no | not run: instrumented rustc for `bun_css` needs >10 GB RAM (OOM-killed); the runtime run compiles it uninstrumented for the same reason |

Drivers (`0002-bsan-drivers.patch`), each test in its own process:

| Crate (C library) | Tests | Result |
|---|---|---|
| bun_zlib (zlib-ng) | 11 | **2 sites of the finding above** (all deflate users); inflate, CRC: no reports |
| bun_zstd (zstd) | 4 | 4 passed, no reports |
| bun_brotli (brotli) | 3 | 3 passed, no reports |
| bun_libdeflate_sys (libdeflate) | 2 | 2 passed, no reports |
| bun_picohttp (picohttpparser) | 3 | 3 passed, no reports |
| bun_libarchive (libarchive + zlib-ng) | 5 | 5 passed, no reports |
| bun_css (pure Rust, real-world stylesheets) | 4 | not run (same `bun_css` OOM) |

## Running it

```sh
# host: build the devcontainer image and start a container
docker build -f .devcontainer/Dockerfile --target image-dev -t bsan-dev .
git clone https://github.com/oven-sh/bun && git -C bun checkout bc7a813b10
experiments/bun/scripts/start-container.sh bsan bsan-dev ./bun
docker cp ~/.bun bsan:/root/.bun     # a bun binary for Bun's configure step
docker exec bsan /workspaces/bsan-bun/scripts/container-setup.sh   # installs bsan + tools

# container, in /workspaces/bun
git apply /workspaces/bsan-bun/bun-patches/0001-toolchain-compat.patch
git apply /workspaces/bsan-bun/bun-patches/0002-bsan-drivers.patch
bun run build --configure-only
/workspaces/bsan-bun/scripts/fetch-dep.sh vendor/lolhtml oven-sh/lol-html <LOLHTML_COMMIT>
/workspaces/bsan-bun/scripts/fetch-dep.sh vendor/rust-argon2 sru-systems/rust-argon2 <RUST_ARGON2_COMMIT> $PWD/patches/rust-argon2/legacy-low-memory.patch
/workspaces/bsan-bun/native/fetch-sources.sh
/workspaces/bsan-bun/native/build-cdeps.sh && /workspaces/bsan-bun/native/build-clibs.sh

# Bun's own tests, one crate at a time (logs/ gets one log per crate)
/workspaces/bsan-bun/scripts/run-crates.sh bun_ptr bun_sys bun_core ...
# a driver crate (needs the C libraries)
EXTRA_RUSTFLAGS="-Clink-arg=@/workspaces/bsan-bun/native/out/clibs.rsp" \
  /workspaces/bsan-bun/scripts/link-loop.sh -p bun_zlib --test bsan_drivers
/workspaces/bsan-bun/scripts/run-each.sh <test binary>   # one process per test
```

`<LOLHTML_COMMIT>`/`<RUST_ARGON2_COMMIT>` are the pins in
`scripts/build/deps/{lolhtml,rust-argon2}.ts`.

Notes:

- `scripts/bsan-test.sh` and `run-each.sh` default to
  `BSAN_OPTIONS=wildcard=0` because of BSan issue 1. In that mode accesses
  through integer-to-pointer casts go unchecked (it can miss bugs, it cannot
  add reports); `BSAN_WILDCARD=1` restores BSan's default semantics. The zlib
  finding was found and reproduced in both modes.
- Bun's tests size themselves down only under `cfg(miri)` (e.g. 2 vs. 128
  seeds, 200 vs. 50,000 items per producer). BSan builds take the native sizes,
  so some tests take a long time. Passing `--cfg=miri` is not an option: Bun
  also uses `cfg(miri)` to switch production code (e.g. `bun_highway`) from
  SIMD FFI to scalar fallbacks.
- Running test binaries directly needs
  `BSAN_SYMBOLIZER=/opt/llvm23/bin/llvm-symbolizer`.
