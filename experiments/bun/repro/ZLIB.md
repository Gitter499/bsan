# Reproducing the bun_zlib bug

**What runs:** an unmodified Bun (`oven-sh/bun@bc7a813b10`) plus one new test file. The
test makes the same calls Bun makes to gzip an HTTP body
([`compress_zlib_streaming`](https://github.com/oven-sh/bun/blob/bc7a813b10b6ef8accc00c931b9a501331ac8c5c/src/http/compress_body.rs#L130)).
It runs under BorrowSanitizer, with Bun's pinned zlib-ng built with BSan instrumentation.

**Needs:** Linux x86_64, Docker, ~25 GB of disk, and internet access for step 1.

## 1. Set up (once)

```sh
git clone -b claude/adoring-meitner-qt7qch https://github.com/Gitter499/bsan.git
cd bsan/experiments/bun
docker build -t bsan-hpc hpc
export STATE=$PWD/state RUNTIME=docker
BUN_PATCHES=0001-toolchain-compat hpc/setup.sh fetch
hpc/setup.sh build
```

`fetch` clones Bun at `bc7a813b10` into `$STATE/bun`, installs the BSan toolchain, and
runs Bun's own configure step (`bun run build --configure-only`).

`build` compiles BSan and builds zlib-ng (plus Bun's other native deps) at Bun's pinned
commits, instrumented.

The only change made to Bun's source is `0001-toolchain-compat`, which adds two attribute
lines to each of 11 crates:

```rust
#![feature(allocator_ext)]
#![allow(stable_features, unused_features)]
```

BSan's nightly is newer than Bun's pinned one, and `allocator_api` was split into
`allocator_ext` in between. The patch changes no code.

## 2. Add the test

Create `$STATE/bun/src/zlib/tests/bsan_repro.rs`:

```rust
// Same calls as http/compress_body.rs `compress_zlib_streaming` (gzip body).
use bun_zlib::{DeflateEncoder, FlushValue, ReturnCode};

#[test]
fn deflate_encoder_step() {
    let input = b"hello world ".repeat(100);
    let mut out = Vec::new();
    let mut encoder = DeflateEncoder::new(6, 15 + 16, 8, 0).unwrap();
    let (_, rc) = encoder.step(&input, &mut out, 64 * 1024, FlushValue::Finish);
    assert_eq!(rc, ReturnCode::StreamEnd);
}
```

## 3. Run it under BSan

```sh
hpc/run.sh 'cd /workspaces/bun &&
  export EXTRA_RUSTFLAGS=-Clink-arg=@/workspaces/bsan-bun/native/out/clibs.rsp &&
  /workspaces/bsan-bun/scripts/link-loop.sh -p bun_zlib --test bsan_repro &&
  /workspaces/bsan-bun/scripts/bsan-test.sh -p bun_zlib --test bsan_repro'
```

`bsan-test.sh` is `cargo +bsan bsan test`, plus the link flags Bun's own build would pass:
the instrumented native libraries, and Bun's `--cfg=bun_asan` system-allocator mode.

`link-loop.sh` first adds aborting stubs for symbols that only Bun's higher-level crates
define. Without them a single crate's test binary doesn't link. This test never calls any
of them.

Expected output: one report, a read inside zlib-ng through the stream pointer it saved at
init, while Bun's `step` holds a protected `&mut` to the stream:

```
error: Undefined Behavior: read access through <…>(unprotected) at alloc…[0x8] is forbidden
    --> /workspaces/bsan-bun/native/src/zlib/deflate.c:1203:22
1203 | if (s->strm->avail_in == 0)
     = help: the accessed tag <…>(unprotected) is foreign to the protected tag <…>(StrongProtector)
     = help: this foreign read access would cause the protected tag <…>(StrongProtector) (currently Unique) to become Disabled
help: the protected tag <…>(StrongProtector) later transitioned to Unique due to a child write access at offsets [0x8..0xc]
stack backtrace:
0: fill_window      at native/src/zlib/deflate.c:1203:22
1: deflate_medium   at native/src/zlib/deflate_medium.c:182:20
2: deflate          at native/src/zlib/deflate.c:977:18
```

(Some Rust frames and "created here" notes show `<hash>:0:0` instead of a line; that is a
BSan debug-info issue, not part of the bug.)

Offset `0x8` is `avail_in` in `z_stream`.

## 4. Optional: check the fix

```sh
hpc/run.sh 'cd /workspaces/bun && git apply /workspaces/bsan-bun/bun-patches/fix-zlib-deflate-backpointer.patch &&
  EXTRA_RUSTFLAGS=-Clink-arg=@/workspaces/bsan-bun/native/out/clibs.rsp /workspaces/bsan-bun/scripts/bsan-test.sh -p bun_zlib --test bsan_repro'
# test result: ok. 1 passed
```

## Where the bug is

- **Bun saves a raw pointer to the stream for zlib.** `DeflateEncoder::new` passes
  `&raw mut *this.strm` to `deflateInit2_`
  ([zlib/lib.rs:899](https://github.com/oven-sh/bun/blob/bc7a813b10b6ef8accc00c931b9a501331ac8c5c/src/zlib/lib.rs#L899)),
  and zlib-ng stores it: `s->strm = strm`
  ([deflate.c:299](https://github.com/zlib-ng/zlib-ng/blob/12731092979c6d07f42da27da673a9f6c7b13586/deflate.c#L299)).
- **Each step takes an exclusive `&mut` to the same stream.**
  `step(strm: &mut zStream_struct, …)`
  ([zlib/lib.rs:1175](https://github.com/oven-sh/bun/blob/bc7a813b10b6ef8accc00c931b9a501331ac8c5c/src/zlib/lib.rs#L1175))
  writes `avail_in`, then calls `deflate`.
- **zlib-ng reads through the saved pointer while that `&mut` is live.**
  `fill_window` reads `s->strm->avail_in`
  ([deflate.c:1203](https://github.com/zlib-ng/zlib-ng/blob/12731092979c6d07f42da27da673a9f6c7b13586/deflate.c#L1203)).
  That is undefined behavior under Tree Borrows. It is also a violation of the `noalias`
  that Rust emits for the `&mut` parameter.

This is the same bug as [flate2-rs#392](https://github.com/rust-lang/flate2-rs/issues/392),
which was fixed in [flate2-rs#394](https://github.com/rust-lang/flate2-rs/pull/394).
