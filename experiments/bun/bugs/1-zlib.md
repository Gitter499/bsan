# Bug 1: zlib reads through a stale stream pointer

When Bun compresses with zlib (gzip/deflate HTTP bodies, WebSocket compression,
`Bun.gzipSync`), zlib saves a pointer to the stream at setup. On every step, Bun takes an
exclusive `&mut` to the same stream, and zlib then reads it through its old pointer. In
Rust that is undefined behavior: the compiler may assume nothing else touches memory behind a
`&mut`. Same bug as [flate2-rs#392](https://github.com/rust-lang/flate2-rs/issues/392).

**Where:** Bun hands zlib the pointer ([`zlib/lib.rs:899`](https://github.com/oven-sh/bun/blob/bc7a813b10b6ef8accc00c931b9a501331ac8c5c/src/zlib/lib.rs#L899)), zlib keeps it
([`deflate.c:299`](https://github.com/zlib-ng/zlib-ng/blob/12731092979c6d07f42da27da673a9f6c7b13586/deflate.c#L299)), Bun's `step(strm: &mut …)` ([`zlib/lib.rs:1175`](https://github.com/oven-sh/bun/blob/bc7a813b10b6ef8accc00c931b9a501331ac8c5c/src/zlib/lib.rs#L1175))
calls `deflate`, which reads through the saved pointer ([`deflate.c:1203`](https://github.com/zlib-ng/zlib-ng/blob/12731092979c6d07f42da27da673a9f6c7b13586/deflate.c#L1203)).

## Reproduce

**1. Build the image (once, ~45 min, ~12 GB).** It is BorrowSanitizer's public image plus
Bun at commit `bc7a813b10`, unmodified:

```sh
docker build -t bun-bsan -f docker/Dockerfile \
  "https://github.com/Gitter499/bsan.git#8b0bb4228d1d5509812b90058b3fc837e45319b7:experiments/bun"
```

**2. Save the test** (the only thing added to Bun):

```sh
cat > repro.rs <<'EOF'
// Same calls Bun makes to gzip an HTTP body (src/http/compress_body.rs, compress_zlib_streaming).
use bun_zlib::{DeflateEncoder, FlushValue};

#[test]
fn gzip_body() {
    let mut encoder = DeflateEncoder::new(6, 15 + 16, 8, 0).unwrap();
    let mut out = Vec::new();
    encoder.step(&b"hello world ".repeat(100), &mut out, 64 * 1024, FlushValue::Finish);
}
EOF
```

**3. Run it under BorrowSanitizer:**

```sh
docker run --rm -v "$PWD/repro.rs:/workspaces/bun/src/zlib/tests/repro.rs" bun-bsan -p bun_zlib --test repro
```

Expected:

```
error: Undefined Behavior: read access through <…>(unprotected) at alloc…[0x8] is forbidden
    --> /workspaces/bsan-bun/native/src/zlib/deflate.c:1203:22
1203 | if (s->strm->avail_in == 0)
     = help: the accessed tag <…>(unprotected) is foreign to the protected tag <…>(StrongProtector)
stack backtrace:
0: fill_window
1: deflate_medium
2: deflate
```

## Fix

Keep the stream behind one raw pointer and never take a `&mut` to it: [`fix-zlib-deflate-backpointer.patch`](https://raw.githubusercontent.com/Gitter499/bsan/8b0bb4228d1d5509812b90058b3fc837e45319b7/experiments/bun/bun-patches/fix-zlib-deflate-backpointer.patch). Same run with the fix applied passes:

```sh
curl -fsSLO https://raw.githubusercontent.com/Gitter499/bsan/8b0bb4228d1d5509812b90058b3fc837e45319b7/experiments/bun/bun-patches/fix-zlib-deflate-backpointer.patch
docker run --rm -e APPLY=/fix.patch -v "$PWD/fix-zlib-deflate-backpointer.patch:/fix.patch" \
  -v "$PWD/repro.rs:/workspaces/bun/src/zlib/tests/repro.rs" bun-bsan -p bun_zlib --test repro
# test result: ok. 1 passed
```
