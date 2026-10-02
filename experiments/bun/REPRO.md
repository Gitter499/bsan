# Reproducing the findings

Each finding has a small crate under [`repro/`](repro). The crate is Bun's own
source (Bun @ `bc7a813b10`), cut down to the code on the failing path. Code
that path does not use is deleted, and nothing on it is replaced by a mock.
Each crate header lists the source files it comes from and everything that
was left out. Everything runs under BSan; Miri is not used.

| Crate | Bun source | Finding |
|---|---|---|
| [`zlib-backpointer`](repro/zlib-backpointer) | `zlib/lib.rs`, `zlib_sys/shared.rs`, `http/compress_body.rs` + the real zlib-ng (instrumented) | 1 |
| [`ast-store-current`](repro/ast-store-current) | `ast/new_store.rs` | 2 |
| [`ast-alloc-reborrow`](repro/ast-alloc-reborrow) | `bun_alloc/ast_alloc.rs` (+ the `e_call`/`e_binary` caller shape from `js_parser/visit/visit_expr.rs`) | 3 |
| [`vm-eventloop`](repro/vm-eventloop) | `jsc/VirtualMachine.rs`, `jsc/event_loop.rs`, `runtime/cli/run_command.rs` | 4 |
| [`dec2flt-protector`](repro/dec2flt-protector) | `parsers/json_stage2.rs` `parse_number_text` | BSan false positive |
| [`adler-hang`](repro/adler-hang) | `bun_hash` Adler-32 | BSan slowdown |

Where a fix exists, the crate has a `fix.diff`. It is the same change as the
Bun patch, applied to the reduced code.

## Running

You need the BSan toolchain (`cargo +bsan bsan`). The zlib crate also needs the
instrumented C libraries, built by `native/build-clibs.sh`. The container
from [README.md § Running it](README.md#running-it) or [`hpc/`](hpc/RUNBOOK.md)
has both.

```sh
/workspaces/bsan-bun/repro/run-all.sh       # in the container
```

The script runs each crate as it is, then again with `fix.diff` applied, and
checks every result against what is expected. The last run's output is in
[`repro/run-all.txt`](repro/run-all.txt):

```
zlib-backpointer     bsan.log            want=report got=report ok
zlib-backpointer     fixed.bsan.log      want=clean  got=clean  ok
ast-store-current    bsan.log            want=report got=report ok
ast-store-current    fixed.bsan.log      want=clean  got=clean  ok
ast-alloc-reborrow   bsan.log            want=report got=report ok
ast-alloc-reborrow   fixed.bsan.log      want=clean  got=clean  ok
vm-eventloop         ensure_waker.bsan.log         want=report got=report ok
vm-eventloop         ensure_waker.fixed.bsan.log   want=clean  got=clean  ok
vm-eventloop         run_start.bsan.log            want=report got=report ok
dec2flt-protector    bsan.log            want=report got=report ok
```

To run a single crate:

```sh
cd repro/<crate>
cargo +bsan bsan run                          # reports
patch -p1 < fix.diff && cargo +bsan bsan run  # clean
patch -p1 -R < fix.diff
```

Each crate's BSan output is saved next to it as `*.bsan.log`. The full Bun
runs that found each bug are listed below.

## 1. bun_zlib: zlib-ng's `z_stream` back-pointer

`repro/zlib-backpointer` follows the HTTP `Content-Encoding: gzip` path:
`compress_zlib_streaming` → `DeflateEncoder::step` → `step(&mut zStream_struct, …)`
→ zlib-ng `deflate`. The only change to the stream setup: Bun sets mimalloc
`zalloc`/`zfree` thunks, and the repro leaves them `None`, so zlib's default
`malloc` is used.

```
error: Undefined Behavior: read access through <609>(unprotected) at alloc83[0x8] is forbidden
    --> native/src/zlib/deflate.c:1203:22      if (s->strm->avail_in == 0)
help: the accessed tag <609> was created here      main.rs:  Self { strm: Box::new(new_zstream()) }
help: the protected tag <650>(StrongProtector) was created here      main.rs:  fn step(
help: ... later transitioned to Unique due to a child write access at offsets [0x8..0xc]
                                                   main.rs:  strm.avail_in = in_len as c_uint;
0: fill_window  1: deflate_medium  2: deflate  3: zlib_backpointer::step
4: DeflateEncoder::step  5: compress_zlib_streaming  6: main
```

With `fix.diff` (the stream is accessed only through the raw pointer zlib holds,
as in `bun-patches/fix-zlib-deflate-backpointer.patch`), the run is clean.

To reproduce in Bun itself, apply `bun-patches/0001` and `0002`, run
`native/fetch-sources.sh`, `build-cdeps.sh` and `build-clibs.sh`, then:

```sh
EXTRA_RUSTFLAGS="-Clink-arg=@/workspaces/bsan-bun/native/out/clibs.rsp" \
  /workspaces/bsan-bun/scripts/link-loop.sh -p bun_zlib --test bsan_drivers
/workspaces/bsan-bun/scripts/run-each.sh <printed test binary>
# fails: http_body_*, gzip_multi_member_body, websocket_*, reader_truncated_and_corrupt, bun_sync_apis_roundtrip
git apply /workspaces/bsan-bun/bun-patches/fix-zlib-deflate-backpointer.patch   # rebuild and rerun: all 11 pass
```

Logs:

- `results/zlib-deflate-encoder.bsan.log`
- `results/zlib-compressor-arraylist.bsan.log`: the second site, `ZlibCompressorArrayList`. This one is not in the reduced crate.
- `results/zlib-fixed-fast-mode.txt`
- `results/zlib-fixed-default-mode.log`

## 2. bun_ast `new_store!`: `current` taken before the Box moves

`repro/ast-store-current` is `new_store!` expanded for one node type, driven
the way each parse drives it: `create`, `append`, then `reset` from
`StoreResetGuard::drop`.

```
error: Undefined Behavior: reborrow through <364>(unprotected) at alloc76[0x0] is forbidden
    --> main.rs:65:35      let head = store.head.as_deref_mut().expect(...)
help: ... later transitioned to Disabled due to a foreign write access at offsets [0x0..0x20]
    --> core/src/ptr/mod.rs:1966:41      intrinsics::write_via_move(dst, src)   (append's ptr.write(data))
4: Store::reset  5: main
```

The "created here" location prints as line 0 (BSan issue 2 in the README). The
tag belongs to the Box moved by `store.head = Some(first)`. With `fix.diff`
(`store.head.insert(...)`, as in `bun-patches/fix-ast-store-current.patch`),
the run is clean.

To reproduce in Bun itself, using Bun's own tests (apply `0001` and `0003`):

```sh
RUST_MIN_STACK=67108864 /workspaces/bsan-bun/scripts/run-crates.sh bun_parsers
```

Logs:

- `results/ast-store-bun_parsers-env_json.bsan.log`
- `results/bun_parsers-unpatched-per-test.txt`: 21 tests report it.
- `results/bun_parsers-with-ast-store-fix.txt`
- `jsc/repro/F1-new_store.bsan.txt`: the runtime run.

## 3. bun_alloc `ast_alloc`: whole-state reborrow per allocation

`repro/ast-alloc-reborrow` contains `AstAllocState`, `AST_ALLOC`,
`active_state`, `ScopedAstAlloc` and the `AstAlloc` allocator. The spill heap
is left out, because only allocations over 512 bytes reach it. `main` follows
the parser: an `AstVec<Expr>` of call arguments, each visited as `&mut Expr`.
The visit allocates more AST data, then writes the arg back (`*e = current`).

```
error: Undefined Behavior: write access through <486>(StrongProtector) at alloc68[0x0] is forbidden
    --> main.rs:117:5      *e = current;
help: the accessed tag <486>(StrongProtector) was created here      fn e_binary(e: &mut Expr)
help: ... later transitioned to Reserved (conflicted) due to a reborrow (acting as a foreign read access) at offsets [0x0..0x4008]
    --> alloc/src/boxed.rs:2299:9      (Box::deref_mut in active_state(): the whole state, chunk included)
```

With `fix.diff` (raw-pointer bump allocation, as in `jsc/fix-02-ast_alloc.patch`),
the run is clean. In the runtime run, the arg had already been written and was
Unique, so it went to Frozen instead of Reserved (conflicted). The cause is the
same. See `jsc/repro/F3-ast_alloc.bsan.txt` (`bun-debug -e 'console.log(1+1)'`;
build: `jsc/build.sh` and `jsc/bun-bsan-build.patch`).

## 4. bun_jsc VirtualMachine / EventLoop

`repro/vm-eventloop` keeps the VM's allocation and self-pointer wiring from
`VirtualMachine::init`, plus the methods on the two observed paths. JSC and uws
are left out: the loop handle is just a pointer value, and the entry promise
settles on the first tick.

- `--bin ensure_waker` reproduces site (a). `ensure_waker(&mut self)` writes
  `uws_loop`, then `vm_ref()` reborrows the whole VM:

  ```
  error: Undefined Behavior: reborrow through <297>(unprotected) (root of the allocation) at alloc65[0x18] is forbidden
      --> lib.rs:117:58      unsafe { self.virtual_machine.unwrap_unchecked().as_ref() }
      = help: this reborrow (acting as a foreign read access) would cause the protected tag <299>(StrongProtector) (currently Unique) to become Disabled
  help: the protected tag <299> was created here      pub fn ensure_waker(&mut self)
  help: ... transitioned to Unique due to a child write access      self.uws_loop = NonNull::new(loop_get());
  ```

  This is the same diagnostic as the runtime's `jsc/repro/F2-eventloop-vm_ref.bsan.txt`.
  With `--features ensure-waker-fix` (= `jsc/fix-03-ensure_waker-partial.patch`), it is clean.
- `--bin run_start --features ensure-waker-fix` gets past (a) and follows
  `Run::start` → `load_entry_point` → `wait_for_promise` → `EventLoop::tick`.
  `tick` writes through `vm.event_loop`, the self-pointer taken from the VM
  root, while `VirtualMachine::wait_for_promise(&mut self)` is protected:

  ```
  error: Undefined Behavior: write access through <334>(StrongProtector) at alloc65[0x8] is forbidden
     --> lib.rs:87:9      self.entered_event_loop_count += 1;
     = help: the accessed tag <334> is foreign to the protected tag <323>(StrongProtector)
  help: the protected tag <323> was created here      pub fn wait_for_promise(&mut self)   (VirtualMachine)
  0: EventLoop::tick  1: EventLoop::wait_for_promise  2: VirtualMachine::wait_for_promise
  3: VirtualMachine::load_entry_point  4: Run::start  5: main
  ```

  In the runtime run, bun_jsc had retags turned off, so the first protector
  that fired was `Run::start`'s `vm: &mut VirtualMachine`
  (`jsc/repro/F2c-run-start-event_loop.bsan.txt`). With every protector on,
  the innermost one on the same path fires first. Both come from the same
  self-pointer. No fix exists: fixing it means refactoring how the VM is owned.

## BSan issues

- **False positive in float parsing** (`repro/dec2flt-protector`): Bun's
  `parse_number_text` underscore branch under `#![forbid(unsafe_code)]`. Any
  UB report on this code is a BSan false positive, and BSan reports one:
  "deallocation … would cause the protected tag (created in
  `core::num::dec2flt::parse.rs:0`) to become Disabled". The Bun-level log is
  `results/false-positive-dec2flt-bun_parsers-lenient_numbers.bsan.log`.
- **Quadratic exposure** (`repro/adler-hang`, Bun's Adler-32):
  `cargo +bsan bsan test` hangs and uses GBs of memory.
  `BSAN_OPTIONS=wildcard=0 cargo +bsan bsan test` takes 3 s (see `results/notes.txt`).
- **Stale shadow from uninstrumented code**: seen in the runtime run only
  (`jsc/repro/FP1-*`, `FP2-*`, `FP3-*`).
