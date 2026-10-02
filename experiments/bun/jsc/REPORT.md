# BSan on Bun's JSC-linked Rust (bun_runtime + bun_jsc + *_jsc): final report

## Summary
* A full **BorrowSanitizer-instrumented `bun-debug`** builds with Bun's own build system and runs JS. All Rust is
  instrumented, std included; JSC/C++ is not. This was not possible a month ago.
* **3 confirmed Bun bugs (Tree Borrows UB).** All three are on the default startup path, and each also reproduces under BSan
  in a small test on Bun's own code (see `../REPRO.md`):
  - F1: `bun_ast::new_store!`
  - F2: VirtualMachine/EventLoop self-pointer aliasing. Design-level; 3 sites observed.
  - F3: `bun_alloc::ast_alloc` bump allocator.
  The fixes for F1 and F3 are patches against upstream Bun, and BSan passes those points once they are applied.
* **Blocker that stopped the JS test runs:** BSan's shadow provenance goes stale when uninstrumented code writes
  memory: C++ bindings, the JSC prebuilt, or Rust crates I compiled without the pass. An instrumented read of that
  memory then gives bogus UAF/OOB reports (FP1-FP3).
  - These hit on every module load (a `BunString` filled by C++).
  - With Bun's C++ instrumented, they hit in WTF/Gigacage init instead.
  - A report aborts the process, so **no `test/` file ran to completion under BSan**.
  - Coverage is the startup path only: CLI argument parsing, bunfig loading, JS parse/visit/transpile,
    VirtualMachine init, the event loop tick, ConsoleObject formatting, and builtin module fetch.
  - To unblock, BSan needs one of: clear stale shadow for memory written by uninstrumented code; treat a provenance
    whose allocation is dead, or unrelated to the address, as wildcard; or a continue-after-report mode.
  - Once unblocked, run-tests.sh and list-batch1.txt (83 test files) are ready to run.

## Confirmed Bun bugs
#### F1. `bun_ast::new_store!` Store::allocate — raw `current` pointer derived from a Box before the Box is moved (Tree Borrows UB)
* Where: src/ast/new_store.rs, `Store::allocate` (macro `new_store!`, instantiated for the Expr/Stmt AST node
  stores in bun_ast). Two sites: first-block path (`store.current = &raw mut *first; store.head = Some(first);`)
  and the overflow path (`let ptr = &raw mut *new_block; *slot = Some(new_block); ptr`).
* Trigger: any JS/TS parse followed by a store reset — hit on **every** `bun-debug` start (bunfig loading:
  `bun_bunfig::arguments::load_bunfig` -> `StoreResetGuard::drop` -> `Store::reset`).
* Why UB: moving the `Box<Block>` into `store.head` retags it (new tag, Reserved). `current` was derived from the
  pre-move tag, so it is not a child of the Box's new tag; `Store::append`'s `ptr.write(data)` through `current`
  is a *foreign write* that makes the Box tag Disabled. The next use of the Box (`store.head.as_deref_mut()` in
  `reset`, which runs in release builds too, not only the `debug_assertions` poison loop) reborrows through a
  Disabled tag.
* BSan report (bun-debug -e 'console.log(1+1)'): repro/F1-new_store.bsan.txt
* Repro: Bun's own `bun_parsers` test `json::tests::env_json` (../REPRO.md).
* Production reachability: yes (every parse in release builds). Practical miscompilation risk is low today (Box
  `noalias` is only emitted for function parameters), but it is UB under Tree Borrows (and Stacked Borrows).
* Fix (fix-01-new_store.patch): take the raw pointer after the move:
  `store.head = Some(Block::new_boxed()); store.current = &raw mut **store.head.as_mut().unwrap();` and
  `&raw mut **slot.insert(Block::new_boxed())`.
* BSan clean with fix: yes. With fix-01 the startup run gets past `Store::reset`; the next reports have other root causes (F2, F3).
* Independently confirmed by the coordinator (Bun's own `bun_parsers` unit tests under `cargo bsan test`).

#### F3. `bun_alloc::ast_alloc` — every AstAlloc allocation reborrows the whole boxed state incl. the inline bump chunk, freezing earlier allocations (Tree Borrows UB)
* Where: src/bun_alloc/ast_alloc.rs. `AstAllocState` keeps the 16 KiB bump buffer *inline*
  (`bump_chunk: [MaybeUninit<u8>; BUMP_CHUNK]`); `heap_alloc` calls `active_state()` =
  `(*AST_ALLOC.as_ptr()).as_deref_mut()` (line 177) which produces a fresh `&mut AstAllocState` via
  `Box::deref_mut` on every allocation, and `bump_alloc(&mut self)` hands out pointers derived from
  `self.bump_chunk.as_mut_ptr()`.
* Why UB: each new `&mut AstAllocState` reborrow is a foreign read for all blocks previously carved from the chunk;
  blocks that were already written go Active -> Frozen, and the next write through them is UB. In Bun this is the
  normal AST flow: an `AstVec<Expr>` (e.g. call arguments) is allocated and filled, more AST data is allocated while
  visiting, then the visitor writes the result back into the vector slot (`*e = current`,
  src/js_parser/visit/visit_expr.rs:848, `P::e_binary`).
* Hit on every `bun-debug -e 'console.log(1+1)'` (transpile of the entry module). BSan report:
  repro/F3-ast_alloc.bsan.txt (write through a protected `&mut Expr` whose parent tag, created at
  `slice::as_mut_ptr` in `bump_alloc`, was Frozen by a `Box::deref_mut` reborrow of the whole state).
  Identified the reborrow site with gdb (7 `Box<AstAllocState>::deref_mut` calls between the store reset and the
  UB, no Block derefs) — gdb-trace.py, gdb2.log.
* Repro: `bun_alloc` test `tests/bsan_repro.rs` (../bun-patches/0004-bsan-repro-tests.patch); passes with the fix.
* Production: every JS/TS parse with an AST scope installed (runtime transpiler, bundler). Practical
  miscompilation risk: low today, but it is exactly the pattern noalias-based optimisations break.
* Fix (../bun-patches/fix-ast-alloc.patch; also removes the then-unused `bump_alloc`/`heap_ptr`): allocation path uses a raw `*mut AstAllocState` carrying the Box's provenance
  (`&raw mut **box`) and touches only `bump_cursor`/`spill` through raw place expressions
  (`bump_alloc_raw`, `heap_ptr_raw`, `active_state_ptr`). Alternative: keep the chunk in a separately allocated
  buffer referenced by a raw pointer.
* BSan clean with fix: yes. With the fix the run gets past the parser; the next reports are FP1 / F2b, not F3.

#### F2. bun_jsc `EventLoop` (embedded in `VirtualMachine`) reborrows its whole parent VM while `&mut self` is live (Tree Borrows UB; design-level, pervasive)
* Where: src/jsc/event_loop.rs `EventLoop::ensure_waker(&mut self)` (line 1062): writes `self.uws_loop`, then
  `self.vm_ref()` (line 1206: `self.virtual_machine.unwrap_unchecked().as_ref()`) creates `&VirtualMachine`
  from the VM's root pointer. `VirtualMachine.regular_event_loop: EventLoop` is a field of that VM (offset 0x6b38
  in the report), so the shared reborrow of the whole VM is a foreign read of the protected, already-written
  (Unique/Active) `&mut EventLoop` -> Disabled while protected = UB.
* Reached on every startup: `RunCommand::boot` -> `VirtualMachine::init` -> `EventLoop::ensure_waker`.
* BSan report: repro/F2-eventloop-vm_ref.bsan.txt. Reduced repro: ../repro/vm-eventloop `--bin ensure_waker`
  (Bun's VirtualMachine/EventLoop code, trimmed), with the same diagnostic.
* Same root cause, many sites: event_loop.rs has 30 `self.vm_ref()` calls inside `&mut self`/`*mut` methods, and
  several `self.vm_ref().as_mut()` where `VirtualMachine::as_mut(&self) -> &mut VirtualMachine`
  (VirtualMachine.rs:964) mints a `&mut` to the whole VM from the thread-local root pointer while `&self` /
  `&mut EventLoop` borrows of parts of it are live. Counted once here.
* Production: yes (release builds run the same code). Miscompilation risk: moderate-low (the protector on
  `&mut self` lets LLVM assume no other access to the EventLoop during the call; `noalias` on `&mut` params is
  emitted in release), here the VM read does not alias a written field, so currently benign in practice.
* Fix direction: never materialise `&VirtualMachine`/`&mut VirtualMachine` while a `&mut` to an embedded field is
  live; read VM fields through the raw pointer (`(*vm).event_loop_handle` via `addr_of!`), or don't take
  `&mut self` on the embedded EventLoop for methods that reach the VM.
* Observed at runtime (BSan): (a) event_loop.rs:1070 `self.vm_ref()` in `ensure_waker` (repro/F2-eventloop-vm_ref.bsan.txt);
  (b) after patching (a) to a raw field read, the next statement event_loop.rs:1083 `(*gc).init(&mut *vm)` in the
  same `ensure_waker` (repro/F2b-ensure_waker-gc-init.bsan.txt) — same root cause; (c) with bun_jsc retags
  off, the protector moves to bun_runtime: `Run::start(self)` (src/runtime/cli/run_command.rs:1287) holds
  `vm: &mut VirtualMachine` (protected field of a by-value arg) while `vm.load_entry_point()` ->
  `wait_for_promise` -> `event_loop_mut()` (= `&mut *self.event_loop`, the `VirtualMachine.event_loop`
  self-pointer created from the VM root pointer in `init`) -> `EventLoop::tick` writes
  `entered_event_loop_count` (event_loop.rs:770): foreign write to a protected `&mut` = UB
  (repro/F2c-run-start-event_loop.bsan.txt; reduced repro ../repro/vm-eventloop `--bin run_start`. With every
  protector on, it fires first at the innermost one on the same path, `VirtualMachine::wait_for_promise(&mut self)`).
  So the root cause is the VM's self/singleton raw pointers (`VirtualMachine.event_loop`, the thread-local VM
  pointer behind `VirtualMachine::get/as_mut`, `EventLoop.virtual_machine`) coexisting with `&mut VirtualMachine`
  / `&mut EventLoop` borrows; it fires on every program run (first event-loop tick). The other ~28 `vm_ref()` /
  `vm_ref().as_mut()` sites in event_loop.rs are matched by pattern only (NOT observed; they are UB only when the
  `&mut EventLoop` bytes were written before the VM reborrow within the protected call).
* Workaround to keep testing: first tried compiling bun_jsc without BSan (`BSAN_SKIP_CRATES`) -> caused FP1 below;
  final setup compiles bun_jsc **and bun_runtime** with the BSan pass but without retags
  (`BSAN_NORETAG_CRATES=bun_jsc,bun_runtime`): OOB/UAF and provenance tracking stay on there, Tree Borrows
  checks remain on for all other crates (std, bun_core/str/alloc/collections, parsers, *_jsc crates, ...).
  Fixing F2 properly is a VM-ownership refactor, out of scope for a sanitizer run.
* Fix patch: no complete fix (it needs a VM-ownership refactor). fix-03-ensure_waker-partial.patch removes only the first observed site (a); BSan then reports (b) in the same function.

## Likely bugs needing confirmation
* The F2-pattern sites that were matched but not observed (see F2). No others.

## BSan false positives / limitations observed
* **FP1 — stale shadow from uninstrumented Rust (a consequence of `BSAN_SKIP_CRATES`, not a Bun bug).** With
  bun_jsc compiled without the pass, `console.log(1+1, [3,1,2].sort(), ...)` reports
  "an access of size 8b at offset 0xfbd... is out of bounds for alloc114063 of size 40b" inside
  `<i64 as Display>::fmt` called from `bun_core::util::io::Writer::write_fmt` <- `ConsoleObject` (bun_jsc).
  The `fmt::Arguments` were built on the stack by uninstrumented code, which doesn't update shadow provenance, so the
  instrumented reader picks up a stale provenance a previous instrumented frame left at that stack address (the
  huge offset shows the pointer and the provenance are unrelated). The same limitation applies to any pointer that
  uninstrumented C/C++ writes into memory that instrumented Rust later loads. Consequence: skipping crates is only
  safe for leaf crates. bun_jsc was re-instrumented (F2 site patched) instead. Report: repro/FP1-*.bsan.txt.
* **FP2 — stale shadow from uninstrumented C++ (bun's bindings).** "trying to access an allocation that has been
  freed" at src/bun_alloc/lib.rs:814 (`WTFStringImplStruct::latin1_slice`) <- `String::to_utf8` <-
  `__bun_fetch_builtin_module` (src/runtime/jsc_hooks.rs:3621) <- `Bun__fetchBuiltinModule` <- C++
  `Bun::fetchESMSourceCode` (ModuleLoader.cpp:1016). The `BunString` lives in a C++ stack frame and its `impl`
  pointer was stored by uninstrumented C++; Rust loads it and gets the stale shadow provenance of a dead Rust stack
  allocation that previously occupied that address -> bogus UAF. Hit on every module load, so it blocks everything.
  Mitigation: instrument Bun's own C/C++ with the BSan pass too (`BSAN_INSTRUMENT_CXX=1` adds
  `-fpass-plugin=libbsan_plugin.so` to bun-only C/C++ flags; JSC/WebKit prebuilt and vendored deps stay
  uninstrumented). Report: repro/FP2-*.bsan.txt. Suggestion for BSan: clear/poison shadow of a stack frame's
  allocas on return (or at least treat a provenance whose alloc is dead *and* whose address doesn't match as
  wildcard), and/or clear shadow for memory written by uninstrumented callees.
* **FP3: stale shadow inside instrumented C++.** With `BSAN_INSTRUMENT_CXX=1` (added to get rid of FP2), startup
  dies in `WTF::initialize()` -> `Gigacage::ensureGigacage()`. This is inline JSC/bmalloc header code compiled into
  a Bun TU, and the config pointer was written by the uninstrumented WebKit prebuilt. Report: "trying to access an
  allocation that has been freed" in `std::bit_cast`. Same mechanism as FP1/FP2. Report: repro/FP3-*.bsan.txt.
* Not hit here, reported by the coordinator: `str::parse::<f64>()` from a heap buffer gives a protector report in
  core::num::dec2flt (BSan FP: it is safe code, Bun's `json::tests::lenient_numbers`, ../REPRO.md).

## Approach (chosen: build a BSan-instrumented `bun-debug` with Bun's own build system)

Key observations that made this feasible (vs. the attempt a month ago):

* Bun's build (scripts/build/rust.ts) no longer runs one opaque `cargo build`: it asks cargo for the unit graph
  and emits one ninja `rustc` edge per crate, **std included (`-Zbuild-std`)**, appending one list of target
  rustflags (`CARGO_ENCODED_RUSTFLAGS`) to every target unit. Host units (build scripts, proc-macros) don't get
  them. That is exactly cargo-bsan's split, so injecting cargo-bsan's flags there instruments std + all ~100
  workspace crates, and the rlibs go straight into bun's clang++ link.
* Bun already has an ASAN mode that does everything a sanitizer with malloc interceptors needs:
  `#[global_allocator] = std::alloc::System` (instead of mimalloc), mimalloc not overriding libc malloc,
  `default_alloc::*` and C++ `Bun::defaultAllocatorFree` switched to libc. BSan tracks heap allocations only
  through its libc malloc interceptor, so these must be on — I extended the `bun_asan` allocator cfgs to
  `any(bun_asan, bsan)` (and `ASAN_ENABLED || BUN_BSAN` on the C++ side).
* Toolchains line up: Bun needs clang 23 / LLVM 23; the BSan toolchain is nightly 2026-09-26 with LLVM 23.1.1 and
  ships clang-23, so `BUN_TOOLCHAIN_RUST=<bsan toolchain>` + `BUN_TOOLCHAIN_LLVM=/opt/llvm23` work.
* WebKit prebuilt (`bun-webkit-linux-amd64-debug.tar.gz`, 431 MB) downloads fine from GitHub releases through the
  proxy. Tarball deps (codeload, blocked) are pre-populated into Bun's tarball cache via `git fetch` +
  `git archive` (prefetch-tarballs.sh); Bun's own fetcher then extracts/patches/stamps them unchanged.

Build config: debug profile, `--asan=off` (ASAN and BSan runtimes are both sanitizer_common-based and can't
coexist; also the asan WebKit prebuilt needs the asan runtime), UBSan disabled under BSan for the same reason.
C/C++ is NOT instrumented (only Rust). Rust debuginfo reduced to 1 and incremental disabled for disk.

### What the patch does (bun-bsan-build.patch)
* `scripts/build/bsan.ts` (new): `BUN_BSAN=1` switch; BSan rustflags (same as cargo-bsan's
  BSAN_DEFAULT_RUSTFLAGS + `-Zllvm-plugins=libbsan_plugin.so`, `--cap-lints=warn`), link flags
  (`--whole-archive libclang_rt.bsan-x86_64.a`, `libbsan_rt.a`, `-u __bsan_preinit_anchor`, system libs).
* rust.ts: append BSan rustflags, `-Zthreads=2`, `CARGO_INCREMENTAL=0`.
* flags.ts: no UBSan under BSan; BSan link flags; `-DBUN_BSAN=1` for bun's C++.
* deps/mimalloc.ts: no malloc override under BSan.
* Rust: global allocator / default_alloc / USE_MIMALLOC use libc under `cfg(bsan)`.
* MimallocWTFMalloc.h: `defaultAllocatorFree` uses `::free` under BUN_BSAN.

## Infrastructure issues hit so far
1. **Nightly drift** (bsan nightly 09-26 vs Bun's pinned 09-15): `allocator_api` split into `allocator_ext`;
   fixed with the coordinator's bun-toolchain-compat.patch (included in bun-bsan-build.patch) + `--cap-lints=warn`.
2. **Instrumented-codegen memory blow-up (BSan scalability, not a Bun bug).** `bun_css` (61k lines) compiled with
   the BSan flags peaks at **~13 GB RSS in a single CGU** even with `--jobs-backend=1` and `-Ccodegen-units=256`
   (frontend is only ~0.8 GB; the spike is LLVM-side, one module at a time, so a few huge functions —
   `-Zdump-mono-stats` shows `BorderHandler::flush_logical` (10.9k MIR stmts), `flush_physical` (8.7k),
   `prefixes::Feature::prefixes_for` (7.4k), `Property::parse/eql` (3.4k)). On a 15 GB no-swap host shared with
   another build this is not compilable. Workaround: `BSAN_SKIP_CRATES` (new in bsan.ts) compiles listed crates
   without the pass/retags (they still get `--cfg=bsan`); bun_css is pure Rust and out of my scope anyway
   (coordinator covers pure crates). The container is memory-capped (`docker update --memory 10g`) so an OOM
   only kills my build.
3. Disk: stripped debug info from the WebKit prebuilt archives (1.1 GB -> 0.6 GB) and deleted its `jsc`/`testFFI`
   binaries (unused by the link) to stay in budget.


## Reproduction
Everything is under /home/user/bsan-bun/jsc/.
1. Start the container: `/home/user/bsan-bun/start-container.sh bsan-jsc bsan-ready -v /home/user/bun-jsc:/workspaces/bun`,
   then `docker update --memory 10g --memory-swap 10g bsan-jsc`.
2. On a Bun checkout at bc7a813b10, run `git apply bun-bsan-build.patch`. It contains:
   - the build changes: scripts/build/bsan.ts, rust.ts, rust/units.ts, flags.ts, deps/mimalloc.ts;
   - the allocator cfgs and the coordinator's toolchain-compat changes;
   - fixes 01/02/03 and the no-instrument pragma in workaround-missing-symbols.cpp.
   The standalone fix patches are fix-01-new_store.patch and ../bun-patches/fix-ast-alloc.patch; both were checked to
   `git apply` cleanly on upstream. fix-03-ensure_waker-partial.patch is only partial.
3. With env.sh sourced, run `bun run build --asan=off --configure-only`, then
   `prefetch-tarballs.sh build/debug/build.ninja build/cache/tarballs`. The prefetch is git-based because codeload
   is blocked.
4. Run `build.sh`. It sources env.sh and runs `bun run build --asan=off -j2`. The env.sh knobs are:
   - `BSAN_SKIP_CRATES=bun_css`
   - `BSAN_NORETAG_CRATES=bun_jsc,bun_runtime`
   - `BSAN_INSTRUMENT_CXX=1`: the last binary was built with it; unset it to get back to the FP2 state.
   - `BSAN_RUST_DEBUGINFO=line-tables-only`
5. Run `source env.sh; build/debug/bun-debug -e 'console.log(1+1)'`. For tests: `run-tests.sh list-batch1.txt <outdir>`.
6. Repros: `../repro/run.sh`, see ../REPRO.md.
Helper scripts:
- run-unit.py: re-runs one planned rustc unit, for the memory experiments.
- gdb-trace.py: address breakpoints with short backtraces. This is how I found F3's reborrow site (gdb2.log).
- memwatch.sh and diskguard.sh.

## Resource notes
* Peak RSS of instrumented rustc:
  - bun_css: about 13 GB in one CGU. It does not compile on this machine, so it is skipped.
  - bun_runtime: about 5-8 GB, about 20 min.
  - A full Rust rebuild takes about 1 h at -j2; a C++-only rebuild about 30 min.
* Disk: /home/user/bun-jsc is about 5-6.5 GB: rust-target about 2 GB, bun-debug about 1.1 GB, stripped WebKit about
  0.6 GB, C++ objects.
