# Bug 3: AST allocator invalidates earlier allocations

The parser allocates small AST lists from a bump buffer inside one big state object. Every
new allocation takes a `&mut` to the *whole* state, buffer included. That invalidates the
pointers to everything allocated before, so when the parser then writes into an earlier list
(e.g. writing a visited call argument back, `*e = current`), it is undefined behavior.

**Where:** [`bun_alloc/ast_alloc.rs:177`](https://github.com/oven-sh/bun/blob/bc7a813b10b6ef8accc00c931b9a501331ac8c5c/src/bun_alloc/ast_alloc.rs#L177) (`&mut` to the whole state on
every allocation), [`bun_alloc/ast_alloc.rs:350`](https://github.com/oven-sh/bun/blob/bc7a813b10b6ef8accc00c931b9a501331ac8c5c/src/bun_alloc/ast_alloc.rs#L350),
[`js_parser/visit/visit_expr.rs:848`](https://github.com/oven-sh/bun/blob/bc7a813b10b6ef8accc00c931b9a501331ac8c5c/src/js_parser/visit/visit_expr.rs#L848) (the write-back).

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
// The parser's pattern (src/js_parser/visit/visit_expr.rs): visit each call argument as
// `&mut`; visiting allocates more AST data, then writes the result back (`*e = current`).
use bun_alloc::MimallocArena;
use bun_alloc::ast_alloc::{AstAlloc, AstVec, ScopedAstAlloc};

fn visit(e: &mut u64) {
    let _more: AstVec<u64> = AstAlloc::vec_with_capacity(4);
    *e += 1;
}

#[test]
fn visit_call_args() {
    let arena = MimallocArena::new();
    let _scope = ScopedAstAlloc::with_spill(arena.heap_ptr());
    let mut args: AstVec<u64> = AstAlloc::vec_with_capacity(2);
    args.push(1);
    args.push(2);
    for arg in args.iter_mut() {
        visit(arg);
    }
}
EOF
```

**3. Run it under BorrowSanitizer:**

```sh
docker run --rm -v "$PWD/repro.rs:/workspaces/bun/src/bun_alloc/tests/repro.rs" bun-bsan -p bun_alloc --test repro
```

Expected:

```
error: Undefined Behavior: write access through <…>(StrongProtector) at alloc…[0x0] is forbidden
  = help: the accessed tag <…>(StrongProtector) has state Reserved (conflicted) which forbids this child write access
help: the accessed tag <…> later transitioned to Reserved (conflicted) due to a reborrow (acting as a foreign read access) at offsets [0x0..0x4010]
stack backtrace:
0: repro::visit
1: repro::visit_call_args
```

(Some locations print as `<hash>:0:0`; that is a BorrowSanitizer debug-info issue, not part of the bug.)

## Fix

Allocate through a raw pointer to the state instead of a `&mut`: [`fix-ast-alloc.patch`](https://raw.githubusercontent.com/Gitter499/bsan/8b0bb4228d1d5509812b90058b3fc837e45319b7/experiments/bun/bun-patches/fix-ast-alloc.patch). Same run with the fix applied passes:

```sh
curl -fsSLO https://raw.githubusercontent.com/Gitter499/bsan/8b0bb4228d1d5509812b90058b3fc837e45319b7/experiments/bun/bun-patches/fix-ast-alloc.patch
docker run --rm -e APPLY=/fix.patch -v "$PWD/fix-ast-alloc.patch:/fix.patch" \
  -v "$PWD/repro.rs:/workspaces/bun/src/bun_alloc/tests/repro.rs" bun-bsan -p bun_alloc --test repro
# test result: ok. 1 passed
```
