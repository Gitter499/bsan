# Bug 2: AST node store writes through a pointer taken before a move

Every parse allocates AST nodes from a block store. When the store creates its first block,
it takes a pointer into the `Box` and *then* moves the `Box` into place. Moving a `Box`
invalidates pointers taken from it before, but nodes are written through that pointer, and
the next `reset` (at the end of every parse) uses the moved `Box`: undefined behavior.

**Where:** [`ast/new_store.rs:273-274`](https://github.com/oven-sh/bun/blob/bc7a813b10b6ef8accc00c931b9a501331ac8c5c/src/ast/new_store.rs#L273-L274) (pointer taken, then the
`Box` moved), [`ast/new_store.rs:236`](https://github.com/oven-sh/bun/blob/bc7a813b10b6ef8accc00c931b9a501331ac8c5c/src/ast/new_store.rs#L236) (`reset` uses the `Box`).

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
// What every parse does (e.g. src/parsers/json5.rs): create the node stores,
// allocate a node, reset the stores when the parse ends.
use bun_ast::{E, Expr, Loc, StoreResetGuard};

#[test]
fn parse_lifecycle() {
    bun_ast::initialize_store();
    let _end_of_parse = StoreResetGuard::new();
    Expr::init(E::String::init(b"hello"), Loc { start: 0 });
}
EOF
```

**3. Run it under BorrowSanitizer:**

```sh
docker run --rm -v "$PWD/repro.rs:/workspaces/bun/src/ast/tests/repro.rs" bun-bsan -p bun_ast --test repro
```

Expected:

```
error: Undefined Behavior: reborrow through <…>(unprotected) at alloc…[0x0] is forbidden
    --> /workspaces/bun/src/ast/new_store.rs:236:69
 236 | let mut it: Option<&mut Block> = store.head.as_deref_mut();
     = help: the accessed tag <…>(unprotected) has state Disabled which forbids this reborrow
help: the accessed tag <…>(unprotected) later transitioned to Disabled due to a foreign write access
```

## Fix

Take the pointer after the `Box` is in place (`store.head.insert(..)`): [`fix-ast-store-current.patch`](https://raw.githubusercontent.com/Gitter499/bsan/8b0bb4228d1d5509812b90058b3fc837e45319b7/experiments/bun/bun-patches/fix-ast-store-current.patch). Same run with the fix applied passes:

```sh
curl -fsSLO https://raw.githubusercontent.com/Gitter499/bsan/8b0bb4228d1d5509812b90058b3fc837e45319b7/experiments/bun/bun-patches/fix-ast-store-current.patch
docker run --rm -e APPLY=/fix.patch -v "$PWD/fix-ast-store-current.patch:/fix.patch" \
  -v "$PWD/repro.rs:/workspaces/bun/src/ast/tests/repro.rs" bun-bsan -p bun_ast --test repro
# test result: ok. 1 passed
```
