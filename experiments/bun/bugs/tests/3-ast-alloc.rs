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
