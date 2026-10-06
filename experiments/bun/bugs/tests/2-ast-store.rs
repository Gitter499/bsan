// What every parse does (e.g. src/parsers/json5.rs): create the node stores,
// allocate a node, reset the stores when the parse ends.
use bun_ast::{E, Expr, Loc, StoreResetGuard};

#[test]
fn parse_lifecycle() {
    bun_ast::initialize_store();
    let _end_of_parse = StoreResetGuard::new();
    Expr::init(E::String::init(b"hello"), Loc { start: 0 });
}
