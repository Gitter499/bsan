// Reduction of bun_alloc::ast_alloc (src/bun_alloc/ast_alloc.rs): the bump chunk lives *inline* in the boxed
// AstAllocState, and every allocation goes through `active_state()` = `(*AST_ALLOC.as_ptr()).as_deref_mut()`,
// i.e. a fresh `&mut AstAllocState` (Box::deref_mut) covering the whole chunk. That reborrow is a foreign read for
// every pointer previously carved from the chunk, so a block that was written and is written again after a later
// allocation is UB under Tree Borrows.
#![feature(thread_local)]
use core::cell::Cell;
use core::mem::MaybeUninit;
const BUMP_CHUNK: usize = 1024;
pub struct AstAllocState { bump_cursor: usize, bump_chunk: [MaybeUninit<u8>; BUMP_CHUNK] }
impl AstAllocState {
    fn bump_alloc(&mut self, size: usize, align: usize) -> Option<*mut u8> {
        let cur = unsafe { self.bump_chunk.as_mut_ptr().cast::<u8>().add(self.bump_cursor) };
        let remaining = BUMP_CHUNK - self.bump_cursor;
        let pad = cur.align_offset(align);
        if pad <= remaining && size <= remaining - pad {
            unsafe { let a = cur.add(pad); self.bump_cursor += pad + size; Some(a) }
        } else { None }
    }
}
#[thread_local]
static AST_ALLOC: Cell<Option<Box<AstAllocState>>> = Cell::new(None);
fn active_state<'a>() -> Option<&'a mut AstAllocState> { unsafe { (*AST_ALLOC.as_ptr()).as_deref_mut() } }
fn heap_alloc(size: usize, align: usize) -> *mut u8 { active_state().unwrap().bump_alloc(size, align).unwrap() }
fn main() {
    let mut b = Box::<AstAllocState>::new_uninit();
    unsafe { (&raw mut (*b.as_mut_ptr()).bump_cursor).write(0); }
    AST_ALLOC.set(Some(unsafe { b.assume_init() }));
    // e.g. an AstVec<Expr> for call args: allocated and filled ...
    let args = heap_alloc(32, 8) as *mut [u64; 4];
    unsafe { args.write([1, 2, 3, 4]) };
    // ... then visiting allocates more AST data ...
    let _other = heap_alloc(16, 8);
    // ... and writes the visited expression back into the args slot (`*e = current`)
    unsafe { (*args)[0] = 5 };
    println!("ok");
}
