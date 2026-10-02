//! Reduced from Bun @ bc7a813b10, src/bun_alloc/ast_alloc.rs. The remaining
//! lines are Bun's. Deleted: the mimalloc spill heap (only requests above
//! BUMP_MAX = 512 bytes reach it), the spare-state recycler, `grow`, and
//! `allocate_zeroed`. `main` is the parser shape from the runtime report
//! (js_parser/visit/visit_expr.rs: `e_call` visits each `AstVec` argument as
//! `&mut Expr`; the visit allocates more AST data and ends with `*e = current`).
//!
//! The bump chunk lives inline in the boxed `AstAllocState`, and every
//! allocation goes through `active_state()`, a fresh `&mut AstAllocState` over
//! the whole state, chunk included. That reborrow is a foreign read for every
//! block carved earlier and freezes it, so a later write to an earlier
//! `AstVec` element is UB.
#![feature(thread_local)]
#![allow(dead_code)] // the fix leaves `bump_alloc`/`active_state` to their other callers in Bun

use core::alloc::{AllocError, Allocator, Layout};
use core::cell::Cell;
use core::mem::MaybeUninit;
use core::ptr::NonNull;

const BUMP_MAX: usize = 512;
const BUMP_CHUNK: usize = 16 * 1024;

pub struct AstAllocState {
    bump_cursor: usize,
    bump_chunk: [MaybeUninit<u8>; BUMP_CHUNK],
}

impl AstAllocState {
    fn new_boxed() -> Box<Self> {
        let mut boxed = Box::<Self>::new_uninit();
        let p = boxed.as_mut_ptr();
        unsafe {
            (&raw mut (*p).bump_cursor).write(0);
            boxed.assume_init()
        }
    }

    fn bump_alloc(&mut self, size: usize, align: usize) -> Option<*mut u8> {
        let cur = unsafe { self.bump_chunk.as_mut_ptr().cast::<u8>().add(self.bump_cursor) };
        let remaining = BUMP_CHUNK - self.bump_cursor;
        let pad = cur.align_offset(align);
        if pad <= remaining && size <= remaining - pad {
            unsafe {
                let aligned = cur.add(pad);
                self.bump_cursor += pad + size;
                Some(aligned)
            }
        } else {
            None
        }
    }
}

#[thread_local]
static AST_ALLOC: Cell<Option<Box<AstAllocState>>> = Cell::new(None);

#[inline(always)]
fn active_state<'a>() -> Option<&'a mut AstAllocState> {
    unsafe { (*AST_ALLOC.as_ptr()).as_deref_mut() }
}

pub fn swap_state(state: Option<Box<AstAllocState>>) -> Option<Box<AstAllocState>> {
    AST_ALLOC.replace(state)
}

pub struct ScopedAstAlloc {
    prev: Option<Box<AstAllocState>>,
}

impl ScopedAstAlloc {
    pub fn with_spill() -> Self {
        let state = AstAllocState::new_boxed(); // acquire_state()
        Self { prev: swap_state(Some(state)) }
    }
}

impl Drop for ScopedAstAlloc {
    fn drop(&mut self) {
        drop(swap_state(self.prev.take())); // release_state()
    }
}

#[derive(Clone, Copy, Default)]
pub struct AstAlloc;
pub type AstVec<T> = Vec<T, AstAlloc>;

fn heap_alloc(layout: Layout) -> *mut u8 {
    let Some(state) = active_state() else { unreachable!("global mimalloc fallback") };
    if layout.size() != 0 && layout.size() <= BUMP_MAX {
        if let Some(p) = state.bump_alloc(layout.size(), layout.align()) {
            return p;
        }
    }
    unreachable!("spill heap")
}

unsafe impl Allocator for AstAlloc {
    fn allocate(&self, layout: Layout) -> Result<NonNull<[u8]>, AllocError> {
        NonNull::new(heap_alloc(layout))
            .map(|p| NonNull::slice_from_raw_parts(p, layout.size()))
            .ok_or(AllocError) // bun_alloc::alloc_result
    }

    unsafe fn deallocate(&self, ptr: NonNull<u8>, layout: Layout) {
        let _ = (ptr, layout);
    }
}

// ── parser shape (js_parser/visit/visit_expr.rs) ────────────────────────────
type Expr = [u64; 2]; // AST payload

fn e_binary(e: &mut Expr) {
    let mut stack: AstVec<Expr> = Vec::with_capacity_in(4, AstAlloc); // more AST data
    stack.push(*e);
    let current = [e[0] + 1, e[1]];
    *e = current;
}

fn main() {
    let _scope = ScopedAstAlloc::with_spill(); // runtime/jsc_hooks.rs: the transpiler's AST scope
    let mut args: AstVec<Expr> = Vec::with_capacity_in(2, AstAlloc); // E::Call args
    args.push([1, 0]);
    args.push([2, 0]);
    for arg in args.iter_mut() {
        e_binary(arg); // p.visit_expr(arg)
    }
    println!("{args:?}");
}
