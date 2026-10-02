//! Reduced from Bun @ bc7a813b10, src/ast/new_store.rs (`new_store!`). The
//! macro is expanded for a single node type, and everything this path does not
//! touch is deleted; the remaining lines are Bun's. `main` is the per-parse
//! lifecycle that `thread_local_ast_store!` drives (`create`, `append` per
//! node, `reset` from `StoreResetGuard::drop`).
//!
//! `allocate` takes `current` from the first `Box<Block>` and then moves the
//! Box into `store.head`, which retags it. Nodes are written through
//! `current`; for the moved Box that is a foreign write, which disables it.
//! `reset` then reborrows `store.head.as_deref_mut()`: UB.

use core::mem::{align_of, size_of, MaybeUninit};
use core::ptr::{addr_of_mut, NonNull};

type Node = [u64; 4]; // any AST payload type
const BLOCK_SIZE: usize = size_of::<Node>() * 256 * 2;

pub struct Store {
    head: Option<Box<Block>>,
    current: *mut Block,
}

#[repr(C, align(16))]
pub struct Block {
    buffer: [MaybeUninit<u8>; BLOCK_SIZE],
    bytes_used: u32,
    next: Option<Box<Block>>,
}

impl Block {
    pub fn zero(this: &mut MaybeUninit<Block>) {
        let this = this.as_mut_ptr();
        unsafe {
            addr_of_mut!((*this).bytes_used).write(0);
            addr_of_mut!((*this).next).write(None);
        }
    }

    pub fn try_alloc<T>(block: &mut Block) -> Option<NonNull<T>> {
        let start = ((block.bytes_used as usize) + align_of::<T>() - 1) & !(align_of::<T>() - 1);
        if start + size_of::<T>() > block.buffer.len() {
            return None;
        }
        block.bytes_used = u32::try_from(start + size_of::<T>()).unwrap();
        Some(unsafe { NonNull::new_unchecked(block.buffer.as_mut_ptr().add(start).cast::<T>()) })
    }

    fn new_boxed() -> Box<Block> {
        let mut b: Box<MaybeUninit<Block>> = Box::new_uninit();
        Block::zero(&mut b);
        unsafe { b.assume_init() }
    }
}

impl Store {
    pub fn init() -> *mut Store {
        Box::into_raw(Box::new(Store { head: None, current: core::ptr::null_mut() }))
    }

    pub fn reset(store: &mut Store) {
        if store.head.is_none() {
            return;
        }
        let head_ptr: *mut Block = {
            let head = store.head.as_deref_mut().expect("head is Some — checked above");
            head.bytes_used = 0;
            core::ptr::from_mut(head)
        };
        store.current = head_ptr;
    }

    fn allocate<T>(store: &mut Store) -> NonNull<T> {
        if store.current.is_null() {
            let mut first = Block::new_boxed();
            store.current = &raw mut *first;
            store.head = Some(first);
        }
        let current: &mut Block = unsafe { &mut *store.current };
        Block::try_alloc::<T>(current).unwrap() // (overflow-block path elided)
    }

    pub fn append<T>(store: &mut Store, data: T) -> NonNull<T> {
        let ptr = Store::allocate::<T>(store);
        unsafe { ptr.as_ptr().write(data) };
        ptr
    }
}

fn main() {
    let store = Store::init(); // thread_local_ast_store!::create
    Store::append::<Node>(unsafe { &mut *store }, [1, 2, 3, 4]); // parser appends a node
    Store::reset(unsafe { &mut *store }); // StoreResetGuard::drop at end of parse
    println!("ok");
}
