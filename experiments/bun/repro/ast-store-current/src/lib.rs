//! Pure-Rust replica of bun_ast's `new_store!` Store (src/ast/new_store.rs): `allocate`
//! caches a raw `current` pointer from the first `Box<Block>` and then moves that Box into
//! `head`; callers write values into the returned slots through `current`; `reset` reborrows
//! `head`. Run: MIRIFLAGS=-Zmiri-tree-borrows cargo +bsan miri test
use core::mem::MaybeUninit;
use core::ptr::NonNull;

const BLOCK_SIZE: usize = 64;

#[repr(C, align(16))]
pub struct Block {
    buffer: [MaybeUninit<u8>; BLOCK_SIZE],
    bytes_used: u32,
    next: Option<Box<Block>>,
}

impl Block {
    fn new_boxed() -> Box<Block> {
        Box::new(Block { buffer: [MaybeUninit::uninit(); BLOCK_SIZE], bytes_used: 0, next: None })
    }
    fn try_alloc<T>(block: &mut Block) -> Option<NonNull<T>> {
        let start = (block.bytes_used as usize).next_multiple_of(align_of::<T>());
        if start + size_of::<T>() > BLOCK_SIZE {
            return None;
        }
        block.bytes_used = (start + size_of::<T>()) as u32;
        Some(unsafe { NonNull::new_unchecked(block.buffer.as_mut_ptr().add(start).cast::<T>()) })
    }
}

pub struct Store {
    head: Option<Box<Block>>,
    current: *mut Block,
}

impl Store {
    pub fn new() -> Self {
        Store { head: None, current: core::ptr::null_mut() }
    }

    // Verbatim structure of new_store.rs `allocate`.
    pub fn allocate<T>(store: &mut Store) -> NonNull<T> {
        if store.current.is_null() {
            let mut first = Block::new_boxed();
            store.current = &raw mut *first;
            store.head = Some(first);
        }
        let current: &mut Block = unsafe { &mut *store.current };
        if let Some(ptr) = Block::try_alloc::<T>(current) {
            return ptr;
        }
        let next_block: *mut Block = match &mut current.next {
            Some(next) => {
                next.bytes_used = 0;
                &raw mut **next
            }
            slot @ None => {
                let mut new_block = Block::new_boxed();
                let ptr = &raw mut *new_block;
                *slot = Some(new_block);
                ptr
            }
        };
        store.current = next_block;
        Block::try_alloc::<T>(unsafe { &mut *store.current }).unwrap()
    }

    // Verbatim structure of new_store.rs `reset` (release path).
    pub fn reset(store: &mut Store) {
        if store.head.is_none() {
            return;
        }
        let head_ptr: *mut Block = {
            let head = store.head.as_deref_mut().expect("head is Some");
            head.bytes_used = 0;
            core::ptr::from_mut(head)
        };
        store.current = head_ptr;
    }
}

/// The repaired shape: take `current` from the Box *after* it is in place.
pub fn allocate_fixed<T>(store: &mut Store) -> NonNull<T> {
    if store.current.is_null() {
        let first = store.head.insert(Block::new_boxed());
        store.current = &raw mut **first;
    }
    let current: &mut Block = unsafe { &mut *store.current };
    Block::try_alloc::<T>(current).expect("replica: single block")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bun_shape_allocate_write_reset() {
        let mut store = Store::new();
        let p = Store::allocate::<u64>(&mut store);
        unsafe { p.as_ptr().write(42) }; // callers move the payload into the slot
        Store::reset(&mut store);
        let q = Store::allocate::<u64>(&mut store);
        unsafe { q.as_ptr().write(7) };
    }

    #[test]
    fn fixed_shape_allocate_write_reset() {
        let mut store = Store::new();
        let p = allocate_fixed::<u64>(&mut store);
        unsafe { p.as_ptr().write(42) };
        Store::reset(&mut store);
        let q = allocate_fixed::<u64>(&mut store);
        unsafe { q.as_ptr().write(7) };
    }
}
