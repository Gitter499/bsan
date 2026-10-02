// Minimal reproduction of bun_ast::new_store! Store::allocate / reset (src/ast/new_store.rs)
use core::mem::MaybeUninit;
use core::ptr::{addr_of_mut, NonNull};

const BLOCK_SIZE: usize = 256;
#[repr(C, align(16))]
pub struct Block {
    buffer: [MaybeUninit<u8>; BLOCK_SIZE],
    bytes_used: u32,
    next: Option<Box<Block>>,
}
impl Block {
    fn zero(this: &mut MaybeUninit<Block>) {
        let this = this.as_mut_ptr();
        unsafe {
            addr_of_mut!((*this).bytes_used).write(0);
            addr_of_mut!((*this).next).write(None);
        }
    }
    fn try_alloc<T>(block: &mut Block) -> Option<NonNull<T>> {
        let start = ((block.bytes_used as usize) + align_of::<T>() - 1) & !(align_of::<T>() - 1);
        if start + size_of::<T>() > block.buffer.len() { return None; }
        block.bytes_used = (start + size_of::<T>()) as u32;
        Some(unsafe { NonNull::new_unchecked(block.buffer.as_mut_ptr().add(start).cast::<T>()) })
    }
    fn new_boxed() -> Box<Block> {
        let mut b: Box<MaybeUninit<Block>> = Box::new_uninit();
        Block::zero(&mut b);
        unsafe { b.assume_init() }
    }
}
pub struct Store { head: Option<Box<Block>>, current: *mut Block }
impl Store {
    fn reset(store: &mut Store) {
        if store.head.is_none() { return; }
        let mut it: Option<&mut Block> = store.head.as_deref_mut(); // <- BSan reports here
        while let Some(block) = it {
            unsafe { core::ptr::write_bytes(block.buffer.as_mut_ptr(), 0xAA, BLOCK_SIZE) };
            it = block.next.as_deref_mut();
        }
        let head = store.head.as_deref_mut().unwrap();
        head.bytes_used = 0;
        store.current = head;
    }
    fn allocate<T>(store: &mut Store) -> NonNull<T> {
        if store.current.is_null() {
            let mut first = Block::new_boxed();
            store.current = &raw mut *first;
            store.head = Some(first);
        }
        let current: &mut Block = unsafe { &mut *store.current };
        if let Some(p) = Block::try_alloc::<T>(current) { return p; }
        unreachable!()
    }
    fn append<T>(store: &mut Store, data: T) -> NonNull<T> {
        let ptr = Store::allocate::<T>(store);
        unsafe { ptr.as_ptr().write(data) };
        ptr
    }
}
fn main() {
    let mut s = Store { head: None, current: core::ptr::null_mut() };
    Store::append(&mut s, [7u64; 5]); // 40-byte node, like the report's [0x0..0x28]
    Store::reset(&mut s);
    println!("ok");
}
