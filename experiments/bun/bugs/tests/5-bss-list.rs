// The resolver's directory-entry store (src/resolver/fs.rs): readdir appends entries,
// later Entry::kind() updates a cached field of an entry stored earlier.
use bun_alloc::BSSList;
use core::cell::Cell;

bun_alloc::bss_list! { entries : Cell<u32>, 2 }

#[test]
fn update_entry_after_more_appends() {
    let mut stored = Vec::new();
    for i in 0..600 {
        let slot = unsafe { BSSList::append_uninit(entries()) }.unwrap();
        let p = unsafe { (*slot).as_mut_ptr() };
        unsafe { p.write(Cell::new(i)) };
        stored.push(p);
    }
    unsafe { &*stored[300] }.set(1); // Entry::kind(): self.cache.set(..)
}
