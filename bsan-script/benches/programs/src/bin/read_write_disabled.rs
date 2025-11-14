fn change(ptr: *mut i32, n: i32) {
    unsafe { *ptr = n };
}

// read or write through a reference with Disabled permission.
fn read_write_disabled() {
    let mut root: i32 = 42;

    // get mutable pointer to root
    let ptr = &mut root as *mut i32;

    let reserved = &mut root;

    change(ptr, 12);

    // reserved is now Disabled

    let _reserved_ptr = reserved as *mut i32;

    // write
    change(ptr, 16);
    // read
    println!("{}", reserved);
}

fn main() {
    read_write_disabled();
}
