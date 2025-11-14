fn change(ptr: *mut i32, n: i32) {
    unsafe { *ptr = n };
}

fn cast_to_mut(ptr: *const i32) -> *mut i32 {
    ptr as *mut i32
}

// write through a reference with a Frozen permission.
fn frozen_permission_write_through() {
    let root: i32 = 42;
    // Frozen permission (shared ref)

    let ref_shared = &root;

    let ptr = ref_shared as *const i32;

    change(cast_to_mut(ptr), 12);

    println!("{}", ref_shared);
}

fn main() {
    frozen_permission_write_through();
}
