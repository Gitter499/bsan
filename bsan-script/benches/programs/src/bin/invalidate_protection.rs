fn change(ptr: *mut i32, n: i32) {
    unsafe { *ptr = n };
}

fn cast_to_mut(ptr: *const i32) -> *mut i32 {
    ptr as *mut i32
}

fn protect(x: &mut i32, mut closure: impl FnMut()) -> i32 {
    let ptr = x as *mut i32;
    change(ptr, 16);
    closure();
    *x
}

// reborrowing is your friend
unsafe fn invalidate_protection() {
    let mut root: i32 = 42;

    let shared_ref = &root;

    let ptr = shared_ref as *const i32;

    // reborrow pointer into new reference

    let new_ref = &mut *cast_to_mut(ptr);

    let closure = move || {
        *new_ref = 12;
    };

    protect(&mut root, closure);

    println!("{}", root);
}

fn main() {
    unsafe { invalidate_protection(); }
}
