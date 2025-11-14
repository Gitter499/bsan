fn dynamic_range() {
    let mut root: Vec<i32> = vec![1, 2, 3];

    let x = &mut root[0];

    unsafe {
        let y = &*(x as *mut i32).add(2);

        println!("{}", y);
    }
}

fn main() {
    dynamic_range();
}
