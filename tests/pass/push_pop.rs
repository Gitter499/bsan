//@run
fn main() {
    let mut v: Vec<i32> = Vec::new();
    for _ in 0..10 {
        v.push(0);
    }
    for _ in 0..v.len() {
        v.pop();
    }
}
