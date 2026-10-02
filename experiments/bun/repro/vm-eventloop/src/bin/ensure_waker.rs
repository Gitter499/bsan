// VirtualMachine::init -> EventLoop::ensure_waker (every `bun` startup).
fn main() {
    vm_eventloop::VirtualMachine::init();
    println!("ok");
}
