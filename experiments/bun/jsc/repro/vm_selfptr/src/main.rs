// Reduction of the F2c report: bun_runtime `Run::start(self)` holds `vm: &mut VirtualMachine` (protected, it is a
// field of a by-value argument) and calls `vm.load_entry_point()` -> `wait_for_promise` -> `event_loop_mut()`, which
// returns `&mut *self.event_loop`, a self-pointer to `regular_event_loop` created in `VirtualMachine::init` from the
// VM's root pointer. `EventLoop::tick` then writes `entered_event_loop_count` through it: a foreign write for the
// protected `&mut VirtualMachine`.
struct EventLoop { entered_event_loop_count: usize }
struct VirtualMachine { regular_event_loop: EventLoop, event_loop: *mut EventLoop }
impl VirtualMachine {
    fn event_loop_mut(&mut self) -> &mut EventLoop { unsafe { &mut *self.event_loop } }
    fn wait_for_promise(&mut self) { self.event_loop_mut().tick() }
}
impl EventLoop { fn tick(&mut self) { self.entered_event_loop_count += 1; } }
struct Run<'a> { vm: &'a mut VirtualMachine }
impl Run<'_> {
    fn start(self) { let Run { vm } = self; let _ = vm.regular_event_loop.entered_event_loop_count; vm.wait_for_promise(); }
}
fn main() {
    let vm: *mut VirtualMachine = Box::into_raw(Box::new(VirtualMachine {
        regular_event_loop: EventLoop { entered_event_loop_count: 0 }, event_loop: core::ptr::null_mut() }));
    unsafe {
        (*vm).event_loop = &raw mut (*vm).regular_event_loop; // VirtualMachine::init
        Run { vm: &mut *vm }.start();
        drop(Box::from_raw(vm));
    }
    println!("ok");
}
