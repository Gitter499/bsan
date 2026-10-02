// Reduction of bun_jsc EventLoop::ensure_waker (src/jsc/event_loop.rs:1062-1070): the EventLoop is embedded in the
// VirtualMachine and holds a NonNull back-pointer to it; a `&mut self` method writes a field and then calls
// `vm_ref()`, which materialises `&VirtualMachine` (covering the EventLoop) from the root pointer.
use core::ptr::NonNull;
struct EventLoop { uws_loop: Option<NonNull<u8>>, virtual_machine: Option<NonNull<VirtualMachine>> }
struct VirtualMachine { event_loop_handle: Option<NonNull<u8>>, regular_event_loop: EventLoop }
impl EventLoop {
    fn vm_ref(&self) -> &'static VirtualMachine { unsafe { self.virtual_machine.unwrap_unchecked().as_ref() } }
    fn ensure_waker(&mut self) {
        if self.uws_loop.is_none() { self.uws_loop = NonNull::new(8 as *mut u8); }
        if self.vm_ref().event_loop_handle.is_none() { /* ... */ }
    }
}
fn main() {
    let vm: *mut VirtualMachine = Box::into_raw(Box::new(VirtualMachine {
        event_loop_handle: None,
        regular_event_loop: EventLoop { uws_loop: None, virtual_machine: None },
    }));
    unsafe {
        (*vm).regular_event_loop.virtual_machine = NonNull::new(vm);
        let el: *mut EventLoop = &raw mut (*vm).regular_event_loop; // VirtualMachine.event_loop
        (*el).ensure_waker();
        drop(Box::from_raw(vm));
    }
    println!("ok");
}
