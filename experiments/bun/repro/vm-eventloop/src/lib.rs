//! Reduced from Bun @ bc7a813b10: src/jsc/VirtualMachine.rs, src/jsc/event_loop.rs and
//! src/runtime/cli/run_command.rs. The remaining lines are Bun's. JSC and uws are
//! left out: `uws::Loop::get()` / `Async::Loop::get()` stand for the process-global
//! loop handle (only the pointer value is stored), and the entry-point promise
//! settles on the first tick.
//!
//! The VM is one allocation and the thread-local `VM` pointer is its root.
//! `EventLoop` is embedded in it (`regular_event_loop`), points back at it
//! (`virtual_machine`), and the VM points at the loop (`event_loop`). Both
//! self-pointers derive from the root, so they coexist with `&mut` borrows of
//! the VM or loop that their accesses do not respect:
//!  - bin/ensure_waker.rs: `EventLoop::ensure_waker(&mut self)` writes a field,
//!    then `self.vm_ref()` reborrows the whole VM (event_loop.rs:1070/1206).
//!  - bin/run_start.rs: `Run::start` holds `vm: &mut VirtualMachine`, and
//!    `tick` writes through `vm.event_loop` (event_loop.rs:770).
#![feature(thread_local)]

use core::cell::Cell;
use core::ptr::{addr_of_mut, NonNull};

#[thread_local]
static VM: Cell<Option<*mut VirtualMachine>> = Cell::new(None);

// uws::Loop::get() / Async::Loop::get(): the process-global loop.
static mut LOOP: u8 = 0;
fn loop_get() -> *mut u8 {
    &raw mut LOOP
}

pub struct VirtualMachine {
    pub event_loop_handle: Option<NonNull<u8>>,
    pub regular_event_loop: EventLoop,
    pub event_loop: *mut EventLoop, // BORROW_FIELD — points at sibling regular_event_loop
    pub hot_reload: u8,
}

pub struct EventLoop {
    pub entered_event_loop_count: isize,
    pub virtual_machine: Option<NonNull<VirtualMachine>>,
    pub uws_loop: Option<NonNull<u8>>,
}

impl VirtualMachine {
    pub fn init() -> *mut VirtualMachine {
        let layout = core::alloc::Layout::new::<VirtualMachine>();
        let vm: *mut VirtualMachine = unsafe {
            let p = alloc::alloc::alloc_zeroed(layout);
            if p.is_null() {
                alloc::alloc::handle_alloc_error(layout);
            }
            p.cast()
        };
        VM.set(Some(vm));
        unsafe {
            // Event-loop wiring (self-pointers).
            let regular = addr_of_mut!((*vm).regular_event_loop);
            (*regular).virtual_machine = NonNull::new(vm);
            addr_of_mut!((*vm).event_loop).write(regular);
        }
        // JSGlobalObject creation. `ensure_waker()` must run before the FFI.
        unsafe { (*vm).regular_event_loop.ensure_waker() };
        vm
    }

    pub fn get_mut_ptr() -> *mut VirtualMachine {
        unsafe { VM.get().unwrap_unchecked() }
    }

    #[allow(clippy::mut_from_ref)]
    pub fn event_loop_mut(&self) -> &mut EventLoop {
        unsafe { &mut *self.event_loop }
    }

    pub fn wait_for_promise(&mut self) {
        self.event_loop_mut().wait_for_promise()
    }

    pub fn load_entry_point(&mut self, _entry_path: &[u8]) {
        let _ = self.wait_for_promise();
    }
}

extern crate alloc;

impl EventLoop {
    pub fn tick(&mut self) {
        self.entered_event_loop_count += 1;
        self.entered_event_loop_count -= 1;
    }

    pub fn wait_for_promise(&mut self) {
        self.tick();
    }

    pub fn ensure_waker(&mut self) {
        if self.uws_loop.is_none() {
            self.uws_loop = NonNull::new(loop_get());
        }
        // `ensure-waker-fix` = jsc/fix-03-ensure_waker-partial.patch (reads the field through the raw
        // back-pointer), needed to get past this site to the one in bin/run_start.rs.
        #[cfg(not(feature = "ensure-waker-fix"))]
        let no_handle = self.vm_ref().event_loop_handle.is_none();
        #[cfg(feature = "ensure-waker-fix")]
        let no_handle = unsafe { (*self.vm()).event_loop_handle.is_none() };
        if no_handle {
            let vm = self.vm();
            unsafe { (*vm).event_loop_handle = Some(NonNull::new(loop_get()).unwrap()) };
        }
    }

    fn vm(&self) -> *mut VirtualMachine {
        unsafe { self.virtual_machine.unwrap_unchecked().as_ptr() }
    }

    #[allow(dead_code)]
    fn vm_ref(&self) -> &'static VirtualMachine {
        unsafe { self.virtual_machine.unwrap_unchecked().as_ref() }
    }
}

// ── runtime/cli/run_command.rs ──────────────────────────────────────────────
pub struct Run<'a> {
    pub vm: &'a mut VirtualMachine,
    pub entry_path: &'a [u8],
}

impl Run<'_> {
    pub fn start(self) {
        let Run { vm, entry_path: entry } = self;
        vm.hot_reload = 0; // vm.hot_reload = ctx.debug.hot_reload
        vm.load_entry_point(entry);
    }
}
