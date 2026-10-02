// RunCommand::boot -> Run::start -> load_entry_point -> wait_for_promise -> EventLoop::tick.
// Built with `--features ensure-waker-fix` so startup gets past the ensure_waker site.
use vm_eventloop::*;
fn main() {
    let vm: &mut VirtualMachine = unsafe { &mut *VirtualMachine::init() };
    Run { vm, entry_path: b"index.js" }.start();
    println!("ok");
}
