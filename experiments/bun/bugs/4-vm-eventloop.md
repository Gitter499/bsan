# Bug 4: VM and event loop alias each other

The JavaScript VM contains its event loop, and each holds a raw pointer to the other. Bun calls
event-loop methods with `&mut self` and, inside them, goes back to the whole VM through the
saved pointer (and vice versa: `Run::start` holds `&mut VirtualMachine` while the event loop
writes to the VM through its own pointer). Accessing memory behind a live `&mut` through another
pointer is undefined behavior. It happens on every `bun` run, during startup.

**Where:** [`jsc/event_loop.rs:1070`](https://github.com/oven-sh/bun/blob/bc7a813b10b6ef8accc00c931b9a501331ac8c5c/src/jsc/event_loop.rs#L1070) (`ensure_waker`: `&mut self`, then
`self.vm_ref()`), [`jsc/VirtualMachine.rs:1041`](https://github.com/oven-sh/bun/blob/bc7a813b10b6ef8accc00c931b9a501331ac8c5c/src/jsc/VirtualMachine.rs#L1041) (`event_loop_mut` through the
VM's self-pointer), [`runtime/cli/run_command.rs:1287`](https://github.com/oven-sh/bun/blob/bc7a813b10b6ef8accc00c931b9a501331ac8c5c/src/runtime/cli/run_command.rs#L1287) (`Run::start`).

## Reproduce

There is no small test for this one: the VM can't be created without JavaScriptCore, so it only
shows up in a BorrowSanitizer build of the whole `bun` binary, which takes hours. What
BorrowSanitizer reported on `bun -e 'console.log(1+1)'`:

```
error: Undefined Behavior: reborrow through <…>(unprotected) (root of the allocation) at alloc…[0x6b38] is forbidden
    --> /workspaces/bun/src/jsc/event_loop.rs:1206:58
1206 | unsafe { self.virtual_machine.unwrap_unchecked().as_ref() }
     = help: this reborrow (acting as a foreign read access) would cause the protected tag <…>(StrongProtector) (currently Unique) to become Disabled
help: the protected tag <…>(StrongProtector) was created here
    --> /workspaces/bun/src/jsc/event_loop.rs:1062:0
1062 | pub fn ensure_waker(&mut self) {
```

Full logs: [`F2-eventloop-vm_ref.bsan.txt`](https://raw.githubusercontent.com/Gitter499/bsan/8b0bb4228d1d5509812b90058b3fc837e45319b7/experiments/bun/jsc/repro/F2-eventloop-vm_ref.bsan.txt),
[`F2c-run-start-event_loop.bsan.txt`](https://raw.githubusercontent.com/Gitter499/bsan/8b0bb4228d1d5509812b90058b3fc837e45319b7/experiments/bun/jsc/repro/F2c-run-start-event_loop.bsan.txt).

## Fix

No complete fix yet; it needs a change to how the VM owns its event loop.
[`fix-03-ensure_waker-partial.patch`](https://raw.githubusercontent.com/Gitter499/bsan/8b0bb4228d1d5509812b90058b3fc837e45319b7/experiments/bun/jsc/fix-03-ensure_waker-partial.patch) fixes only the first site.
