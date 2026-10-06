# Bug 6: `bun build --compile` for macOS writes through a read-only reference

To build a macOS executable, Bun copies a macOS `bun` binary and patches its load commands.
It walks the load commands with an iterator over a *shared* (`&`) view of the bytes, then writes
the updated commands through pointers taken from that shared view. Writing through a pointer
derived from a shared reference is undefined behavior; the compiler may assume those bytes never
change.

**Where:** [`exe_format/macho.rs:486`](https://github.com/oven-sh/bun/blob/bc7a813b10b6ef8accc00c931b9a501331ac8c5c/src/exe_format/macho.rs#L486) (iterator over `&self.data`),
[`exe_format/macho.rs:384`](https://github.com/oven-sh/bun/blob/bc7a813b10b6ef8accc00c931b9a501331ac8c5c/src/exe_format/macho.rs#L384) (`as_ptr().cast_mut()`), writes at lines 403–475;
called from [`standalone_graph/StandaloneModuleGraph.rs:2312`](https://github.com/oven-sh/bun/blob/bc7a813b10b6ef8accc00c931b9a501331ac8c5c/src/standalone_graph/StandaloneModuleGraph.rs#L2312).
The image includes the template Bun downloads for `--target=bun-darwin-x64` (`bun-v1.4.2`).

## Reproduce

**1. Build the image (once, ~45 min, ~12 GB).** It is BorrowSanitizer's public image plus
Bun at commit `bc7a813b10`, unmodified:

```sh
docker build -t bun-bsan -f docker/Dockerfile \
  "https://github.com/Gitter499/bsan.git#8b0bb4228d1d5509812b90058b3fc837e45319b7:experiments/bun"
```

**2. Save the test** (the only thing added to Bun):

```sh
cat > repro.rs <<'EOF'
// Same calls as `bun build --compile --target=bun-darwin-x64`
// (src/standalone_graph/StandaloneModuleGraph.rs: MachoFile::init + write_section).
use bun_exe_format::macho::MachoFile;

#[test]
fn compile_for_macos() {
    let template = std::fs::read("/templates/bun-darwin-x64/bun").unwrap();
    let module_graph = vec![0u8; 1 << 20];
    let mut exe = MachoFile::init(&template, module_graph.len()).unwrap();
    exe.write_section(&module_graph).unwrap();
}
EOF
```

**3. Run it under BorrowSanitizer:**

```sh
docker run --rm -v "$PWD/repro.rs:/workspaces/bun/src/exe_format/tests/repro.rs" bun-bsan -p bun_exe_format --test repro
```

Expected:

```
error: Undefined Behavior: write access through <…>(unprotected) at alloc…[0x810] is forbidden
    --> /workspaces/bun/src/exe_format/macho.rs:453:25
 453 | core::ptr::write_unaligned(
     = help: the accessed tag <…>(unprotected) has state Frozen which forbids this child write access
help: the accessed tag <…>(unprotected) was created here, in the initial state Frozen
    --> …/core/src/slice/mod.rs:730:0
 730 | pub const fn as_ptr(&self) -> *const T {
```

## Fix

Collect the commands first, then write through a pointer taken from `&mut self.data`: [`fix-macho-load-command-writes.patch`](https://raw.githubusercontent.com/Gitter499/bsan/8b0bb4228d1d5509812b90058b3fc837e45319b7/experiments/bun/bun-patches/fix-macho-load-command-writes.patch). Same run with the fix applied passes:

```sh
curl -fsSLO https://raw.githubusercontent.com/Gitter499/bsan/8b0bb4228d1d5509812b90058b3fc837e45319b7/experiments/bun/bun-patches/fix-macho-load-command-writes.patch
docker run --rm -e APPLY=/fix.patch -v "$PWD/fix-macho-load-command-writes.patch:/fix.patch" \
  -v "$PWD/repro.rs:/workspaces/bun/src/exe_format/tests/repro.rs" bun-bsan -p bun_exe_format --test repro
# test result: ok. 1 passed
```
