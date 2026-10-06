# Bug 5: resolver's directory-entry cache invalidates stored entries

The module resolver stores every directory entry it reads in a growing list. Once the list
spills into heap blocks (after about 8,400 entries, which a `node_modules` tree easily reaches),
each new entry takes a `&mut` to the whole block, and starting a new block turns the previous
one back into a `Box`. Both invalidate pointers to entries stored earlier. The resolver later
updates a cached field of such an entry (`Entry::kind`), which is undefined behavior.

**Where:** [`bun_alloc/lib.rs:1642`](https://github.com/oven-sh/bun/blob/bc7a813b10b6ef8accc00c931b9a501331ac8c5c/src/bun_alloc/lib.rs#L1642) (`&mut` to the whole block per entry),
[`bun_alloc/lib.rs:1717`](https://github.com/oven-sh/bun/blob/bc7a813b10b6ef8accc00c931b9a501331ac8c5c/src/bun_alloc/lib.rs#L1717) (old block turned back into a `Box`),
[`resolver/fs.rs:495`](https://github.com/oven-sh/bun/blob/bc7a813b10b6ef8accc00c931b9a501331ac8c5c/src/resolver/fs.rs#L495) (entries stored), [`resolver/fs.rs:222`](https://github.com/oven-sh/bun/blob/bc7a813b10b6ef8accc00c931b9a501331ac8c5c/src/resolver/fs.rs#L222) (later write).

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
// The resolver's directory-entry store (src/resolver/fs.rs): readdir appends entries,
// later Entry::kind() updates a cached field of an entry stored earlier.
use bun_alloc::BSSList;
use core::cell::Cell;

bun_alloc::bss_list! { entries : Cell<u32>, 2 }

#[test]
fn update_entry_after_more_appends() {
    let mut stored = Vec::new();
    for i in 0..600 {
        let slot = unsafe { BSSList::append_uninit(entries()) }.unwrap();
        let p = unsafe { (*slot).as_mut_ptr() };
        unsafe { p.write(Cell::new(i)) };
        stored.push(p);
    }
    unsafe { &*stored[300] }.set(1); // Entry::kind(): self.cache.set(..)
}
EOF
```

**3. Run it under BorrowSanitizer:**

```sh
docker run --rm -v "$PWD/repro.rs:/workspaces/bun/src/bun_alloc/tests/repro.rs" bun-bsan -p bun_alloc --test repro
```

Expected:

```
error: Undefined Behavior: write access through <…>(StrongProtector) at alloc…[0xb8] is forbidden
  = help: the conflicting tag <…>(unprotected) has state Frozen which forbids this child write access
stack backtrace:
0: core::mem::replace::<u32>
1: <core::cell::Cell<u32>>::replace
2: <core::cell::Cell<u32>>::set
```

(Some locations print as `<hash>:0:0`; that is a BorrowSanitizer debug-info issue, not part of the bug.)

## Fix

Hand out entries through raw pointers and keep old blocks as raw pointers until teardown: [`fix-bss-list-append.patch`](https://raw.githubusercontent.com/Gitter499/bsan/8b0bb4228d1d5509812b90058b3fc837e45319b7/experiments/bun/bun-patches/fix-bss-list-append.patch). Same run with the fix applied passes:

```sh
curl -fsSLO https://raw.githubusercontent.com/Gitter499/bsan/8b0bb4228d1d5509812b90058b3fc837e45319b7/experiments/bun/bun-patches/fix-bss-list-append.patch
docker run --rm -e APPLY=/fix.patch -v "$PWD/fix-bss-list-append.patch:/fix.patch" \
  -v "$PWD/repro.rs:/workspaces/bun/src/bun_alloc/tests/repro.rs" bun-bsan -p bun_alloc --test repro
# test result: ok. 1 passed
```
