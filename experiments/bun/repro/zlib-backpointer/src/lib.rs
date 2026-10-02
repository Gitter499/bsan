//! Pure-Rust replica of bun_zlib's DeflateEncoder/step (src/zlib/lib.rs) against a mock
//! `deflate` that behaves like zlib-ng: `deflateInit2_` stores the stream pointer in its
//! internal state (`s->strm = strm`), and `deflate()` reads/writes the stream through that
//! stored pointer (`fill_window`/`read_buf`: `s->strm->avail_in -= len`, ...).
//! Run: cargo +bsan miri test   (MIRIFLAGS=-Zmiri-tree-borrows)

#[repr(C)]
pub struct ZStream {
    pub next_in: *const u8,
    pub avail_in: u32,
    pub total_in: u64,
    pub next_out: *mut u8,
    pub avail_out: u32,
    pub total_out: u64,
    pub state: *mut DeflateState,
}

pub struct DeflateState {
    strm: *mut ZStream, // zlib-ng: deflate_state::strm
}

/// mock deflateInit2_: allocate state, remember the stream pointer.
pub unsafe fn deflate_init(strm: *mut ZStream) {
    let s = Box::into_raw(Box::new(DeflateState { strm }));
    unsafe { (*strm).state = s };
}

/// mock deflate(): "compress" by copying, going through the *stored* pointer like
/// zlib-ng's fill_window -> read_buf(s->strm, ...).
pub unsafe fn deflate(strm: *mut ZStream) -> i32 {
    unsafe {
        let s = (*strm).state;
        let st = (*s).strm; // stored pointer, not the argument
        let n = (*st).avail_in.min((*st).avail_out);
        core::ptr::copy_nonoverlapping((*st).next_in, (*st).next_out, n as usize);
        (*st).avail_in -= n; // read_buf: strm->avail_in -= len
        (*st).next_in = (*st).next_in.add(n as usize);
        (*st).total_in += n as u64;
        (*st).avail_out -= n;
        (*st).next_out = (*st).next_out.add(n as usize);
        (*st).total_out += n as u64;
        0
    }
}

pub unsafe fn deflate_end(strm: *mut ZStream) {
    unsafe { drop(Box::from_raw((*strm).state)) };
}

fn new_zstream() -> ZStream {
    ZStream {
        next_in: core::ptr::null(),
        avail_in: 0,
        total_in: 0,
        next_out: core::ptr::null_mut(),
        avail_out: 0,
        total_out: 0,
        state: core::ptr::null_mut(),
    }
}

// ── verbatim structure of bun_zlib (src/zlib/lib.rs) ──────────────────────────
pub struct DeflateEncoder {
    strm: Box<ZStream>,
}

impl DeflateEncoder {
    pub fn new() -> Self {
        let mut this = Self { strm: Box::new(new_zstream()) };
        unsafe { deflate_init(&raw mut *this.strm) };
        this
    }
    pub fn step(&mut self, input: &[u8], out: &mut Vec<u8>, reserve: usize) -> (usize, i32) {
        step(&mut self.strm, input, out, reserve, usize::MAX, deflate)
    }
}

impl Drop for DeflateEncoder {
    fn drop(&mut self) {
        unsafe { deflate_end(&raw mut *self.strm) };
    }
}

fn step(
    strm: &mut ZStream,
    input: &[u8],
    out: &mut Vec<u8>,
    reserve: usize,
    limit: usize,
    op: unsafe fn(*mut ZStream) -> i32,
) -> (usize, i32) {
    out.reserve(reserve);
    let in_len = input.len().min(u32::MAX as usize);
    strm.next_in = input.as_ptr();
    strm.avail_in = in_len as u32;
    let spare = out.spare_capacity_mut();
    let out_len = spare.len().min(limit).min(u32::MAX as usize);
    strm.next_out = spare.as_mut_ptr().cast::<u8>();
    strm.avail_out = out_len as u32;
    let rc = unsafe { op(&raw mut *strm) };
    let produced = out_len - strm.avail_out as usize;
    unsafe { out.set_len(out.len() + produced) };
    let consumed = in_len - strm.avail_in as usize;
    (consumed, rc)
}

// ── the candidate fix: one raw pointer, never a &mut ZStream ──────────────────
pub struct FixedEncoder {
    strm: core::ptr::NonNull<ZStream>,
}

impl FixedEncoder {
    pub fn new() -> Self {
        let strm = core::ptr::NonNull::from(Box::leak(Box::new(new_zstream())));
        unsafe { deflate_init(strm.as_ptr()) };
        Self { strm }
    }
    pub fn step(&mut self, input: &[u8], out: &mut Vec<u8>, reserve: usize) -> (usize, i32) {
        fixed_step(self.strm.as_ptr(), input, out, reserve, usize::MAX, deflate)
    }
}

impl Drop for FixedEncoder {
    fn drop(&mut self) {
        unsafe {
            deflate_end(self.strm.as_ptr());
            drop(Box::from_raw(self.strm.as_ptr()));
        }
    }
}

fn fixed_step(
    strm: *mut ZStream,
    input: &[u8],
    out: &mut Vec<u8>,
    reserve: usize,
    limit: usize,
    op: unsafe fn(*mut ZStream) -> i32,
) -> (usize, i32) {
    out.reserve(reserve);
    let in_len = input.len().min(u32::MAX as usize);
    let spare = out.spare_capacity_mut();
    let out_len = spare.len().min(limit).min(u32::MAX as usize);
    let (rc, avail_in, avail_out) = unsafe {
        (*strm).next_in = input.as_ptr();
        (*strm).avail_in = in_len as u32;
        (*strm).next_out = spare.as_mut_ptr().cast::<u8>();
        (*strm).avail_out = out_len as u32;
        let rc = op(strm);
        (rc, (*strm).avail_in, (*strm).avail_out)
    };
    let produced = out_len - avail_out as usize;
    unsafe { out.set_len(out.len() + produced) };
    (in_len - avail_in as usize, rc)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bun_structure() {
        let mut enc = DeflateEncoder::new();
        let mut out = Vec::new();
        let (consumed, _) = enc.step(b"hello world", &mut out, 64);
        assert_eq!(consumed, 11);
        assert_eq!(out, b"hello world");
    }

    #[test]
    fn fixed_structure() {
        let mut enc = FixedEncoder::new();
        let mut out = Vec::new();
        let (consumed, _) = enc.step(b"hello world", &mut out, 64);
        assert_eq!(consumed, 11);
        assert_eq!(out, b"hello world");
    }
}
