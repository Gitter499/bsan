# Applies the candidate DeflateEncoder/InflateDecoder/step fix to src/zlib/lib.rs (run from Bun root).
p='src/zlib/lib.rs'; s=open(p).read()
def rep(old,new,count=1):
    global s
    assert s.count(old)==count, (old, s.count(old))
    s=s.replace(old,new)
rep('''/// RAII deflate (compression) stream. `deflateEnd` on drop.
pub struct DeflateEncoder {
    strm: Box<zStream_struct>,
}''','''/// Heap-pinned `z_stream` accessed only through the raw pointer zlib was initialized with.
///
/// zlib-ng's `deflate_state` keeps `s->strm` (the pointer passed to `deflateInit2_`) and reads
/// and writes the stream through it inside `deflate()` (`fill_window`/`read_buf`,
/// `deflate_stored`, `trees.c`). Under Tree Borrows that pointer must stay valid across calls,
/// so Rust never creates a `&mut zStream_struct` (a fresh, protected unique borrow) for a live
/// stream; every access goes through the one raw pointer zlib also holds.
struct ZStreamBox(core::ptr::NonNull<zStream_struct>);

impl ZStreamBox {
    fn new() -> Self {
        Self(core::ptr::NonNull::from(Box::leak(Box::new(new_zstream()))))
    }
    #[inline]
    fn ptr(&self) -> *mut zStream_struct {
        self.0.as_ptr()
    }
}

impl Drop for ZStreamBox {
    fn drop(&mut self) {
        // SAFETY: allocated by `Box::new` in `new`; freed exactly once here, after the owner's
        // `deflateEnd`/`inflateEnd`.
        drop(unsafe { Box::from_raw(self.0.as_ptr()) });
    }
}

/// RAII deflate (compression) stream. `deflateEnd` on drop.
pub struct DeflateEncoder {
    strm: ZStreamBox,
}''')
rep('''        let mut this = Self {
            strm: Box::new(new_zstream()),
        };
        // SAFETY: strm is fully initialized; version/size match the linked zlib.
        let rc = unsafe {
            deflateInit2_(
                &raw mut *this.strm,''','''        let this = Self {
            strm: ZStreamBox::new(),
        };
        // SAFETY: strm is fully initialized; version/size match the linked zlib.
        let rc = unsafe {
            deflateInit2_(
                this.strm.ptr(),''')
rep('''        self.strm.avail_out as u32''','''        // SAFETY: strm is live for the lifetime of self.
        unsafe { (*self.strm.ptr()).avail_out as u32 }''',2)
rep('''unsafe { deflateReset(&raw mut *self.strm) }''','''unsafe { deflateReset(self.strm.ptr()) }''')
rep('''&mut self.strm,''','''self.strm.ptr(),''',3)
rep('''unsafe { deflateEnd(&raw mut *self.strm) };''','''unsafe { deflateEnd(self.strm.ptr()) };''')
rep('''    strm: Box<zStream_struct>,
    pub(crate) state: State,''','''    strm: ZStreamBox,
    pub(crate) state: State,''')
rep('''        let mut this = Self {
            strm: Box::new(new_zstream()),
            state: State::Uninitialized,''','''        let this = Self {
            strm: ZStreamBox::new(),
            state: State::Uninitialized,''')
rep('''            inflateInit2_(
                &raw mut *this.strm,''','''            inflateInit2_(
                this.strm.ptr(),''')
rep('''let rc = unsafe { inflateReset(&raw mut *self.strm) };''','''let rc = unsafe { inflateReset(self.strm.ptr()) };''')
rep('''if input.is_empty() && self.strm.avail_in == 0 {''','''// SAFETY: strm is live for the lifetime of self.
                    if input.is_empty() && unsafe { (*self.strm.ptr()).avail_in } == 0 {''')
rep('''unsafe { inflateEnd(&raw mut *self.strm) };''','''unsafe { inflateEnd(self.strm.ptr()) };''')
rep('''fn step(
    strm: &mut zStream_struct,''','''fn step(
    strm: *mut zStream_struct,''')
rep('''    let in_len = input.len().min(u32::MAX as usize);
    strm.next_in = input.as_ptr();
    strm.avail_in = in_len as uInt;

    let spare = out.spare_capacity_mut();
    let out_len = spare.len().min(limit).min(u32::MAX as usize);
    strm.next_out = spare.as_mut_ptr().cast::<u8>();
    strm.avail_out = out_len as uInt;

    // SAFETY: strm was initialized by deflateInit2_/inflateInit2_; input is
    // valid for `in_len` bytes; spare is valid write-only storage for
    // `out_len` bytes. zlib writes at most `out_len - avail_out` bytes.
    let rc = unsafe { op(&raw mut *strm, flush) };

    let produced = out_len - strm.avail_out as usize;''','''    let in_len = input.len().min(u32::MAX as usize);
    let spare = out.spare_capacity_mut();
    let out_len = spare.len().min(limit).min(u32::MAX as usize);
    // SAFETY: strm is the live stream zlib was initialized with (see `ZStreamBox`); field
    // writes go through that same pointer. input is valid for `in_len` bytes; spare is valid
    // write-only storage for `out_len` bytes. zlib writes at most `out_len - avail_out` bytes.
    let (rc, avail_in, avail_out) = unsafe {
        (*strm).next_in = input.as_ptr();
        (*strm).avail_in = in_len as uInt;
        (*strm).next_out = spare.as_mut_ptr().cast::<u8>();
        (*strm).avail_out = out_len as uInt;
        let rc = op(strm, flush);
        (rc, (*strm).avail_in, (*strm).avail_out)
    };

    let produced = out_len - avail_out as usize;''')
rep('''    let consumed = in_len - strm.avail_in as usize;''','''    let consumed = in_len - avail_in as usize;''')

# ── ZlibCompressorArrayList (Bun.deflateSync/gzipSync): same back-pointer issue, with the
# z_stream inline in the struct (so `read_all(&mut self)`'s protector covers it). Move it to a
# ZStreamBox and access it only through that raw pointer.
rep('''pub struct ZlibCompressorArrayList<'a> {
    // We operate directly through `list_ptr` (a `&'a mut Vec<u8>`).
    pub(crate) list_ptr: &'a mut Vec<u8>,
    pub(crate) zlib: zStream_struct,''','''pub struct ZlibCompressorArrayList<'a> {
    // We operate directly through `list_ptr` (a `&'a mut Vec<u8>`).
    pub(crate) list_ptr: &'a mut Vec<u8>,
    /// Separate allocation: zlib-ng keeps a back-pointer to it (see `ZStreamBox`).
    zlib: ZStreamBox,''')
rep('''            unsafe { deflateEnd(&raw mut self.zlib) };
            self.state = ZlibCompressorArrayListState::End;''','''            unsafe { deflateEnd(self.zlib.ptr()) };
            self.state = ZlibCompressorArrayListState::End;''')
rep('''            zlib: bun_core::ffi::zeroed(),
            state: ZlibCompressorArrayListState::Uninitialized,
        });

        let list_len = zlib_reader.list_ptr.len();
        zlib_reader.zlib = zStream_struct {''','''            zlib: ZStreamBox::new(),
            state: ZlibCompressorArrayListState::Uninitialized,
        });

        let list_len = zlib_reader.list_ptr.len();
        let user_data = (&raw mut *zlib_reader).cast::<c_void>();
        // SAFETY: freshly allocated stream, not yet shared with zlib.
        unsafe { *zlib_reader.zlib.ptr() = zStream_struct {''')
rep('''            alloc_func: Some(zlib_mi_malloc),
            free_func: Some(zlib_mi_free),

            internal_state: core::ptr::null_mut(),
            user_data: (&raw mut *zlib_reader).cast::<c_void>(),

            data_type: DataType::Unknown as c_int,
            adler: 0,
            reserved: 0,
        };

        // SAFETY: zlib_reader.zlib is fully initialized; version/size match the linked zlib.
        match unsafe {
            deflateInit2_(
                &raw mut zlib_reader.zlib,''','''            alloc_func: Some(zlib_mi_malloc),
            free_func: Some(zlib_mi_free),

            internal_state: core::ptr::null_mut(),
            user_data,

            data_type: DataType::Unknown as c_int,
            adler: 0,
            reserved: 0,
        } };

        // SAFETY: zlib_reader.zlib is fully initialized; version/size match the linked zlib.
        match unsafe {
            deflateInit2_(
                zlib_reader.zlib.ptr(),''')
rep('''                    deflateBound(
                        &raw mut zlib_reader.zlib,''','''                    deflateBound(
                        zlib_reader.zlib.ptr(),''')
rep('''                zlib_reader.zlib.avail_out = zlib_reader.list_ptr.capacity() as uInt;
                zlib_reader.zlib.next_out = zlib_reader.list_ptr.as_mut_ptr();''','''                // SAFETY: the stream zlib holds; written through the same pointer.
                unsafe {
                    (*zlib_reader.zlib.ptr()).avail_out = zlib_reader.list_ptr.capacity() as uInt;
                    (*zlib_reader.zlib.ptr()).next_out = zlib_reader.list_ptr.as_mut_ptr();
                }''')
# error_message (compressor is the second occurrence; the reader keeps its inline stream)
old_err = '''        if !self.zlib.err_msg.is_null() {
            // SAFETY: err_msg is a NUL-terminated C string from zlib.
            return Some(
                unsafe { bun_core::ffi::cstr(self.zlib.err_msg.cast::<c_char>()) }.to_bytes(),
            );
        }'''
assert s.count(old_err) == 2
i = s.index(old_err, s.index(old_err) + 1)
s = s[:i] + '''        // SAFETY: the live stream (see `ZStreamBox`).
        let err_msg = unsafe { (*self.zlib.ptr()).err_msg };
        if !err_msg.is_null() {
            // SAFETY: err_msg is a NUL-terminated C string from zlib.
            return Some(unsafe { bun_core::ffi::cstr(err_msg.cast::<c_char>()) }.to_bytes());
        }''' + s[i+len(old_err):]
rep('''                if self.zlib.avail_out == 0 {
                    if self.list_ptr.try_reserve(4096).is_err() {''','''                let z = self.zlib.ptr();
                // SAFETY: `z` is the live stream zlib holds (see `ZStreamBox`).
                if unsafe { (*z).avail_out } == 0 {
                    if self.list_ptr.try_reserve(4096).is_err() {''')
rep('''                    let (next_out, avail_out) = unsafe { self.list_ptr.reserve_expand_tail(0) };
                    self.zlib.next_out = next_out;
                    self.zlib.avail_out = avail_out as uInt;
                }

                if self.zlib.avail_out == 0 {
                    return Err(ZlibError::ShortRead);
                }

                // SAFETY: self.zlib was initialized via deflateInit2_.
                let rc = unsafe { deflate(&raw mut self.zlib, FlushValue::Finish) };''','''                    let (next_out, avail_out) = unsafe { self.list_ptr.reserve_expand_tail(0) };
                    // SAFETY: `z` is the live stream zlib holds (see `ZStreamBox`).
                    unsafe {
                        (*z).next_out = next_out;
                        (*z).avail_out = avail_out as uInt;
                    }
                }

                // SAFETY: `z` is the live stream zlib holds (see `ZStreamBox`).
                if unsafe { (*z).avail_out } == 0 {
                    return Err(ZlibError::ShortRead);
                }

                // SAFETY: self.zlib was initialized via deflateInit2_.
                let rc = unsafe { deflate(z, FlushValue::Finish) };''')
rep('''                        unsafe { self.list_ptr.set_len(self.zlib.total_out as usize) };''','''                        unsafe { self.list_ptr.set_len((*z).total_out as usize) };''')
rep('''        self.list_ptr.truncate(self.zlib.total_out as usize);''','''        // SAFETY: the live stream (see `ZStreamBox`).
        self.list_ptr.truncate(unsafe { (*self.zlib.ptr()).total_out } as usize);''')

open(p,'w').write(s)
print("applied")
