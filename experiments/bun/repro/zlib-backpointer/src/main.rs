//! Reduced from Bun @ bc7a813b10. Every item is Bun's code with the parts this
//! path does not use deleted; nothing is mocked. zlib is the real zlib-ng Bun
//! vendors, compiled with BSan instrumentation.
//!
//! Path: HTTP `Content-Encoding: gzip` body compression
//!   http/compress_body.rs  compress_zlib_streaming
//!   -> zlib/lib.rs         DeflateEncoder::step -> step(&mut zStream_struct, ..)
//!   -> zlib-ng             deflate -> fill_window: reads s->strm->avail_in
//!
//! `DeflateEncoder::new` hands `&raw mut *this.strm` to `deflateInit2_`, which
//! stores it in `s->strm`. `step` later receives the stream as a protected
//! `&mut`, and zlib-ng accesses it through the stored init-time pointer:
//! a foreign access to a protected tag.

#![allow(non_camel_case_types)]

use core::ffi::{c_char, c_int, c_uint, c_ulong, c_void};
use core::mem::size_of;

// ── zlib_sys/shared.rs ──────────────────────────────────────────────────────
#[repr(C)]
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum ReturnCode { Ok = 0, StreamEnd = 1, NeedDict = 2, ErrNo = -1, StreamError = -2,
    DataError = -3, MemError = -4, BufError = -5, VersionError = -6 }

#[repr(C)]
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum FlushValue { NoFlush = 0, Finish = 4 }

#[repr(C)]
pub struct zStream_struct {
    pub next_in: *const u8,
    pub avail_in: c_uint,
    pub total_in: c_ulong,
    pub next_out: *mut u8,
    pub avail_out: c_uint,
    pub total_out: c_ulong,
    pub err_msg: *const c_char,
    pub internal_state: *mut c_void,
    // Bun passes mimalloc thunks; None = zlib's default malloc/free.
    pub alloc_func: Option<unsafe extern "C" fn(*mut c_void, c_uint, c_uint) -> *mut c_void>,
    pub free_func: Option<unsafe extern "C" fn(*mut c_void, *mut c_void)>,
    pub user_data: *mut c_void,
    pub data_type: c_int,
    pub adler: c_ulong,
    pub reserved: c_ulong,
}
pub type z_streamp = *mut zStream_struct;

// ── zlib/lib.rs ─────────────────────────────────────────────────────────────
unsafe extern "C" {
    pub safe fn zlibVersion() -> *const c_char;
    pub fn deflate(strm: z_streamp, flush: FlushValue) -> ReturnCode;
    pub fn deflateEnd(stream: z_streamp) -> ReturnCode;
    pub fn deflateInit2_(strm: z_streamp, level: c_int, method: c_int, window_bits: c_int,
        mem_level: c_int, strategy: c_int, version: *const u8, stream_size: c_int) -> ReturnCode;
}

/// RAII deflate (compression) stream. `deflateEnd` on drop.
pub struct DeflateEncoder {
    strm: Box<zStream_struct>,
}

impl DeflateEncoder {
    pub fn new(level: c_int, window_bits: c_int, mem_level: c_int, strategy: c_int) -> Self {
        let mut this = Self { strm: Box::new(new_zstream()) };
        // SAFETY: strm is fully initialized; version/size match the linked zlib.
        let rc = unsafe {
            deflateInit2_(
                &raw mut *this.strm,
                level,
                8, // Z_DEFLATED
                window_bits,
                mem_level,
                strategy,
                zlibVersion().cast::<u8>(),
                size_of::<zStream_struct>() as c_int,
            )
        };
        assert_eq!(rc, ReturnCode::Ok);
        this
    }

    pub fn step(&mut self, input: &[u8], out: &mut Vec<u8>, reserve: usize, flush: FlushValue)
        -> (usize, ReturnCode) {
        step(&mut self.strm, input, out, reserve, usize::MAX, flush, deflate)
    }
}

impl Drop for DeflateEncoder {
    fn drop(&mut self) {
        unsafe { deflateEnd(&raw mut *self.strm) };
    }
}

fn new_zstream() -> zStream_struct {
    zStream_struct {
        next_in: core::ptr::null(),
        avail_in: 0,
        total_in: 0,
        next_out: core::ptr::null_mut(),
        avail_out: 0,
        total_out: 0,
        err_msg: core::ptr::null(),
        alloc_func: None,
        free_func: None,
        internal_state: core::ptr::null_mut(),
        user_data: core::ptr::null_mut(),
        data_type: 2, // DataType::Unknown
        adler: 0,
        reserved: 0,
    }
}

/// Shared body of [`DeflateEncoder::step`] / [`InflateDecoder::step`].
fn step(
    strm: &mut zStream_struct,
    input: &[u8],
    out: &mut Vec<u8>,
    reserve: usize,
    limit: usize,
    flush: FlushValue,
    op: unsafe extern "C" fn(*mut zStream_struct, FlushValue) -> ReturnCode,
) -> (usize, ReturnCode) {
    if out.try_reserve(reserve).is_err() {
        return (0, ReturnCode::MemError);
    }

    let in_len = input.len().min(u32::MAX as usize);
    strm.next_in = input.as_ptr();
    strm.avail_in = in_len as c_uint;

    let spare = out.spare_capacity_mut();
    let out_len = spare.len().min(limit).min(u32::MAX as usize);
    strm.next_out = spare.as_mut_ptr().cast::<u8>();
    strm.avail_out = out_len as c_uint;

    let rc = unsafe { op(&raw mut *strm, flush) };

    let produced = out_len - strm.avail_out as usize;
    unsafe { out.set_len(out.len() + produced) }; // bun_core::vec::commit_spare
    let consumed = in_len - strm.avail_in as usize;
    (consumed, rc)
}

// ── http/compress_body.rs ───────────────────────────────────────────────────
fn compress_zlib_streaming(input: &[u8], gzip: bool, level: Option<i32>, out: &mut Vec<u8>) {
    let window_bits = if gzip { 15 + 16 } else { 15 };
    let level = level.unwrap_or(6).min(9);
    let mut encoder = DeflateEncoder::new(level, window_bits, 8, 0);

    let mut remaining = input;
    loop {
        let flush = if remaining.len() <= u32::MAX as usize { FlushValue::Finish } else { FlushValue::NoFlush };
        let reserve = if out.capacity() == out.len() { 64 * 1024 } else { 0 };
        let (consumed, rc) = encoder.step(remaining, out, reserve, flush);
        remaining = &remaining[consumed..];
        match rc {
            ReturnCode::StreamEnd => return,
            ReturnCode::Ok => continue,
            rc => panic!("deflate: {rc:?}"),
        }
    }
}

fn main() {
    let body = b"hello hello hello hello world ".repeat(100);
    let mut out = Vec::new();
    compress_zlib_streaming(&body, true, None, &mut out);
    println!("gzip: {} -> {} bytes", body.len(), out.len());
}
