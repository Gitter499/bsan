// Same calls Bun makes to gzip an HTTP body (src/http/compress_body.rs, compress_zlib_streaming).
use bun_zlib::{DeflateEncoder, FlushValue};

#[test]
fn gzip_body() {
    let mut encoder = DeflateEncoder::new(6, 15 + 16, 8, 0).unwrap();
    let mut out = Vec::new();
    encoder.step(&b"hello world ".repeat(100), &mut out, 64 * 1024, FlushValue::Finish);
}
