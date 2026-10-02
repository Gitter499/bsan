//! BSan false positive. Reduced from Bun @ bc7a813b10,
//! src/parsers/json_stage2.rs `parse_number_text` (the underscore branch that
//! `json::tests::lenient_numbers` hits with `[1_000_000]`). The lines are Bun's.
//! There is no `unsafe` here (`forbid(unsafe_code)`) and std is sound, so any
//! UB report is a sanitizer false positive.
#![forbid(unsafe_code)]

fn parse_number_text(text: &[u8], underscores: bool) -> Option<f64> {
    let owned: Vec<u8>;
    let digits: &[u8] = if underscores {
        owned = text.iter().copied().filter(|&c| c != b'_').collect();
        &owned
    } else {
        text
    };
    core::str::from_utf8(digits).ok().and_then(|s| s.parse::<f64>().ok())
}

fn main() {
    println!("{:?}", parse_number_text(b"1_000_000", true));
}
