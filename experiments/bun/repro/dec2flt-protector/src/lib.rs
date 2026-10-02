//! Safe-Rust shape of bun_parsers' `parse_number_text` (json_stage2.rs): collect digits into
//! a Vec, parse it as f64 through `str::parse`, drop the Vec. No unsafe anywhere.
//! Run: cargo +bsan bsan test
fn parse_digits(text: &[u8]) -> Option<f64> {
    let owned: Vec<u8> = text.iter().copied().filter(|&c| c != b'_').collect();
    core::str::from_utf8(&owned).ok().and_then(|s| s.parse::<f64>().ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_float() {
        assert_eq!(parse_digits(b"1.5"), Some(1.5));
    }

    #[test]
    fn underscored_float() {
        assert_eq!(parse_digits(b"1_000.25"), Some(1000.25));
    }

    #[test]
    fn exponent() {
        assert_eq!(parse_digits(b"1e3"), Some(1000.0));
    }

    #[test]
    fn leading_dot() {
        assert_eq!(parse_digits(b".5"), Some(0.5));
    }

    #[test]
    fn invalid() {
        assert_eq!(parse_digits(b"1e"), None);
    }
}

#[cfg(test)]
mod variants {
    fn with_vec<T>(s: &str, f: impl Fn(&str) -> T) -> T {
        let owned: Vec<u8> = s.as_bytes().to_vec();
        f(core::str::from_utf8(&owned).unwrap())
    }

    #[test]
    fn parse_u64() {
        assert_eq!(with_vec("12345", |s| s.parse::<u64>().unwrap()), 12345);
    }

    #[test]
    fn parse_f32() {
        assert_eq!(with_vec("1.5", |s| s.parse::<f32>().unwrap()), 1.5);
    }

    #[test]
    fn parse_f64_inf() {
        assert_eq!(with_vec("inf", |s| s.parse::<f64>().unwrap()), f64::INFINITY);
    }

    #[test]
    fn parse_f64_static_str() {
        // No heap buffer involved: nothing is freed afterwards.
        assert_eq!("1.5".parse::<f64>().unwrap(), 1.5);
    }
}
