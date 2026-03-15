/// Round `n` up to the next multiple of 8.
pub fn pad8(n: usize) -> usize {
    (n + 7) & !7
}

/// Pad `data` with zero bytes to an 8-byte boundary.
pub fn pad_bytes(data: &[u8]) -> Vec<u8> {
    let padded_len = pad8(data.len());
    let mut out = Vec::with_capacity(padded_len);
    out.extend_from_slice(data);
    out.resize(padded_len, 0);
    out
}

/// UTF-8 encode, null-terminate, pad to 8-byte boundary.
pub fn encode_string(s: &str) -> Vec<u8> {
    let raw_len = s.len() + 1; // +1 for null terminator
    let padded_len = pad8(raw_len);
    let mut out = Vec::with_capacity(padded_len);
    out.extend_from_slice(s.as_bytes());
    out.push(0);
    out.resize(padded_len, 0);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pad8() {
        assert_eq!(pad8(0), 0);
        assert_eq!(pad8(1), 8);
        assert_eq!(pad8(7), 8);
        assert_eq!(pad8(8), 8);
        assert_eq!(pad8(9), 16);
    }

    #[test]
    fn test_pad_bytes() {
        assert_eq!(pad_bytes(b""), b"");
        assert_eq!(pad_bytes(b"a"), b"a\0\0\0\0\0\0\0");
        assert_eq!(pad_bytes(b"12345678"), b"12345678");
        assert_eq!(pad_bytes(b"123456789").len(), 16);
    }

    #[test]
    fn test_encode_string() {
        let result = encode_string("hi");
        // "hi" + null = 3 bytes, padded to 8
        assert_eq!(result.len(), 8);
        assert_eq!(&result[..2], b"hi");
        assert_eq!(result[2], 0); // null terminator
    }
}
