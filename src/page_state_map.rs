use crate::types::PageState;

/// Encode page states as 2 bits per page, MSB-first packing.
///
/// Each byte holds 4 page states:
/// bits 7-6 = page 0, bits 5-4 = page 1, bits 3-2 = page 2, bits 1-0 = page 3.
pub fn encode_page_state_map(page_states: &[PageState]) -> Vec<u8> {
    if page_states.is_empty() {
        return Vec::new();
    }

    let num_bytes = page_states.len().div_ceil(4);
    let mut result = vec![0u8; num_bytes];

    for (i, state) in page_states.iter().enumerate() {
        let byte_idx = i / 4;
        let bit_pos = 6 - (i % 4) * 2; // 6, 4, 2, 0
        result[byte_idx] |= (*state as u8 & 0x03) << bit_pos;
    }

    result
}

/// Decode a page state map back into page states.
pub fn decode_page_state_map(data: &[u8], num_pages: usize) -> Vec<PageState> {
    let mut states = Vec::with_capacity(num_pages);

    for i in 0..num_pages {
        let byte_idx = i / 4;
        let bit_pos = 6 - (i % 4) * 2;
        let value = (data[byte_idx] >> bit_pos) & 0x03;
        states.push(PageState::try_from(value).unwrap_or(PageState::Unmapped));
    }

    states
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty() {
        assert_eq!(encode_page_state_map(&[]), Vec::<u8>::new());
    }

    #[test]
    fn test_single_captured() {
        // CAPTURED(00) -> bits 7-6 = 00, rest = 00 -> 0x00
        let result = encode_page_state_map(&[PageState::Captured]);
        assert_eq!(result, vec![0x00]);
    }

    #[test]
    fn test_four_states() {
        // CAPTURED(00), FAILED(01), UNMAPPED(10), CAPTURED(00)
        // bits: 00_01_10_00 = 0x18
        let result = encode_page_state_map(&[
            PageState::Captured,
            PageState::Failed,
            PageState::Unmapped,
            PageState::Captured,
        ]);
        assert_eq!(result, vec![0x18]);
    }

    #[test]
    fn test_mixed_three_states() {
        // CAPTURED(00), FAILED(01), CAPTURED(00)
        // bits: 00_01_00_00 = 0x10
        let result = encode_page_state_map(&[
            PageState::Captured,
            PageState::Failed,
            PageState::Captured,
        ]);
        assert_eq!(result, vec![0x10]);
    }

    #[test]
    fn test_roundtrip() {
        let states = vec![
            PageState::Captured,
            PageState::Failed,
            PageState::Unmapped,
            PageState::Captured,
            PageState::Failed,
        ];
        let encoded = encode_page_state_map(&states);
        let decoded = decode_page_state_map(&encoded, states.len());
        assert_eq!(decoded, states);
    }
}
