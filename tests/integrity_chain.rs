use libmsl::constants::*;
use libmsl::types::*;
use libmsl::writer::MslWriter;

#[test]
fn test_integrity_chain_minimal() {
    let mut buf = Vec::new();
    let header = FileHeader::default();
    let writer = MslWriter::new(&mut buf, &header, CompAlgo::None).unwrap();
    writer.finalize().unwrap();

    // Block 0 (EoC) PrevHash = BLAKE3(file header)
    let header_hash = blake3::hash(&buf[..HEADER_SIZE]);
    let prev_hash = &buf[HEADER_SIZE + 48..HEADER_SIZE + 48 + 32];
    assert_eq!(prev_hash, header_hash.as_bytes());

    // FileHash in EoC = BLAKE3(everything before EoC)
    let file_hash = &buf[HEADER_SIZE + BLOCK_HEADER_SIZE..HEADER_SIZE + BLOCK_HEADER_SIZE + 32];
    let expected = blake3::hash(&buf[..HEADER_SIZE]);
    assert_eq!(file_hash, expected.as_bytes());
}

#[test]
fn test_integrity_chain_with_region() {
    let mut buf = Vec::new();
    let header = FileHeader { pid: 123, ..FileHeader::default() };
    let mut writer = MslWriter::new(&mut buf, &header, CompAlgo::None).unwrap();

    let region = MemoryRegionPayload {
        base_addr: 0x1000,
        region_size: 4096,
        protection: 1,
        region_type: RegionType::Anon,
        page_size: 4096,
        num_pages: 1,
        timestamp_ns: 0,
        page_states: vec![PageState::Captured],
        page_data: vec![0xCCu8; 4096],
    };
    writer.write_memory_region(&region, None).unwrap();
    writer.finalize().unwrap();

    let data = &buf;

    // Block 0 (MemoryRegion) PrevHash = BLAKE3(header)
    let header_hash = blake3::hash(&data[..HEADER_SIZE]);
    assert_eq!(
        &data[HEADER_SIZE + 48..HEADER_SIZE + 80],
        header_hash.as_bytes()
    );

    // Block 1 (EoC): find it
    let block0_len = u32::from_le_bytes(data[HEADER_SIZE + 8..HEADER_SIZE + 12].try_into().unwrap()) as usize;
    let block1_start = HEADER_SIZE + block0_len;

    // Block 1 PrevHash = BLAKE3(block0_bytes)
    let block0_bytes = &data[HEADER_SIZE..HEADER_SIZE + block0_len];
    let block0_hash = blake3::hash(block0_bytes);
    assert_eq!(
        &data[block1_start + 48..block1_start + 80],
        block0_hash.as_bytes()
    );

    // EoC FileHash = BLAKE3(everything before EoC)
    let eoc_payload_start = block1_start + BLOCK_HEADER_SIZE;
    let file_hash = &data[eoc_payload_start..eoc_payload_start + 32];
    let expected = blake3::hash(&data[..block1_start]);
    assert_eq!(file_hash, expected.as_bytes());
}

#[test]
fn test_integrity_validation_via_reader() {
    use libmsl::reader::MslSliceReader;

    let mut buf = Vec::new();
    let header = FileHeader { pid: 456, ..FileHeader::default() };
    let mut writer = MslWriter::new(&mut buf, &header, CompAlgo::None).unwrap();

    let region = MemoryRegionPayload {
        base_addr: 0x5000,
        region_size: 8192,
        protection: 7,
        region_type: RegionType::Stack,
        page_size: 4096,
        num_pages: 2,
        timestamp_ns: 0,
        page_states: vec![PageState::Captured, PageState::Captured],
        page_data: vec![0xFFu8; 8192],
    };
    writer.write_memory_region(&region, None).unwrap();
    writer.finalize().unwrap();

    let reader = MslSliceReader::new(&buf);
    reader.validate_integrity().unwrap(); // Should not panic/error
}

#[test]
fn test_integrity_detects_corruption() {
    use libmsl::reader::MslSliceReader;

    let mut buf = Vec::new();
    let header = FileHeader::default();
    let writer = MslWriter::new(&mut buf, &header, CompAlgo::None).unwrap();
    writer.finalize().unwrap();

    // Corrupt a byte in the file header
    buf[20] ^= 0xFF;

    let reader = MslSliceReader::new(&buf);
    assert!(reader.validate_integrity().is_err());
}
