use libmsl::constants::*;
use libmsl::types::*;
use libmsl::writer::MslWriter;

#[test]
fn test_minimal_msl_starts_with_magic() {
    let mut buf = Vec::new();
    let header = FileHeader::default();
    let writer = MslWriter::new(&mut buf, &header, CompAlgo::None).unwrap();
    writer.finalize().unwrap();

    assert!(buf.len() > HEADER_SIZE);
    assert_eq!(&buf[..8], FILE_MAGIC);
}

#[test]
fn test_header_is_64_bytes() {
    let mut buf = Vec::new();
    let header = FileHeader::default();
    let writer = MslWriter::new(&mut buf, &header, CompAlgo::None).unwrap();
    writer.finalize().unwrap();
    // Header (64) + EoC block; just check total is > 64
    assert!(buf.len() > HEADER_SIZE);
}

#[test]
fn test_endianness_byte() {
    let mut buf = Vec::new();
    let header = FileHeader::default();
    let writer = MslWriter::new(&mut buf, &header, CompAlgo::None).unwrap();
    writer.finalize().unwrap();
    assert_eq!(buf[8], Endianness::Little as u8);
}

#[test]
fn test_header_size_field() {
    let mut buf = Vec::new();
    let header = FileHeader::default();
    let writer = MslWriter::new(&mut buf, &header, CompAlgo::None).unwrap();
    writer.finalize().unwrap();
    assert_eq!(buf[9], HEADER_SIZE as u8);
}

#[test]
fn test_version_field() {
    let mut buf = Vec::new();
    let header = FileHeader::default();
    let writer = MslWriter::new(&mut buf, &header, CompAlgo::None).unwrap();
    writer.finalize().unwrap();
    assert_eq!(buf[10], VERSION_MAJOR);
    assert_eq!(buf[11], VERSION_MINOR);
}

#[test]
fn test_eoc_block_starts_at_64() {
    let mut buf = Vec::new();
    let header = FileHeader::default();
    let writer = MslWriter::new(&mut buf, &header, CompAlgo::None).unwrap();
    writer.finalize().unwrap();
    assert_eq!(&buf[HEADER_SIZE..HEADER_SIZE + 4], BLOCK_MAGIC);
}

#[test]
fn test_eoc_block_type() {
    let mut buf = Vec::new();
    let header = FileHeader::default();
    let writer = MslWriter::new(&mut buf, &header, CompAlgo::None).unwrap();
    writer.finalize().unwrap();
    let block_type = u16::from_le_bytes([buf[HEADER_SIZE + 4], buf[HEADER_SIZE + 5]]);
    assert_eq!(block_type, BlockType::EndOfCapture as u16);
}

#[test]
fn test_eoc_prev_hash_is_header_hash() {
    let mut buf = Vec::new();
    let header = FileHeader::default();
    let writer = MslWriter::new(&mut buf, &header, CompAlgo::None).unwrap();
    writer.finalize().unwrap();

    let header_bytes = &buf[..HEADER_SIZE];
    let expected = blake3::hash(header_bytes);

    let prev_hash_offset = HEADER_SIZE + 48;
    assert_eq!(&buf[prev_hash_offset..prev_hash_offset + 32], expected.as_bytes());
}

#[test]
fn test_eoc_file_hash() {
    let mut buf = Vec::new();
    let header = FileHeader::default();
    let writer = MslWriter::new(&mut buf, &header, CompAlgo::None).unwrap();
    writer.finalize().unwrap();

    let header_bytes = &buf[..HEADER_SIZE];
    let expected = blake3::hash(header_bytes);

    // EoC payload starts after block header at offset HEADER_SIZE + BLOCK_HEADER_SIZE
    let eoc_payload_offset = HEADER_SIZE + BLOCK_HEADER_SIZE;
    let file_hash = &buf[eoc_payload_offset..eoc_payload_offset + 32];
    assert_eq!(file_hash, expected.as_bytes());
}

#[test]
fn test_pid_field() {
    let mut buf = Vec::new();
    let header = FileHeader {
        pid: 42,
        ..FileHeader::default()
    };
    let writer = MslWriter::new(&mut buf, &header, CompAlgo::None).unwrap();
    writer.finalize().unwrap();

    let pid = u32::from_le_bytes(buf[52..56].try_into().unwrap());
    assert_eq!(pid, 42);
}
