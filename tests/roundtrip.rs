use libmsl::constants::*;
use libmsl::types::*;
use libmsl::writer::MslWriter;
use libmsl::reader::MslSliceReader;

fn make_test_header() -> FileHeader {
    FileHeader {
        endianness: Endianness::Little,
        version_major: VERSION_MAJOR,
        version_minor: VERSION_MINOR,
        flags: 0,
        cap_bitmap: 0x03,
        dump_uuid: *uuid::Uuid::new_v4().as_bytes(),
        timestamp_ns: 1_000_000_000,
        os_type: OsType::Linux,
        arch_type: ArchType::X86_64,
        pid: 9999,
    }
}

#[test]
fn test_roundtrip_header_only() {
    let mut buf = Vec::new();
    let header = make_test_header();
    let writer = MslWriter::new(&mut buf, &header, CompAlgo::None).unwrap();
    writer.finalize().unwrap();

    let mut reader = MslSliceReader::new(&buf);
    let read_header = reader.read_header().unwrap();
    assert_eq!(read_header.pid, 9999);
    assert_eq!(read_header.os_type, OsType::Linux);
    assert_eq!(read_header.arch_type, ArchType::X86_64);
    assert_eq!(read_header.cap_bitmap, 0x03);

    let block = reader.next_block().unwrap().unwrap();
    assert!(matches!(block, Block::EndOfCapture { .. }));
    assert!(reader.next_block().unwrap().is_none());
}

#[test]
fn test_roundtrip_with_regions() {
    let mut buf = Vec::new();
    let header = make_test_header();
    let mut writer = MslWriter::new(&mut buf, &header, CompAlgo::None).unwrap();

    // Region 1: 2 captured pages
    let region1 = MemoryRegionPayload {
        base_addr: 0x10000,
        region_size: 8192,
        protection: 5,
        region_type: RegionType::Image,
        page_size: 4096,
        num_pages: 2,
        timestamp_ns: 1_000_000_000,
        page_states: vec![PageState::Captured, PageState::Captured],
        page_data: [vec![0xAAu8; 4096], vec![0xBBu8; 4096]].concat(),
    };
    writer.write_memory_region(&region1, None).unwrap();

    // Region 2: mixed states
    let region2 = MemoryRegionPayload {
        base_addr: 0x20000,
        region_size: 4096 * 3,
        protection: 3,
        region_type: RegionType::Heap,
        page_size: 4096,
        num_pages: 3,
        timestamp_ns: 1_000_000_000,
        page_states: vec![PageState::Captured, PageState::Failed, PageState::Captured],
        page_data: [vec![0x11u8; 4096], vec![0x22u8; 4096]].concat(),
    };
    writer.write_memory_region(&region2, None).unwrap();

    writer.finalize().unwrap();

    // Read back
    let mut reader = MslSliceReader::new(&buf);
    let read_header = reader.read_header().unwrap();
    assert_eq!(read_header.pid, 9999);

    // Block 0: MemoryRegion
    let block0 = reader.next_block().unwrap().unwrap();
    match &block0 {
        Block::MemoryRegion { payload, .. } => {
            assert_eq!(payload.base_addr, 0x10000);
            assert_eq!(payload.region_size, 8192);
            assert_eq!(payload.protection, 5);
            assert_eq!(payload.region_type, RegionType::Image);
            assert_eq!(payload.num_pages, 2);
            assert_eq!(payload.page_states, vec![PageState::Captured, PageState::Captured]);
            assert_eq!(&payload.page_data[..4096], &[0xAAu8; 4096]);
            assert_eq!(&payload.page_data[4096..8192], &[0xBBu8; 4096]);
        }
        _ => panic!("Expected MemoryRegion"),
    }

    // Block 1: MemoryRegion
    let block1 = reader.next_block().unwrap().unwrap();
    match &block1 {
        Block::MemoryRegion { payload, .. } => {
            assert_eq!(payload.base_addr, 0x20000);
            assert_eq!(payload.num_pages, 3);
            assert_eq!(
                payload.page_states,
                vec![PageState::Captured, PageState::Failed, PageState::Captured]
            );
        }
        _ => panic!("Expected MemoryRegion"),
    }

    // Block 2: EoC
    let block2 = reader.next_block().unwrap().unwrap();
    assert!(matches!(block2, Block::EndOfCapture { .. }));
}

#[test]
fn test_roundtrip_with_modules() {
    let mut buf = Vec::new();
    let header = make_test_header();
    let mut writer = MslWriter::new(&mut buf, &header, CompAlgo::None).unwrap();

    let modules = vec![
        ModuleEntryPayload {
            base_addr: 0x400000,
            module_size: 0x10000,
            path: "/usr/lib/libc.so.6".to_string(),
            version: "2.31".to_string(),
            disk_hash: [0u8; 32],
            native_blob: Vec::new(),
        },
        ModuleEntryPayload {
            base_addr: 0x7f0000,
            module_size: 0x5000,
            path: "/lib/ld.so".to_string(),
            version: String::new(),
            disk_hash: [0u8; 32],
            native_blob: vec![0xDE, 0xAD],
        },
    ];
    writer.write_module_list(&modules).unwrap();
    writer.finalize().unwrap();

    // Read back
    let mut reader = MslSliceReader::new(&buf);
    reader.read_header().unwrap();

    // Block 0: ModuleListIndex
    let block0 = reader.next_block().unwrap().unwrap();
    match &block0 {
        Block::ModuleListIndex { header, payload } => {
            assert_eq!(payload.count, 2);
            assert_eq!(header.flags & HAS_CHILDREN, HAS_CHILDREN);
        }
        _ => panic!("Expected ModuleListIndex"),
    }

    // Block 1: ModuleEntry
    let block1 = reader.next_block().unwrap().unwrap();
    match &block1 {
        Block::ModuleEntry { header: blk_hdr, payload } => {
            assert_eq!(payload.base_addr, 0x400000);
            assert_eq!(payload.path, "/usr/lib/libc.so.6");
            assert_eq!(payload.version, "2.31");
            // Parent UUID should match index block
            if let Block::ModuleListIndex { header: idx_hdr, .. } = &block0 {
                assert_eq!(blk_hdr.parent_uuid, idx_hdr.block_uuid);
            }
        }
        _ => panic!("Expected ModuleEntry"),
    }

    // Block 2: ModuleEntry
    let block2 = reader.next_block().unwrap().unwrap();
    match &block2 {
        Block::ModuleEntry { payload, .. } => {
            assert_eq!(payload.path, "/lib/ld.so");
            assert_eq!(payload.native_blob, vec![0xDE, 0xAD]);
        }
        _ => panic!("Expected ModuleEntry"),
    }

    // Block 3: EoC
    let block3 = reader.next_block().unwrap().unwrap();
    assert!(matches!(block3, Block::EndOfCapture { .. }));
}

#[test]
fn test_block_sequence_types() {
    let mut buf = Vec::new();
    let header = make_test_header();
    let mut writer = MslWriter::new(&mut buf, &header, CompAlgo::None).unwrap();

    let region = MemoryRegionPayload {
        base_addr: 0x10000,
        region_size: 8192,
        protection: 5,
        region_type: RegionType::Image,
        page_size: 4096,
        num_pages: 2,
        timestamp_ns: 1_000_000_000,
        page_states: vec![PageState::Captured, PageState::Captured],
        page_data: vec![0xAAu8; 8192],
    };
    writer.write_memory_region(&region, None).unwrap();
    writer.write_memory_region(&region, None).unwrap();

    let modules = vec![
        ModuleEntryPayload {
            base_addr: 0x400000,
            module_size: 0x10000,
            path: "/usr/lib/libc.so.6".to_string(),
            version: "2.31".to_string(),
            disk_hash: [0u8; 32],
            native_blob: Vec::new(),
        },
        ModuleEntryPayload {
            base_addr: 0x7f0000,
            module_size: 0x5000,
            path: "/lib/ld.so".to_string(),
            version: String::new(),
            disk_hash: [0u8; 32],
            native_blob: vec![0xDE, 0xAD],
        },
    ];
    writer.write_module_list(&modules).unwrap();
    writer.finalize().unwrap();

    // Verify block sequence by parsing raw bytes
    let data = &buf;
    let mut offset = HEADER_SIZE;
    let mut block_types = Vec::new();

    while offset < data.len() {
        assert_eq!(&data[offset..offset + 4], BLOCK_MAGIC);
        let block_type = u16::from_le_bytes([data[offset + 4], data[offset + 5]]);
        let block_length = u32::from_le_bytes(data[offset + 8..offset + 12].try_into().unwrap()) as usize;
        block_types.push(block_type);
        offset += block_length;
    }

    assert_eq!(block_types, vec![
        BlockType::MemoryRegion as u16,
        BlockType::MemoryRegion as u16,
        BlockType::ModuleListIndex as u16,
        BlockType::ModuleEntry as u16,
        BlockType::ModuleEntry as u16,
        BlockType::EndOfCapture as u16,
    ]);
}

#[test]
fn test_page_state_map_mixed() {
    let mut buf = Vec::new();
    let header = make_test_header();
    let mut writer = MslWriter::new(&mut buf, &header, CompAlgo::None).unwrap();

    // 3 pages: CAPTURED, FAILED, CAPTURED -> PSM byte = 0x10
    let region = MemoryRegionPayload {
        base_addr: 0x20000,
        region_size: 4096 * 3,
        protection: 3,
        region_type: RegionType::Heap,
        page_size: 4096,
        num_pages: 3,
        timestamp_ns: 0,
        page_states: vec![PageState::Captured, PageState::Failed, PageState::Captured],
        page_data: vec![0x11u8; 8192],
    };
    writer.write_memory_region(&region, None).unwrap();
    writer.finalize().unwrap();

    // PSM byte at: HEADER_SIZE + BLOCK_HEADER_SIZE + 32
    let psm_offset = HEADER_SIZE + BLOCK_HEADER_SIZE + 32;
    assert_eq!(buf[psm_offset], 0x10);
}

#[test]
fn test_string_padding() {
    let mut buf = Vec::new();
    let header = make_test_header();
    let mut writer = MslWriter::new(&mut buf, &header, CompAlgo::None).unwrap();

    let modules = vec![ModuleEntryPayload {
        base_addr: 0x400000,
        module_size: 0x10000,
        path: "/usr/lib/libc.so.6".to_string(), // 18 chars + null = 19, padded to 24
        version: "2.31".to_string(),
        disk_hash: [0u8; 32],
        native_blob: Vec::new(),
    }];
    writer.write_module_list(&modules).unwrap();
    writer.finalize().unwrap();

    // Find ModuleEntry block (second block after ModuleListIndex)
    let mut offset = HEADER_SIZE;
    // Skip ModuleListIndex
    let block_len = u32::from_le_bytes(buf[offset + 8..offset + 12].try_into().unwrap()) as usize;
    offset += block_len;

    // Now at ModuleEntry
    let mod_payload_offset = offset + BLOCK_HEADER_SIZE;
    // path_len at offset 16 within payload
    let path_len = u16::from_le_bytes([
        buf[mod_payload_offset + 16],
        buf[mod_payload_offset + 17],
    ]) as usize;

    // Path starts at offset 24 within payload
    let path_start = mod_payload_offset + 24;
    let path_data = &buf[path_start..path_start + path_len];

    // Check path content
    assert_eq!(&path_data[..18], b"/usr/lib/libc.so.6");
    assert!(path_data.contains(&0)); // null terminated
    assert_eq!(path_len % 8, 0); // padded to 8B
}
