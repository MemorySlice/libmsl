use std::io::Read;

use crate::constants::*;
use crate::error::{MslError, Result};
use crate::integrity::IntegrityChain;
use crate::page_state_map::decode_page_state_map;
use crate::padding::pad8;
use crate::types::*;

// Helper to read little-endian values from a byte slice
fn read_u16_le(data: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(data[offset..offset + 2].try_into().unwrap())
}

fn read_u32_le(data: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap())
}

fn read_u64_le(data: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(data[offset..offset + 8].try_into().unwrap())
}

/// Decode a null-terminated, padded string from a byte slice.
fn decode_string(data: &[u8]) -> String {
    let end = data.iter().position(|&b| b == 0).unwrap_or(data.len());
    std::str::from_utf8(&data[..end]).unwrap_or("").to_string()
}

/// Parse a FileHeader from a 64-byte slice.
fn parse_file_header(data: &[u8; HEADER_SIZE]) -> Result<FileHeader> {
    if &data[0..8] != FILE_MAGIC {
        return Err(MslError::BadFileMagic);
    }
    let version_major = data[10];
    let version_minor = data[11];
    if version_major != VERSION_MAJOR {
        return Err(MslError::UnsupportedVersion { major: version_major, minor: version_minor });
    }

    let endianness = Endianness::try_from(data[8])
        .map_err(|_| MslError::UnsupportedVersion { major: version_major, minor: version_minor })?;
    let os_type = OsType::try_from(read_u16_le(data, 48) as u8)
        .unwrap_or(OsType::Linux);
    let arch_type = ArchType::try_from(read_u16_le(data, 50) as u8)
        .unwrap_or(ArchType::X86_64);

    let mut dump_uuid = [0u8; 16];
    dump_uuid.copy_from_slice(&data[24..40]);

    Ok(FileHeader {
        endianness,
        version_major,
        version_minor,
        flags: read_u32_le(data, 12),
        cap_bitmap: read_u64_le(data, 16),
        dump_uuid,
        timestamp_ns: read_u64_le(data, 40),
        os_type,
        arch_type,
        pid: read_u32_le(data, 52),
    })
}

/// Parse a BlockHeader from an 80-byte slice.
fn parse_block_header(data: &[u8; BLOCK_HEADER_SIZE]) -> Result<BlockHeader> {
    if &data[0..4] != BLOCK_MAGIC {
        return Err(MslError::BadBlockMagic);
    }

    let mut block_uuid = [0u8; 16];
    block_uuid.copy_from_slice(&data[16..32]);
    let mut parent_uuid = [0u8; 16];
    parent_uuid.copy_from_slice(&data[32..48]);
    let mut prev_hash = [0u8; HASH_SIZE];
    prev_hash.copy_from_slice(&data[48..80]);

    Ok(BlockHeader {
        block_type: BlockType::try_from(read_u16_le(data, 4))?,
        flags: read_u16_le(data, 6),
        block_length: read_u32_le(data, 8),
        block_uuid,
        parent_uuid,
        prev_hash,
    })
}

/// Parse a MemoryRegion payload from raw bytes (no decompression here).
fn parse_memory_region_payload(data: &[u8]) -> Result<MemoryRegionPayload> {
    if data.len() < 32 {
        return Err(MslError::UnexpectedEof);
    }

    let base_addr = read_u64_le(data, 0);
    let region_size = read_u64_le(data, 8);
    let protection = data[16];
    let region_type = RegionType::try_from(data[17]).unwrap_or(RegionType::Unknown);
    let page_size = read_u16_le(data, 18);
    let num_pages = read_u32_le(data, 20);
    let timestamp_ns = read_u64_le(data, 24);

    // Page state map
    let psm_raw_len = (num_pages as usize).div_ceil(4);
    let psm_padded_len = pad8(psm_raw_len);
    let psm_start = 32;
    let psm_end = psm_start + psm_raw_len;

    let page_states = if psm_raw_len > 0 && data.len() >= psm_end {
        decode_page_state_map(&data[psm_start..psm_end], num_pages as usize)
    } else {
        Vec::new()
    };

    // Page data (rest after padded PSM)
    let page_data_start = psm_start + psm_padded_len;
    let page_data = if page_data_start < data.len() {
        data[page_data_start..].to_vec()
    } else {
        Vec::new()
    };

    Ok(MemoryRegionPayload {
        base_addr,
        region_size,
        protection,
        region_type,
        page_size,
        num_pages,
        timestamp_ns,
        page_states,
        page_data,
    })
}

/// Parse a ModuleEntry payload.
fn parse_module_entry_payload(data: &[u8]) -> Result<ModuleEntryPayload> {
    if data.len() < 24 {
        return Err(MslError::UnexpectedEof);
    }

    let base_addr = read_u64_le(data, 0);
    let module_size = read_u64_le(data, 8);
    let path_len = read_u16_le(data, 16) as usize;
    let version_len = read_u16_le(data, 18) as usize;
    // [20..24] reserved

    let mut offset = 24;

    if offset + path_len > data.len() {
        return Err(MslError::UnexpectedEof);
    }

    // Path: encoded string (null-terminated, padded)
    let path = decode_string(&data[offset..offset + path_len]);
    offset += path_len;

    if offset + version_len > data.len() {
        return Err(MslError::UnexpectedEof);
    }

    // Version
    let version = decode_string(&data[offset..offset + version_len]);
    offset += version_len;

    // Disk hash (32 bytes)
    let mut disk_hash = [0u8; HASH_SIZE];
    if offset + HASH_SIZE <= data.len() {
        disk_hash.copy_from_slice(&data[offset..offset + HASH_SIZE]);
    }
    offset += HASH_SIZE;

    // Blob length + reserved
    let blob_len = if offset + 4 <= data.len() {
        read_u32_le(data, offset) as usize
    } else {
        0
    };
    offset += 8; // blob_len(4) + reserved(4)

    let native_blob = if blob_len > 0 && offset + blob_len <= data.len() {
        data[offset..offset + blob_len].to_vec()
    } else {
        Vec::new()
    };

    Ok(ModuleEntryPayload {
        base_addr,
        module_size,
        path,
        version,
        disk_hash,
        native_blob,
    })
}

/// Parse a ModuleListIndex payload.
fn parse_module_list_index_payload(data: &[u8]) -> Result<ModuleListIndexPayload> {
    if data.len() < 4 {
        return Err(MslError::UnexpectedEof);
    }
    Ok(ModuleListIndexPayload {
        count: read_u32_le(data, 0),
    })
}

/// Parse an EndOfCapture payload.
fn parse_eoc_payload(data: &[u8]) -> Result<EndOfCapturePayload> {
    if data.len() < 40 {
        return Err(MslError::UnexpectedEof);
    }
    let mut file_hash = [0u8; HASH_SIZE];
    file_hash.copy_from_slice(&data[0..HASH_SIZE]);
    let acq_end_ns = read_u64_le(data, HASH_SIZE);

    Ok(EndOfCapturePayload {
        file_hash,
        acq_end_ns,
    })
}

/// Parse a block payload into a Block enum variant.
fn parse_block(header: BlockHeader, payload: &[u8]) -> Result<Block> {
    match header.block_type {
        BlockType::MemoryRegion => {
            let p = parse_memory_region_payload(payload)?;
            Ok(Block::MemoryRegion { header, payload: p })
        }
        BlockType::ModuleEntry => {
            let p = parse_module_entry_payload(payload)?;
            Ok(Block::ModuleEntry { header, payload: p })
        }
        BlockType::ModuleListIndex => {
            let p = parse_module_list_index_payload(payload)?;
            Ok(Block::ModuleListIndex { header, payload: p })
        }
        BlockType::EndOfCapture => {
            let p = parse_eoc_payload(payload)?;
            Ok(Block::EndOfCapture { header, payload: p })
        }
        _ => Ok(Block::Unknown {
            header,
            raw_payload: payload.to_vec(),
        }),
    }
}

// ---------------------------------------------------------------
// Streaming reader
// ---------------------------------------------------------------

/// Streaming MSL reader for `Read` sources.
pub struct MslReader<R: Read> {
    input: R,
    done: bool,
}

impl<R: Read> MslReader<R> {
    pub fn new(input: R) -> Self {
        Self { input, done: false }
    }

    /// Read and parse the 64-byte file header.
    pub fn read_header(&mut self) -> Result<FileHeader> {
        let mut buf = [0u8; HEADER_SIZE];
        self.input.read_exact(&mut buf).map_err(|_| MslError::UnexpectedEof)?;
        parse_file_header(&buf)
    }

    /// Read the next block. Returns None after EndOfCapture.
    pub fn next_block(&mut self) -> Result<Option<Block>> {
        if self.done {
            return Ok(None);
        }

        let mut hdr_buf = [0u8; BLOCK_HEADER_SIZE];
        match self.input.read_exact(&mut hdr_buf) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
            Err(e) => return Err(MslError::Io(e)),
        }

        let block_header = parse_block_header(&hdr_buf)?;
        let payload_len = block_header.block_length as usize - BLOCK_HEADER_SIZE;
        let mut payload_buf = vec![0u8; payload_len];
        self.input.read_exact(&mut payload_buf).map_err(|_| MslError::UnexpectedEof)?;

        let block = parse_block(block_header, &payload_buf)?;

        if matches!(&block, Block::EndOfCapture { .. }) {
            self.done = true;
        }

        Ok(Some(block))
    }

    /// Read entire file: header + all blocks until EndOfCapture.
    pub fn read_all(mut self) -> Result<(FileHeader, Vec<Block>)> {
        let header = self.read_header()?;
        let mut blocks = Vec::new();
        while let Some(block) = self.next_block()? {
            blocks.push(block);
        }
        Ok((header, blocks))
    }
}

// ---------------------------------------------------------------
// Zero-copy slice reader
// ---------------------------------------------------------------

/// Zero-copy MSL reader over a byte slice.
pub struct MslSliceReader<'a> {
    data: &'a [u8],
    offset: usize,
    done: bool,
}

impl<'a> MslSliceReader<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, offset: 0, done: false }
    }

    /// Parse the 64-byte file header.
    pub fn read_header(&mut self) -> Result<FileHeader> {
        if self.data.len() < HEADER_SIZE {
            return Err(MslError::UnexpectedEof);
        }
        let buf: &[u8; HEADER_SIZE] = self.data[..HEADER_SIZE].try_into().unwrap();
        let header = parse_file_header(buf)?;
        self.offset = HEADER_SIZE;
        Ok(header)
    }

    /// Read the next block. Returns None after EndOfCapture.
    pub fn next_block(&mut self) -> Result<Option<Block>> {
        if self.done || self.offset >= self.data.len() {
            return Ok(None);
        }

        if self.offset + BLOCK_HEADER_SIZE > self.data.len() {
            return Err(MslError::UnexpectedEof);
        }

        let hdr_buf: &[u8; BLOCK_HEADER_SIZE] = self.data[self.offset..self.offset + BLOCK_HEADER_SIZE]
            .try_into().unwrap();
        let block_header = parse_block_header(hdr_buf)?;

        let payload_start = self.offset + BLOCK_HEADER_SIZE;
        let payload_len = block_header.block_length as usize - BLOCK_HEADER_SIZE;
        let payload_end = payload_start + payload_len;

        if payload_end > self.data.len() {
            return Err(MslError::UnexpectedEof);
        }

        let payload = &self.data[payload_start..payload_end];
        let block = parse_block(block_header, payload)?;

        self.offset = payload_end;

        if matches!(&block, Block::EndOfCapture { .. }) {
            self.done = true;
        }

        Ok(Some(block))
    }

    /// Validate integrity chain over the entire file.
    pub fn validate_integrity(&self) -> Result<()> {
        let data = self.data;
        if data.len() < HEADER_SIZE {
            return Err(MslError::UnexpectedEof);
        }

        let mut chain = IntegrityChain::new();
        chain.feed_header(&data[..HEADER_SIZE]);

        let mut offset = HEADER_SIZE;
        let mut block_index = 0;

        while offset < data.len() {
            if offset + BLOCK_HEADER_SIZE > data.len() {
                return Err(MslError::UnexpectedEof);
            }

            // Check prev_hash in block header
            let prev_hash = &data[offset + 48..offset + 80];
            if prev_hash != chain.prev_hash() {
                return Err(MslError::IntegrityMismatch { block_index });
            }

            let block_length = read_u32_le(data, offset + 8) as usize;
            let block_end = offset + block_length;
            if block_end > data.len() {
                return Err(MslError::UnexpectedEof);
            }

            let block_bytes = &data[offset..block_end];

            // Check if this is EoC
            let block_type = read_u16_le(data, offset + 4);
            if block_type == BlockType::EndOfCapture as u16 {
                // Verify file hash
                let payload_start = offset + BLOCK_HEADER_SIZE;
                let file_hash = &data[payload_start..payload_start + HASH_SIZE];
                let expected = chain.finalize();
                if file_hash != expected {
                    return Err(MslError::FileHashMismatch);
                }
                return Ok(());
            }

            chain.feed_block(block_bytes);
            offset = block_end;
            block_index += 1;
        }

        Ok(())
    }
}
