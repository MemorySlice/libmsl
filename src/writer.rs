use std::io::Write;
use uuid::Uuid;
use crate::constants::*;
use crate::error::Result;
use crate::types::*;
use crate::padding::{pad8, pad_bytes, encode_string};
use crate::page_state_map::encode_page_state_map;
use crate::integrity::IntegrityChain;
use crate::compression::compress;

/// Streaming MSL file writer.
///
/// Usage:
/// ```ignore
/// let mut writer = MslWriter::new(output, header, CompAlgo::None)?;
/// writer.write_memory_region(&region)?;
/// writer.write_module_list(&modules)?;
/// writer.finalize()?;
/// ```
pub struct MslWriter<W: Write> {
    output: W,
    comp_algo: CompAlgo,
    chain: IntegrityChain,
}

impl<W: Write> MslWriter<W> {
    /// Create a new writer, immediately serializing the 64-byte file header.
    pub fn new(mut output: W, header: &FileHeader, comp_algo: CompAlgo) -> Result<Self> {
        let header_bytes = Self::serialize_header(header);
        output.write_all(&header_bytes)?;
        let mut chain = IntegrityChain::new();
        chain.feed_header(&header_bytes);
        Ok(Self { output, comp_algo, chain })
    }

    fn serialize_header(h: &FileHeader) -> [u8; HEADER_SIZE] {
        let mut buf = [0u8; HEADER_SIZE];
        buf[0..8].copy_from_slice(FILE_MAGIC);
        buf[8] = h.endianness as u8;
        buf[9] = HEADER_SIZE as u8;
        buf[10] = h.version_major;
        buf[11] = h.version_minor;
        buf[12..16].copy_from_slice(&h.flags.to_le_bytes());
        buf[16..24].copy_from_slice(&h.cap_bitmap.to_le_bytes());
        buf[24..40].copy_from_slice(&h.dump_uuid);
        buf[40..48].copy_from_slice(&h.timestamp_ns.to_le_bytes());
        buf[48..50].copy_from_slice(&(h.os_type as u16).to_le_bytes());
        buf[50..52].copy_from_slice(&(h.arch_type as u16).to_le_bytes());
        buf[52..56].copy_from_slice(&h.pid.to_le_bytes());
        // buf[56..64] is reserved zeros (already zero)
        buf
    }

    /// Write a MemoryRegion block. Returns the block's UUID.
    pub fn write_memory_region(
        &mut self,
        region: &MemoryRegionPayload,
        parent_uuid: Option<&[u8; 16]>,
    ) -> Result<[u8; 16]> {
        let psm = encode_page_state_map(&region.page_states);
        let padded_psm = pad_bytes(&psm);

        // Compress page data if non-empty
        let page_data = if region.page_data.is_empty() {
            Vec::new()
        } else {
            compress(&region.page_data, self.comp_algo)?
        };

        // Build payload: 32-byte fixed header + padded PSM + page_data
        let mut payload = Vec::with_capacity(32 + padded_psm.len() + page_data.len());
        payload.extend_from_slice(&region.base_addr.to_le_bytes());    // 8B
        payload.extend_from_slice(&region.region_size.to_le_bytes());  // 8B
        payload.push(region.protection);                                // 1B
        payload.push(region.region_type as u8);                        // 1B
        payload.extend_from_slice(&region.page_size.to_le_bytes());    // 2B
        payload.extend_from_slice(&region.num_pages.to_le_bytes());    // 4B
        payload.extend_from_slice(&region.timestamp_ns.to_le_bytes()); // 8B
        payload.extend_from_slice(&padded_psm);
        payload.extend_from_slice(&page_data);

        self.write_block(BlockType::MemoryRegion, &payload, 0, parent_uuid)
    }

    /// Write a ModuleListIndex block with HAS_CHILDREN, then individual ModuleEntry blocks.
    /// Returns the index block's UUID.
    pub fn write_module_list(&mut self, modules: &[ModuleEntryPayload]) -> Result<[u8; 16]> {
        // ModuleListIndex payload: count(4B) + reserved(4B) = 8 bytes
        let mut index_payload = Vec::with_capacity(8);
        index_payload.extend_from_slice(&(modules.len() as u32).to_le_bytes());
        index_payload.extend_from_slice(&0u32.to_le_bytes());

        let index_uuid = self.write_block(
            BlockType::ModuleListIndex,
            &index_payload,
            HAS_CHILDREN,
            None,
        )?;

        for module in modules {
            self.write_module_entry(module, &index_uuid)?;
        }

        Ok(index_uuid)
    }

    fn write_module_entry(
        &mut self,
        module: &ModuleEntryPayload,
        parent_uuid: &[u8; 16],
    ) -> Result<[u8; 16]> {
        let path_encoded = encode_string(&module.path);
        let version_encoded = encode_string(&module.version);

        let cap = 24 + path_encoded.len() + version_encoded.len()
            + HASH_SIZE + 8 + module.native_blob.len();
        let mut payload = Vec::with_capacity(cap);
        payload.extend_from_slice(&module.base_addr.to_le_bytes());     // 8B
        payload.extend_from_slice(&module.module_size.to_le_bytes());   // 8B
        payload.extend_from_slice(&(path_encoded.len() as u16).to_le_bytes()); // 2B
        payload.extend_from_slice(&(version_encoded.len() as u16).to_le_bytes()); // 2B
        payload.extend_from_slice(&0u32.to_le_bytes());                 // 4B reserved
        payload.extend_from_slice(&path_encoded);
        payload.extend_from_slice(&version_encoded);
        payload.extend_from_slice(&module.disk_hash);                   // 32B
        payload.extend_from_slice(&(module.native_blob.len() as u32).to_le_bytes()); // 4B
        payload.extend_from_slice(&0u32.to_le_bytes());                 // 4B reserved
        if !module.native_blob.is_empty() {
            payload.extend_from_slice(&module.native_blob);
        }

        self.write_block(BlockType::ModuleEntry, &payload, 0, Some(parent_uuid))
    }

    /// Write End-of-Capture block and flush. Consumes the writer.
    pub fn finalize(mut self) -> Result<W> {
        let file_hash = self.chain.finalize();
        let acq_end_ns: u64 = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64;

        // EoC payload: file_hash(32B) + acq_end_ns(8B) + reserved(8B) = 48 bytes
        let mut payload = Vec::with_capacity(48);
        payload.extend_from_slice(&file_hash);
        payload.extend_from_slice(&acq_end_ns.to_le_bytes());
        payload.extend_from_slice(&[0u8; 8]); // reserved

        self.write_block(BlockType::EndOfCapture, &payload, 0, None)?;
        self.output.flush()?;
        Ok(self.output)
    }

    /// Write a complete block (header + payload + padding), update integrity chain.
    /// Returns the block's UUID.
    fn write_block(
        &mut self,
        block_type: BlockType,
        payload: &[u8],
        flags: u16,
        parent_uuid: Option<&[u8; 16]>,
    ) -> Result<[u8; 16]> {
        let block_uuid = *Uuid::new_v4().as_bytes();
        let parent = parent_uuid.copied().unwrap_or([0u8; 16]);

        let pad_len = pad8(payload.len()) - payload.len();
        let block_length = (BLOCK_HEADER_SIZE + payload.len() + pad_len) as u32;

        let mut block_header = [0u8; BLOCK_HEADER_SIZE];
        block_header[0..4].copy_from_slice(BLOCK_MAGIC);
        block_header[4..6].copy_from_slice(&(block_type as u16).to_le_bytes());
        block_header[6..8].copy_from_slice(&flags.to_le_bytes());
        block_header[8..12].copy_from_slice(&block_length.to_le_bytes());
        // [12..16] reserved = 0
        block_header[16..32].copy_from_slice(&block_uuid);
        block_header[32..48].copy_from_slice(&parent);
        block_header[48..80].copy_from_slice(self.chain.prev_hash());

        self.output.write_all(&block_header)?;
        self.output.write_all(payload)?;
        let padding = [0u8; 7];
        if pad_len > 0 {
            self.output.write_all(&padding[..pad_len])?;
        }

        // Feed integrity chain: header + payload + padding
        self.chain.feed_block_varparts(&block_header, payload, &padding[..pad_len]);

        Ok(block_uuid)
    }
}
