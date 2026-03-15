use crate::constants::HASH_SIZE;

/// BLAKE3-based integrity chain for MSL files.
pub struct IntegrityChain {
    prev_hash: [u8; HASH_SIZE],
    file_hasher: blake3::Hasher,
}

impl IntegrityChain {
    pub fn new() -> Self {
        Self {
            prev_hash: [0u8; HASH_SIZE],
            file_hasher: blake3::Hasher::new(),
        }
    }

    /// Current prev_hash for the next block.
    pub fn prev_hash(&self) -> &[u8; HASH_SIZE] {
        &self.prev_hash
    }

    /// Hash file header bytes, update chain.
    pub fn feed_header(&mut self, header_bytes: &[u8]) -> [u8; HASH_SIZE] {
        self.feed(header_bytes)
    }

    /// Hash a complete block, update chain.
    pub fn feed_block(&mut self, block_bytes: &[u8]) -> [u8; HASH_SIZE] {
        self.feed(block_bytes)
    }

    /// Hash a block from header + payload parts without full concatenation.
    pub fn feed_block_parts(&mut self, header: &[u8], payload: &[u8]) -> [u8; HASH_SIZE] {
        let mut block_hasher = blake3::Hasher::new();
        for part in [header, payload] {
            self.file_hasher.update(part);
            block_hasher.update(part);
        }
        self.prev_hash = *block_hasher.finalize().as_bytes();
        self.prev_hash
    }

    /// Hash a block from multiple parts (header + payload + padding).
    pub fn feed_block_varparts(&mut self, header: &[u8], payload: &[u8], padding: &[u8]) -> [u8; HASH_SIZE] {
        let mut block_hasher = blake3::Hasher::new();
        for part in [header, payload, padding] {
            self.file_hasher.update(part);
            block_hasher.update(part);
        }
        self.prev_hash = *block_hasher.finalize().as_bytes();
        self.prev_hash
    }

    /// Return BLAKE3 digest of the entire file so far (for EoC FileHash).
    pub fn finalize(&self) -> [u8; HASH_SIZE] {
        let hash = self.file_hasher.clone().finalize();
        *hash.as_bytes()
    }

    fn feed(&mut self, data: &[u8]) -> [u8; HASH_SIZE] {
        self.file_hasher.update(data);
        self.prev_hash = *blake3::hash(data).as_bytes();
        self.prev_hash
    }
}

impl Default for IntegrityChain {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_initial_prev_hash_is_zeros() {
        let chain = IntegrityChain::new();
        assert_eq!(chain.prev_hash(), &[0u8; 32]);
    }

    #[test]
    fn test_feed_header_updates_prev_hash() {
        let mut chain = IntegrityChain::new();
        let header = b"test header data";
        let hash = chain.feed_header(header);
        assert_eq!(hash, *blake3::hash(header).as_bytes());
        assert_eq!(chain.prev_hash(), &hash);
    }

    #[test]
    fn test_feed_block_parts_matches_feed_block() {
        let mut chain1 = IntegrityChain::new();
        let mut chain2 = IntegrityChain::new();

        let header_data = b"header";
        chain1.feed_header(header_data);
        chain2.feed_header(header_data);

        let block_header = b"block_hdr";
        let block_payload = b"block_payload";
        let mut full_block = block_header.to_vec();
        full_block.extend_from_slice(block_payload);

        chain1.feed_block(&full_block);
        chain2.feed_block_parts(block_header, block_payload);

        assert_eq!(chain1.prev_hash(), chain2.prev_hash());
        assert_eq!(chain1.finalize(), chain2.finalize());
    }
}
