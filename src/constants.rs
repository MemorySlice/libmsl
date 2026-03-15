// constants.rs
pub const FILE_MAGIC: &[u8; 8] = b"MEMSLICE";
pub const BLOCK_MAGIC: &[u8; 4] = b"MSLC";
pub const HEADER_SIZE: usize = 64;
pub const BLOCK_HEADER_SIZE: usize = 80;
pub const HASH_SIZE: usize = 32;
pub const HAS_CHILDREN: u16 = 0x0001;
pub const VERSION_MAJOR: u8 = 1;
pub const VERSION_MINOR: u8 = 0;
