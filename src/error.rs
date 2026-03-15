use thiserror::Error;

#[derive(Debug, Error)]
pub enum MslError {
    #[error("invalid file magic bytes")]
    BadFileMagic,
    #[error("invalid block magic bytes")]
    BadBlockMagic,
    #[error("unsupported version {major}.{minor}")]
    UnsupportedVersion { major: u8, minor: u8 },
    #[error("integrity chain mismatch at block {block_index}")]
    IntegrityMismatch { block_index: usize },
    #[error("file hash mismatch")]
    FileHashMismatch,
    #[error("invalid {type_name} value: {value}")]
    InvalidEnumValue { type_name: &'static str, value: u64 },
    #[error("unknown block type: 0x{0:04x}")]
    UnknownBlockType(u16),
    #[error("unknown compression algorithm: {0}")]
    UnknownCompAlgo(u8),
    #[error("decompression failed: {0}")]
    DecompressionFailed(String),
    #[error("unexpected end of file")]
    UnexpectedEof,
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, MslError>;
