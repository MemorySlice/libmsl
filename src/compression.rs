use crate::error::{MslError, Result};
use crate::types::CompAlgo;

/// Compress data using the specified algorithm.
pub fn compress(data: &[u8], algo: CompAlgo) -> Result<Vec<u8>> {
    match algo {
        CompAlgo::None => Ok(data.to_vec()),
        CompAlgo::Zstd => compress_zstd(data),
        CompAlgo::Lz4 => compress_lz4(data),
    }
}

/// Decompress data using the specified algorithm.
pub fn decompress(data: &[u8], algo: CompAlgo) -> Result<Vec<u8>> {
    match algo {
        CompAlgo::None => Ok(data.to_vec()),
        CompAlgo::Zstd => decompress_zstd(data),
        CompAlgo::Lz4 => decompress_lz4(data),
    }
}

#[cfg(feature = "compress-zstd")]
fn compress_zstd(data: &[u8]) -> Result<Vec<u8>> {
    zstd::encode_all(std::io::Cursor::new(data), 3)
        .map_err(|e| MslError::DecompressionFailed(format!("ZSTD compress: {e}")))
}

#[cfg(not(feature = "compress-zstd"))]
fn compress_zstd(_data: &[u8]) -> Result<Vec<u8>> {
    Err(MslError::DecompressionFailed(
        "ZSTD support not enabled (enable feature 'compress-zstd')".into(),
    ))
}

#[cfg(feature = "compress-zstd")]
fn decompress_zstd(data: &[u8]) -> Result<Vec<u8>> {
    zstd::decode_all(std::io::Cursor::new(data))
        .map_err(|e| MslError::DecompressionFailed(format!("ZSTD decompress: {e}")))
}

#[cfg(not(feature = "compress-zstd"))]
fn decompress_zstd(_data: &[u8]) -> Result<Vec<u8>> {
    Err(MslError::DecompressionFailed(
        "ZSTD support not enabled (enable feature 'compress-zstd')".into(),
    ))
}

#[cfg(feature = "compress-lz4")]
fn compress_lz4(data: &[u8]) -> Result<Vec<u8>> {
    Ok(lz4_flex::compress_prepend_size(data))
}

#[cfg(not(feature = "compress-lz4"))]
fn compress_lz4(_data: &[u8]) -> Result<Vec<u8>> {
    Err(MslError::DecompressionFailed(
        "LZ4 support not enabled (enable feature 'compress-lz4')".into(),
    ))
}

#[cfg(feature = "compress-lz4")]
fn decompress_lz4(data: &[u8]) -> Result<Vec<u8>> {
    lz4_flex::decompress_size_prepended(data)
        .map_err(|e| MslError::DecompressionFailed(format!("LZ4 decompress: {e}")))
}

#[cfg(not(feature = "compress-lz4"))]
fn decompress_lz4(_data: &[u8]) -> Result<Vec<u8>> {
    Err(MslError::DecompressionFailed(
        "LZ4 support not enabled (enable feature 'compress-lz4')".into(),
    ))
}
