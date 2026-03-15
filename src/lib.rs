//! `libmsl` — Rust library for reading and writing MSL (Memory Slice) files.

pub mod constants;
pub mod error;
pub mod types;
pub mod padding;
pub mod page_state_map;
pub mod integrity;
pub mod compression;
pub mod writer;
pub mod reader;

pub use error::{MslError, Result};
pub use types::*;
pub use writer::MslWriter;
pub use reader::{MslReader, MslSliceReader};
