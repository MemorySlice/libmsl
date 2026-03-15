# LibMSL

A Rust library for reading and writing MSL (Memory Slice) binary format files — a structured format for capturing and storing process memory snapshots.

## Overview

MSL files store memory region dumps alongside module metadata, with built-in integrity verification via BLAKE3 hash chains. The format supports optional compression (Zstandard, LZ4) and tracks OS/architecture information, timestamps, and process IDs.

**File structure:** File Header → Block sequence (MemoryRegion, ModuleEntry, ModuleListIndex) → EndOfCapture with file hash.

## Features

- **Streaming reader** (`MslReader`) and **zero-copy slice reader** (`MslSliceReader`)
- **Streaming writer** (`MslWriter`) with automatic integrity chain management
- BLAKE3-based hash chain integrity verification
- Optional Zstandard and LZ4 compression
- Page-level state tracking (captured / failed / unmapped)
- UUID-based block hierarchy for parent-child relationships
- 8-byte aligned binary layout

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
libmsl = { path = "../libmsl" }
```

To enable compression:

```toml
[dependencies]
libmsl = { path = "../libmsl", features = ["compress-all"] }
```

## Quick Start

### Writing an MSL file

```rust
use libmsl::*;

let mut buf = Vec::new();
let header = FileHeader { pid: 1234, ..Default::default() };
let mut writer = MslWriter::new(&mut buf, &header, CompAlgo::None)?;

let region = MemoryRegionPayload {
    base_addr: 0x7f000000,
    region_size: 4096,
    protection: 5, // r-x
    region_type: RegionType::Image,
    page_size: 4096,
    num_pages: 1,
    timestamp_ns: 0,
    page_states: vec![PageState::Captured],
    page_data: vec![0u8; 4096],
};

writer.write_memory_region(&region, None)?;
writer.finalize()?;
```

### Reading an MSL file

```rust
use libmsl::*;

let mut reader = MslSliceReader::new(&data);
let header = reader.read_header()?;

while let Some(block) = reader.next_block()? {
    match block {
        Block::MemoryRegion { payload, .. } => {
            println!("Region at {:#x}, {} pages", payload.base_addr, payload.num_pages);
        }
        Block::ModuleEntry { payload, .. } => {
            println!("Module: {}", payload.path);
        }
        _ => {}
    }
}
```

### Validating integrity

```rust
let reader = MslSliceReader::new(&data);
reader.validate_integrity()?; // verifies full BLAKE3 hash chain
```

## Cargo Features

| Feature          | Description                          |
|------------------|--------------------------------------|
| `std` (default)  | Standard library support             |
| `compress-zstd`  | Zstandard compression via `zstd`     |
| `compress-lz4`   | LZ4 compression via `lz4_flex`       |
| `compress-all`   | Enable both compression algorithms   |

## License

Apache 2.0
