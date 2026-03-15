use crate::error::MslError;

// ---------------------------------------------------------------------------
// Helper macro for TryFrom<primitive> on repr enums
// ---------------------------------------------------------------------------

macro_rules! impl_try_from {
    ($enum_ty:ty, $prim:ty, $err_expr:expr, $($variant:ident => $value:expr),+ $(,)?) => {
        impl TryFrom<$prim> for $enum_ty {
            type Error = MslError;

            fn try_from(value: $prim) -> Result<Self, MslError> {
                match value {
                    $( $value => Ok(<$enum_ty>::$variant), )+
                    _ => Err($err_expr(value)),
                }
            }
        }
    };
}

// ---------------------------------------------------------------------------
// Endianness
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Endianness {
    Little = 1,
    Big = 2,
}

impl_try_from!(
    Endianness, u8,
    |v| MslError::InvalidEnumValue { type_name: "Endianness", value: v as u64 },
    Little => 1,
    Big => 2,
);

// ---------------------------------------------------------------------------
// OsType
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum OsType {
    Windows = 0,
    Linux = 1,
    MacOS = 2,
    Android = 3,
    IOS = 4,
}

impl_try_from!(
    OsType, u8,
    |v| MslError::InvalidEnumValue { type_name: "OsType", value: v as u64 },
    Windows => 0,
    Linux => 1,
    MacOS => 2,
    Android => 3,
    IOS => 4,
);

// ---------------------------------------------------------------------------
// ArchType
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ArchType {
    X86 = 0,
    X86_64 = 1,
    ARM64 = 2,
    ARM32 = 3,
}

impl_try_from!(
    ArchType, u8,
    |v| MslError::InvalidEnumValue { type_name: "ArchType", value: v as u64 },
    X86 => 0,
    X86_64 => 1,
    ARM64 => 2,
    ARM32 => 3,
);

// ---------------------------------------------------------------------------
// BlockType
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum BlockType {
    MemoryRegion = 0x0001,
    ModuleEntry = 0x0002,
    ModuleListIndex = 0x0010,
    ImportProvenance = 0x0030,
    EndOfCapture = 0x0FFF,
}

impl_try_from!(
    BlockType, u16,
    MslError::UnknownBlockType,
    MemoryRegion => 0x0001,
    ModuleEntry => 0x0002,
    ModuleListIndex => 0x0010,
    ImportProvenance => 0x0030,
    EndOfCapture => 0x0FFF,
);

// ---------------------------------------------------------------------------
// CompAlgo
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CompAlgo {
    None = 0,
    Zstd = 1,
    Lz4 = 2,
}

impl_try_from!(
    CompAlgo, u8,
    MslError::UnknownCompAlgo,
    None => 0,
    Zstd => 1,
    Lz4 => 2,
);

// ---------------------------------------------------------------------------
// PageState
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PageState {
    Captured = 0,
    Failed = 1,
    Unmapped = 2,
}

impl_try_from!(
    PageState, u8,
    |v| MslError::InvalidEnumValue { type_name: "PageState", value: v as u64 },
    Captured => 0,
    Failed => 1,
    Unmapped => 2,
);

// ---------------------------------------------------------------------------
// RegionType
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum RegionType {
    Unknown = 0,
    Heap = 1,
    Stack = 2,
    Image = 3,
    MappedFile = 4,
    Anon = 5,
    SharedMem = 6,
    Other = 0xFF,
}

impl_try_from!(
    RegionType, u8,
    |v| MslError::InvalidEnumValue { type_name: "RegionType", value: v as u64 },
    Unknown => 0,
    Heap => 1,
    Stack => 2,
    Image => 3,
    MappedFile => 4,
    Anon => 5,
    SharedMem => 6,
    Other => 0xFF,
);

// ---------------------------------------------------------------------------
// Structs
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct FileHeader {
    pub endianness: Endianness,
    pub version_major: u8,
    pub version_minor: u8,
    pub flags: u32,
    pub cap_bitmap: u64,
    pub dump_uuid: [u8; 16],
    pub timestamp_ns: u64,
    pub os_type: OsType,
    pub arch_type: ArchType,
    pub pid: u32,
}

impl Default for FileHeader {
    fn default() -> Self {
        Self {
            endianness: Endianness::Little,
            version_major: 1,
            version_minor: 0,
            flags: 0,
            cap_bitmap: 0,
            dump_uuid: [0u8; 16],
            timestamp_ns: 0,
            os_type: OsType::Linux,
            arch_type: ArchType::X86_64,
            pid: 0,
        }
    }
}

#[derive(Debug, Clone)]
pub struct BlockHeader {
    pub block_type: BlockType,
    pub flags: u16,
    pub block_length: u32,
    pub block_uuid: [u8; 16],
    pub parent_uuid: [u8; 16],
    pub prev_hash: [u8; 32],
}

impl Default for BlockHeader {
    fn default() -> Self {
        Self {
            block_type: BlockType::EndOfCapture,
            flags: 0,
            block_length: 0,
            block_uuid: [0u8; 16],
            parent_uuid: [0u8; 16],
            prev_hash: [0u8; 32],
        }
    }
}

#[derive(Debug, Clone)]
pub struct MemoryRegionPayload {
    pub base_addr: u64,
    pub region_size: u64,
    pub protection: u8,
    pub region_type: RegionType,
    pub page_size: u16,
    pub num_pages: u32,
    pub timestamp_ns: u64,
    pub page_states: Vec<PageState>,
    pub page_data: Vec<u8>,
}

impl Default for MemoryRegionPayload {
    fn default() -> Self {
        Self {
            base_addr: 0,
            region_size: 0,
            protection: 0,
            region_type: RegionType::Unknown,
            page_size: 4096,
            num_pages: 0,
            timestamp_ns: 0,
            page_states: Vec::new(),
            page_data: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct ModuleEntryPayload {
    pub base_addr: u64,
    pub module_size: u64,
    pub path: String,
    pub version: String,
    pub disk_hash: [u8; 32],
    pub native_blob: Vec<u8>,
}


#[derive(Debug, Clone, Default)]
pub struct ModuleListIndexPayload {
    pub count: u32,
}


#[derive(Debug, Clone, Default)]
pub struct EndOfCapturePayload {
    pub file_hash: [u8; 32],
    pub acq_end_ns: u64,
}


// ---------------------------------------------------------------------------
// Block (sum type over all block variants)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub enum Block {
    MemoryRegion {
        header: BlockHeader,
        payload: MemoryRegionPayload,
    },
    ModuleEntry {
        header: BlockHeader,
        payload: ModuleEntryPayload,
    },
    ModuleListIndex {
        header: BlockHeader,
        payload: ModuleListIndexPayload,
    },
    EndOfCapture {
        header: BlockHeader,
        payload: EndOfCapturePayload,
    },
    Unknown {
        header: BlockHeader,
        raw_payload: Vec<u8>,
    },
}
