use crate::nt::dump::model::ProcessArchitecture::AMD64;
use std::arch::asm;
use windows::Win32::Foundation::HANDLE;

pub const MINIDUMP_SIGNATURE: u32 = 0x504D444D; // 'MDMP'
pub const MINIDUMP_VERSION: u16 = 42899;
pub const MINIDUMP_IMPL_VERSION: u16 = 0;
pub const SIZE_OF_MINIDUMP_MODULE: usize = 108;
pub const SIZE_OF_HEADER :usize = 32;
pub const SIZE_OF_DIRECTORY :usize = 12;

#[cfg(target_arch = "x86_64")]
const PEB_OFFSET: usize = 0x60;

#[cfg(target_arch = "x86")]
const PEB_OFFSET: usize = 0x30;

enum ProcessArchitecture {
    AMD64 = 9,
    INTEL = 0,
}

// x64
#[cfg(target_arch = "x86_64")]
pub const PROCESS_PARAMETERS_OFFSET: usize = 0x20;
#[cfg(target_arch = "x86_64")]
pub const OS_MAJOR_VERSION_OFFSET: usize = 0x118;
#[cfg(target_arch = "x86_64")]
pub const OS_MINOR_VERSION_OFFSET: usize = 0x11C;
#[cfg(target_arch = "x86_64")]
pub const OS_BUILD_NUMBER_OFFSET: usize = 0x120;
#[cfg(target_arch = "x86_64")]
pub const OS_PLATFORM_ID_OFFSET: usize = 0x124;
#[cfg(target_arch = "x86_64")]
pub const CSD_VERSION_OFFSET: usize = 0x2e8;
#[cfg(target_arch = "x86_64")]
pub const PROCESSOR_ARCHITECTURE: usize = AMD64 as usize;
#[cfg(target_arch = "x86_64")]
pub const SIZE_OF_SYSTEM_INFO_STREAM: usize = 48;

// x86
#[cfg(target_arch = "x86")]
pub const PROCESS_PARAMETERS_OFFSET: usize = 0x10;
#[cfg(target_arch = "x86")]
pub const OS_MAJOR_VERSION_OFFSET: usize = 0xA4;
#[cfg(target_arch = "x86")]
pub const OS_MINOR_VERSION_OFFSET: usize = 0xA8;
#[cfg(target_arch = "x86")]
pub const OS_BUILD_NUMBER_OFFSET: usize = 0xAC;
#[cfg(target_arch = "x86")]
pub const OS_PLATFORM_ID_OFFSET: usize = 0xB0;
#[cfg(target_arch = "x86")]
pub const CSD_VERSION_OFFSET: usize = 0x1F0;
#[cfg(target_arch = "x86")]
pub const PROCESSOR_ARCHITECTURE: usize = INTEL as usize;
#[cfg(target_arch = "x86")]
pub const SIZE_OF_SYSTEM_INFO_STREAM: usize = 56;


pub enum MiniDumpType {
    MiniDumpNormal = 0,
}

pub enum StreamType{
    SystemInfoStream = 7,
    ModuleListStream = 4,
    Memory64ListStream = 9,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct MiniDumpSystemInfo {
    pub processor_architecture: i16,
    pub processor_level: i16,
    pub processor_revision: i16,
    pub number_of_processors: i8,
    pub product_type: i8,
    pub major_version: u32,
    pub minor_version: u32,
    pub build_number: u32,
    pub platform_id: u32,
    pub csd_version_rva: u32,
    pub suite_mask: i16,
    pub reserved2: i16,
    #[cfg(target_arch = "x86_64")]
    pub processor_features1: u64,
    #[cfg(target_arch = "x86_64")]
    pub processor_features2: u64,
    #[cfg(target_arch = "x86")]
    pub vendor_id1: u32,
    #[cfg(target_arch = "x86")]
    pub vendor_id2: u32,
    #[cfg(target_arch = "x86")]
    pub vendor_id3: u32,
    #[cfg(target_arch = "x86")]
    pub version_information: u32,
    #[cfg(target_arch = "x86")]
    pub feature_information: u32,
    #[cfg(target_arch = "x86")]
    pub amd_extended_cpu_features: u32,
}

#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
pub struct MiniDumpLocationDescriptor {
    pub data_size: u32,
    pub rva: u32,
}

#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
pub struct VsFixedFileInfo {
    // remplis selon la définition Windows VS_FIXEDFILEINFO
    pub signature: u32,
    pub struct_version: u32,
    pub file_version_ms: u32,
    pub file_version_ls: u32,
    pub product_version_ms: u32,
    pub product_version_ls: u32,
    pub file_flags_mask: u32,
    pub file_flags: u32,
    pub file_os: u32,
    pub file_type: u32,
    pub file_subtype: u32,
    pub file_date_ms: u32,
    pub file_date_ls: u32,
}

#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
pub struct MiniDumpModule {
    pub base_of_image: u64,
    pub size_of_image: u32,
    pub check_sum: u32,
    pub time_date_stamp: u32,
    pub module_name_rva: u32,
    pub version_info: VsFixedFileInfo,
    pub cv_record: MiniDumpLocationDescriptor,
    pub misc_record: MiniDumpLocationDescriptor,
    pub reserved0: u64,
    pub reserved1: u64,
}


#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct MiniDumpDirectory {
    pub stream_type: u32,
    pub data_size: u32,
    pub rva: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct MiniDumpHeader {
    pub signature: u32,
    pub version: u16,
    pub implementation_version: u16,
    pub number_of_streams: u32,
    pub stream_directory_rva: u32,
    pub check_sum: u32,
    pub reserved: u32,
    pub time_date_stamp: u32,
    pub flags: u32,
}

#[repr(C)]
#[derive(Debug, Default)]
pub struct MiniDumpMemoryDescriptor64 {
    pub start_of_memory_range: u64,
    pub data_size: u64,
    pub state: u32,
    pub protect: u32,
    pub typ: u32,
}


#[repr(C)]
#[derive(Debug)]
pub struct DumpContext {
    pub h_process: HANDLE,
    pub base_address: *mut core::ffi::c_void,
    pub rva: u32,
    pub dump_max_size: u32,
    pub signature: u32,
    pub version: u16,
    pub implementation_version: u16,
    pub buf: Vec<u8>,
}

impl DumpContext {
    pub fn append(&mut self, data: &[u8]) -> Result<(), DumpError> {
        let size = data.len() as u32;
        let new_rva = self.rva.checked_add(size).ok_or_else(|| {
            log::error!("The dump size exceeds the 32-bit address space!");
            DumpError::InvalidState
        })?;

        if new_rva >= self.dump_max_size {
            log::error!("The dump is too big, please increase DUMP_MAX_SIZE.");
            return Err(DumpError::WriteFailed);
        }
        self.rva = new_rva;
        self.buf.extend_from_slice(data);
        Ok(())
    }

    pub fn write_at(&mut self, offset: u32, data: &[u8]) -> Result<(), DumpError> {
        let offset = offset as usize;
        self.buf[offset..offset + data.len()].copy_from_slice(data);
        Ok(())
    }

}

#[derive(Debug)]
pub enum DumpError {
    Io(std::io::Error),
    InvalidState,
    WriteFailed,
}

pub fn get_peb() -> *const u8 {
    let peb: *const u8;
    unsafe {
        asm!(
        "mov {}, gs:[{}]",
        out(reg) peb,
        const PEB_OFFSET
        );
    }
    peb
}

pub fn rva<T>(base: *const u8, offset: usize) -> *const T {
    (base as usize + offset) as *const T
}

// list of modules relevant to mimikatz
pub const IMPORTANT_MODULES: &[&str] = &[
    "lsasrv.dll",
    "msv1_0.dll",
    "tspkg.dll",
    "wdigest.dll",
    "kerberos.dll",
    "livessp.dll",
    "dpapisrv.dll",
    "kdcsvc.dll",
    "cryptdll.dll",
    "lsadb.dll",
    "samsrv.dll",
    "rsaenh.dll",
    "ncrypt.dll",
    "ncryptprov.dll",
    "eventlog.dll",
    "wevtsvc.dll",
    "termsrv.dll",
    "cloudap.dll",
];