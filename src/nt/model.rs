use windows::Win32::Foundation::{HANDLE, UNICODE_STRING};
use windows::Win32::Security::GENERIC_MAPPING;

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct SYSTEM_PROCESS_INFORMATION {
    pub next_entry_offset: u32,
    pub number_of_threads: u32,
    pub _reserved: [u8; 48],
    pub image_name: UNICODE_STRING,
    pub base_priority: i32,
    pub unique_process_id: usize,
    pub _reserved2: [usize; 2],
}

#[repr(C)]
pub struct SYSTEM_HANDLE_INFORMATION_EX {
    pub number_of_handles: usize,
    pub reserved: usize,
    pub handles: [SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX; 0],
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX {
    pub object: *mut core::ffi::c_void,
    pub unique_process_id: usize,
    pub handle_value: HANDLE,
    pub granted_access: u32,
    pub creator_back_trace_index: u16,
    pub object_type_index: u16,
    pub handle_attributes: u32,
    pub reserved: u32,
}

#[repr(C)]
pub struct OBJECT_BASIC_INFORMATION {
    pub attributes: u32,
    pub granted_access: u32,
    pub handle_count: u32,
    pub pointer_count: u32,
    pub reserved: [u32; 10],
}

#[repr(C)]
#[derive(Debug)]
pub struct OBJECT_TYPE_INFORMATION {
    pub type_name: UNICODE_STRING,
    pub total_number_of_objects: u32,
    pub total_number_of_handles: u32,
    pub total_paged_pool_usage: u32,
    pub total_non_paged_pool_usage: u32,
    pub total_name_pool_usage: u32,
    pub total_handle_table_usage: u32,
    pub high_water_number_of_objects: u32,
    pub high_water_number_of_handles: u32,
    pub high_water_paged_pool_usage: u32,
    pub high_water_non_paged_pool_usage: u32,
    pub high_water_name_pool_usage: u32,
    pub high_water_handle_table_usage: u32,
    pub invalid_attributes: u32,
    pub generic_mapping: GENERIC_MAPPING,
    pub valid_access_mask: u32,
    pub security_required: u8,       // BOOLEAN
    pub maintain_handle_count: u8,   // BOOLEAN
    pub type_index: u8,              // UCHAR
    pub reserved_byte: i8,           // CHAR
    pub pool_type: u32,
    pub default_paged_pool_charge: u32,
    pub default_non_paged_pool_charge: u32,
}

#[repr(C)]
pub struct OBJECT_TYPES_INFORMATION {
    pub number_of_types: u32,
    // suivi immédiatement par OBJECT_TYPE_INFORMATION[]
}

#[repr(C)]
pub struct CLIENT_ID {
    pub unique_process: *mut core::ffi::c_void,
    pub unique_thread: *mut core::ffi::c_void,
}

#[repr(C)]
pub struct OBJECT_ATTRIBUTES {
    pub length: u32,
    pub root_directory: *mut core::ffi::c_void,
    pub object_name: *mut core::ffi::c_void,
    pub attributes: u32,
    pub security_descriptor: *mut core::ffi::c_void,
    pub security_quality_of_service: *mut core::ffi::c_void,
}

