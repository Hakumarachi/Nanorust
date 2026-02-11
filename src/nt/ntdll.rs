use std::ffi::c_void;
use ntapi::ntmmapi::MEMORY_INFORMATION_CLASS;
use windows::Win32::Foundation::{HANDLE, NTSTATUS};
use crate::nt::model::{CLIENT_ID, OBJECT_ATTRIBUTES};

pub const NtCurrentProcess: HANDLE = HANDLE(-1isize as *mut c_void);


#[link(name = "ntdll")]
extern "system" {
    pub fn NtQuerySystemInformation(
        system_information_class: u32,
        system_information: *mut core::ffi::c_void,
        system_information_length: u32,
        return_length: *mut u32,
    ) -> NTSTATUS;

    pub fn NtQueryObject(
        handle: &mut HANDLE,
        object_information_class: u32,
        object_information: *mut core::ffi::c_void,
        object_information_length: u32,
        return_length: *mut u32,
    ) -> NTSTATUS;

    pub fn NtOpenProcess(
        process_handle: &mut HANDLE,
        desired_access: u32,
        object_attributes: &mut OBJECT_ATTRIBUTES,
        client_id: &mut CLIENT_ID,
    ) -> NTSTATUS;

    pub fn NtDuplicateObject(
        source_process_handle: HANDLE,
        source_handle: HANDLE,
        target_process_handle: HANDLE,
        target_handle: *mut HANDLE,
        desired_access: u32,
        handle_attributes: u32,
        options: u32,
    ) -> NTSTATUS;

    pub fn NtQueryInformationProcess(
        process_handle: HANDLE,
        process_information_class: u32,
        process_information: *mut core::ffi::c_void,
        process_information_length: u32,
        return_length: *mut u32,
    ) -> NTSTATUS;

    pub fn NtReadVirtualMemory(
        process_handle: HANDLE,
        base_address: *const core::ffi::c_void,
        buffer: *mut core::ffi::c_void,
        number_of_bytes_to_read: usize,
        number_of_bytes_read: *mut usize,
    ) -> NTSTATUS;

    pub fn NtQueryVirtualMemory(
        process_handle: HANDLE,
        base_address: *const core::ffi::c_void,
        memory_information_class: MEMORY_INFORMATION_CLASS,
        memory_information: *mut core::ffi::c_void,
        memory_information_length: usize,
        return_length: *mut usize,
    ) -> NTSTATUS;

    pub fn NtSetInformationProcess(
        process_handle: HANDLE,
        process_information_class: u32,
        process_information: *mut c_void,
        process_information_length: u32,
    ) -> NTSTATUS;
}

