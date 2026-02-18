use crate::utils::utils::nt_success;
use crate::core::structs::{CLIENT_ID, OBJECT_ATTRIBUTES};
use crate::syscall::syscalls::{NtOpenProcess, NtQueryInformationProcess, NtQueryObject, NtQuerySystemInformation, NtQueryVirtualMemory, NtReadVirtualMemory};
use log::{error, debug};
use ntapi::ntmmapi::MEMORY_INFORMATION_CLASS;
use std::ffi::c_void;
use windows::Win32::Foundation::{HANDLE, STATUS_INFO_LENGTH_MISMATCH, STATUS_PARTIAL_COPY};
use windows::Win32::System::Memory::MEMORY_BASIC_INFORMATION;

pub struct NtQuerySystemInformationClasses;
pub struct NtQueryObjectClasses;
pub struct NtOpenProcessAccess;

impl NtQuerySystemInformationClasses {
    pub const SYSTEM_PROCESS_INFORMATION: u32 = 5;
    pub const SYSTEM_EXTENDED_HANDLE_INFORMATION: u32 = 64;
}

impl NtQueryObjectClasses {
    pub const OBJECT_BASIC_INFORMATION: u32 = 0;
    pub const OBJECT_NAME_INFORMATION: u32 = 1;
    pub const OBJECT_TYPE_INFORMATION: u32 = 2;
    pub const OBJECT_TYPES_INFORMATION: u32 = 3;
    pub const OBJECT_HANDLE_FLAG_INFORMATION: u32 = 4;
    pub const OBJECT_SESSION_INFORMATION: u32 = 5;
}

impl NtOpenProcessAccess {
    pub const PROCESS_DUP_HANDLE: u32 = 0x0040;
    pub const DUPLICATE_SAME_ACCESS: u32 = 0x0002;
}

pub fn query_system_info(class: u32) -> Option<Vec<u8>> {
    unsafe {
        let mut size: u32 = 0x10000; // 64 KB initial
        let mut buffer: Vec<u8>;

        loop {
            buffer = vec![0u8; size as usize];

            let mut return_len = 0u32;
            let status = NtQuerySystemInformation(
                class,
                buffer.as_mut_ptr() as *mut _,
                size,
                &mut (return_len),
            );

            if nt_success(status) {
                buffer.truncate(return_len as usize);
                return Some(buffer);
            }

            if status == STATUS_INFO_LENGTH_MISMATCH {
                size = return_len;
                continue;
            }
            else{
                debug!("Failed to query system information");
                debug!("status: {:x}", status.0);
                debug!("buffer length: {}", buffer.len());
            }
            return None;
        }
    }
}

pub fn query_object(h: &mut HANDLE, class: u32) -> Option<Vec<u8>> {
    unsafe {
        let mut size: u32 = 0x10000; // 64 KB initial
        let mut buffer: Vec<u8>;

        loop {
            buffer = vec![0u8; size as usize];

            let mut return_len = 0u32;
            let status = NtQueryObject(
                h,
                class,
                buffer.as_mut_ptr() as *mut _,
                size,
                &mut return_len,
            );

            if nt_success(status) {
                buffer.truncate(return_len as usize);
                return Some(buffer);
            }

            if status == STATUS_INFO_LENGTH_MISMATCH {
                size = return_len;
                continue;
            }

            return None;
        }
    }
}

pub fn get_process_handle(pid: usize, permissions: u32, attributes: u32) -> Option<HANDLE> {
    unsafe {
        let mut handle = HANDLE::default();
        let mut client_id = CLIENT_ID {
            unique_process: pid as *mut core::ffi::c_void,
            unique_thread: core::ptr::null_mut(),
        };
        let mut object_attributes = OBJECT_ATTRIBUTES {
            length: core::mem::size_of::<OBJECT_ATTRIBUTES>() as u32,
            root_directory: core::ptr::null_mut(),
            object_name: core::ptr::null_mut(),
            attributes,
            security_descriptor: core::ptr::null_mut(),
            security_quality_of_service: core::ptr::null_mut(),
        };

        let status = NtOpenProcess(
            &mut handle,
            permissions,
            &mut object_attributes,
            &mut client_id,
        );

        debug!("NtOpenProcess status: {:?}", status);

        if nt_success(status) {
            Some(handle)
        } else {
            None
        }
    }
}

pub fn get_process_image(h_process: HANDLE, process_information_class: u32, mut size : u32) -> Option<Vec<u8>> {
    unsafe {
        let mut return_len = 0u32;

        loop {
            let mut buffer = vec![0u8; size as usize];


            let status = NtQueryInformationProcess(
                h_process,
                process_information_class,
                buffer.as_mut_ptr() as _,
                size,
                &mut return_len,
            );

            if nt_success(status) {
                return Some(buffer);
            }

            if status == STATUS_INFO_LENGTH_MISMATCH {
                error!("Size: {}", size);
                size = return_len;
                continue;
            }

            return None;
        }
    }
}

pub fn query_virtual_memory(h_process: HANDLE, base_addr: *mut c_void, mic : MEMORY_INFORMATION_CLASS) -> Option<Vec<u8>> {
    unsafe {
        let mut size: usize = size_of::<MEMORY_BASIC_INFORMATION>();
        let mut return_len = 0usize;
        loop {
            let mut buffer = vec![0u8; size];
            let status = NtQueryVirtualMemory(
                h_process,
                base_addr,
                mic,
                buffer.as_mut_ptr() as *mut _,
                size,
                &mut return_len
            );
            if nt_success(status) {

                return Some(buffer)
            }

            if status == STATUS_INFO_LENGTH_MISMATCH {
                error!("Size: {}", size);
                size = return_len;
                continue;
            }
            return None;
        }
    }
}

pub fn read_virtual_memory(h_process: HANDLE, base_addr: *mut c_void, size : usize) -> Option<(Vec<u8>, usize)> {

        let mut return_len = 0usize;
        let mut buffer = vec![0u8; size];
        for i in 0..2 {
            let status = NtReadVirtualMemory(
                h_process,
                base_addr,
                buffer.as_mut_ptr() as *mut c_void,
                size,
                &mut (return_len) as *mut usize,
            );
            if nt_success(status) {
                return Some((buffer, return_len))
            }

            else if status == STATUS_PARTIAL_COPY {
                debug!(
                    "Partial read: read {} / {} bytes",
                    return_len,
                    size
                );
                return Some((buffer, return_len));
            }
            debug!("status: {:x}", status.0);
        }
    None
}
