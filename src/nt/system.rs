use log::{debug, error, info};
use windows::Win32::Foundation::{HANDLE, STATUS_INFO_LENGTH_MISMATCH};
use crate::nt::model::{CLIENT_ID, OBJECT_ATTRIBUTES};
use crate::nt::ntdll::{NtOpenProcess, NtQueryInformationProcess, NtQueryObject, NtQuerySystemInformation};
use crate::nt::status::nt_success;

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

pub fn get_process_image(hProcess: HANDLE, process_information_class: u32) -> Option<Vec<u8>> {
    unsafe {
        let mut size: u32 = 300;
        let mut return_len = 0u32;

        loop {
            let mut buffer = vec![0u8; size as usize];


            let status = NtQueryInformationProcess(
                hProcess,
                process_information_class,
                buffer.as_mut_ptr() as *mut _,
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

