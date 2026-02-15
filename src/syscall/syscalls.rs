use crate::nt::structs::{CLIENT_ID, OBJECT_ATTRIBUTES};
use crate::syscall::resolver::get_syscall;
use crate::syscall::runner::run_syscall10;
use ntapi::ntmmapi::MEMORY_INFORMATION_CLASS;
use std::ffi::c_void;
use windows::Win32::Foundation::{HANDLE, NTSTATUS};


pub fn NtQuerySystemInformation(
    system_information_class: u32,
    system_information: *mut c_void,
    system_information_length: u32,
    return_length: *mut u32,
) -> NTSTATUS {
    unsafe {
        let syscall = get_syscall("NtQuerySystemInformation");
        let args: [usize; 10] = [
            system_information_class as _,
            system_information as _,
            system_information_length as _,
            return_length as _,
            0,0,0,0,0,0
        ];
        let ret = run_syscall10(syscall.p_address, args);
        NTSTATUS{
            0: ret
        }
    }
}

pub fn NtQueryObject(
    handle: &mut HANDLE,
    object_information_class: u32,
    object_information: *mut core::ffi::c_void,
    object_information_length: u32,
    return_length: *mut u32,
) -> NTSTATUS {
    unsafe {
        let syscall = get_syscall("NtQueryObject");
        let args: [usize; 10] = [
            handle as *mut HANDLE as _,
            object_information_class as _,
            object_information as _,
            object_information_length as _,
            return_length as _,
            0,0,0,0,0
        ];
        let ret = run_syscall10(syscall.p_address, args);
        NTSTATUS{
            0: ret
        }
    }
}

pub fn NtOpenProcess(
    process_handle: &mut HANDLE,
    desired_access: u32,
    object_attributes: &mut OBJECT_ATTRIBUTES,
    client_id: &mut CLIENT_ID,
) -> NTSTATUS {
    unsafe {
        let syscall = get_syscall("NtOpenProcess");
        let args: [usize; 10] = [
            process_handle as *mut HANDLE as _,
            desired_access as _,
            object_attributes as *mut _ as _,
            client_id as *mut _ as _,
            0,0,0,0,0,0
        ];
        let ret = run_syscall10(syscall.p_address, args);
        NTSTATUS{
            0: ret
        }
    }
}

pub fn NtDuplicateObject(
    source_process_handle: HANDLE,
    source_handle: HANDLE,
    target_process_handle: HANDLE,
    target_handle: *mut HANDLE,
    desired_access: u32,
    handle_attributes: u32,
    options: u32,
) -> NTSTATUS{
    unsafe {
        let syscall = get_syscall("NtDuplicateObject");
        let args: [usize; 10] = [
            source_process_handle.0 as _,
            source_handle.0 as _,
            target_process_handle.0 as _,
            target_handle as *mut _ as _,
            desired_access as _,
            handle_attributes as _,
            options as _,
            0,0,0
        ];
        let ret = run_syscall10(syscall.p_address, args);
        NTSTATUS{
            0: ret
        }
    }
}

pub fn NtQueryInformationProcess(
    process_handle: HANDLE,
    process_information_class: u32,
    process_information: *mut c_void,
    process_information_length: u32,
    return_length: *mut u32,
) -> NTSTATUS{
    unsafe {
        let syscall = get_syscall("NtQueryInformationProcess");
        let args: [usize; 10] = [
            process_handle.0 as _,
            process_information_class as _,
            process_information as _,
            process_information_length as _,
            return_length as _,
            0,0,0,0,0
        ];
        let ret = run_syscall10(syscall.p_address, args);
        NTSTATUS{
            0: ret
        }
    }
}

pub fn NtReadVirtualMemory(
    process_handle: HANDLE,
    base_address: *const c_void,
    buffer: *mut c_void,
    number_of_bytes_to_read: usize,
    number_of_bytes_read: *mut usize,
) -> NTSTATUS{
    unsafe {
        let syscall = get_syscall("NtReadVirtualMemory");
        let args: [usize; 10] = [
            process_handle.0 as _,
            base_address as _,
            buffer as _,
            number_of_bytes_to_read as _,
            number_of_bytes_read as _,
            0,0,0,0,0
        ];
        let ret = run_syscall10(syscall.p_address, args);
        NTSTATUS{
            0: ret
        }
    }
}

pub fn NtQueryVirtualMemory(
    process_handle: HANDLE,
    base_address: *const c_void,
    memory_information_class: MEMORY_INFORMATION_CLASS,
    memory_information: *mut c_void,
    memory_information_length: usize,
    return_length: *mut usize,
) -> NTSTATUS{
    unsafe {
        let syscall = get_syscall("NtQueryVirtualMemory");
        let args: [usize; 10] = [
            process_handle.0 as _,
            base_address as _,
            memory_information_class as _,
            memory_information as _,
            memory_information_length as _,
            return_length as _,
            0,0,0,0
        ];
        let ret = run_syscall10(syscall.p_address, args);
        NTSTATUS{
            0: ret
        }
    }
}

pub fn NtSetInformationProcess(
    process_handle: HANDLE,
    process_information_class: u32,
    process_information: *mut c_void,
    process_information_length: u32,
) -> NTSTATUS {
    unsafe {
        let syscall = get_syscall("NtSetInformationProcess");
        let args: [usize; 10] = [
            process_handle.0 as _,
            process_information_class as _,
            process_information as _,
            process_information_length as _,
            0,0,0,0,0,0
        ];
        let ret = run_syscall10(syscall.p_address, args);
        NTSTATUS{
            0: ret
        }
    }
}


pub const NT_CURRENT_PROCESS: HANDLE = HANDLE(-1isize as *mut c_void);
