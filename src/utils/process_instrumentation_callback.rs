use std::ffi::c_void;
use std::ptr::null_mut;
use log::{debug, error};
use crate::syscall::syscalls::{NtSetInformationProcess, NT_CURRENT_PROCESS};
use crate::nt::ntdll::nt_success;

const PROCESS_INSTRUMENTATION_CALLBACK: u32 = 40;

#[repr(C)]
struct ProcessInstrumentationCallbackInformation {
    version: u32,
    reserved: u32,
    callback: *mut c_void,
}

pub fn remove_syscall_callback_hook() -> bool {
    debug!("Starting remove_syscall_callback_hook");
    unsafe {
        let mut info = ProcessInstrumentationCallbackInformation {
            version: if cfg!(target_arch = "x86_64") { 0 } else { 1 },
            reserved: 0,
            callback: null_mut(), // remove callback
        };

        let status = NtSetInformationProcess(
            NT_CURRENT_PROCESS,
            PROCESS_INSTRUMENTATION_CALLBACK,
            &mut info as *mut _ as *mut c_void,
            size_of::<ProcessInstrumentationCallbackInformation>() as u32,
        );

        if !nt_success(status) {
            error!("NtSetInformationProcess failed: 0x{:?}", status);
            false
        } else {
            debug!("Instrumentation callback removed");
            true
        }
    }
}
