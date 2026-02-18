use log::{debug, info, trace};
use std::mem::size_of;
use windows::Win32::Foundation::HANDLE;
use windows_sys::Win32::Foundation::UNICODE_STRING;

use crate::core::process::model::ProcessInfo;
use crate::core::structs::SYSTEM_PROCESS_INFORMATION;
use crate::syscall::system::{get_process_image, query_system_info, NtQuerySystemInformationClasses};
use crate::utils::utils::unicode_to_string;

pub static mut PROCESSES: Option<Vec<ProcessInfo>> = None;



pub fn get_process_info() -> Option<()>{
    let buffer = query_system_info(NtQuerySystemInformationClasses::SYSTEM_PROCESS_INFORMATION)?;
    debug!("buffer length: {}", buffer.len());
    let mut processes = Vec::new();
    let mut lprocesses = Vec::new();
    let mut offset = 0usize;

    loop {
        let spi = unsafe {
            &*(buffer.as_ptr().add(offset)
                as *const SYSTEM_PROCESS_INFORMATION)
        };

        unsafe {
            let proc_info = std::ptr::read(spi);
            processes.push(proc_info);
            lprocesses.push(ProcessInfo{pid: proc_info.unique_process_id, name: unicode_to_string(&proc_info.image_name)});
        }

        if spi.next_entry_offset == 0 {
            break;
        }

        offset += spi.next_entry_offset as usize;
    }

    unsafe { PROCESSES = Some(lprocesses) };

    Some(())
}

pub fn get_process_image_file_name(hProcess : HANDLE) -> Option<String> {
    let buffer = get_process_image(hProcess, 27, 300);

    unsafe {
        let buffer = buffer?;
        let us = buffer.as_ptr() as *const UNICODE_STRING;

        // Taille réelle du buffer UTF‑16
        let total_bytes = buffer.len();
        let string_bytes = total_bytes.checked_sub(size_of::<UNICODE_STRING>())?;

        let wchar_len = string_bytes / 2;

        let str_ptr = (us as *const u8)
            .add(size_of::<UNICODE_STRING>()) as *const u16;

        let slice = std::slice::from_raw_parts(str_ptr, wchar_len);

        // Coupe au premier \0 si présent
        let nul = slice.iter().position(|&c| c == 0).unwrap_or(slice.len());

        Some(String::from_utf16_lossy(&slice[..nul]))
    }
}

pub fn get_pid_by_name_nt(name: &str) -> Option<usize> {
    unsafe {
        if PROCESSES.is_none() || PROCESSES.as_ref().unwrap().is_empty() {
            get_process_info()?;
        }
        if let Some(processes) = &PROCESSES {
            for process in processes.iter() {
                if process.name.eq_ignore_ascii_case(name) {
                    return Some(process.pid);
                }
            }

        }
    }
    None
}

pub fn get_name_by_pid_nt(pid: usize) -> Option<String> {
    unsafe {
        if PROCESSES.is_none() || PROCESSES.as_ref().unwrap().is_empty() {
            get_process_info()?;
        }

        if let Some(processes) = &PROCESSES {
            for process in processes.iter() {
                if process.pid == pid {
                    debug!("PID: {}, Name: {}", process.pid, process.name);
                    return Some(process.name.clone());
                }
            }
        }
    }
    None
}

pub fn get_all_process_except(pid: usize) -> Vec<ProcessInfo>{

        let local_pid = std::process::id() as usize;
        let mut selected_processes = Vec::new();

        unsafe {
            if PROCESSES.is_none() || PROCESSES.as_ref().unwrap().is_empty() {
                get_process_info();
            }

            if let Some(processes) = &PROCESSES {
                for process in processes.iter() {
                    if process.pid == local_pid { continue; }
                    if process.pid == pid { continue; }
                    if process.pid == 0 { continue; }
                    if process.pid == 4 { continue; }
                    trace!("PID: {}, Name: {}", process.pid, process.name);
                    selected_processes.push(process.clone());
                }
            }
        }
    info!("Selected processes: {}", selected_processes.len());
    selected_processes
}
