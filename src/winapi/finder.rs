#[cfg(target_os = "windows")]
use windows::Win32::{
    Foundation::{CloseHandle, HANDLE},
    System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot,
        Process32FirstW,
        Process32NextW,
        PROCESSENTRY32W,
        TH32CS_SNAPPROCESS,
    },
};

use std::ffi::OsString;
#[cfg(target_os = "windows")]
use std::os::windows::ffi::OsStringExt;

#[cfg(target_os = "windows")]
fn widestr_to_string(wide: &[u16]) -> alloc::string::String {
    let len = wide.iter().position(|&c| c == 0).unwrap_or(wide.len());
    OsString::from_wide(&wide[..len])
        .to_string_lossy()
        .to_string()
}

#[cfg(target_os = "windows")]
pub fn get_pid_by_name(target: &str) -> Option<u32> {
    unsafe {
        let snapshot: HANDLE =
            CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0).ok()?;

        let mut entry = PROCESSENTRY32W::default();
        entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;

        if Process32FirstW(snapshot, &mut entry).is_ok() {
            loop {
                let name = widestr_to_string(&entry.szExeFile);

                if name.eq_ignore_ascii_case(target) {
                    let _ = CloseHandle(snapshot);
                    return Some(entry.th32ProcessID);
                }

                if !Process32NextW(snapshot, &mut entry).is_ok() {
                    break;
                }
            }
        }

        let _ = CloseHandle(snapshot);
        None
    }
}