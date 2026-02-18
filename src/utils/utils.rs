use windows::Win32::Foundation::{NTSTATUS, UNICODE_STRING};
use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};

pub fn unicode_to_string(u: &UNICODE_STRING) -> String {
    if u.Length == 0 || u.Buffer.is_null() {
        return String::new();
    }

    let slice = unsafe {
        std::slice::from_raw_parts(
            u.Buffer.0,
            (u.Length / 2) as usize
        )
    };

    String::from_utf16_lossy(slice)
}

use windows::Win32::Foundation::HANDLE;
use log::{debug, error, info};
use crate::core::process::get_process_image_file_name;

pub unsafe fn is_lsass(h_process: HANDLE) -> bool {
    let file_name = get_process_image_file_name(
        h_process
    );

    if file_name.is_none() {
        error!("Failed to get core image file name");
        return false;
    }

    let file_name_str = file_name.unwrap();
    debug!("Process image file name: {}", file_name_str);

    if file_name_str.to_lowercase().ends_with("\\lsass.exe"){
        return true;
    }

    false
}

pub fn get_full_path(filename: &str) -> std::io::Result<String> {
    let path = Path::new(filename);

    let abs: PathBuf = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };

    // Prefix with \??\ for NT-style path
    let nt_path = format!(r"\\??\\{}", abs.to_string_lossy());
    Ok(nt_path)
}

pub fn write_buffer(path: &str, buffer: &[u8]) -> std::io::Result<()> {
    let mut file = File::create(path)?;
    file.write_all(buffer)?;
    Ok(())
}

pub fn nt_success(status: NTSTATUS) -> bool {
    status.0 >= 0
}