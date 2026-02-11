use windows::Win32::System::SystemInformation::{
    GetVersionExW, OSVERSIONINFOW,
};
use windows::Win32::System::Threading::{
    PROCESS_CREATE_PROCESS,
    PROCESS_QUERY_INFORMATION,
    PROCESS_QUERY_LIMITED_INFORMATION,
    PROCESS_VM_READ,
};

/// Generic function to get LSASS permissions based on Windows version
///
/// # Arguments
/// * `base_permission` - The base permission flag to use (e.g., PROCESS_VM_READ or PROCESS_CREATE_PROCESS)
fn get_lsass_permissions(base_permission: u32) -> u32 {
    unsafe {
        let mut version = OSVERSIONINFOW {
            dwOSVersionInfoSize: std::mem::size_of::<OSVERSIONINFOW>() as u32,
            ..Default::default()
        };

        // Using GetVersionExW instead
        let _ = GetVersionExW(&mut version as *mut _);

        let mut access = base_permission;

        if version.dwMajorVersion <= 6 {
            access |= PROCESS_QUERY_INFORMATION.0;
        } else {
            access |= PROCESS_QUERY_LIMITED_INFORMATION.0;
        }

        access
    }
}

pub fn get_lsass_min_permissions() -> u32 {
    get_lsass_permissions(PROCESS_VM_READ.0)
}

pub fn get_lsass_clone_permissions() -> u32 {
    get_lsass_permissions(PROCESS_CREATE_PROCESS.0)
}
