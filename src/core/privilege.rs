use windows::core::w;
use windows::Win32::Foundation::{CloseHandle, LUID};
use windows::Win32::Security::{AdjustTokenPrivileges, GetTokenInformation, LookupPrivilegeValueW, TokenPrivileges, LUID_AND_ATTRIBUTES, SE_DEBUG_NAME, SE_PRIVILEGE_ENABLED, TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES, TOKEN_QUERY};
use windows::Win32::System::Threading::{
    GetCurrentProcess, OpenProcessToken,
};

pub fn enable_debug_privilege() -> bool {
    unsafe {
        let mut token = Default::default();

        // 1️⃣ Ouvrir le token du core courant
        if !OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            &mut token,
        ).is_ok() {
            return false;
        }

        // 2️⃣ Obtenir le LUID de SeDebugPrivilege
        let mut luid = LUID::default();

        if !LookupPrivilegeValueW(
            None,
            w!("SeDebugPrivilege"),
            &mut luid,
        ).is_ok() {
            let _ = CloseHandle(token);
            return false;
        }

        // 3️⃣ Activer le privilège
        let tp = TOKEN_PRIVILEGES {
            PrivilegeCount: 1,
            Privileges: [LUID_AND_ATTRIBUTES {
                Luid: luid,
                Attributes: SE_PRIVILEGE_ENABLED,
            }],
        };

        let success = AdjustTokenPrivileges(
            token,
            false,
            Some(&tp),
            0,
            None,
            None,
        ).is_ok();

        let _ = CloseHandle(token);
        success
    }
}

pub fn is_debug_privilege_enabled() -> bool {
    unsafe {
        let mut token_handle = Default::default();

        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token_handle).is_err() {
            return false;
        }

        let mut return_length = 0u32;
        let _ = GetTokenInformation(
            token_handle,
            TokenPrivileges,
            None,
            0,
            &mut return_length,
        );

        if return_length == 0 {
            let _ = CloseHandle(token_handle);
            return false;
        }

        let mut buffer = vec![0u8; return_length as usize];

        if GetTokenInformation(
            token_handle,
            TokenPrivileges,
            Some(buffer.as_mut_ptr() as *mut _),
            return_length,
            &mut return_length,
        ).is_err() {
            let _ = CloseHandle(token_handle);
            return false;
        }

        let privileges = &*(buffer.as_ptr() as *const TOKEN_PRIVILEGES);

        let mut debug_luid = LUID::default();
        if LookupPrivilegeValueW(
            None,
            SE_DEBUG_NAME,
            &mut debug_luid,
        ).is_err() {
            let _ = CloseHandle(token_handle);
            return false;
        }

        let privilege_array = std::slice::from_raw_parts(
            &privileges.Privileges as *const LUID_AND_ATTRIBUTES,
            privileges.PrivilegeCount as usize,
        );

        for priv_attr in privilege_array {
            if priv_attr.Luid.LowPart == debug_luid.LowPart
                && priv_attr.Luid.HighPart == debug_luid.HighPart {
                let _ = CloseHandle(token_handle);
                return (priv_attr.Attributes & SE_PRIVILEGE_ENABLED).0 != 0;
            }
        }

        let _ = CloseHandle(token_handle);
        false
    }
}