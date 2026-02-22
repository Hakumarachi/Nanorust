use log::{debug, error};
use windows::Win32::Foundation::HANDLE;
use windows::Win32::Security::{LUID_AND_ATTRIBUTES, SE_PRIVILEGE_ENABLED, TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES, TOKEN_QUERY};
use crate::syscall::syscalls::NtCurrentProcess;
use crate::syscall::system::{adjust_privileges_token, open_process_token, query_information_token};
use crate::core::token::model::TOKEN_INFORMATION_CLASS;

pub fn enable_debug_privilege() -> bool {
       chek_token_privilege(None, "SeDebugPrivilege", true)
}

pub fn is_debug_privilege_enabled() -> bool {
    chek_token_privilege(None, "SeDebugPrivilege", false)
}

fn chek_token_privilege(mut h_token: Option<HANDLE>, privilege_name: &str, enable_privilege: bool) -> bool {
    // TODO : Dynamically resolve LookupPrivilegeNameW function from ADVAPI32_DLL

    if h_token.is_none() {
            h_token = open_process_token(NtCurrentProcess, TOKEN_QUERY.0 | TOKEN_ADJUST_PRIVILEGES.0);
    }

    if h_token.is_none() {
        error!("NtOpenProcessToken Failed");
        return false;
    }
    let h_token = h_token.unwrap();

    let data = query_information_token(h_token, TOKEN_INFORMATION_CLASS::TokenPrivileges as u32, 0);

    let privileges: &[LUID_AND_ATTRIBUTES];

    match data {
        Some((buffer, len)) => {
            if len > 0 {
                let tp_ptr = buffer.as_ptr() as *const TOKEN_PRIVILEGES;
                let privilege_count = unsafe { (*tp_ptr).PrivilegeCount };

                let privileges_ptr = unsafe { (*tp_ptr).Privileges.as_ptr() };

                privileges = unsafe {
                    std::slice::from_raw_parts(privileges_ptr as *mut _, privilege_count as usize)
                };

                debug!("Privilege count: {}", privilege_count);
                for privilege in privileges.iter() {
                    debug!("LUID: {:x?}, Attr: {:x?}", privilege.Luid, privilege.Attributes);
                }
            }
            else {
                error!("NtOpenProcessToken Failed");
                return false;
            }
        }
        None => {
            error!("NtOpenProcessToken Failed");
            return false;
        }
    }

    debug!("Get names... ");

    for privilege in privileges {
        let name : String;

        let success = luid_to_privilege_name(privilege.Luid.LowPart);

        if success.is_some() {
            name = success.unwrap().to_string();
        }
        else {
            error!("Unable to resolve privilege name");
            continue;
        }

        if name.eq_ignore_ascii_case(privilege_name){
            if privilege.Attributes.0 & SE_PRIVILEGE_ENABLED.0 != 0 {
                debug!("Privilege {} is enable", privilege_name);
                return true;
            }
            let mut tkp : TOKEN_PRIVILEGES = TOKEN_PRIVILEGES::default();

            tkp.PrivilegeCount = 1;
            tkp.Privileges[0].Luid = privilege.Luid;
            tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

            if enable_privilege {
                let success = adjust_privileges_token(
                    h_token,
                    false,
                    &mut tkp,
                    size_of::<TOKEN_PRIVILEGES>() as _,
                );
                if success.is_some() {
                    debug!("Privilege {} enabled", privilege_name);
                    return true;
                }
                return false
            } else {
                debug!("Privilege {} is disable", privilege_name);
                return false
            }
        }
    }
    false
}

fn luid_to_privilege_name(low: u32) -> Option<&'static str> {
    match low {
        2  => Some("SeCreateTokenPrivilege"),
        3  => Some("SeAssignPrimaryTokenPrivilege"),
        4  => Some("SeLockMemoryPrivilege"),
        5  => Some("SeIncreaseQuotaPrivilege"),
        6  => Some("SeMachineAccountPrivilege"),
        7  => Some("SeTcbPrivilege"),
        8  => Some("SeSecurityPrivilege"),
        9  => Some("SeTakeOwnershipPrivilege"),
        10 => Some("SeLoadDriverPrivilege"),
        11 => Some("SeSystemProfilePrivilege"),
        12 => Some("SeSystemtimePrivilege"),
        13 => Some("SeProfileSingleProcessPrivilege"),
        14 => Some("SeIncreaseBasePriorityPrivilege"),
        15 => Some("SeCreatePagefilePrivilege"),
        16 => Some("SeCreatePermanentPrivilege"),
        17 => Some("SeBackupPrivilege"),
        18 => Some("SeRestorePrivilege"),
        19 => Some("SeShutdownPrivilege"),
        20 => Some("SeDebugPrivilege"),
        21 => Some("SeAuditPrivilege"),
        22 => Some("SeSystemEnvironmentPrivilege"),
        23 => Some("SeChangeNotifyPrivilege"),
        24 => Some("SeRemoteShutdownPrivilege"),
        25 => Some("SeUndockPrivilege"),
        26 => Some("SeSyncAgentPrivilege"),
        27 => Some("SeEnableDelegationPrivilege"),
        28 => Some("SeManageVolumePrivilege"),
        29 => Some("SeImpersonatePrivilege"),
        30 => Some("SeCreateGlobalPrivilege"),
        31 => Some("SeTrustedCredManAccessPrivilege"),
        32 => Some("SeRelabelPrivilege"),
        33 => Some("SeIncreaseWorkingSetPrivilege"),
        34 => Some("SeTimeZonePrivilege"),
        35 => Some("SeCreateSymbolicLinkPrivilege"),
        _  => None,
    }
}