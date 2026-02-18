use crate::syscall::gates::*;
use std::collections::HashMap;
use log::debug;

static mut NTDLL_BASE: *mut u8 = std::ptr::null_mut();

static mut SYSCALLS: Option<HashMap<u32, VxTableEntry>> = None;

pub unsafe fn init_syscalls() {
    NTDLL_BASE = get_loaded_module_by_hash(0x1edab0ed)
        .expect("Failed to get NTDLL base");

    SYSCALLS = Some(HashMap::new())
}

pub unsafe fn get_syscall(func_name: &str) -> VxTableEntry {
    if NTDLL_BASE.is_null() {
        init_syscalls();
    }
    let hash = dbj2_hash(func_name.as_bytes());
    let map = SYSCALLS.as_mut().unwrap();

    if let Some(info) = map.get(&hash) {
        return *info;
    }

    let info = hells_halos_tartarus_gate(NTDLL_BASE, hash)
        .expect(&format!("Failed to resolve syscall {}", func_name));

    map.insert(hash, info);
    info
}