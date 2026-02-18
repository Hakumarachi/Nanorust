use log::debug;

use crate::core::structs::{OBJECT_TYPES_INFORMATION, OBJECT_TYPE_INFORMATION, SYSTEM_HANDLE_INFORMATION_EX, SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX};
use crate::syscall::system::{query_object, query_system_info, NtQueryObjectClasses, NtQuerySystemInformationClasses};
use std::collections::HashMap;
use std::mem::size_of;

pub static mut HANDLES: Option<Vec<SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX>> = None;
pub static mut TYPE_INDEX_TABLE: Option<HashMap<u16, String>> = None;


pub struct HandleTypes;

impl HandleTypes {
    pub const PROCESS_HANDLE_TYPE: &str = "Process";
}


#[inline]
fn align_up(ptr: usize, align: usize) -> usize {
    (ptr + align - 1) & !(align - 1)
}

pub fn get_extended_handle_info() -> Option<()> {
    let buffer = query_system_info(NtQuerySystemInformationClasses::SYSTEM_EXTENDED_HANDLE_INFORMATION)?;

    unsafe {
        let info = buffer.as_ptr() as *const SYSTEM_HANDLE_INFORMATION_EX;
        let count = (*info).number_of_handles;

        let handles_ptr = (*info).handles.as_ptr();
        let handles = std::slice::from_raw_parts(handles_ptr, count);

        HANDLES = Some(handles.to_vec());

        Some(())
    }
}


fn build_type_index_table() -> Option<()> {
    use windows::Win32::Foundation::HANDLE;

    let mut handle = HANDLE::default();
    let buffer = query_object(
        &mut handle,
        NtQueryObjectClasses::OBJECT_TYPES_INFORMATION,
    )?;

    let mut map = HashMap::new();

    unsafe {
        let base = buffer.as_ptr() as usize;
        let types = base as *const OBJECT_TYPES_INFORMATION;
        let count = (*types).number_of_types as usize;

        let mut entry_ptr = align_up(
            base + size_of::<OBJECT_TYPES_INFORMATION>(),
            size_of::<usize>(),
        );

        for _ in 0..count {
            let entry = &*(entry_ptr as *const OBJECT_TYPE_INFORMATION);

            let us = &entry.type_name;
            let name = String::from_utf16_lossy(
                std::slice::from_raw_parts(
                    us.Buffer.0,
                    (us.Length / 2) as usize,
                ),
            );

            let type_index = entry.type_index as u16;

            debug!("TypeIndex {} => {}", type_index, name);
            map.insert(type_index, name);

            entry_ptr = align_up(
                entry_ptr
                    + size_of::<OBJECT_TYPE_INFORMATION>()
                    + us.MaximumLength as usize,
                size_of::<usize>(),
            );
        }
        TYPE_INDEX_TABLE = Some(map);
    }

    Some(())
}

pub fn get_type_index_by_name(name: &str) -> Option<u32> {
    unsafe {
        // Check if we need to build the type table
        if TYPE_INDEX_TABLE.is_none() || TYPE_INDEX_TABLE.as_ref().unwrap().is_empty() {
            build_type_index_table();
        }

        // Now safely access the populated type table
        if let Some(type_table) = &TYPE_INDEX_TABLE {
            for (type_index, type_name) in type_table.iter() {
                if type_name.eq_ignore_ascii_case(name) {
                    return Some(*type_index as u32);
                }
            }
        }
        None
    }
}

