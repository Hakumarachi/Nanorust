use crate::nt::dump::model::rva;
use crate::nt::system::{get_process_image, read_virtual_memory};
use core::ffi::c_void;
use log::{debug, error};
use ntapi::ntldr::LDR_DATA_TABLE_ENTRY;
use std::mem::size_of;
use std::ptr;
use std::ptr::read_unaligned;
use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::Threading::PROCESS_BASIC_INFORMATION;

const MAX_PATH: usize = 260;

#[repr(C)] // pour que l'alignement et l'ordre des champs soient compatibles C
pub struct ModuleInfo {
    pub dll_base: u64,               // ULONG64
    pub size_of_image: u32,          // ULONG32
    pub dll_name: [u16; 260],         // char[512]
    pub name_rva: u32,               // ULONG32
    pub time_date_stamp: u32,        // ULONG32
    pub check_sum: u32,
}

impl ModuleInfo {
    pub fn new() -> Self {
        Self {
            dll_base: 0,
            size_of_image: 0,
            dll_name: [0u16; 260],
            name_rva: 0,
            time_date_stamp: 0,
            check_sum: 0,
        }
    }
}

const LDR_POINTER_OFFSET : usize = 0x18;
const MODULE_LIST_POINTER_OFFSET : usize =  0x10;

#[cfg(feature = "ssp")]
fn get_peb_address(h_process: HANDLE) -> *const u8 {
    get_peb()
}

#[cfg(not(feature = "ssp"))]
fn get_peb_address(h_process: HANDLE) -> *const u8 {
    debug!("Getting PEB address");
    let mut basic_info : PROCESS_BASIC_INFORMATION = PROCESS_BASIC_INFORMATION::default();
    unsafe {

        let buffer = get_process_image(h_process, 0, size_of::<PROCESS_BASIC_INFORMATION>() as u32);

        if buffer.is_none(){
            error!("NtQueryInformationProcess failed");
            return core::ptr::null();
        }

        let buffer = buffer.unwrap();

        basic_info = read_unaligned(buffer.as_ptr() as *const PROCESS_BASIC_INFORMATION);

        basic_info.PebBaseAddress as *const u8
    }
}

fn get_module_list_address(h_process: HANDLE, is_lsass: bool) -> usize {
    debug!("Getting module list address");
    debug!("p0: {:?}", h_process);
    debug!("is_lsass: {:?}", is_lsass);

    let peb_address = get_peb_address(h_process);
    debug!("peb_address: {:?}", peb_address);


    let mut ldr_address: isize;

    let ldr_pointer= rva::<c_void>(peb_address, LDR_POINTER_OFFSET) ;
    debug!("ldr pointer: {:?}", ldr_pointer);
    let size : usize = size_of::<usize>();



    let data = read_virtual_memory(h_process, ldr_pointer as *mut c_void, size);

    if data.is_none() {
        error!("NtReadVirtualMemory failed");
        return 0;
    }

    let (buffer, _) = data.unwrap();


    ldr_address = unsafe { read_unaligned(buffer.as_ptr() as *const isize) } ;
    debug!("ldr_address: 0x{:x}", ldr_address);


    let module_list_pointer = rva::<c_void>(ldr_address as *const _, MODULE_LIST_POINTER_OFFSET);

    debug!("module_list_pointer: {:?}", module_list_pointer);

    let data = read_virtual_memory(h_process, module_list_pointer as *mut c_void, size);

    if data.is_none() {
        error!("NtReadVirtualMemory failed");
        return 0
    }

    let (buffer, _) = data.unwrap();

    let ldr_entry_address: usize = unsafe { read_unaligned(buffer.as_ptr() as *const usize) };

    debug!("ldr_entry_address: {:?}", ldr_entry_address);
    ldr_entry_address

}

fn read_ldr_entry(h_process: HANDLE, ldr_entry_address: *const c_void, ldr_entry: &mut LDR_DATA_TABLE_ENTRY, base_dll_name: &mut [u16]) -> bool {
    unsafe {

        let data = read_virtual_memory(h_process, ldr_entry_address as *mut c_void, size_of::<LDR_DATA_TABLE_ENTRY>());

        if data.is_none(){
            error!("NtReadVirtualMemory failed");
            return false
        }

        let (buffer, _) = data.unwrap();

        if !buffer.is_empty(){
            ptr::copy_nonoverlapping(
                buffer.as_ptr(),
                ldr_entry as *mut LDR_DATA_TABLE_ENTRY as *mut u8,
                size_of::<LDR_DATA_TABLE_ENTRY>(),
            );
        } else {
            error!("Buffer is empty");
            return false
        }


        let data = read_virtual_memory(
            h_process,
            ldr_entry.BaseDllName.Buffer as *mut c_void,
            ldr_entry.BaseDllName.Length as usize
        );

        if data.is_none(){
            error!("NtReadVirtualMemory failed");
            return false
        }

        let (buffer, _) = data.unwrap();

        if !buffer.is_empty() {
            ptr::copy_nonoverlapping(
                buffer.as_ptr(),
                base_dll_name as *mut [u16] as *mut u8,
                std::cmp::min(buffer.len(), MAX_PATH),
            );
        } else {
            debug!("Buffer vide, skipping copy");
        }
    }
    true
}

fn add_new_module(h_process : HANDLE, ldr_entry: &mut LDR_DATA_TABLE_ENTRY) -> Option<ModuleInfo> {

    let mut new_module = ModuleInfo::new();

    new_module.dll_base = ldr_entry.DllBase as *const _ as u64;
    new_module.size_of_image = ldr_entry.SizeOfImage;
    new_module.time_date_stamp = ldr_entry.TimeDateStamp;
    new_module.check_sum = ldr_entry.BaseNameHashValue;

    let name_size = std::cmp::min(ldr_entry.FullDllName.Length as usize, size_of_val(&new_module.dll_name));

    let data = read_virtual_memory(
        h_process,
        ldr_entry.FullDllName.Buffer as *mut c_void,
        name_size
    );

    if data.is_none(){
        error!("Add New Module -> NtReadVirtualMemory failed");
        return None
    }

    let (buffer, _) = data.unwrap();

    if !buffer.is_empty(){
        new_module.dll_name = unsafe {read_unaligned(buffer.as_ptr() as *const _)};
    }

    Some(new_module)
}

pub fn find_modules(h_process : HANDLE, important_modules : Vec<&str>, is_lsass: bool) -> Option<Vec<ModuleInfo>> {

    debug!("Finding modules");

    debug!("h_process: {:?}", h_process);
    debug!("important_modules: {:?}", important_modules);
    debug!("is_lsass: {:?}", is_lsass);
    debug!("Number of modules: {}", important_modules.len() );

    let ldr_entry_address = get_module_list_address(h_process, is_lsass);

    debug!("ldr_entry_address: {:?}", ldr_entry_address);

    let mut first_ldr_entry_address: *const c_void = ptr::null();
    let mut dlls_found: u16 = 0;
    let mut ldr_entry: LDR_DATA_TABLE_ENTRY = unsafe { std::mem::zeroed() };
    let mut base_dll_name: [u16; MAX_PATH];
    let mut found_modules: Vec<String> = Vec::new();
    let mut current_ldr_entry_address = ldr_entry_address;

    let mut module_list : Vec<ModuleInfo> = Vec::new();

    while (dlls_found < important_modules.len() as u16) {
        base_dll_name = [0u16; MAX_PATH];
        let success = read_ldr_entry(h_process, current_ldr_entry_address as *const c_void, &mut ldr_entry, &mut base_dll_name);
        if !success {
            error!("Failed to read LDR entry");
            return None;
        }

        if first_ldr_entry_address.is_null() {
            first_ldr_entry_address = current_ldr_entry_address as *const c_void;
            debug!("first_ldr_entry_address: {:?}", first_ldr_entry_address);
        }

        for module in &important_modules {
            // Convert UTF-16 array to a String for comparison
            let dll_name = String::from_utf16_lossy(&base_dll_name[..base_dll_name.iter().position(|&x| x == 0).unwrap_or(base_dll_name.len())]);
            if module.eq_ignore_ascii_case(&dll_name) {
                debug!("Found module: {} at {:x}", dll_name, current_ldr_entry_address );
                found_modules.push(dll_name.to_string());

                let new_module = add_new_module(h_process, &mut ldr_entry);

                if !new_module.is_some() {
                    error!("Failed to add module");
                    return None
                }

                (&mut module_list).push(new_module.unwrap());

                dlls_found += 1;
                break
            }
        }
        current_ldr_entry_address = ldr_entry.InLoadOrderLinks.Flink as usize;
        if current_ldr_entry_address == (first_ldr_entry_address as usize) {
            break;
        }

    }
    Some(module_list)
}

