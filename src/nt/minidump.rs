use std::fs::File;
use std::os::windows::io::AsRawHandle;
use log::info;
use windows::{
    Win32::{
        Foundation::{HANDLE},
        System::Diagnostics::Debug::{
            MiniDumpWriteDump,
            MiniDumpWithFullMemory,
        },
    },
};

pub fn dump_process(hprocess: HANDLE, pid: u32, path: &str) -> bool {
    unsafe{

        let out_file = File::create(path);

        let success = MiniDumpWriteDump(
            hprocess,
            pid,
            HANDLE(out_file.unwrap().as_raw_handle() as _),
            MiniDumpWithFullMemory,
            None,
            None,
            None,
        );

        if success.is_ok() {
            info!("Process successfully dumped to {}", path);
            return true;
        }

        false
    }
}