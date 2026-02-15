use clap::{ArgAction, Parser};


/// Nanodump - Process memory dumping tool
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Args {
    /// Get core ID
    #[arg(long, default_value_t = 0)]
    pub lsass_pid: u32,

    /// Only print lsass pid value
    #[arg(long)]
    pub get_pid_and_leave: bool,

    /// Increase verbosity (-v, -vv, -vvv)
    #[arg(short, long, action = ArgAction::Count)]
    pub verbose: u8,

    /// Quiet mode (no output)
    #[arg(short, long)]
    pub quiet: bool,

    /// Write dump to disk
    #[arg(short, long)]
    pub write_dump_to_disk: bool,

    /// Dump path
    #[arg(short, long, default_value= "dump.bin")]
    pub path: String,
}

pub fn parse_args() -> Args {
    Args::parse()
}