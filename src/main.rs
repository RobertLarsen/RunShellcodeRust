//! This crate builds a Linux command line tool for executing shellcode

use clap::Parser;
use std::str::FromStr;
use anyhow::Result;

mod error;
use error::ShellcodeError;

mod shellcode_source;
use shellcode_source::ShellcodeSource;

mod shellcode;
use shellcode::{Shellcode, ShellcodeContext};

/// Run shellcode from standard in, a TCP server or from a file
#[derive(Parser,Debug)]
struct Args {
    /// Use IPv4 for the TCP server
    #[arg(short='4', long, action)]
    ipv4: bool,
    /// Use IPv6 for the TCP server
    #[arg(short='6', long, action)]
    ipv6: bool,
    /// Fork the TCP server for each client
    #[arg(short, long, action)]
    fork: bool,
    /// Timeout in milliseconds for reading shellcode on network``
    #[arg(short, long, action, default_value_t=100)]
    tcp_timeout: u64,
    /// Change user id to this before executing shellcode
    #[arg(short, long, action)]
    uid: Option<u32>,
    /// Change group id to this before executing shellcode
    #[arg(short, long, action)]
    gid: Option<u32>,
    /// Change root directory prior to executing the shellcode
    #[arg(short, long, value_name = "ROOT PATH")]
    chroot: Option<String>,
    /// Mark shellcode memory as writable
    #[arg(short, long, action)]
    writable: bool,
    /// Source of shellcode. Standard in if absent or the string '-', TCP port if integer, otherwise path to
    /// file.
    source: Option<String>,
}

fn main() -> Result<()> {
    let args = Args::parse();
    let source = match &args.source {
        Some(s) => ShellcodeSource::from_str(&s),
        None => Ok(ShellcodeSource::Stdin),
    };

    source?
        .drain(&args)?
        .execute(&args)?;
    Ok(())
}
