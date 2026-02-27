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

fn parse_hex_usize(s: &str) -> Result<usize> {
    Ok((if let Some(sub) = s.strip_prefix("0x") {
        usize::from_str_radix(sub, 16)
    } else {
        usize::from_str(s)
    }).map_err(|_| ShellcodeError::LoadAddressParseError)?)
}

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
    /// Load shellcode at this address
    #[arg(short, long, action, value_parser = parse_hex_usize)]
    load_address: Option<usize>,
    /// Make `access` system call prior to executing shellcode
    #[arg(short, long, action)]
    pre_access: Option<String>,
    /// Make `access` system call after having executed shellcode
    #[arg(short='o', long, action)]
    post_access: Option<String>,
    /// Source of shellcode. Standard in if absent or the string '-', TCP port if integer, otherwise path to
    /// file.
    source: Option<String>,
}

fn main() -> Result<()> {
    let args = Args::parse();
    let source = match &args.source {
        Some(s) => ShellcodeSource::from_str(s),
        None => Ok(ShellcodeSource::Stdin),
    };

    source?
        .drain(&args)?
        .execute(&args)?;
    Ok(())
}
