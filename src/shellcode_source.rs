//! Sources of shellcode

use crate::{
    Args,
    ShellcodeError,
};
use std::{
    fs::File,
    path::PathBuf,
    io::{
        self,
        Read,
        ErrorKind,
    },
    net::{
        TcpListener,
        SocketAddr,
    },
    str::FromStr,
    time::Duration,
};
use nix::{
    sys::wait::waitpid,
    unistd::{
        fork,
        ForkResult,
    }
};
use anyhow::Result;

use crate::{Shellcode, ShellcodeContext};

/// A ShellcodeSource is something that can provide a shellcode.
#[derive(Clone, Debug)]
pub enum ShellcodeSource {
    /// Shellcode from standard in
    Stdin,
    /// Shellcode from a TCP port
    TcpPort(u16),
    /// Shellcode from a file path
    File(PathBuf),
}

/// Read until end of blocking stream or until a non blocking stream would have blocked
fn drain<T: Read>(input: &mut T) -> Result<Vec<u8>> {
    let mut result = Vec::new();
    let mut buf = [0u8; 256];
    loop {
        match input.read(&mut buf) {
            Ok(len) => {
                if len > 0 {
                    result.extend_from_slice(&buf[0..len]);
                } else {
                    return Ok(result)
                }
            },
            Err(e) => {
                return if e.kind() == ErrorKind::WouldBlock {
                    Ok(result)
                } else {
                    Err(e.into())
                }
            }
        }
    }
}

impl ShellcodeSource {
    /// Read shellcode from this source
    pub fn drain(&self, args: &Args) -> Result<Shellcode> {
        match self {
            ShellcodeSource::Stdin => {
                Ok(Shellcode::new(drain(&mut io::stdin())?, ShellcodeContext::Nothing))
            },
            ShellcodeSource::File(path) => {
                let mut file = File::open(path)?;
                Ok(Shellcode::new(drain(&mut file)?, ShellcodeContext::Nothing))
            }
            ShellcodeSource::TcpPort(port) => {
                let addr = if args.ipv4 == args.ipv6 || args.ipv6 {
                    SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 0], *port))
                } else {
                    SocketAddr::from(([0, 0, 0, 0], *port))
                };
                let listener = TcpListener::bind(addr)?;

                loop {
                    let (mut stream, _) = listener.accept()?;
                    stream.set_read_timeout(Some(Duration::from_millis(args.tcp_timeout)))?;
                    let res = drain(&mut stream)?;
                    stream.set_read_timeout(None)?;
                    if args.fork {
                        match unsafe {fork()} {
                            Ok(ForkResult::Parent{child, ..}) => {
                                waitpid(child, None)?;
                            },
                            Err(e) => return Err(e.into()),
                            Ok(ForkResult::Child) => {
                                match unsafe {fork()} {
                                    Ok(ForkResult::Parent{..}) => {
                                        std::process::exit(0);
                                    },
                                    Err(e) => return Err(e.into()),
                                    Ok(ForkResult::Child) => return Ok(Shellcode::new(res, ShellcodeContext::NetworkSocket(stream))),
                                }
                            }
                        }
                    } else {
                        return Ok(Shellcode::new(res, ShellcodeContext::NetworkSocket(stream)));
                    }
                }
            }
        }
    }
}

impl FromStr for ShellcodeSource {
    type Err = ShellcodeError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s == "-" {
            Ok(ShellcodeSource::Stdin)
        } else if let Ok(port) = s.parse::<u16>() {
            Ok(ShellcodeSource::TcpPort(port))
        } else if let Ok(path) = PathBuf::from_str(&s) {
            Ok(ShellcodeSource::File(path))
        } else {
            Err(ShellcodeError::ShellcodeSourceParseError)
        }
    }
}
