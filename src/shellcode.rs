//! Representation and execution of shellcode

use libc::{
    setgid,
    setuid,
    chroot,
    mmap,
    mprotect,
    c_void,
    c_char,
    PROT_READ,
    PROT_WRITE,
    PROT_EXEC,
    MAP_ANONYMOUS,
    MAP_PRIVATE,
    MAP_FIXED,
    MAP_FAILED,
};
use std::{
    mem::transmute,
    net::TcpStream,
};
use crate::{Args, ShellcodeError};
use anyhow::Result;

#[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
const INS_TRAP: [u8; 1] = [0xcc];
#[cfg(target_arch = "aarch64")]
const INS_TRAP: [u8; 4] = [0x00, 0x00, 0x20, 0xd4];
#[cfg(target_arch = "arm")]
const INS_TRAP: [u8; 4] = [0xf0, 0x01, 0xf0, 0xe7];

/// Things needed for shellcode execution.
/// This should contain things that Rust would otherwise free before the
/// shellcode runs such as TCP network streams.
pub enum ShellcodeContext {
    /// If shellcode does not need anything
    Nothing,
    /// We want to keep the source network connection alive
    #[allow(dead_code)]
    NetworkSocket(TcpStream),
}

/// This represents a shellcode and what we can do with it
pub struct Shellcode {
    /// The actual opcodes of the shellcode
    opcodes: Vec<u8>,
    /// Shellcode context.
    /// We never actively use this but we want to prevent Rust from freeing it.
    #[allow(dead_code)]
    context: ShellcodeContext,
}

impl Shellcode {
    /// Create a new shellcode for executing the specified opcode while holding on to the specified
    /// context
    pub fn new(opcodes: Vec<u8>, context: ShellcodeContext) -> Self {
        Self { opcodes, context }
    }

    /// Execute this shellcode configured by the specified arguments
    pub fn execute(&self, args: &Args) -> Result<()> {
        unsafe {
            if let Some(ref path) = &args.chroot {
                let mut path = path.clone();
                path.push('\0');
                if chroot(path.as_ptr() as *const c_char) != 0 {
                    return Err(ShellcodeError::ChrootFailed.into());
                }
            }

            if let Some(gid) = &args.gid {
                if setgid(*gid) != 0 {
                    return Err(ShellcodeError::SetGidFailed.into());
                }
            }

            if let Some(uid) = &args.uid {
                if setuid(*uid) != 0 {
                    return Err(ShellcodeError::SetUidFailed.into());
                }
            }

            #[cfg(any(target_arch="x86", target_arch="x86_64", target_arch="aarch64", target_arch="arm"))]
            let opcodes = if args.prepend_breakpoint {
                &[&INS_TRAP[..], &self.opcodes[..]].concat()
            } else {
                &self.opcodes
            };
            #[cfg(not(any(target_arch="x86", target_arch="x86_64", target_arch="aarch64", target_arch="arm")))]
            let opcodes = &self.opcodes;

            let (addr, flags) = if let Some(addr) = args.load_address {
                (addr as *mut c_void, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED)
            } else {
                (std::ptr::null_mut::<c_void>(), MAP_PRIVATE | MAP_ANONYMOUS)
            };
            let map_size = (opcodes.len() + 4096) & !4095;
            let map = mmap(addr, // Address
                       map_size, // Size
                       PROT_READ | PROT_WRITE, // Protection
                       flags, // Flags
                       -1, // FD
                        0 // Offset
                       ) as *mut u8;

            if map as *mut c_void == MAP_FAILED {
                return Err(ShellcodeError::MemoryMappingFailed.into());
            }

            std::ptr::copy(opcodes.as_ptr(), map, opcodes.len());
            let mut prot = PROT_READ | PROT_EXEC;
            if args.writable {
                prot |= PROT_WRITE;
            }
            mprotect(map as *mut c_void, map_size, prot);
            let shellcode_fn: extern "C" fn() = transmute(map);
            if let Some(s) = &args.pre_access {
                let _  = nix::unistd::access(&s[..], nix::unistd::AccessFlags::F_OK);
            }
            shellcode_fn();
            if let Some(s) = &args.post_access {
                let _  = nix::unistd::access(s.as_str(), nix::unistd::AccessFlags::F_OK);
            }
        }
        Ok(())
    }
}
