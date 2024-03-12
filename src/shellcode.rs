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
    MAP_FAILED,
};
use std::{
    mem::transmute,
    net::TcpStream,
};
use crate::{Args, ShellcodeError};
use anyhow::Result;

/// Things needed for shellcode execution.
/// This should contain things that Rust would otherwise free before the
/// shellcode runs such as TCP network streams.
pub enum ShellcodeContext {
    /// If shellcode does not need anything
    Nothing,
    /// We want to keep the source network connection alive
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

            let map_size = (self.opcodes.len() + 4096) & !4095;
            let map = mmap(0 as *mut c_void, // Address
                       map_size, // Size
                       PROT_READ | PROT_WRITE, // Protection
                       MAP_PRIVATE | MAP_ANONYMOUS, // Flags
                       -1, // FD
                        0 // Offset
                       ) as *mut u8;

            if map as *mut c_void == MAP_FAILED {
                return Err(ShellcodeError::MemoryMappingFailed.into());
            }

            std::ptr::copy(self.opcodes.as_ptr(), map, self.opcodes.len());
            let mut prot = PROT_READ | PROT_EXEC;
            if args.writable {
                prot |= PROT_WRITE;
            }
            mprotect(map as *mut c_void, map_size, prot);
            let shellcode_fn: extern "C" fn() -> ! = transmute(map);
            shellcode_fn();
        }
    }
}
