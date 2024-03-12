//! What could possibly go wrong? Look here to find out.

use std::{
    fmt,
    error::Error,
};

/// These are the things that could go wrong during retrieval and execution of shellcode
#[derive(Debug, PartialEq, Eq)]
pub enum ShellcodeError {
    /// Source string does not follow required convention
    ShellcodeSourceParseError,
    /// Could not map memory for executing shellcode
    MemoryMappingFailed,
    /// Could not change root directory (requires `CAP_SYS_CHROOT`)
    ChrootFailed,
    /// Could not set user id
    SetUidFailed,
    /// Could not set group id
    SetGidFailed,
}

impl ShellcodeError {
    fn as_str(&self) -> &str {
        match self {
            ShellcodeError::ShellcodeSourceParseError => "Could not parse shellcode source",
            ShellcodeError::MemoryMappingFailed => "Memory mapping failed",
            ShellcodeError::ChrootFailed => "Changing root failed",
            ShellcodeError::SetUidFailed => "Setting UID failed",
            ShellcodeError::SetGidFailed => "Setting GID failed",
        }
    }
}

impl fmt::Display for ShellcodeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f,"{}", self.as_str())
    }
}

impl Error for ShellcodeError {
    fn description(&self) -> &str {
        self.as_str()
    }
}
