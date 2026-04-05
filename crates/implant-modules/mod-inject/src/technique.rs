//! Injection technique implementations
//!
//! Each submodule implements a different injection technique:
//! - win32: Classic VirtualAllocEx + CreateRemoteThread (Tier 1)
//! - ntapi: NT API with direct syscalls potential (Tier 2)
//! - apc: Asynchronous Procedure Call injection (Tier 3)
//! - hijack: Thread context hijacking (Tier 4)
//! - earlybird: Early Bird APC injection into suspended process (Tier 3 variant)
//! - stomping: Module stomping over DLL .text section (Tier 4 variant)
//! - ppid: PPID spoofing helpers (T1134.004)
//! - arg_spoof: Argument spoofing via PEB CommandLine overwrite (T1564)
//! - hollowing: Classic process hollowing — T1055.012
//! - txf_hollowing: Transacted (Phantom) hollowing via TxF — T1055.012 variant

#[cfg(windows)]
pub mod apc;
pub mod arg_spoof;
#[cfg(windows)]
pub mod earlybird;
#[cfg(windows)]
pub mod hijack;
#[cfg(windows)]
pub mod hollowing;
#[cfg(windows)]
pub mod ntapi;
pub mod ppid;
#[cfg(windows)]
pub mod stomping;
#[cfg(windows)]
pub mod txf_hollowing;
#[cfg(windows)]
pub mod win32;

// Stub modules for non-Windows compilation
#[cfg(not(windows))]
pub mod win32 {
    use crate::InjectionResult;
    use common::KrakenError;
    pub fn inject(
        _pid: u32,
        _sc: &[u8],
        _wait: bool,
        _timeout: u32,
    ) -> Result<InjectionResult, KrakenError> {
        Err(KrakenError::Module("not supported on this platform".into()))
    }
}

#[cfg(not(windows))]
pub mod ntapi {
    use crate::InjectionResult;
    use common::KrakenError;
    pub fn inject(
        _pid: u32,
        _sc: &[u8],
        _wait: bool,
        _timeout: u32,
    ) -> Result<InjectionResult, KrakenError> {
        Err(KrakenError::Module("not supported on this platform".into()))
    }
}

#[cfg(not(windows))]
pub mod apc {
    use crate::InjectionResult;
    use common::KrakenError;
    pub fn inject(
        _pid: u32,
        _sc: &[u8],
        _wait: bool,
        _timeout: u32,
    ) -> Result<InjectionResult, KrakenError> {
        Err(KrakenError::Module("not supported on this platform".into()))
    }
}

#[cfg(not(windows))]
pub mod hijack {
    use crate::InjectionResult;
    use common::KrakenError;
    pub fn inject(
        _pid: u32,
        _sc: &[u8],
        _wait: bool,
        _timeout: u32,
    ) -> Result<InjectionResult, KrakenError> {
        Err(KrakenError::Module("not supported on this platform".into()))
    }
}

#[cfg(not(windows))]
pub mod earlybird {
    use crate::InjectionResult;
    use common::KrakenError;
    pub fn inject(
        _executable_path: &str,
        _sc: &[u8],
        _wait: bool,
        _timeout: u32,
        _parent_pid: Option<u32>,
    ) -> Result<InjectionResult, KrakenError> {
        Err(KrakenError::Module("not supported on this platform".into()))
    }
    pub fn inject_default(
        _sc: &[u8],
        _wait: bool,
        _timeout: u32,
    ) -> Result<InjectionResult, KrakenError> {
        Err(KrakenError::Module("not supported on this platform".into()))
    }
}

#[cfg(not(windows))]
pub mod stomping {
    use crate::InjectionResult;
    use common::KrakenError;
    pub fn inject(
        _pid: u32,
        _sc: &[u8],
        _wait: bool,
        _timeout: u32,
    ) -> Result<InjectionResult, KrakenError> {
        Err(KrakenError::Module("not supported on this platform".into()))
    }
}

#[cfg(not(windows))]
pub mod hollowing {
    use common::KrakenError;
    pub fn hollow(_target: &str, _payload: &[u8]) -> Result<u32, KrakenError> {
        Err(KrakenError::Module(
            "Process hollowing only supported on Windows".into(),
        ))
    }
}

#[cfg(not(windows))]
pub mod txf_hollowing {
    use common::KrakenError;
    pub fn txf_hollow(_target_exe: &str, _payload: &[u8]) -> Result<u32, KrakenError> {
        Err(KrakenError::Module(
            "Transacted hollowing only supported on Windows".into(),
        ))
    }
}
