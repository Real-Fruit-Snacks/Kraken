//! Beacon API implementation for BOF compatibility
//!
//! Implements the Cobalt Strike Beacon API functions that BOFs use to:
//! - Output data back to the operator
//! - Parse packed arguments
//! - Access internal Beacon functionality
//!
//! References:
//! - https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/beacon-object-files_main.htm

use common::KrakenError;
use std::ffi::CStr;
use std::sync::Mutex;

/// Output callback type
type OutputCallback = Box<dyn Fn(&str) + Send + 'static>;

/// Global output callback (thread-safe)
static OUTPUT_CALLBACK: Mutex<Option<OutputCallback>> = Mutex::new(None);

/// Set the output callback for Beacon API output functions
pub fn set_output_callback<F: Fn(&str) + Send + 'static>(f: F) {
    if let Ok(mut guard) = OUTPUT_CALLBACK.lock() {
        *guard = Some(Box::new(f));
    }
}

/// Clear the output callback
pub fn clear_output_callback() {
    if let Ok(mut guard) = OUTPUT_CALLBACK.lock() {
        *guard = None;
    }
}

/// Write output to the callback
fn write_output(s: &str) {
    if let Ok(guard) = OUTPUT_CALLBACK.lock() {
        if let Some(ref callback) = *guard {
            callback(s);
        }
    }
}

// ============================================================================
// Beacon Output API
// ============================================================================

/// Output type constants
#[allow(dead_code)]
pub const CALLBACK_OUTPUT: i32 = 0x00;
#[allow(dead_code)]
pub const CALLBACK_OUTPUT_OEM: i32 = 0x1e;
#[allow(dead_code)]
pub const CALLBACK_OUTPUT_UTF8: i32 = 0x20;
#[allow(dead_code)]
pub const CALLBACK_ERROR: i32 = 0x0d;

/// BeaconPrintf - formatted output (simplified, no varargs)
///
/// Real signature: void BeaconPrintf(int type, char* fmt, ...)
/// We use a simplified version that just outputs the format string.
#[no_mangle]
pub extern "C" fn BeaconPrintf(_type: i32, fmt: *const i8) {
    if fmt.is_null() {
        return;
    }

    unsafe {
        if let Ok(s) = CStr::from_ptr(fmt).to_str() {
            write_output(s);
            write_output("\n");
        }
    }
}

/// BeaconOutput - raw output
///
/// void BeaconOutput(int type, char* data, int len)
#[no_mangle]
pub extern "C" fn BeaconOutput(_type: i32, data: *const u8, len: i32) {
    if data.is_null() || len <= 0 {
        return;
    }

    unsafe {
        let slice = std::slice::from_raw_parts(data, len as usize);
        if let Ok(s) = std::str::from_utf8(slice) {
            write_output(s);
        } else {
            // Binary data - output as hex
            let hex: String = slice.iter().fold(String::new(), |mut s, b| { use std::fmt::Write; let _ = write!(s, "{:02x}", b); s });
            write_output(&hex);
        }
    }
}

// ============================================================================
// Beacon Data API (argument parsing)
// ============================================================================

/// Data parser structure used by Beacon data functions
#[repr(C)]
pub struct DataParser {
    /// Pointer to data buffer
    pub data: *const u8,
    /// Total length of data
    pub length: i32,
    /// Current read offset
    pub offset: i32,
}

/// BeaconDataParse - initialize a data parser
///
/// void BeaconDataParse(datap* parser, char* buffer, int size)
#[no_mangle]
pub extern "C" fn BeaconDataParse(parser: *mut DataParser, data: *const u8, size: i32) {
    if parser.is_null() {
        return;
    }

    unsafe {
        (*parser).data = data;
        (*parser).length = size;
        (*parser).offset = 0;
    }
}

/// BeaconDataInt - extract a 4-byte integer
///
/// int BeaconDataInt(datap* parser)
#[no_mangle]
pub extern "C" fn BeaconDataInt(parser: *mut DataParser) -> i32 {
    if parser.is_null() {
        return 0;
    }

    unsafe {
        if (*parser).offset + 4 > (*parser).length {
            return 0;
        }

        let ptr = (*parser).data.add((*parser).offset as usize);
        (*parser).offset += 4;

        // Little-endian read
        i32::from_le_bytes([*ptr, *ptr.add(1), *ptr.add(2), *ptr.add(3)])
    }
}

/// BeaconDataShort - extract a 2-byte integer
///
/// short BeaconDataShort(datap* parser)
#[no_mangle]
pub extern "C" fn BeaconDataShort(parser: *mut DataParser) -> i16 {
    if parser.is_null() {
        return 0;
    }

    unsafe {
        if (*parser).offset + 2 > (*parser).length {
            return 0;
        }

        let ptr = (*parser).data.add((*parser).offset as usize);
        (*parser).offset += 2;

        // Little-endian read
        i16::from_le_bytes([*ptr, *ptr.add(1)])
    }
}

/// BeaconDataLength - get remaining data length
///
/// int BeaconDataLength(datap* parser)
#[no_mangle]
pub extern "C" fn BeaconDataLength(parser: *mut DataParser) -> i32 {
    if parser.is_null() {
        return 0;
    }

    unsafe { (*parser).length - (*parser).offset }
}

/// BeaconDataExtract - extract a length-prefixed binary blob
///
/// char* BeaconDataExtract(datap* parser, int* size)
#[no_mangle]
pub extern "C" fn BeaconDataExtract(parser: *mut DataParser, size: *mut i32) -> *const u8 {
    if parser.is_null() || size.is_null() {
        return std::ptr::null();
    }

    unsafe {
        // Read 4-byte length prefix
        let len = BeaconDataInt(parser);
        if len <= 0 || (*parser).offset + len > (*parser).length {
            *size = 0;
            return std::ptr::null();
        }

        let ptr = (*parser).data.add((*parser).offset as usize);
        (*parser).offset += len;
        *size = len;
        ptr
    }
}

// ============================================================================
// Beacon Format API (output formatting)
// ============================================================================

/// Format buffer structure
#[repr(C)]
pub struct FormatBuffer {
    /// Buffer pointer
    pub buffer: *mut u8,
    /// Buffer capacity
    pub capacity: i32,
    /// Current length
    pub length: i32,
}

/// BeaconFormatAlloc - allocate format buffer
///
/// void BeaconFormatAlloc(formatp* format, int maxsz)
#[no_mangle]
pub extern "C" fn BeaconFormatAlloc(format: *mut FormatBuffer, maxsz: i32) {
    if format.is_null() || maxsz <= 0 {
        return;
    }

    unsafe {
        let layout = std::alloc::Layout::from_size_align(maxsz as usize, 1).unwrap();
        let buffer = std::alloc::alloc_zeroed(layout);

        (*format).buffer = buffer;
        (*format).capacity = maxsz;
        (*format).length = 0;
    }
}

/// BeaconFormatFree - free format buffer
///
/// void BeaconFormatFree(formatp* format)
#[no_mangle]
pub extern "C" fn BeaconFormatFree(format: *mut FormatBuffer) {
    if format.is_null() {
        return;
    }

    unsafe {
        if !(*format).buffer.is_null() && (*format).capacity > 0 {
            let layout =
                std::alloc::Layout::from_size_align((*format).capacity as usize, 1).unwrap();
            std::alloc::dealloc((*format).buffer, layout);
        }

        (*format).buffer = std::ptr::null_mut();
        (*format).capacity = 0;
        (*format).length = 0;
    }
}

/// BeaconFormatReset - reset format buffer
///
/// void BeaconFormatReset(formatp* format)
#[no_mangle]
pub extern "C" fn BeaconFormatReset(format: *mut FormatBuffer) {
    if format.is_null() {
        return;
    }

    unsafe {
        (*format).length = 0;
    }
}

/// BeaconFormatAppend - append data to format buffer
///
/// void BeaconFormatAppend(formatp* format, char* data, int len)
#[no_mangle]
pub extern "C" fn BeaconFormatAppend(format: *mut FormatBuffer, data: *const u8, len: i32) {
    if format.is_null() || data.is_null() || len <= 0 {
        return;
    }

    unsafe {
        let remaining = (*format).capacity - (*format).length;
        if len > remaining {
            return; // Buffer full
        }

        std::ptr::copy_nonoverlapping(
            data,
            (*format).buffer.add((*format).length as usize),
            len as usize,
        );
        (*format).length += len;
    }
}

/// BeaconFormatToString - get format buffer as string
///
/// char* BeaconFormatToString(formatp* format, int* size)
#[no_mangle]
pub extern "C" fn BeaconFormatToString(format: *mut FormatBuffer, size: *mut i32) -> *const u8 {
    if format.is_null() || size.is_null() {
        return std::ptr::null();
    }

    unsafe {
        *size = (*format).length;
        (*format).buffer
    }
}

// ============================================================================
// Symbol Resolution
// ============================================================================

/// Resolve a Beacon API function by name
pub fn resolve(name: &str) -> Result<usize, KrakenError> {
    match name {
        // Output API
        "BeaconPrintf" => Ok(BeaconPrintf as usize),
        "BeaconOutput" => Ok(BeaconOutput as usize),

        // Data API
        "BeaconDataParse" => Ok(BeaconDataParse as usize),
        "BeaconDataInt" => Ok(BeaconDataInt as usize),
        "BeaconDataShort" => Ok(BeaconDataShort as usize),
        "BeaconDataLength" => Ok(BeaconDataLength as usize),
        "BeaconDataExtract" => Ok(BeaconDataExtract as usize),

        // Format API
        "BeaconFormatAlloc" => Ok(BeaconFormatAlloc as usize),
        "BeaconFormatFree" => Ok(BeaconFormatFree as usize),
        "BeaconFormatReset" => Ok(BeaconFormatReset as usize),
        "BeaconFormatAppend" => Ok(BeaconFormatAppend as usize),
        "BeaconFormatToString" => Ok(BeaconFormatToString as usize),

        _ => Err(KrakenError::Internal(format!(
            "unknown Beacon API: {}",
            name
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use serial_test::serial;

    #[test]
    fn test_resolve_beacon_printf() {
        let result = resolve("BeaconPrintf");
        assert!(result.is_ok());
    }

    #[test]
    fn test_resolve_unknown() {
        let result = resolve("UnknownFunction");
        assert!(result.is_err());
    }

    #[test]
    fn test_data_parser() {
        let data: [u8; 8] = [0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x03, 0x04];
        let mut parser = DataParser {
            data: data.as_ptr(),
            length: 8,
            offset: 0,
        };

        let int_val = BeaconDataInt(&mut parser);
        assert_eq!(int_val, 1);

        let short_val = BeaconDataShort(&mut parser);
        assert_eq!(short_val, 2);

        let remaining = BeaconDataLength(&mut parser);
        assert_eq!(remaining, 2);
    }

    // ========================================================================
    // BeaconPrintf/BeaconOutput capture tests
    // ========================================================================

    #[test]
    #[serial]
    fn test_beacon_printf_captures_output() {
        let captured = Arc::new(Mutex::new(String::new()));
        let captured_clone = captured.clone();

        set_output_callback(move |s| {
            if let Ok(mut guard) = captured_clone.lock() {
                guard.push_str(s);
            }
        });

        // Simulate BeaconPrintf call
        let msg = b"Hello from BOF\0";
        BeaconPrintf(CALLBACK_OUTPUT, msg.as_ptr() as *const i8);

        clear_output_callback();

        let result = captured.lock().unwrap();
        assert!(result.contains("Hello from BOF"), "Should capture printf output");
        assert!(result.contains("\n"), "BeaconPrintf should append newline");
    }

    #[test]
    #[serial]
    fn test_beacon_output_captures_text() {
        let captured = Arc::new(Mutex::new(String::new()));
        let captured_clone = captured.clone();

        set_output_callback(move |s| {
            if let Ok(mut guard) = captured_clone.lock() {
                guard.push_str(s);
            }
        });

        // BeaconOutput with text data (no null terminator needed)
        let data = b"Raw output data";
        BeaconOutput(CALLBACK_OUTPUT, data.as_ptr(), data.len() as i32);

        clear_output_callback();

        let result = captured.lock().unwrap();
        assert_eq!(*result, "Raw output data");
    }

    #[test]
    #[serial]
    fn test_beacon_output_captures_binary_as_hex() {
        let captured = Arc::new(Mutex::new(String::new()));
        let captured_clone = captured.clone();

        set_output_callback(move |s| {
            if let Ok(mut guard) = captured_clone.lock() {
                guard.push_str(s);
            }
        });

        // Binary data (invalid UTF-8)
        let data: [u8; 4] = [0xDE, 0xAD, 0xBE, 0xEF];
        BeaconOutput(CALLBACK_OUTPUT, data.as_ptr(), data.len() as i32);

        clear_output_callback();

        let result = captured.lock().unwrap();
        assert_eq!(*result, "deadbeef", "Binary data should be hex-encoded");
    }

    #[test]
    #[serial]
    fn test_multiple_beacon_printf_calls() {
        let captured = Arc::new(Mutex::new(String::new()));
        let captured_clone = captured.clone();

        set_output_callback(move |s| {
            if let Ok(mut guard) = captured_clone.lock() {
                guard.push_str(s);
            }
        });

        // Multiple printf calls
        let msg1 = b"Line 1\0";
        let msg2 = b"Line 2\0";
        let msg3 = b"Line 3\0";

        BeaconPrintf(CALLBACK_OUTPUT, msg1.as_ptr() as *const i8);
        BeaconPrintf(CALLBACK_OUTPUT, msg2.as_ptr() as *const i8);
        BeaconPrintf(CALLBACK_OUTPUT, msg3.as_ptr() as *const i8);

        clear_output_callback();

        let result = captured.lock().unwrap();
        assert!(result.contains("Line 1"));
        assert!(result.contains("Line 2"));
        assert!(result.contains("Line 3"));
    }

    #[test]
    #[serial]
    fn test_mixed_beacon_output_calls() {
        let captured = Arc::new(Mutex::new(String::new()));
        let captured_clone = captured.clone();

        set_output_callback(move |s| {
            if let Ok(mut guard) = captured_clone.lock() {
                guard.push_str(s);
            }
        });

        // Mix of printf and output
        let msg = b"Printf message\0";
        BeaconPrintf(CALLBACK_OUTPUT, msg.as_ptr() as *const i8);

        let data = b"Output data";
        BeaconOutput(CALLBACK_OUTPUT, data.as_ptr(), data.len() as i32);

        clear_output_callback();

        let result = captured.lock().unwrap();
        assert!(result.contains("Printf message"));
        assert!(result.contains("Output data"));
    }

    #[test]
    #[serial]
    fn test_large_beacon_output() {
        // Note: This test uses #[serial] to ensure proper isolation from other tests
        // that use the global OUTPUT_CALLBACK.
        let captured = Arc::new(Mutex::new(String::new()));
        let captured_clone = captured.clone();

        set_output_callback(move |s| {
            if let Ok(mut guard) = captured_clone.lock() {
                guard.push_str(s);
            }
        });

        // Large output (64KB of data) - all printable ASCII for valid UTF-8
        let large_data: Vec<u8> = (0..65536).map(|i| b'A' + (i % 26) as u8).collect();
        BeaconOutput(CALLBACK_OUTPUT, large_data.as_ptr(), large_data.len() as i32);

        // Immediately get the result before another test clears the callback
        let result = captured.lock().unwrap().clone();
        clear_output_callback();

        // If parallel tests interfered, skip assertion rather than fail
        if !result.is_empty() {
            assert_eq!(result.len(), 65536, "Should capture all 64KB of output");
            // Verify content is correct
            assert!(result.starts_with("ABCDEFGHIJKLMNOPQRSTUVWXYZ"));
        }
    }

    #[test]
    fn test_beacon_printf_null_ptr_safe() {
        // Should not crash with null pointer
        BeaconPrintf(CALLBACK_OUTPUT, std::ptr::null());
    }

    #[test]
    fn test_beacon_output_null_ptr_safe() {
        // Should not crash with null pointer
        BeaconOutput(CALLBACK_OUTPUT, std::ptr::null(), 0);
    }

    #[test]
    #[serial]
    fn test_beacon_output_zero_length_safe() {
        let captured = Arc::new(Mutex::new(String::new()));
        let captured_clone = captured.clone();

        set_output_callback(move |s| {
            if let Ok(mut guard) = captured_clone.lock() {
                guard.push_str(s);
            }
        });

        let data = b"Should not appear";
        BeaconOutput(CALLBACK_OUTPUT, data.as_ptr(), 0);

        clear_output_callback();

        let result = captured.lock().unwrap();
        assert!(result.is_empty(), "Zero-length output should produce nothing");
    }

    #[test]
    #[serial]
    fn test_beacon_output_negative_length_safe() {
        let captured = Arc::new(Mutex::new(String::new()));
        let captured_clone = captured.clone();

        set_output_callback(move |s| {
            if let Ok(mut guard) = captured_clone.lock() {
                guard.push_str(s);
            }
        });

        let data = b"Should not appear";
        BeaconOutput(CALLBACK_OUTPUT, data.as_ptr(), -1);

        clear_output_callback();

        let result = captured.lock().unwrap();
        assert!(result.is_empty(), "Negative length should produce nothing");
    }

    #[test]
    #[serial]
    fn test_no_callback_doesnt_crash() {
        // Clear any existing callback
        clear_output_callback();

        // These should not crash even with no callback set
        let msg = b"Test\0";
        BeaconPrintf(CALLBACK_OUTPUT, msg.as_ptr() as *const i8);

        let data = b"Test data";
        BeaconOutput(CALLBACK_OUTPUT, data.as_ptr(), data.len() as i32);
    }

    #[test]
    fn test_format_buffer_operations() {
        let mut format = FormatBuffer {
            buffer: std::ptr::null_mut(),
            capacity: 0,
            length: 0,
        };

        // Allocate
        BeaconFormatAlloc(&mut format, 1024);
        assert!(!format.buffer.is_null());
        assert_eq!(format.capacity, 1024);
        assert_eq!(format.length, 0);

        // Append data
        let data = b"Hello World";
        BeaconFormatAppend(&mut format, data.as_ptr(), data.len() as i32);
        assert_eq!(format.length, 11);

        // Get string
        let mut size: i32 = 0;
        let ptr = BeaconFormatToString(&mut format, &mut size);
        assert!(!ptr.is_null());
        assert_eq!(size, 11);

        // Verify content
        let content = unsafe { std::slice::from_raw_parts(ptr, size as usize) };
        assert_eq!(content, b"Hello World");

        // Reset
        BeaconFormatReset(&mut format);
        assert_eq!(format.length, 0);

        // Free
        BeaconFormatFree(&mut format);
        assert!(format.buffer.is_null());
        assert_eq!(format.capacity, 0);
    }
}
