//! Simple BMP encoder — no external image crate required.
//!
//! Produces a valid 32-bpp BMP from raw BGRA pixel data.

use crate::capture::CapturedFrame;
use common::KrakenError;

/// Encode a captured frame as a BMP file in memory.
///
/// The GDI pixels are already in BGRA order which BMP expects, so no
/// channel swapping is necessary.
pub fn encode_bmp(frame: &CapturedFrame) -> Result<Vec<u8>, KrakenError> {
    let width = frame.width;
    let height = frame.height;
    let pixel_data_size = (width * height * 4) as usize;

    // BMP file header (14 bytes) + DIB header BITMAPINFOHEADER (40 bytes)
    let header_size: u32 = 14 + 40;
    let file_size: u32 = header_size + pixel_data_size as u32;

    let mut out: Vec<u8> = Vec::with_capacity(file_size as usize);

    // --- BMP file header ---
    out.extend_from_slice(b"BM");                          // signature
    out.extend_from_slice(&file_size.to_le_bytes());       // file size
    out.extend_from_slice(&0u16.to_le_bytes());            // reserved1
    out.extend_from_slice(&0u16.to_le_bytes());            // reserved2
    out.extend_from_slice(&header_size.to_le_bytes());     // pixel data offset

    // --- BITMAPINFOHEADER (40 bytes) ---
    out.extend_from_slice(&40u32.to_le_bytes());           // header size
    out.extend_from_slice(&(width as i32).to_le_bytes());  // width
    // Positive height = bottom-up. We captured top-down (negative biHeight),
    // so we store height as negative to keep correct orientation.
    out.extend_from_slice(&(-(height as i32)).to_le_bytes()); // height (negative = top-down)
    out.extend_from_slice(&1u16.to_le_bytes());            // color planes
    out.extend_from_slice(&32u16.to_le_bytes());           // bits per pixel
    out.extend_from_slice(&0u32.to_le_bytes());            // compression (BI_RGB)
    out.extend_from_slice(&(pixel_data_size as u32).to_le_bytes()); // image size
    out.extend_from_slice(&0i32.to_le_bytes());            // X pixels per meter
    out.extend_from_slice(&0i32.to_le_bytes());            // Y pixels per meter
    out.extend_from_slice(&0u32.to_le_bytes());            // colors in table
    out.extend_from_slice(&0u32.to_le_bytes());            // important colors

    // --- Pixel data (BGRA) ---
    out.extend_from_slice(&frame.pixels);

    Ok(out)
}
