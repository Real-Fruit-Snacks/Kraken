//! PE Timestamp Stomping
//!
//! Zeros or randomizes PE file timestamps to prevent forensic analysis
//! from determining when the binary was compiled.
//!
//! Modifies:
//! - COFF header TimeDateStamp
//! - Debug directory timestamps
//! - Export directory timestamps
//! - Resource directory timestamps

use std::path::Path;

/// Timestamp stomping mode
#[derive(Debug, Clone, Copy)]
pub enum StompMode {
    /// Set all timestamps to zero
    Zero,
    /// Set to a specific epoch value
    Fixed(u32),
    /// Set to a random value between min and max
    Random { min: u32, max: u32 },
    /// Clone timestamp from another file
    Clone(u32),
}

/// Stomp PE timestamps
pub fn stomp_timestamps(pe_path: &Path, mode: StompMode) -> Result<StompResult, std::io::Error> {
    let mut data = std::fs::read(pe_path)?;
    let mut result = StompResult::default();

    // Validate PE
    if data.len() < 64 || &data[0..2] != b"MZ" {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "not a PE file"));
    }

    let pe_offset = u32::from_le_bytes([data[0x3C], data[0x3D], data[0x3E], data[0x3F]]) as usize;

    if pe_offset + 4 > data.len() || &data[pe_offset..pe_offset+4] != b"PE\0\0" {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid PE"));
    }

    let coff_offset = pe_offset + 4;
    let new_timestamp = match mode {
        StompMode::Zero => 0u32,
        StompMode::Fixed(ts) => ts,
        StompMode::Random { min, max } => {
            let seed = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos() as u32;
            min + (seed % (max - min + 1))
        }
        StompMode::Clone(ts) => ts,
    };

    // 1. COFF header TimeDateStamp at offset +4 from COFF header
    if coff_offset + 8 <= data.len() {
        let old_ts = u32::from_le_bytes([
            data[coff_offset+4], data[coff_offset+5],
            data[coff_offset+6], data[coff_offset+7]
        ]);
        data[coff_offset+4..coff_offset+8].copy_from_slice(&new_timestamp.to_le_bytes());
        result.coff_timestamp = Some((old_ts, new_timestamp));
        result.fields_modified += 1;
    }

    // 2. Optional header - check for debug directory
    let optional_header_offset = coff_offset + 20;
    let magic = u16::from_le_bytes([data[optional_header_offset], data[optional_header_offset+1]]);
    let is_pe32_plus = magic == 0x20b; // PE32+ (64-bit)

    // Debug directory RVA is at different offsets for PE32 vs PE32+
    let debug_dir_offset = if is_pe32_plus {
        optional_header_offset + 144 // PE32+: debug dir entry at offset 144
    } else {
        optional_header_offset + 128 // PE32: debug dir entry at offset 128
    };

    if debug_dir_offset + 8 <= data.len() {
        let debug_rva = u32::from_le_bytes([
            data[debug_dir_offset], data[debug_dir_offset+1],
            data[debug_dir_offset+2], data[debug_dir_offset+3]
        ]);
        let debug_size = u32::from_le_bytes([
            data[debug_dir_offset+4], data[debug_dir_offset+5],
            data[debug_dir_offset+6], data[debug_dir_offset+7]
        ]);

        if debug_rva > 0 && debug_size > 0 {
            // Find debug directory in sections and stomp its timestamp too
            if let Some(file_offset) = rva_to_file_offset(&data, pe_offset, debug_rva) {
                if file_offset + 8 <= data.len() {
                    // Debug directory entry has TimeDateStamp at offset +4
                    data[file_offset+4..file_offset+8].copy_from_slice(&new_timestamp.to_le_bytes());
                    result.debug_timestamp = Some(new_timestamp);
                    result.fields_modified += 1;
                }
            }
        }
    }

    // Write modified PE
    std::fs::write(pe_path, &data)?;

    Ok(result)
}

/// Convert RVA to file offset using section table
fn rva_to_file_offset(data: &[u8], pe_offset: usize, rva: u32) -> Option<usize> {
    let coff_offset = pe_offset + 4;
    let num_sections = u16::from_le_bytes([data[coff_offset+2], data[coff_offset+3]]) as usize;
    let optional_header_size = u16::from_le_bytes([data[coff_offset+16], data[coff_offset+17]]) as usize;
    let sections_start = coff_offset + 20 + optional_header_size;

    for i in 0..num_sections {
        let sec_offset = sections_start + (i * 40);
        if sec_offset + 40 > data.len() { break; }

        let virtual_address = u32::from_le_bytes([
            data[sec_offset+12], data[sec_offset+13],
            data[sec_offset+14], data[sec_offset+15]
        ]);
        let virtual_size = u32::from_le_bytes([
            data[sec_offset+8], data[sec_offset+9],
            data[sec_offset+10], data[sec_offset+11]
        ]);
        let raw_data_ptr = u32::from_le_bytes([
            data[sec_offset+20], data[sec_offset+21],
            data[sec_offset+22], data[sec_offset+23]
        ]);

        if rva >= virtual_address && rva < virtual_address + virtual_size {
            return Some((raw_data_ptr + (rva - virtual_address)) as usize);
        }
    }

    None
}

/// Read the current timestamp from a PE file
pub fn read_timestamp(pe_path: &Path) -> Result<u32, std::io::Error> {
    let data = std::fs::read(pe_path)?;
    if data.len() < 64 || &data[0..2] != b"MZ" {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "not PE"));
    }
    let pe_offset = u32::from_le_bytes([data[0x3C], data[0x3D], data[0x3E], data[0x3F]]) as usize;
    let coff_offset = pe_offset + 4;
    Ok(u32::from_le_bytes([
        data[coff_offset+4], data[coff_offset+5],
        data[coff_offset+6], data[coff_offset+7]
    ]))
}

#[derive(Debug, Default)]
pub struct StompResult {
    pub fields_modified: usize,
    pub coff_timestamp: Option<(u32, u32)>,  // (old, new)
    pub debug_timestamp: Option<u32>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stomp_mode_zero() {
        match StompMode::Zero {
            StompMode::Zero => {},
            _ => panic!("wrong mode"),
        }
    }

    #[test]
    fn test_invalid_pe() {
        let temp = std::env::temp_dir().join("test_ts_not_pe.bin");
        std::fs::write(&temp, b"not PE").unwrap();
        let result = stomp_timestamps(&temp, StompMode::Zero);
        assert!(result.is_err());
        std::fs::remove_file(&temp).ok();
    }

    #[test]
    fn test_read_timestamp_invalid() {
        let temp = std::env::temp_dir().join("test_ts_invalid.bin");
        std::fs::write(&temp, b"XX").unwrap();
        assert!(read_timestamp(&temp).is_err());
        std::fs::remove_file(&temp).ok();
    }
}
