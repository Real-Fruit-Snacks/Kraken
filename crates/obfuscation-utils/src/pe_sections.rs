//! PE Section Name Randomization
//!
//! Renames well-known PE section names to random 8-character names
//! to evade static YARA rules and signature-based detection.
//!
//! ## Usage
//! Applied as a post-build step on the compiled implant binary.

use std::path::Path;

/// Well-known section names that should be randomized
const KNOWN_SECTIONS: &[&str] = &[
    ".text", ".data", ".rdata", ".bss", ".rsrc",
    ".reloc", ".edata", ".idata", ".tls", ".pdata",
];

/// PE section header (simplified)
#[derive(Debug, Clone)]
pub struct SectionHeader {
    pub name: [u8; 8],
    pub virtual_size: u32,
    pub virtual_address: u32,
    pub raw_data_size: u32,
    pub raw_data_ptr: u32,
    pub characteristics: u32,
    pub offset_in_file: u64,  // Where this header is in the file
}

/// Randomize PE section names in a binary file
pub fn randomize_sections(pe_path: &Path) -> Result<Vec<(String, String)>, std::io::Error> {
    let mut data = std::fs::read(pe_path)?;
    let mut renames = Vec::new();

    // Validate PE signature
    if data.len() < 64 {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "file too small"));
    }

    // Check MZ header
    if &data[0..2] != b"MZ" {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "not a PE file"));
    }

    // Get PE header offset from e_lfanew (offset 0x3C)
    let pe_offset = u32::from_le_bytes([data[0x3C], data[0x3D], data[0x3E], data[0x3F]]) as usize;

    // Verify PE signature
    if pe_offset + 4 > data.len() || &data[pe_offset..pe_offset+4] != b"PE\0\0" {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid PE signature"));
    }

    // COFF header starts at pe_offset + 4
    let coff_offset = pe_offset + 4;
    let num_sections = u16::from_le_bytes([data[coff_offset+2], data[coff_offset+3]]) as usize;
    let optional_header_size = u16::from_le_bytes([data[coff_offset+16], data[coff_offset+17]]) as usize;

    // Section headers start after optional header
    let sections_offset = coff_offset + 20 + optional_header_size;

    for i in 0..num_sections {
        let section_offset = sections_offset + (i * 40); // Each section header is 40 bytes

        if section_offset + 40 > data.len() {
            break;
        }

        // Read section name (first 8 bytes)
        let mut name_bytes = [0u8; 8];
        name_bytes.copy_from_slice(&data[section_offset..section_offset+8]);

        let name = std::str::from_utf8(&name_bytes)
            .unwrap_or("")
            .trim_end_matches('\0')
            .to_string();

        // Check if this is a known section name
        if KNOWN_SECTIONS.iter().any(|&known| known == name) {
            let new_name = generate_random_section_name();
            let mut new_bytes = [0u8; 8];
            let name_slice = new_name.as_bytes();
            new_bytes[..name_slice.len().min(8)].copy_from_slice(&name_slice[..name_slice.len().min(8)]);

            data[section_offset..section_offset+8].copy_from_slice(&new_bytes);
            renames.push((name, new_name));
        }
    }

    // Write modified PE
    std::fs::write(pe_path, &data)?;

    Ok(renames)
}

/// Generate a random section name (8 chars max, starts with '.')
fn generate_random_section_name() -> String {
    let chars: Vec<char> = "abcdefghijklmnopqrstuvwxyz".chars().collect();
    let mut name = String::with_capacity(8);
    name.push('.');

    // Use simple PRNG from system time
    let mut seed = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64;

    for _ in 0..6 {
        seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        let idx = (seed >> 33) as usize % chars.len();
        name.push(chars[idx]);
    }

    name
}

/// List sections in a PE file without modifying
pub fn list_sections(pe_path: &Path) -> Result<Vec<String>, std::io::Error> {
    let data = std::fs::read(pe_path)?;

    if data.len() < 64 || &data[0..2] != b"MZ" {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "not a PE file"));
    }

    let pe_offset = u32::from_le_bytes([data[0x3C], data[0x3D], data[0x3E], data[0x3F]]) as usize;
    let coff_offset = pe_offset + 4;
    let num_sections = u16::from_le_bytes([data[coff_offset+2], data[coff_offset+3]]) as usize;
    let optional_header_size = u16::from_le_bytes([data[coff_offset+16], data[coff_offset+17]]) as usize;
    let sections_offset = coff_offset + 20 + optional_header_size;

    let mut sections = Vec::new();
    for i in 0..num_sections {
        let offset = sections_offset + (i * 40);
        if offset + 8 > data.len() { break; }

        let name = std::str::from_utf8(&data[offset..offset+8])
            .unwrap_or("")
            .trim_end_matches('\0')
            .to_string();
        sections.push(name);
    }

    Ok(sections)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_random_section_name() {
        let name = generate_random_section_name();
        assert!(name.starts_with('.'));
        assert!(name.len() <= 8);
        assert!(name.len() >= 2);
    }

    #[test]
    fn test_random_names_are_different() {
        let name1 = generate_random_section_name();
        std::thread::sleep(std::time::Duration::from_millis(1));
        let name2 = generate_random_section_name();
        // Names should be different (probabilistically)
        // Not guaranteed due to timing, but very likely
        assert_ne!(name1, name2);
    }

    #[test]
    fn test_known_sections_list() {
        assert!(KNOWN_SECTIONS.contains(&".text"));
        assert!(KNOWN_SECTIONS.contains(&".data"));
        assert!(KNOWN_SECTIONS.contains(&".rdata"));
    }

    // Test with a minimal PE file
    #[test]
    fn test_invalid_pe() {
        let temp = std::env::temp_dir().join("test_not_pe.bin");
        std::fs::write(&temp, b"not a PE file").unwrap();
        let result = randomize_sections(&temp);
        assert!(result.is_err());
        std::fs::remove_file(&temp).ok();
    }
}
