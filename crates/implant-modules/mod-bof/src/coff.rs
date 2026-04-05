//! COFF (Common Object File Format) parser for BOF files
//!
//! Parses x64 COFF object files as produced by MSVC or MinGW compilers.
//! Extracts sections, symbols, and relocations needed for in-memory loading.

use common::KrakenError;

/// COFF file header (20 bytes for standard COFF)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct CoffHeader {
    machine: u16,
    number_of_sections: u16,
    time_date_stamp: u32,
    pointer_to_symbol_table: u32,
    number_of_symbols: u32,
    size_of_optional_header: u16,
    characteristics: u16,
}

/// Section header (40 bytes)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct SectionHeader {
    name: [u8; 8],
    virtual_size: u32,
    virtual_address: u32,
    size_of_raw_data: u32,
    pointer_to_raw_data: u32,
    pointer_to_relocations: u32,
    pointer_to_linenumbers: u32,
    number_of_relocations: u16,
    number_of_linenumbers: u16,
    characteristics: u32,
}

/// Symbol table entry (18 bytes)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct SymbolEntry {
    name: [u8; 8], // Short name or string table offset
    value: u32,
    section_number: i16,
    type_: u16,
    storage_class: u8,
    number_of_aux_symbols: u8,
}

/// Relocation entry size in COFF (10 bytes, not padded)
const RELOCATION_ENTRY_SIZE: usize = 10;

/// Machine type constants
const IMAGE_FILE_MACHINE_AMD64: u16 = 0x8664;
const IMAGE_FILE_MACHINE_I386: u16 = 0x014c;

/// Section characteristics
#[allow(dead_code)]
pub const IMAGE_SCN_CNT_CODE: u32 = 0x00000020;
#[allow(dead_code)]
pub const IMAGE_SCN_CNT_INITIALIZED_DATA: u32 = 0x00000040;
#[allow(dead_code)]
pub const IMAGE_SCN_CNT_UNINITIALIZED_DATA: u32 = 0x00000080;
pub const IMAGE_SCN_MEM_EXECUTE: u32 = 0x20000000;
#[allow(dead_code)]
pub const IMAGE_SCN_MEM_READ: u32 = 0x40000000;
#[allow(dead_code)]
pub const IMAGE_SCN_MEM_WRITE: u32 = 0x80000000;

/// Relocation types (AMD64)
pub const IMAGE_REL_AMD64_ADDR64: u16 = 0x0001;
#[allow(dead_code)]
pub const IMAGE_REL_AMD64_ADDR32NB: u16 = 0x0003;
pub const IMAGE_REL_AMD64_REL32: u16 = 0x0004;
pub const IMAGE_REL_AMD64_REL32_1: u16 = 0x0005;
pub const IMAGE_REL_AMD64_REL32_2: u16 = 0x0006;
pub const IMAGE_REL_AMD64_REL32_3: u16 = 0x0007;
pub const IMAGE_REL_AMD64_REL32_4: u16 = 0x0008;
pub const IMAGE_REL_AMD64_REL32_5: u16 = 0x0009;

/// Parsed COFF file
pub struct CoffFile {
    pub sections: Vec<Section>,
    pub symbols: Vec<CoffSymbol>,
    pub relocations: Vec<(usize, Vec<CoffRelocation>)>,
    pub is_64bit: bool,
}

/// Parsed section
pub struct Section {
    pub name: String,
    pub data: Vec<u8>,
    pub characteristics: u32,
    pub virtual_size: u32,
}

/// Parsed symbol
#[derive(Debug, Clone)]
pub struct CoffSymbol {
    pub name: String,
    pub value: u32,
    pub section: i16,
    pub storage_class: u8,
}

/// Parsed relocation
#[derive(Debug, Clone)]
pub struct CoffRelocation {
    pub offset: u32,
    pub symbol_index: u32,
    pub reloc_type: u16,
}

/// Read a struct from a byte slice with bounds checking
fn read_struct<T: Copy>(data: &[u8], offset: usize) -> Result<T, KrakenError> {
    let size = std::mem::size_of::<T>();
    if offset + size > data.len() {
        return Err(KrakenError::Internal("read out of bounds".into()));
    }
    // Safe because we checked bounds above
    Ok(unsafe { std::ptr::read_unaligned(data[offset..].as_ptr() as *const T) })
}

impl CoffFile {
    /// Parse a COFF object file from bytes
    pub fn parse(data: &[u8]) -> Result<Self, KrakenError> {
        const HEADER_SIZE: usize = std::mem::size_of::<CoffHeader>();

        if data.len() < HEADER_SIZE {
            return Err(KrakenError::Internal("COFF data too small".into()));
        }

        // Parse header (copy to avoid alignment issues)
        let header: CoffHeader = read_struct(data, 0)?;

        // Verify machine type
        let is_64bit = match header.machine {
            IMAGE_FILE_MACHINE_AMD64 => true,
            IMAGE_FILE_MACHINE_I386 => false,
            _ => {
                return Err(KrakenError::Internal(format!(
                    "unsupported COFF machine type: 0x{:04x}",
                    header.machine
                )))
            }
        };

        let num_sections = header.number_of_sections as usize;
        let num_symbols = header.number_of_symbols as usize;
        let symbol_table_offset = header.pointer_to_symbol_table as usize;

        // String table follows symbol table
        let string_table_offset = symbol_table_offset + (num_symbols * 18);

        // Parse sections
        let section_header_offset = HEADER_SIZE + header.size_of_optional_header as usize;
        let mut sections = Vec::with_capacity(num_sections);
        let mut section_headers = Vec::with_capacity(num_sections);

        for i in 0..num_sections {
            let offset = section_header_offset + i * std::mem::size_of::<SectionHeader>();
            let section_header: SectionHeader = read_struct(data, offset)?;

            let name = parse_section_name(&section_header.name, data, string_table_offset)?;

            let section_data = if section_header.pointer_to_raw_data > 0
                && section_header.size_of_raw_data > 0
            {
                let start = section_header.pointer_to_raw_data as usize;
                let end = start + section_header.size_of_raw_data as usize;
                if end > data.len() {
                    return Err(KrakenError::Internal("section data out of bounds".into()));
                }
                data[start..end].to_vec()
            } else {
                // Uninitialized data section (BSS)
                vec![0u8; section_header.virtual_size as usize]
            };

            sections.push(Section {
                name,
                data: section_data,
                characteristics: section_header.characteristics,
                virtual_size: section_header.virtual_size,
            });
            section_headers.push(section_header);
        }

        // Parse symbols - must maintain raw indices for relocations
        let mut symbols = Vec::with_capacity(num_symbols);
        let mut i = 0;
        while i < num_symbols {
            let offset = symbol_table_offset + i * 18;
            let symbol: SymbolEntry = read_struct(data, offset)?;

            let name = parse_symbol_name(&symbol.name, data, string_table_offset)?;

            symbols.push(CoffSymbol {
                name,
                value: symbol.value,
                section: symbol.section_number,
                storage_class: symbol.storage_class,
            });

            // Add placeholder entries for auxiliary symbols to maintain index alignment
            // Relocations reference raw symbol table indices
            for _ in 0..symbol.number_of_aux_symbols {
                symbols.push(CoffSymbol {
                    name: String::new(),
                    value: 0,
                    section: 0,
                    storage_class: 0,
                });
            }

            i += 1 + symbol.number_of_aux_symbols as usize;
        }

        // Parse relocations per section
        let mut relocations = Vec::new();
        for (section_idx, section_header) in section_headers.iter().enumerate() {
            if section_header.number_of_relocations > 0 {
                let reloc_offset = section_header.pointer_to_relocations as usize;
                let mut section_relocs = Vec::new();

                for r in 0..section_header.number_of_relocations as usize {
                    let offset = reloc_offset + r * RELOCATION_ENTRY_SIZE;
                    if offset + RELOCATION_ENTRY_SIZE > data.len() {
                        return Err(KrakenError::Internal("relocation out of bounds".into()));
                    }

                    // Read relocation fields manually (10-byte packed structure)
                    let virtual_address = u32::from_le_bytes([
                        data[offset],
                        data[offset + 1],
                        data[offset + 2],
                        data[offset + 3],
                    ]);
                    let symbol_table_index = u32::from_le_bytes([
                        data[offset + 4],
                        data[offset + 5],
                        data[offset + 6],
                        data[offset + 7],
                    ]);
                    let reloc_type = u16::from_le_bytes([data[offset + 8], data[offset + 9]]);

                    section_relocs.push(CoffRelocation {
                        offset: virtual_address,
                        symbol_index: symbol_table_index,
                        reloc_type,
                    });
                }

                relocations.push((section_idx, section_relocs));
            }
        }

        Ok(Self {
            sections,
            symbols,
            relocations,
            is_64bit,
        })
    }
}

/// Parse section name (may be in string table if > 8 chars)
fn parse_section_name(
    name_bytes: &[u8; 8],
    data: &[u8],
    string_table_offset: usize,
) -> Result<String, KrakenError> {
    // If name starts with '/', it's an offset into string table
    if name_bytes[0] == b'/' {
        let offset_str = std::str::from_utf8(&name_bytes[1..])
            .map_err(|_| KrakenError::Internal("invalid section name offset".into()))?
            .trim_end_matches('\0');

        let offset: usize = offset_str
            .parse()
            .map_err(|_| KrakenError::Internal("invalid section name offset".into()))?;

        let start = string_table_offset + offset;
        return read_null_terminated_string(data, start);
    }

    // Otherwise, it's an inline name (up to 8 chars, null-padded)
    let end = name_bytes.iter().position(|&b| b == 0).unwrap_or(8);
    String::from_utf8(name_bytes[..end].to_vec())
        .map_err(|_| KrakenError::Internal("invalid section name".into()))
}

/// Parse symbol name (may be in string table if > 8 chars)
fn parse_symbol_name(
    name_bytes: &[u8; 8],
    data: &[u8],
    string_table_offset: usize,
) -> Result<String, KrakenError> {
    // If first 4 bytes are zero, remaining 4 bytes are offset into string table
    let zeroes = u32::from_le_bytes([name_bytes[0], name_bytes[1], name_bytes[2], name_bytes[3]]);

    if zeroes == 0 {
        let offset =
            u32::from_le_bytes([name_bytes[4], name_bytes[5], name_bytes[6], name_bytes[7]])
                as usize;
        let start = string_table_offset + offset;
        return read_null_terminated_string(data, start);
    }

    // Otherwise, it's an inline name (up to 8 chars, null-padded)
    let end = name_bytes.iter().position(|&b| b == 0).unwrap_or(8);
    String::from_utf8(name_bytes[..end].to_vec())
        .map_err(|_| KrakenError::Internal("invalid symbol name".into()))
}

/// Read null-terminated string from data
fn read_null_terminated_string(data: &[u8], start: usize) -> Result<String, KrakenError> {
    if start >= data.len() {
        return Err(KrakenError::Internal("string offset out of bounds".into()));
    }

    let end = data[start..]
        .iter()
        .position(|&b| b == 0)
        .map(|pos| start + pos)
        .unwrap_or(data.len());

    String::from_utf8(data[start..end].to_vec())
        .map_err(|_| KrakenError::Internal("invalid string".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_invalid_data() {
        let result = CoffFile::parse(&[0x00, 0x01, 0x02]);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_wrong_machine() {
        // Create minimal COFF header with wrong machine type
        let mut data = vec![0u8; 20];
        data[0] = 0x00; // Wrong machine type
        data[1] = 0x00;
        let result = CoffFile::parse(&data);
        assert!(result.is_err());
    }

    // ========================================================================
    // Edge Case Tests - Malformed COFF Headers
    // ========================================================================

    #[test]
    fn test_parse_empty_data() {
        let result = CoffFile::parse(&[]);
        assert!(result.is_err());
        if let Err(e) = result {
            assert!(e.to_string().contains("too small"));
        }
    }

    #[test]
    fn test_parse_exactly_header_size_but_invalid() {
        // Exactly 20 bytes (header size) but with invalid machine
        let data = vec![0x00u8; 20];
        let result = CoffFile::parse(&data);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_valid_amd64_machine() {
        // Create valid AMD64 header with no sections
        let mut data = vec![0u8; 20];
        // Machine: AMD64 (0x8664)
        data[0] = 0x64;
        data[1] = 0x86;
        // Number of sections: 0
        data[2] = 0x00;
        data[3] = 0x00;
        // Other fields: 0

        let result = CoffFile::parse(&data);
        assert!(result.is_ok());
        let coff = result.unwrap();
        assert!(coff.is_64bit);
        assert!(coff.sections.is_empty());
    }

    #[test]
    fn test_parse_valid_i386_machine() {
        // Create valid i386 header with no sections
        let mut data = vec![0u8; 20];
        // Machine: i386 (0x014c)
        data[0] = 0x4c;
        data[1] = 0x01;
        // Number of sections: 0
        data[2] = 0x00;
        data[3] = 0x00;

        let result = CoffFile::parse(&data);
        assert!(result.is_ok());
        let coff = result.unwrap();
        assert!(!coff.is_64bit);
    }

    #[test]
    fn test_parse_section_header_out_of_bounds() {
        let mut data = vec![0u8; 20];
        // Machine: AMD64
        data[0] = 0x64;
        data[1] = 0x86;
        // Number of sections: 10 (but data is only 20 bytes)
        data[2] = 0x0A;
        data[3] = 0x00;

        let result = CoffFile::parse(&data);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_section_data_out_of_bounds() {
        // Create header with one section that points to data beyond buffer
        // Section header layout:
        //   name: [u8; 8] - offset 0
        //   virtual_size: u32 - offset 8
        //   virtual_address: u32 - offset 12
        //   size_of_raw_data: u32 - offset 16
        //   pointer_to_raw_data: u32 - offset 20
        let mut data = vec![0u8; 100];
        // Machine: AMD64
        data[0] = 0x64;
        data[1] = 0x86;
        // Number of sections: 1
        data[2] = 0x01;
        data[3] = 0x00;

        // Section header starts at offset 20 (after COFF header)
        let section_start = 20;
        // pointer_to_raw_data at section_start + 20 = 40
        data[section_start + 20] = 0x00; // pointer_to_raw_data = 0x1000 (beyond buffer)
        data[section_start + 21] = 0x10;
        data[section_start + 22] = 0x00;
        data[section_start + 23] = 0x00;
        // size_of_raw_data at section_start + 16 = 36
        data[section_start + 16] = 0x10; // size = 16 bytes
        data[section_start + 17] = 0x00;
        data[section_start + 18] = 0x00;
        data[section_start + 19] = 0x00;

        let result = CoffFile::parse(&data);
        assert!(result.is_err(), "should fail when section data points beyond buffer");
    }

    #[test]
    fn test_parse_symbol_table_out_of_bounds() {
        let mut data = vec![0u8; 20];
        // Machine: AMD64
        data[0] = 0x64;
        data[1] = 0x86;
        // Number of sections: 0
        data[2] = 0x00;
        data[3] = 0x00;
        // pointer_to_symbol_table: points beyond buffer
        data[8] = 0xFF;
        data[9] = 0xFF;
        data[10] = 0xFF;
        data[11] = 0xFF;
        // number_of_symbols: 1
        data[12] = 0x01;

        let result = CoffFile::parse(&data);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_relocation_out_of_bounds() {
        // Create COFF with section that has relocations pointing beyond buffer
        let mut data = vec![0u8; 100];
        // Machine: AMD64
        data[0] = 0x64;
        data[1] = 0x86;
        // Number of sections: 1
        data[2] = 0x01;
        data[3] = 0x00;

        // Section header at offset 20
        // pointer_to_relocations at offset 24 in section header (offset 44 total)
        data[44] = 0xFF;
        data[45] = 0xFF;
        // number_of_relocations at offset 32 in section header (offset 52 total)
        data[52] = 0x01;

        let result = CoffFile::parse(&data);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_section_name_inline() {
        // Test that short section names (<=8 chars) work
        let name: [u8; 8] = *b".text\0\0\0";
        let result = parse_section_name(&name, &[], 0);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), ".text");
    }

    #[test]
    fn test_parse_section_name_full_8_chars() {
        // Test section name that uses all 8 characters
        let name: [u8; 8] = *b"12345678";
        let result = parse_section_name(&name, &[], 0);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "12345678");
    }

    #[test]
    fn test_parse_section_name_string_table() {
        // Test section name that references string table
        // Name starts with '/' followed by decimal offset
        let name: [u8; 8] = *b"/4\0\0\0\0\0\0";
        // String table: size (4 bytes) + ".longsectionname\0"
        let mut data = vec![0u8; 50];
        // String at offset 4 in string table
        let string = b".longsectionname\0";
        data[4..4 + string.len()].copy_from_slice(string);

        let result = parse_section_name(&name, &data, 0);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), ".longsectionname");
    }

    #[test]
    fn test_parse_section_name_invalid_offset() {
        // Invalid string table offset
        let name: [u8; 8] = *b"/abc\0\0\0\0"; // Non-numeric offset
        let result = parse_section_name(&name, &[], 0);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_symbol_name_inline() {
        // Symbol name <= 8 chars
        let name: [u8; 8] = *b"_main\0\0\0";
        let result = parse_symbol_name(&name, &[], 0);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "_main");
    }

    #[test]
    fn test_parse_symbol_name_string_table() {
        // Symbol name > 8 chars (first 4 bytes are 0, next 4 are offset)
        let mut name: [u8; 8] = [0u8; 8];
        // Offset 4 in little-endian
        name[4] = 4;
        name[5] = 0;
        name[6] = 0;
        name[7] = 0;

        let mut data = vec![0u8; 50];
        let string = b"very_long_function_name\0";
        data[4..4 + string.len()].copy_from_slice(string);

        let result = parse_symbol_name(&name, &data, 0);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "very_long_function_name");
    }

    #[test]
    fn test_read_null_terminated_string_at_end() {
        // String at end of buffer without null terminator
        let data = b"no_null";
        let result = read_null_terminated_string(data, 0);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "no_null");
    }

    #[test]
    fn test_read_null_terminated_string_offset_beyond_buffer() {
        let data = b"short";
        let result = read_null_terminated_string(data, 100);
        assert!(result.is_err());
    }

    #[test]
    fn test_read_struct_out_of_bounds() {
        let data = [0u8; 10];
        let result: Result<u64, _> = read_struct(&data, 5); // Needs 8 bytes, only 5 available
        assert!(result.is_err());
    }

    #[test]
    fn test_coff_with_bss_section() {
        // BSS sections have zero pointer_to_raw_data but non-zero virtual_size
        let mut data = vec![0u8; 80];
        // Machine: AMD64
        data[0] = 0x64;
        data[1] = 0x86;
        // Number of sections: 1
        data[2] = 0x01;

        // Section header at offset 20
        // name: .bss
        data[20..28].copy_from_slice(b".bss\0\0\0\0");
        // virtual_size: 0x100
        data[28] = 0x00;
        data[29] = 0x01;
        // pointer_to_raw_data: 0 (BSS section)
        // size_of_raw_data: 0

        let result = CoffFile::parse(&data);
        assert!(result.is_ok());
        let coff = result.unwrap();
        assert_eq!(coff.sections.len(), 1);
        // BSS should be zero-filled
        assert!(coff.sections[0].data.iter().all(|&b| b == 0));
    }

    #[test]
    fn test_coff_many_sections() {
        // Verify handling of multiple sections
        let num_sections: u16 = 5;
        let header_size = 20;
        let section_header_size = 40;
        let total_size = header_size + (num_sections as usize * section_header_size);
        let mut data = vec![0u8; total_size];

        // Machine: AMD64
        data[0] = 0x64;
        data[1] = 0x86;
        // Number of sections
        data[2] = num_sections as u8;
        data[3] = (num_sections >> 8) as u8;

        // Set section names
        for i in 0..num_sections as usize {
            let offset = header_size + i * section_header_size;
            data[offset..offset + 4].copy_from_slice(format!(".s{:02}", i).as_bytes());
        }

        let result = CoffFile::parse(&data);
        assert!(result.is_ok());
        let coff = result.unwrap();
        assert_eq!(coff.sections.len(), num_sections as usize);
    }
}
