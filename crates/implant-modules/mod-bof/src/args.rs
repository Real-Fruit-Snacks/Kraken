//! BOF Argument Packing
//!
//! Compatible with Cobalt Strike's BeaconDataParse format.
//! Each argument is encoded as: type_byte (u8) + length (u32 LE) + data bytes.
//! The final buffer is prefixed with the total payload length (u32 LE).

/// Pack arguments for BOF execution using the BeaconDataParse wire format.
///
/// Usage:
/// ```rust
/// use mod_bof::args::BofArgPacker;
/// let mut p = BofArgPacker::new();
/// p.add_int(42);
/// p.add_str("hello");
/// let buf = p.build();
/// ```
pub struct BofArgPacker {
    buffer: Vec<u8>,
}

impl BofArgPacker {
    /// Create a new, empty packer.
    pub fn new() -> Self {
        Self {
            buffer: Vec::new(),
        }
    }

    /// Add a signed 32-bit integer argument (type byte 0x01).
    pub fn add_int(&mut self, value: i32) {
        self.buffer.push(0x01); // type: int
        self.buffer.extend_from_slice(&4u32.to_le_bytes());
        self.buffer.extend_from_slice(&value.to_le_bytes());
    }

    /// Add a signed 16-bit short argument (type byte 0x02).
    pub fn add_short(&mut self, value: i16) {
        self.buffer.push(0x02); // type: short
        self.buffer.extend_from_slice(&2u32.to_le_bytes());
        self.buffer.extend_from_slice(&value.to_le_bytes());
    }

    /// Add a UTF-8 string argument, null-terminated (type byte 0x03).
    pub fn add_str(&mut self, value: &str) {
        self.buffer.push(0x03); // type: string
        let bytes = value.as_bytes();
        // length includes the null terminator
        self.buffer
            .extend_from_slice(&((bytes.len() + 1) as u32).to_le_bytes());
        self.buffer.extend_from_slice(bytes);
        self.buffer.push(0x00); // null terminator
    }

    /// Add a UTF-16LE wide string argument, null-terminated (type byte 0x04).
    pub fn add_wstr(&mut self, value: &str) {
        self.buffer.push(0x04); // type: wstring
        let wide: Vec<u16> = value.encode_utf16().chain(std::iter::once(0u16)).collect();
        let bytes: Vec<u8> = wide
            .iter()
            .flat_map(|w| w.to_le_bytes())
            .collect();
        self.buffer
            .extend_from_slice(&(bytes.len() as u32).to_le_bytes());
        self.buffer.extend_from_slice(&bytes);
    }

    /// Add raw binary data (type byte 0x05).
    pub fn add_binary(&mut self, data: &[u8]) {
        self.buffer.push(0x05); // type: binary
        self.buffer
            .extend_from_slice(&(data.len() as u32).to_le_bytes());
        self.buffer.extend_from_slice(data);
    }

    /// Finalize and return the packed buffer.
    ///
    /// The returned buffer starts with a 4-byte LE length prefix encoding the
    /// total number of payload bytes that follow, matching the BeaconDataParse
    /// convention used by Cobalt Strike BOFs.
    pub fn build(self) -> Vec<u8> {
        let mut result = Vec::with_capacity(4 + self.buffer.len());
        result.extend_from_slice(&(self.buffer.len() as u32).to_le_bytes());
        result.extend(self.buffer);
        result
    }
}

impl Default for BofArgPacker {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_build_has_zero_length_prefix() {
        let p = BofArgPacker::new();
        let buf = p.build();
        assert_eq!(buf.len(), 4);
        let prefix = u32::from_le_bytes(buf[0..4].try_into().unwrap());
        assert_eq!(prefix, 0);
    }

    #[test]
    fn test_add_int() {
        let mut p = BofArgPacker::new();
        p.add_int(0x12345678i32);
        let buf = p.build();

        // 4-byte size prefix + 1 type + 4 len + 4 data = 13
        assert_eq!(buf.len(), 13);

        let payload_size = u32::from_le_bytes(buf[0..4].try_into().unwrap());
        assert_eq!(payload_size, 9);

        assert_eq!(buf[4], 0x01); // type int
        let arg_len = u32::from_le_bytes(buf[5..9].try_into().unwrap());
        assert_eq!(arg_len, 4);
        let val = i32::from_le_bytes(buf[9..13].try_into().unwrap());
        assert_eq!(val, 0x12345678);
    }

    #[test]
    fn test_add_short() {
        let mut p = BofArgPacker::new();
        p.add_short(-1i16);
        let buf = p.build();

        // 4 prefix + 1 type + 4 len + 2 data = 11
        assert_eq!(buf.len(), 11);

        let payload_size = u32::from_le_bytes(buf[0..4].try_into().unwrap());
        assert_eq!(payload_size, 7);

        assert_eq!(buf[4], 0x02); // type short
        let arg_len = u32::from_le_bytes(buf[5..9].try_into().unwrap());
        assert_eq!(arg_len, 2);
        let val = i16::from_le_bytes(buf[9..11].try_into().unwrap());
        assert_eq!(val, -1i16);
    }

    #[test]
    fn test_add_str() {
        let mut p = BofArgPacker::new();
        p.add_str("hi");
        let buf = p.build();

        // payload: 1 type + 4 len + 2 chars + 1 null = 8
        // total: 4 prefix + 8 = 12
        assert_eq!(buf.len(), 12);

        let payload_size = u32::from_le_bytes(buf[0..4].try_into().unwrap());
        assert_eq!(payload_size, 8);

        assert_eq!(buf[4], 0x03); // type string
        let arg_len = u32::from_le_bytes(buf[5..9].try_into().unwrap());
        assert_eq!(arg_len, 3); // "hi" + null
        assert_eq!(&buf[9..11], b"hi");
        assert_eq!(buf[11], 0x00); // null terminator
    }

    #[test]
    fn test_add_wstr() {
        let mut p = BofArgPacker::new();
        p.add_wstr("ab");
        let buf = p.build();

        // "ab\0" in UTF-16LE = 3 u16 = 6 bytes
        // payload: 1 type + 4 len + 6 data = 11
        // total: 4 + 11 = 15
        assert_eq!(buf.len(), 15);

        assert_eq!(buf[4], 0x04); // type wstring
        let arg_len = u32::from_le_bytes(buf[5..9].try_into().unwrap());
        assert_eq!(arg_len, 6);
        // 'a' = 0x61 0x00, 'b' = 0x62 0x00, null = 0x00 0x00
        assert_eq!(&buf[9..15], &[0x61, 0x00, 0x62, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn test_add_binary() {
        let data = [0xDE, 0xAD, 0xBE, 0xEF];
        let mut p = BofArgPacker::new();
        p.add_binary(&data);
        let buf = p.build();

        // payload: 1 type + 4 len + 4 data = 9
        // total: 4 + 9 = 13
        assert_eq!(buf.len(), 13);

        assert_eq!(buf[4], 0x05); // type binary
        let arg_len = u32::from_le_bytes(buf[5..9].try_into().unwrap());
        assert_eq!(arg_len, 4);
        assert_eq!(&buf[9..13], &data);
    }

    #[test]
    fn test_size_prefix_matches_payload_length() {
        let mut p = BofArgPacker::new();
        p.add_int(1);
        p.add_str("test");
        p.add_binary(&[0xAA, 0xBB]);
        let buf = p.build();

        let prefix = u32::from_le_bytes(buf[0..4].try_into().unwrap()) as usize;
        assert_eq!(prefix, buf.len() - 4);
    }

    #[test]
    fn test_multiple_args_ordering() {
        let mut p = BofArgPacker::new();
        p.add_int(1);
        p.add_short(2);
        let buf = p.build();

        // int: 1+4+4=9, short: 1+4+2=7, total payload=16
        let payload_size = u32::from_le_bytes(buf[0..4].try_into().unwrap());
        assert_eq!(payload_size, 16);
        assert_eq!(buf[4], 0x01); // int first
        assert_eq!(buf[13], 0x02); // short second
    }
}
