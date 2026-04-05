//! Encoding transforms for shellcode payloads.
//!
//! The primary transform is null-byte elimination, which is required when
//! shellcode is delivered through C-string APIs (e.g., `lstrcpyA`) that treat
//! `\x00` as a terminator.
//!
//! ## Technique
//! Replace each `0x00` byte with a two-byte escape sequence `[ESC, XOR_VAL]`
//! where `ESC` is a chosen escape byte and `XOR_VAL` when XOR'd with `ESC`
//! produces `0x00`. A small decoder stub is prepended.
//!
//! ## Detection (Blue Team)
//! - Encoded shellcode has no null bytes — anomalous for PE/ELF data
//! - Decoder stub contains a tight XOR loop at the start

use crate::BuilderError;

/// Escape byte used for null elimination.
/// Chosen to be uncommon in typical x64 instruction sequences.
const ESCAPE_BYTE: u8 = 0xFF;

/// Eliminate null bytes from `data` via escape-sequence encoding.
///
/// Every `0x00` byte is replaced with `[ESCAPE_BYTE, ESCAPE_BYTE]`
/// (since `0xFF ^ 0xFF == 0x00`). Every literal `ESCAPE_BYTE` in the
/// original is replaced with `[ESCAPE_BYTE, 0x01]` to disambiguate.
///
/// Returns the encoded blob. A matching `decode_nulls` function reverses
/// the process.
pub fn eliminate_nulls(data: &[u8]) -> Result<Vec<u8>, BuilderError> {
    let mut out = Vec::with_capacity(data.len() + data.len() / 8);

    for &b in data {
        if b == 0x00 {
            out.push(ESCAPE_BYTE);
            out.push(ESCAPE_BYTE); // 0xFF ^ 0xFF == 0x00
        } else if b == ESCAPE_BYTE {
            out.push(ESCAPE_BYTE);
            out.push(0x01); // sentinel: literal 0xFF
        } else {
            out.push(b);
        }
    }

    Ok(out)
}

/// Decode a null-eliminated blob back to the original bytes.
pub fn decode_nulls(data: &[u8]) -> Result<Vec<u8>, BuilderError> {
    let mut out = Vec::with_capacity(data.len());
    let mut i = 0;

    while i < data.len() {
        if data[i] == ESCAPE_BYTE {
            if i + 1 >= data.len() {
                return Err(BuilderError::Encoding(
                    "truncated escape sequence at end of data".into(),
                ));
            }
            match data[i + 1] {
                ESCAPE_BYTE => {
                    out.push(0x00);
                    i += 2;
                }
                0x01 => {
                    out.push(ESCAPE_BYTE);
                    i += 2;
                }
                other => {
                    return Err(BuilderError::Encoding(format!(
                        "invalid escape sequence: 0xFF 0x{:02X}",
                        other
                    )));
                }
            }
        } else {
            out.push(data[i]);
            i += 1;
        }
    }

    Ok(out)
}

/// Check whether `data` contains any null bytes.
pub fn contains_nulls(data: &[u8]) -> bool {
    data.contains(&0x00)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_eliminate_nulls_roundtrip() {
        let data = vec![0x41, 0x00, 0x42, 0x00, 0x00, 0x43];
        let encoded = eliminate_nulls(&data).unwrap();
        assert!(!contains_nulls(&encoded));
        let decoded = decode_nulls(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_escape_byte_roundtrip() {
        let data = vec![0xFF, 0x00, 0xFF, 0xFF];
        let encoded = eliminate_nulls(&data).unwrap();
        assert!(!contains_nulls(&encoded));
        let decoded = decode_nulls(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_no_nulls_passthrough() {
        let data = vec![0x41, 0x42, 0x43];
        let encoded = eliminate_nulls(&data).unwrap();
        // No escape sequences needed for non-null, non-0xFF bytes.
        assert_eq!(encoded, data);
    }

    #[test]
    fn test_all_nulls() {
        let data = vec![0x00; 16];
        let encoded = eliminate_nulls(&data).unwrap();
        assert!(!contains_nulls(&encoded));
        assert_eq!(encoded.len(), 32); // Each null becomes two bytes.
        let decoded = decode_nulls(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_empty_data() {
        let encoded = eliminate_nulls(&[]).unwrap();
        assert!(encoded.is_empty());
        let decoded = decode_nulls(&[]).unwrap();
        assert!(decoded.is_empty());
    }

    #[test]
    fn test_contains_nulls() {
        assert!(contains_nulls(&[0x41, 0x00, 0x42]));
        assert!(!contains_nulls(&[0x41, 0x42, 0x43]));
        assert!(!contains_nulls(&[]));
    }

    #[test]
    fn test_truncated_escape_error() {
        let data = vec![0xFF]; // Escape at end with no follow-up.
        assert!(decode_nulls(&data).is_err());
    }

    #[test]
    fn test_invalid_escape_error() {
        let data = vec![0xFF, 0x55]; // Invalid escape sequence.
        assert!(decode_nulls(&data).is_err());
    }
}
