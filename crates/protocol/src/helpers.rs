//! Protocol helper functions

use common::KrakenError;
use prost::Message;

/// Encode a protobuf message to bytes
pub fn encode<M: Message>(msg: &M) -> Vec<u8> {
    msg.encode_to_vec()
}

/// Decode bytes to a protobuf message
pub fn decode<M: Message + Default>(bytes: &[u8]) -> Result<M, KrakenError> {
    M::decode(bytes).map_err(|e| KrakenError::Protocol(format!("decode error: {}", e)))
}

/// Encode with length prefix (4 bytes big-endian)
pub fn encode_with_length<M: Message>(msg: &M) -> Vec<u8> {
    let encoded = msg.encode_to_vec();
    let len = encoded.len() as u32;

    let mut result = Vec::with_capacity(4 + encoded.len());
    result.extend_from_slice(&len.to_be_bytes());
    result.extend(encoded);
    result
}

/// Decode with length prefix
pub fn decode_with_length<M: Message + Default>(bytes: &[u8]) -> Result<(M, usize), KrakenError> {
    if bytes.len() < 4 {
        return Err(KrakenError::Protocol(
            "message too short for length prefix".into(),
        ));
    }

    let len = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;

    if bytes.len() < 4 + len {
        return Err(KrakenError::Protocol(format!(
            "message truncated: expected {} bytes, got {}",
            len,
            bytes.len() - 4
        )));
    }

    let msg = decode(&bytes[4..4 + len])?;
    Ok((msg, 4 + len))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Uuid;

    // ---- encode / decode ----

    #[test]
    fn test_encode_decode_roundtrip() {
        let uuid = Uuid {
            value: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
        };

        let encoded = encode(&uuid);
        let decoded: Uuid = decode(&encoded).unwrap();

        assert_eq!(uuid.value, decoded.value);
    }

    #[test]
    fn test_encode_empty_message() {
        // A Uuid with an empty value field encodes to a zero-byte payload
        // (protobuf omits default/empty fields).
        let uuid = Uuid { value: vec![] };
        let encoded = encode(&uuid);
        let decoded: Uuid = decode(&encoded).unwrap();
        assert_eq!(decoded.value, Vec::<u8>::new());
    }

    #[test]
    fn test_encode_produces_bytes() {
        let uuid = Uuid {
            value: vec![0xDE, 0xAD, 0xBE, 0xEF],
        };
        let encoded = encode(&uuid);
        // Must be non-empty (protobuf field tag + data)
        assert!(!encoded.is_empty());
    }

    #[test]
    fn test_decode_invalid_bytes_returns_error() {
        // Random garbage bytes that are not valid protobuf for Uuid
        let garbage = vec![0xFF, 0xFE, 0xFD, 0xFC];
        let result: Result<Uuid, _> = decode(&garbage);
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(err_msg.contains("decode error"));
    }

    #[test]
    fn test_decode_empty_slice_gives_default() {
        // An empty byte slice is valid protobuf for a message with all default fields.
        let decoded: Uuid = decode(&[]).unwrap();
        assert_eq!(decoded.value, Vec::<u8>::new());
    }

    #[test]
    fn test_encode_large_payload() {
        // 64 KiB value — exercises any length-handling paths
        let large = vec![0xABu8; 65536];
        let uuid = Uuid { value: large.clone() };
        let encoded = encode(&uuid);
        let decoded: Uuid = decode(&encoded).unwrap();
        assert_eq!(decoded.value, large);
    }

    // ---- encode_with_length / decode_with_length ----

    #[test]
    fn test_length_prefixed_encoding() {
        let uuid = Uuid {
            value: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
        };

        let encoded = encode_with_length(&uuid);
        let (decoded, consumed): (Uuid, _) = decode_with_length(&encoded).unwrap();

        assert_eq!(uuid.value, decoded.value);
        assert_eq!(consumed, encoded.len());
    }

    #[test]
    fn test_encode_with_length_prefix_is_big_endian() {
        let uuid = Uuid {
            value: vec![0u8; 4],
        };
        let encoded = encode_with_length(&uuid);
        // First 4 bytes are the big-endian length of the protobuf payload
        let declared_len =
            u32::from_be_bytes([encoded[0], encoded[1], encoded[2], encoded[3]]) as usize;
        assert_eq!(declared_len, encoded.len() - 4);
    }

    #[test]
    fn test_decode_with_length_empty_message() {
        let uuid = Uuid { value: vec![] };
        let encoded = encode_with_length(&uuid);
        let (decoded, consumed): (Uuid, _) = decode_with_length(&encoded).unwrap();
        assert_eq!(decoded.value, Vec::<u8>::new());
        assert_eq!(consumed, encoded.len());
    }

    #[test]
    fn test_decode_with_length_too_short_for_prefix() {
        // Fewer than 4 bytes — cannot even read the length prefix
        let result: Result<(Uuid, usize), _> = decode_with_length(&[0x00, 0x00, 0x01]);
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(err_msg.contains("too short"));
    }

    #[test]
    fn test_decode_with_length_truncated_payload() {
        let uuid = Uuid {
            value: vec![1, 2, 3, 4, 5, 6, 7, 8],
        };
        let mut encoded = encode_with_length(&uuid);
        // Drop the last byte to make the payload shorter than declared
        encoded.pop();
        let result: Result<(Uuid, usize), _> = decode_with_length(&encoded);
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(err_msg.contains("truncated"));
    }

    #[test]
    fn test_decode_with_length_consumes_exact_bytes() {
        // Two messages concatenated — consumed should equal only the first message
        let uuid1 = Uuid { value: vec![1u8; 16] };
        let uuid2 = Uuid { value: vec![2u8; 16] };
        let mut buf = encode_with_length(&uuid1);
        buf.extend(encode_with_length(&uuid2));

        let (decoded1, consumed1): (Uuid, _) = decode_with_length(&buf).unwrap();
        assert_eq!(decoded1.value, vec![1u8; 16]);

        let (decoded2, _): (Uuid, _) = decode_with_length(&buf[consumed1..]).unwrap();
        assert_eq!(decoded2.value, vec![2u8; 16]);
    }

    #[test]
    fn test_encode_with_length_large_payload() {
        let large = vec![0x55u8; 65536];
        let uuid = Uuid { value: large.clone() };
        let encoded = encode_with_length(&uuid);
        let (decoded, consumed): (Uuid, _) = decode_with_length(&encoded).unwrap();
        assert_eq!(decoded.value, large);
        assert_eq!(consumed, encoded.len());
    }
}
