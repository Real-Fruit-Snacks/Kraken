//! DNS-safe encoding/decoding for C2 data
//!
//! Uses RFC 4648 Base32 (case-insensitive, no padding) to encode binary data
//! into DNS-safe labels. Each label is limited to 63 characters per DNS spec.

/// Maximum length of a single DNS label
pub const MAX_LABEL_LEN: usize = 63;

/// Maximum total query name length
pub const MAX_QUERY_LEN: usize = 253;

/// Base32 alphabet (RFC 4648, uppercase for DNS compatibility)
const BASE32_ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// Reverse lookup table for decoding
const BASE32_DECODE: [i8; 128] = {
    let mut table = [-1i8; 128];
    let mut i = 0;
    while i < 32 {
        table[BASE32_ALPHABET[i] as usize] = i as i8;
        // Also accept lowercase
        if BASE32_ALPHABET[i] >= b'A' && BASE32_ALPHABET[i] <= b'Z' {
            table[(BASE32_ALPHABET[i] + 32) as usize] = i as i8;
        }
        i += 1;
    }
    table
};

/// Encode binary data to base32 string
///
/// Returns a string suitable for use in DNS labels (uppercase, no padding).
pub fn encode_base32(data: &[u8]) -> String {
    if data.is_empty() {
        return String::new();
    }

    let output_len = (data.len() * 8 + 4) / 5;
    let mut output = Vec::with_capacity(output_len);

    let mut buffer: u64 = 0;
    let mut bits_in_buffer = 0;

    for &byte in data {
        buffer = (buffer << 8) | byte as u64;
        bits_in_buffer += 8;

        while bits_in_buffer >= 5 {
            bits_in_buffer -= 5;
            let index = ((buffer >> bits_in_buffer) & 0x1F) as usize;
            output.push(BASE32_ALPHABET[index]);
        }
    }

    // Handle remaining bits
    if bits_in_buffer > 0 {
        let index = ((buffer << (5 - bits_in_buffer)) & 0x1F) as usize;
        output.push(BASE32_ALPHABET[index]);
    }

    // Safe because we only use ASCII characters
    unsafe { String::from_utf8_unchecked(output) }
}

/// Decode base32 string to binary data
///
/// Accepts both uppercase and lowercase input.
pub fn decode_base32(input: &str) -> Option<Vec<u8>> {
    if input.is_empty() {
        return Some(Vec::new());
    }

    let mut output = Vec::with_capacity(input.len() * 5 / 8);
    let mut buffer: u64 = 0;
    let mut bits_in_buffer = 0;

    for &byte in input.as_bytes() {
        if byte >= 128 {
            return None;
        }

        let value = BASE32_DECODE[byte as usize];
        if value < 0 {
            // Skip invalid characters (including padding '=')
            if byte == b'=' {
                continue;
            }
            return None;
        }

        buffer = (buffer << 5) | value as u64;
        bits_in_buffer += 5;

        if bits_in_buffer >= 8 {
            bits_in_buffer -= 8;
            output.push((buffer >> bits_in_buffer) as u8);
        }
    }

    Some(output)
}

/// Split encoded data into DNS-safe labels
///
/// Each label is at most `max_label_len` characters (default 63).
pub fn split_into_labels(encoded: &str, max_label_len: usize) -> Vec<&str> {
    let max_len = max_label_len.min(MAX_LABEL_LEN);
    encoded
        .as_bytes()
        .chunks(max_len)
        .map(|chunk| {
            // Safe because encode_base32 only produces ASCII
            unsafe { std::str::from_utf8_unchecked(chunk) }
        })
        .collect()
}

/// Build a DNS query name from data and domain
///
/// Format: `<label1>.<label2>...<nonce>.<domain>`
pub fn build_query_name(data: &[u8], nonce: &str, domain: &str, max_label_len: usize) -> String {
    let encoded = encode_base32(data);
    let labels = split_into_labels(&encoded, max_label_len);

    let mut query = String::new();
    for label in labels {
        query.push_str(label);
        query.push('.');
    }
    query.push_str(nonce);
    query.push('.');
    query.push_str(domain);

    query
}

/// Parse data and nonce from a DNS query name
///
/// Returns `(nonce, decoded_data)` on success.
pub fn parse_query_name(name: &str, domain: &str) -> Option<(String, Vec<u8>)> {
    // Remove trailing dot if present
    let name = name.strip_suffix('.').unwrap_or(name);

    // Check domain suffix
    if !name.to_lowercase().ends_with(&domain.to_lowercase()) {
        return None;
    }

    // Remove domain suffix
    let prefix = &name[..name.len() - domain.len()];
    let prefix = prefix.strip_suffix('.').unwrap_or(prefix);

    // Split into labels
    let labels: Vec<&str> = prefix.split('.').collect();
    if labels.is_empty() {
        return None;
    }

    // Last label before domain is the nonce
    let nonce = labels.last()?.to_string();

    // Remaining labels contain the encoded data
    let data_labels = &labels[..labels.len() - 1];
    let encoded: String = data_labels.concat();

    let data = decode_base32(&encoded)?;

    Some((nonce, data))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_empty() {
        assert_eq!(encode_base32(&[]), "");
    }

    #[test]
    fn test_encode_hello() {
        // "hello" in base32 is "NBSWY3DP" (without padding)
        assert_eq!(encode_base32(b"hello"), "NBSWY3DP");
    }

    #[test]
    fn test_encode_decode_roundtrip() {
        let test_cases = [
            &b""[..],
            &b"a"[..],
            &b"ab"[..],
            &b"abc"[..],
            &b"abcd"[..],
            &b"abcde"[..],
            &b"hello world"[..],
            &[0u8, 1, 2, 3, 255, 254, 253][..],
        ];

        for data in test_cases {
            let encoded = encode_base32(data);
            let decoded = decode_base32(&encoded).expect("decode failed");
            assert_eq!(decoded, data, "roundtrip failed for {:?}", data);
        }
    }

    #[test]
    fn test_decode_case_insensitive() {
        let data = b"test";
        let encoded = encode_base32(data);

        // Should decode both uppercase and lowercase
        assert_eq!(decode_base32(&encoded), Some(data.to_vec()));
        assert_eq!(decode_base32(&encoded.to_lowercase()), Some(data.to_vec()));
    }

    #[test]
    fn test_decode_invalid() {
        assert_eq!(decode_base32("!!!"), None);
        assert_eq!(decode_base32("AB CD"), None); // space is invalid
    }

    #[test]
    fn test_split_into_labels() {
        let encoded = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        let labels = split_into_labels(encoded, 10);

        assert_eq!(labels.len(), 4);
        assert_eq!(labels[0], "ABCDEFGHIJ");
        assert_eq!(labels[1], "KLMNOPQRST");
        assert_eq!(labels[2], "UVWXYZ2345");
        assert_eq!(labels[3], "67");
    }

    #[test]
    fn test_build_query_name() {
        let data = b"hello";
        let nonce = "abc123";
        let domain = "c2.example.com";

        let query = build_query_name(data, nonce, domain, 63);
        assert_eq!(query, "NBSWY3DP.abc123.c2.example.com");
    }

    #[test]
    fn test_parse_query_name() {
        let query = "NBSWY3DP.abc123.c2.example.com";
        let domain = "c2.example.com";

        let (nonce, data) = parse_query_name(query, domain).unwrap();
        assert_eq!(nonce, "abc123");
        assert_eq!(data, b"hello");
    }

    #[test]
    fn test_parse_query_name_with_trailing_dot() {
        let query = "NBSWY3DP.abc123.c2.example.com.";
        let domain = "c2.example.com";

        let result = parse_query_name(query, domain);
        assert!(result.is_some());
    }

    #[test]
    fn test_parse_query_name_multiple_labels() {
        // Large data that spans multiple labels
        let data = b"This is a longer message that will span multiple DNS labels";
        let nonce = "nonce123";
        let domain = "test.local";

        let query = build_query_name(data, nonce, domain, 20);
        let (parsed_nonce, parsed_data) = parse_query_name(&query, domain).unwrap();

        assert_eq!(parsed_nonce, nonce);
        assert_eq!(parsed_data, data);
    }

    #[test]
    fn test_label_length_limit() {
        let long_string = "A".repeat(200);
        let labels = split_into_labels(&long_string, MAX_LABEL_LEN);
        for label in &labels {
            assert!(label.len() <= MAX_LABEL_LEN);
        }
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        /// Any binary data survives base32 encode → decode roundtrip
        #[test]
        fn base32_roundtrip(data in prop::collection::vec(any::<u8>(), 0..1024)) {
            let encoded = encode_base32(&data);
            let decoded = decode_base32(&encoded).expect("decode should succeed");
            prop_assert_eq!(decoded, data);
        }

        /// Base32 decoding is case-insensitive
        #[test]
        fn base32_case_insensitive(data in prop::collection::vec(any::<u8>(), 1..256)) {
            let encoded = encode_base32(&data);
            let upper = decode_base32(&encoded.to_uppercase());
            let lower = decode_base32(&encoded.to_lowercase());
            prop_assert_eq!(&upper, &lower);
            prop_assert_eq!(upper, Some(data));
        }

        /// Encoded output only contains valid base32 characters
        #[test]
        fn base32_valid_chars(data in prop::collection::vec(any::<u8>(), 0..512)) {
            let encoded = encode_base32(&data);
            for c in encoded.chars() {
                prop_assert!(
                    BASE32_ALPHABET.contains(&(c as u8)),
                    "invalid char '{}' in encoded output", c
                );
            }
        }

        /// Split labels never exceed max length
        #[test]
        fn split_respects_max_len(
            data in prop::collection::vec(any::<u8>(), 1..512),
            max_len in 10usize..=63
        ) {
            let encoded = encode_base32(&data);
            let labels = split_into_labels(&encoded, max_len);
            for label in &labels {
                prop_assert!(
                    label.len() <= max_len,
                    "label length {} exceeds max {}", label.len(), max_len
                );
            }
        }

        /// DNS query name build → parse roundtrip preserves data
        #[test]
        fn query_name_roundtrip(
            data in prop::collection::vec(any::<u8>(), 1..256),
            nonce in "[a-z0-9]{4,12}",
        ) {
            let domain = "c2.test.local";
            let query = build_query_name(&data, &nonce, domain, 63);
            let (parsed_nonce, parsed_data) = parse_query_name(&query, domain)
                .expect("parse should succeed");
            prop_assert_eq!(parsed_nonce, nonce);
            prop_assert_eq!(parsed_data, data);
        }

        /// Query names with varying label sizes roundtrip correctly
        #[test]
        fn query_name_varying_labels(
            data in prop::collection::vec(any::<u8>(), 10..128),
            max_label in 15usize..=63,
        ) {
            let domain = "test.example.com";
            let nonce = "n0nc3";
            let query = build_query_name(&data, nonce, domain, max_label);
            let (_, parsed_data) = parse_query_name(&query, domain)
                .expect("parse should succeed");
            prop_assert_eq!(parsed_data, data);
        }

        /// Trailing dot in query name is handled correctly
        #[test]
        fn query_name_trailing_dot(data in prop::collection::vec(any::<u8>(), 1..64)) {
            let domain = "c2.local";
            let nonce = "xyz";
            let query = build_query_name(&data, nonce, domain, 63);

            // With trailing dot
            let query_with_dot = format!("{}.", query);
            let result = parse_query_name(&query_with_dot, domain);
            prop_assert!(result.is_some());

            let (_, parsed_data) = result.unwrap();
            prop_assert_eq!(parsed_data, data);
        }
    }
}
