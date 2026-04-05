//! DNS Transport Integration Tests
//!
//! Tests the complete DNS transport flow including:
//! - Encoding/decoding roundtrips for various payload sizes
//! - DNS query building and response parsing
//! - Chunking for large payloads across multiple labels
//! - TXT and A record handling
//! - Error handling and edge cases

use mod_dns::encode::{
    build_query_name, decode_base32, encode_base32, parse_query_name, split_into_labels,
    MAX_LABEL_LEN,
};
use mod_dns::packet::{
    build_query, extract_a_data, extract_txt_data, parse_response, AckStatus, RecordType,
};
use mod_dns::{DnsConfig, DnsTransport};

// ---------------------------------------------------------------------------
// Encoding Integration Tests
// ---------------------------------------------------------------------------

mod encoding {
    use super::*;

    #[test]
    fn test_encode_decode_various_sizes() {
        let sizes = [0, 1, 2, 3, 4, 5, 8, 16, 32, 64, 100, 255, 512, 1024];

        for size in sizes {
            let data: Vec<u8> = (0..size).map(|i| (i % 256) as u8).collect();
            let encoded = encode_base32(&data);
            let decoded = decode_base32(&encoded).expect("decode should succeed");
            assert_eq!(decoded, data, "roundtrip failed for size {}", size);
        }
    }

    #[test]
    fn test_encode_all_byte_values() {
        // Test that all possible byte values survive encoding
        let data: Vec<u8> = (0..=255).collect();
        let encoded = encode_base32(&data);
        let decoded = decode_base32(&encoded).expect("decode should succeed");
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_encode_produces_valid_dns_chars() {
        let test_data = vec![
            vec![0xFF; 100],
            vec![0x00; 100],
            (0..100).map(|i| i as u8).collect(),
            b"Hello, World! 123".to_vec(),
        ];

        for data in test_data {
            let encoded = encode_base32(&data);
            for c in encoded.chars() {
                assert!(
                    c.is_ascii_uppercase() || c.is_ascii_digit(),
                    "invalid char '{}' in encoded output",
                    c
                );
                // Verify it's in valid base32 alphabet
                assert!(
                    "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".contains(c),
                    "char '{}' not in base32 alphabet",
                    c
                );
            }
        }
    }

    #[test]
    fn test_case_insensitive_decode() {
        let data = b"test data for case insensitivity";
        let encoded = encode_base32(data);

        // Uppercase
        let decoded_upper = decode_base32(&encoded).unwrap();
        assert_eq!(decoded_upper, data);

        // Lowercase
        let decoded_lower = decode_base32(&encoded.to_lowercase()).unwrap();
        assert_eq!(decoded_lower, data);

        // Mixed case
        let mixed: String = encoded
            .chars()
            .enumerate()
            .map(|(i, c)| {
                if i % 2 == 0 {
                    c.to_ascii_lowercase()
                } else {
                    c.to_ascii_uppercase()
                }
            })
            .collect();
        let decoded_mixed = decode_base32(&mixed).unwrap();
        assert_eq!(decoded_mixed, data);
    }

    #[test]
    fn test_invalid_characters_rejected() {
        let invalid_inputs = [
            "INVALID!",
            "SPACE HERE",
            "TAB\tHERE",
            "NEWLINE\nHERE",
            "SPECIAL@#$",
            "EMOJI😀",
        ];

        for input in invalid_inputs {
            assert!(
                decode_base32(input).is_none(),
                "should reject invalid input: {}",
                input
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Label Splitting Tests
// ---------------------------------------------------------------------------

mod label_splitting {
    use super::*;

    #[test]
    fn test_split_respects_max_label_length() {
        let test_cases = [
            (10, 100),
            (20, 200),
            (63, 500),
            (30, 150),
        ];

        for (max_len, data_size) in test_cases {
            let data: Vec<u8> = (0..data_size).map(|i| (i % 256) as u8).collect();
            let encoded = encode_base32(&data);
            let labels = split_into_labels(&encoded, max_len);

            for label in &labels {
                assert!(
                    label.len() <= max_len,
                    "label length {} exceeds max {} for data size {}",
                    label.len(),
                    max_len,
                    data_size
                );
            }

            // Verify concatenation recovers original
            let rejoined: String = labels.concat();
            assert_eq!(rejoined, encoded);
        }
    }

    #[test]
    fn test_label_split_preserves_data() {
        let data = b"This is a test message that should be split into multiple labels";
        let encoded = encode_base32(data);

        for max_len in [10, 20, 30, 40, 50, 63] {
            let labels = split_into_labels(&encoded, max_len);
            let rejoined: String = labels.concat();
            let decoded = decode_base32(&rejoined).unwrap();
            assert_eq!(decoded, data, "data not preserved with max_len={}", max_len);
        }
    }

    #[test]
    fn test_max_label_len_enforced() {
        let long_data = vec![0xAB; 500];
        let encoded = encode_base32(&long_data);
        let labels = split_into_labels(&encoded, MAX_LABEL_LEN);

        for label in labels {
            assert!(label.len() <= MAX_LABEL_LEN);
        }
    }
}

// ---------------------------------------------------------------------------
// Query Name Building Tests
// ---------------------------------------------------------------------------

mod query_names {
    use super::*;

    #[test]
    fn test_query_name_format() {
        let data = b"hello";
        let nonce = "abc123";
        let domain = "c2.example.com";

        let query = build_query_name(data, nonce, domain, 63);

        assert!(query.contains(nonce));
        assert!(query.ends_with(domain));
        assert!(query.contains('.'));
    }

    #[test]
    fn test_query_name_roundtrip() {
        let test_cases = [
            (b"hello".as_slice(), "nonce1", "c2.test.local"),
            (b"".as_slice(), "n", "a.b"),
            (&[0xFF; 100], "abc123", "long.domain.example.com"),
            (b"test data 123".as_slice(), "xyz789", "c2.local"),
        ];

        for (data, nonce, domain) in test_cases {
            let query = build_query_name(data, nonce, domain, 63);
            let (parsed_nonce, parsed_data) =
                parse_query_name(&query, domain).expect("parse should succeed");

            assert_eq!(parsed_nonce, nonce);
            assert_eq!(parsed_data, data);
        }
    }

    #[test]
    fn test_query_name_with_trailing_dot() {
        let data = b"test";
        let nonce = "abc";
        let domain = "c2.local";

        let query = build_query_name(data, nonce, domain, 63);
        let query_with_dot = format!("{}.", query);

        let result = parse_query_name(&query_with_dot, domain);
        assert!(result.is_some());

        let (parsed_nonce, parsed_data) = result.unwrap();
        assert_eq!(parsed_nonce, nonce);
        assert_eq!(parsed_data, data);
    }

    #[test]
    fn test_query_name_large_payload_chunking() {
        // Large payload that requires multiple labels
        let data: Vec<u8> = (0..500).map(|i| (i % 256) as u8).collect();
        let nonce = "session123";
        let domain = "c2.example.com";

        let query = build_query_name(&data, nonce, domain, 63);

        // Verify query is well-formed
        assert!(query.ends_with(domain));
        assert!(query.contains(nonce));

        // Verify roundtrip
        let (parsed_nonce, parsed_data) =
            parse_query_name(&query, domain).expect("parse should succeed");
        assert_eq!(parsed_nonce, nonce);
        assert_eq!(parsed_data, data);
    }

    #[test]
    fn test_query_name_varying_label_sizes() {
        let data = b"consistent data for varying label sizes";

        for max_label in [15, 20, 30, 40, 50, 63] {
            let nonce = "nonce";
            let domain = "test.local";

            let query = build_query_name(data, nonce, domain, max_label);

            // Verify all labels respect max size
            let parts: Vec<&str> = query.split('.').collect();
            for part in &parts[..parts.len() - 2] {
                // Exclude nonce and domain parts
                if !part.is_empty() {
                    assert!(
                        part.len() <= max_label,
                        "label '{}' exceeds max {} at label_size={}",
                        part,
                        max_label,
                        max_label
                    );
                }
            }

            // Verify roundtrip
            let (_, parsed_data) = parse_query_name(&query, domain).unwrap();
            assert_eq!(parsed_data, data);
        }
    }

    #[test]
    fn test_query_name_wrong_domain_rejected() {
        let query = "NBSWY3DP.nonce.c2.example.com";
        let wrong_domain = "other.domain.com";

        assert!(parse_query_name(query, wrong_domain).is_none());
    }
}

// ---------------------------------------------------------------------------
// DNS Packet Tests
// ---------------------------------------------------------------------------

mod packets {
    use super::*;

    #[test]
    fn test_build_query_structure() {
        let query = build_query(0x1234, "test.example.com", RecordType::TXT);

        // Header checks
        assert!(query.len() >= 12, "query too short for header");
        assert_eq!(query[0], 0x12);
        assert_eq!(query[1], 0x34);

        // Flags: standard query with RD
        assert_eq!(query[2], 0x01);
        assert_eq!(query[3], 0x00);

        // QDCOUNT = 1
        assert_eq!(query[4], 0x00);
        assert_eq!(query[5], 0x01);
    }

    #[test]
    fn test_build_query_different_record_types() {
        let record_types = [
            (RecordType::A, 1u16),
            (RecordType::TXT, 16u16),
            (RecordType::AAAA, 28u16),
        ];

        for (record_type, expected_value) in record_types {
            let query = build_query(0x0001, "test.local", record_type);

            // QTYPE is at end - 4 bytes (2 for QTYPE, 2 for QCLASS)
            let qtype_pos = query.len() - 4;
            let qtype = u16::from_be_bytes([query[qtype_pos], query[qtype_pos + 1]]);

            assert_eq!(
                qtype, expected_value,
                "wrong QTYPE for {:?}",
                record_type
            );
        }
    }

    #[test]
    fn test_parse_a_response() {
        // Build a minimal A record response
        let mut packet = vec![
            0xAB, 0xCD, // Transaction ID
            0x81, 0x80, // Flags: response
            0x00, 0x00, // QDCOUNT = 0
            0x00, 0x01, // ANCOUNT = 1
            0x00, 0x00, // NSCOUNT
            0x00, 0x00, // ARCOUNT
        ];

        // Answer section
        packet.extend(&[
            0xC0, 0x0C, // Name pointer
            0x00, 0x01, // Type: A
            0x00, 0x01, // Class: IN
            0x00, 0x00, 0x01, 0x2C, // TTL: 300
            0x00, 0x04, // RDLENGTH: 4
            0x00, 0x00, 0x00, 0x01, // RDATA: 0.0.0.1 (Success)
        ]);

        let response = parse_response(&packet).expect("parse should succeed");
        assert_eq!(response.transaction_id, 0xABCD);
        assert!(response.is_response);
        assert_eq!(response.response_code, 0);
        assert_eq!(response.answers.len(), 1);

        let a_data = extract_a_data(&response).expect("should have A record");
        assert_eq!(AckStatus::from(a_data), AckStatus::Success);
    }

    #[test]
    fn test_parse_txt_response() {
        let mut packet = vec![
            0x00, 0x01, // Transaction ID
            0x81, 0x80, // Flags
            0x00, 0x00, // QDCOUNT
            0x00, 0x01, // ANCOUNT
            0x00, 0x00, // NSCOUNT
            0x00, 0x00, // ARCOUNT
        ];

        let txt_content = b"NBSWY3DP"; // base32 "hello"

        packet.extend(&[
            0xC0, 0x0C, // Name pointer
            0x00, 0x10, // Type: TXT
            0x00, 0x01, // Class: IN
            0x00, 0x00, 0x00, 0x3C, // TTL
        ]);
        // RDLENGTH
        packet.push(0x00);
        packet.push((txt_content.len() + 1) as u8);
        // TXT string
        packet.push(txt_content.len() as u8);
        packet.extend(txt_content);

        let response = parse_response(&packet).expect("parse should succeed");
        let txt_data = extract_txt_data(&response).expect("should have TXT record");

        assert_eq!(txt_data, txt_content);
    }

    #[test]
    fn test_parse_truncated_packet_rejected() {
        // Too short for header
        assert!(parse_response(&[0x00; 5]).is_none());
        assert!(parse_response(&[0x00; 11]).is_none());
    }

    #[test]
    fn test_ack_status_all_values() {
        let ack_tests = [
            ([0, 0, 0, 0], AckStatus::NoTasks),
            ([0, 0, 0, 1], AckStatus::Success),
            ([0, 0, 0, 2], AckStatus::Resend),
            ([0, 0, 0, 3], AckStatus::Error),
            ([1, 2, 3, 4], AckStatus::Unknown),
            ([0, 0, 1, 0], AckStatus::Unknown),
            ([255, 255, 255, 255], AckStatus::Unknown),
        ];

        for (addr, expected) in ack_tests {
            assert_eq!(
                AckStatus::from(addr),
                expected,
                "wrong status for {:?}",
                addr
            );
        }
    }

    #[test]
    fn test_parse_response_with_nxdomain() {
        // NXDOMAIN response (rcode = 3)
        let packet = vec![
            0x00, 0x01, // Transaction ID
            0x81, 0x83, // Flags: response + NXDOMAIN
            0x00, 0x00, // QDCOUNT
            0x00, 0x00, // ANCOUNT
            0x00, 0x00, // NSCOUNT
            0x00, 0x00, // ARCOUNT
        ];

        let response = parse_response(&packet).expect("parse should succeed");
        assert_eq!(response.response_code, 3);
        assert!(response.answers.is_empty());
    }
}

// ---------------------------------------------------------------------------
// Transport Configuration Tests
// ---------------------------------------------------------------------------

mod transport_config {
    use super::*;
    use common::Transport;

    #[test]
    fn test_default_config() {
        let config = DnsConfig::default();

        assert_eq!(config.max_label_size, 63);
        assert_eq!(config.timeout_secs, 5);
        assert_eq!(config.max_retries, 3);
        assert_eq!(config.domain, "c2.example.com");
    }

    #[test]
    fn test_transport_id() {
        let transport = DnsTransport::new(DnsConfig::default());
        assert_eq!(transport.id(), "dns");
    }

    #[test]
    fn test_transport_availability() {
        let transport = DnsTransport::new(DnsConfig::default());
        assert!(transport.is_available());
    }

    #[test]
    fn test_transport_nonce_generation() {
        let t1 = DnsTransport::new(DnsConfig::default());
        let t2 = DnsTransport::new(DnsConfig::default());

        // Each transport should have unique nonce
        assert_ne!(t1.nonce(), t2.nonce());

        // Nonces should be 16 hex chars
        assert_eq!(t1.nonce().len(), 16);
        assert_eq!(t2.nonce().len(), 16);

        // Nonces should be valid hex
        assert!(t1.nonce().chars().all(|c| c.is_ascii_hexdigit()));
        assert!(t2.nonce().chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_transport_with_explicit_nonce() {
        let config = DnsConfig::default();
        let transport = DnsTransport::with_nonce(config, "custom_nonce_123".to_string());

        assert_eq!(transport.nonce(), "custom_nonce_123");
    }

    #[test]
    fn test_transport_reset_changes_nonce() {
        let mut transport = DnsTransport::new(DnsConfig::default());
        let nonce1 = transport.nonce().to_string();

        transport.reset();
        let nonce2 = transport.nonce().to_string();

        assert_ne!(nonce1, nonce2);
        assert!(transport.is_available());
    }

    #[test]
    fn test_custom_config() {
        let config = DnsConfig {
            resolver: "1.1.1.1:53".parse().unwrap(),
            domain: "custom.domain.com".to_string(),
            max_label_size: 30,
            jitter_ms: (50, 100),
            timeout_secs: 10,
            max_retries: 5,
        };

        let transport = DnsTransport::new(config.clone());
        assert_eq!(transport.nonce().len(), 16);

        // Config values should be stored
        // (Can't directly access config, but verify transport works)
        assert!(transport.is_available());
    }
}

// ---------------------------------------------------------------------------
// Edge Case Tests
// ---------------------------------------------------------------------------

mod edge_cases {
    use super::*;

    #[test]
    fn test_empty_data_encoding() {
        let encoded = encode_base32(&[]);
        assert!(encoded.is_empty());

        let decoded = decode_base32("").unwrap();
        assert!(decoded.is_empty());
    }

    #[test]
    fn test_single_byte_encoding() {
        for byte in 0..=255u8 {
            let data = vec![byte];
            let encoded = encode_base32(&data);
            let decoded = decode_base32(&encoded).unwrap();
            assert_eq!(decoded, data, "roundtrip failed for byte {}", byte);
        }
    }

    #[test]
    fn test_query_name_empty_data() {
        let query = build_query_name(&[], "nonce", "domain.com", 63);
        assert!(query.contains("nonce"));
        assert!(query.ends_with("domain.com"));

        let (parsed_nonce, parsed_data) =
            parse_query_name(&query, "domain.com").expect("parse should succeed");
        assert_eq!(parsed_nonce, "nonce");
        assert!(parsed_data.is_empty());
    }

    #[test]
    fn test_very_long_domain() {
        let long_domain = "a.b.c.d.e.f.g.h.i.j.k.l.m.n.o.p.example.com";
        let data = b"test";
        let nonce = "n";

        let query = build_query_name(data, nonce, long_domain, 63);
        let (parsed_nonce, parsed_data) =
            parse_query_name(&query, long_domain).expect("parse should succeed");

        assert_eq!(parsed_nonce, nonce);
        assert_eq!(parsed_data, data);
    }

    #[test]
    fn test_minimum_label_size() {
        let data = b"test";
        let nonce = "n";
        let domain = "d.com";

        // Very small label size
        let query = build_query_name(data, nonce, domain, 2);
        let (_, parsed_data) = parse_query_name(&query, domain).unwrap();
        assert_eq!(parsed_data, data);
    }

    #[test]
    fn test_binary_data_patterns() {
        let patterns: Vec<Vec<u8>> = vec![
            vec![0x00; 50],          // All zeros
            vec![0xFF; 50],          // All ones
            (0..50).collect(),       // Sequential
            vec![0x55; 50],          // Alternating bits
            vec![0xAA; 50],          // Alternating bits (inverted)
        ];

        for pattern in patterns {
            let encoded = encode_base32(&pattern);
            let decoded = decode_base32(&encoded).unwrap();
            assert_eq!(decoded, pattern);
        }
    }
}

// ---------------------------------------------------------------------------
// Chunked Payload Tests
// ---------------------------------------------------------------------------

mod chunked_payloads {
    use super::*;

    #[test]
    fn test_large_payload_chunking() {
        // Simulate a large task result being sent
        let large_data: Vec<u8> = (0..2048).map(|i| (i % 256) as u8).collect();
        let nonce = "session456";
        let domain = "c2.target.com";

        // Build query with standard label size
        let query = build_query_name(&large_data, nonce, domain, 63);

        // Verify it can be parsed back
        let (parsed_nonce, parsed_data) =
            parse_query_name(&query, domain).expect("parse should succeed");

        assert_eq!(parsed_nonce, nonce);
        assert_eq!(parsed_data, large_data);
    }

    #[test]
    fn test_chunk_boundaries() {
        // Test various data sizes that hit chunk boundaries
        let nonce = "n";
        let domain = "d.com";

        for size in [1, 5, 10, 63, 64, 100, 126, 127, 189, 190, 252, 253, 500] {
            let data: Vec<u8> = (0..size).map(|i| (i % 256) as u8).collect();
            let query = build_query_name(&data, nonce, domain, 63);
            let (_, parsed_data) = parse_query_name(&query, domain).unwrap();
            assert_eq!(parsed_data, data, "failed at size {}", size);
        }
    }

    #[test]
    fn test_consistent_chunking() {
        // Same data should produce same query
        let data = b"consistent chunking test data";
        let nonce = "fixed";
        let domain = "test.com";

        let query1 = build_query_name(data, nonce, domain, 63);
        let query2 = build_query_name(data, nonce, domain, 63);

        assert_eq!(query1, query2);
    }
}
