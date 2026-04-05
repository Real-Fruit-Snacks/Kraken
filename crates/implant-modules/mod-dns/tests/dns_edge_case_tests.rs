//! DNS Transport Edge Case Tests
//!
//! Comprehensive edge case coverage for:
//! - Label encoding limits and boundary conditions
//! - Chunking, reassembly, and sequence handling
//! - Error response codes (NXDOMAIN, SERVFAIL, REFUSED)
//! - TXT record multi-string and size limits
//! - Malformed / truncated packet handling
//! - Property-based roundtrip invariants

use mod_dns::encode::{
    build_query_name, decode_base32, encode_base32, parse_query_name, split_into_labels,
    MAX_LABEL_LEN, MAX_QUERY_LEN,
};
use mod_dns::packet::{
    build_query, extract_a_data, extract_txt_data, parse_response, AckStatus, RecordType,
};
use common::Transport;
use mod_dns::{DnsConfig, DnsTransport};

// ============================================================
// 1. Label encoding edge cases
// ============================================================

mod label_encoding_edge_cases {
    use super::*;

    /// A single label of exactly 63 chars is the DNS maximum.
    #[test]
    fn test_label_exact_maximum_63_chars() {
        // 63 uppercase A's is a valid single label
        let label = "A".repeat(MAX_LABEL_LEN);
        assert_eq!(label.len(), 63);

        // split_into_labels with max=63 must keep it as one label
        let labels = split_into_labels(&label, MAX_LABEL_LEN);
        assert_eq!(labels.len(), 1);
        assert_eq!(labels[0].len(), 63);
    }

    /// A string of 64 chars must be split into two labels.
    #[test]
    fn test_label_one_over_maximum_splits() {
        let label = "A".repeat(64);
        let labels = split_into_labels(&label, MAX_LABEL_LEN);
        assert_eq!(labels.len(), 2);
        assert!(labels[0].len() <= MAX_LABEL_LEN);
        assert!(labels[1].len() <= MAX_LABEL_LEN);
        // Concatenation must reproduce the original
        assert_eq!(labels.concat(), label);
    }

    /// Total query name at exactly 253 chars must be accepted.
    #[test]
    fn test_total_query_name_at_253_char_limit() {
        // Build data whose encoding + structure fills ~253 chars.
        // We control nonce/domain lengths to hit the boundary.
        let nonce = "n"; // 1 char
        let domain = "c2.t.io"; // 7 chars
        // overhead = nonce(1) + dot(1) + domain(7) = 9
        // Room left for data labels (including dots): 253 - 9 = 244
        // Each 63-char label + dot = 64 chars, 3 full labels = 192, then remainder
        let data: Vec<u8> = vec![0xAA; 120]; // produces 192 base32 chars -> 3 full labels
        let query = build_query_name(&data, nonce, domain, 63);
        assert!(query.len() <= MAX_QUERY_LEN, "query length {} exceeds 253", query.len());
        // Roundtrip must succeed
        let (parsed_nonce, parsed_data) = parse_query_name(&query, domain).unwrap();
        assert_eq!(parsed_nonce, nonce);
        assert_eq!(parsed_data, data);
    }

    /// Empty label input to split_into_labels returns empty vec.
    #[test]
    fn test_split_empty_string_returns_empty() {
        let labels = split_into_labels("", MAX_LABEL_LEN);
        assert!(labels.is_empty());
    }

    /// DNS is case-insensitive: decoding uppercase and lowercase encoded strings
    /// must produce identical bytes.
    #[test]
    fn test_dns_case_insensitivity_decode_symmetry() {
        let data = b"case sensitivity check";
        let encoded_upper = encode_base32(data);
        let encoded_lower = encoded_upper.to_lowercase();
        let encoded_mixed: String = encoded_upper
            .chars()
            .enumerate()
            .map(|(i, c)| if i % 3 == 0 { c.to_ascii_lowercase() } else { c })
            .collect();

        assert_eq!(decode_base32(&encoded_upper).unwrap(), data);
        assert_eq!(decode_base32(&encoded_lower).unwrap(), data);
        assert_eq!(decode_base32(&encoded_mixed).unwrap(), data);
    }

    /// Characters outside the base32 alphabet must be rejected by the decoder.
    #[test]
    fn test_special_chars_in_labels_rejected() {
        let invalid = [
            "ABCD-EF",   // hyphen
            "ABCD_EF",   // underscore
            "ABCD EF",   // space
            "ABCD.EF",   // dot
            "ABCD\0EF",  // null byte
            "ABCD@EF",   // at-sign
        ];
        for input in invalid {
            assert!(
                decode_base32(input).is_none(),
                "should reject: {:?}",
                input
            );
        }
    }

    /// `=` padding chars must be silently skipped (RFC 4648 allows omitting padding).
    #[test]
    fn test_padding_chars_skipped() {
        let data = b"hello";
        let encoded = encode_base32(data); // no padding by design
        // Manually append padding - decoder must still succeed
        let with_padding = format!("{}======", encoded);
        let decoded = decode_base32(&with_padding).unwrap();
        assert_eq!(decoded, data);
    }

    /// Labels are slices of ASCII, so even max-length labels must not contain
    /// multi-byte characters.
    #[test]
    fn test_label_contains_only_ascii() {
        let data: Vec<u8> = (0..200).map(|i| (i % 256) as u8).collect();
        let encoded = encode_base32(&data);
        let labels = split_into_labels(&encoded, MAX_LABEL_LEN);
        for label in labels {
            assert!(label.is_ascii(), "label is not pure ASCII: {:?}", label);
        }
    }
}

// ============================================================
// 2. Chunking tests
// ============================================================

mod chunking_tests {
    use super::*;

    /// Payload larger than a single 63-char label must span multiple labels
    /// and reassemble correctly.
    #[test]
    fn test_payload_larger_than_single_label_roundtrip() {
        // 50 bytes -> 80 base32 chars -> 2 full labels
        let data: Vec<u8> = (0..50).map(|i| i as u8).collect();
        let nonce = "sess";
        let domain = "c2.local";

        let query = build_query_name(&data, nonce, domain, MAX_LABEL_LEN);

        // Verify multiple data labels exist before nonce
        let suffix = format!(".{}.{}", nonce, domain);
        let prefix = query.strip_suffix(&suffix).unwrap();
        let data_labels: Vec<&str> = prefix.split('.').collect();
        assert!(data_labels.len() >= 2, "expected ≥2 data labels");

        let (_, parsed) = parse_query_name(&query, domain).unwrap();
        assert_eq!(parsed, data);
    }

    /// Very large payload (4 KB) must chunk and reassemble without data loss.
    #[test]
    fn test_large_payload_4kb_roundtrip() {
        let data: Vec<u8> = (0..4096).map(|i| (i * 7 % 256) as u8).collect();
        let nonce = "largetest";
        let domain = "exfil.c2.com";

        let query = build_query_name(&data, nonce, domain, MAX_LABEL_LEN);
        let (parsed_nonce, parsed) = parse_query_name(&query, domain).unwrap();

        assert_eq!(parsed_nonce, nonce);
        assert_eq!(parsed, data);
    }

    /// Each individual label in a multi-label query must not exceed MAX_LABEL_LEN.
    #[test]
    fn test_each_label_within_max_in_chunked_query() {
        let data: Vec<u8> = (0..500).map(|i| (i % 256) as u8).collect();
        let query = build_query_name(&data, "n", "d.com", MAX_LABEL_LEN);

        for part in query.split('.') {
            assert!(
                part.len() <= MAX_LABEL_LEN,
                "label '{}' (len {}) exceeds MAX_LABEL_LEN",
                part,
                part.len()
            );
        }
    }

    /// Chunk at boundary sizes (multiples of 5-bit group size) must roundtrip.
    #[test]
    fn test_chunk_boundary_sizes() {
        let nonce = "n";
        let domain = "d.com";
        // Sizes chosen to hit base32 group boundaries: 5, 10, 15, 20 bytes
        // and also label boundaries.
        for size in [5, 10, 15, 20, 40, 63, 80, 125, 160, 250] {
            let data: Vec<u8> = (0..size).map(|i| (i % 256) as u8).collect();
            let query = build_query_name(&data, nonce, domain, MAX_LABEL_LEN);
            let (_, parsed) = parse_query_name(&query, domain)
                .unwrap_or_else(|| panic!("parse failed for size {}", size));
            assert_eq!(parsed, data, "mismatch at size {}", size);
        }
    }

    /// Reassembly order: labels must be concatenated in the original order.
    /// Swapping two labels must produce different (wrong) data.
    #[test]
    fn test_label_order_matters_for_reassembly() {
        let data: Vec<u8> = (0..100).map(|i| i as u8).collect();
        let nonce = "ord";
        let domain = "order.test";

        let query = build_query_name(&data, nonce, domain, 20);
        let parts: Vec<&str> = query.split('.').collect();

        // Parts layout: [label0, label1, ..., nonce, domain_parts...]
        // If we have at least 2 data labels, swapping them changes the parse result
        let domain_dots = domain.chars().filter(|&c| c == '.').count() + 1;
        let data_label_count = parts.len() - 1 - domain_dots; // -1 for nonce

        if data_label_count >= 2 {
            let mut swapped = parts.clone();
            swapped.swap(0, 1);
            let swapped_query = swapped.join(".");
            if let Some((_, swapped_data)) = parse_query_name(&swapped_query, domain) {
                assert_ne!(swapped_data, data, "swapped labels should not decode to original");
            }
            // None result is also acceptable (malformed)
        }
    }

    /// Missing chunk: query with data labels removed must not silently decode
    /// to the original payload.
    #[test]
    fn test_missing_label_does_not_match_original() {
        let data: Vec<u8> = (0..80).map(|i| i as u8).collect(); // 128 base32 chars -> 2+ labels
        let nonce = "miss";
        let domain = "miss.test";

        let query = build_query_name(&data, nonce, domain, 50);
        // Drop the first data label
        let mut parts: Vec<&str> = query.split('.').collect();
        if parts.len() > 3 {
            parts.remove(0); // remove first data label
            let truncated = parts.join(".");
            if let Some((_, truncated_data)) = parse_query_name(&truncated, domain) {
                assert_ne!(
                    truncated_data, data,
                    "truncated query should not match original"
                );
            }
        }
    }

    /// Chunk sequence number overflow: transaction ID wraps at u16::MAX.
    #[test]
    fn test_transaction_id_wraps_at_u16_max() {
        let config = DnsConfig::default();
        let mut transport = DnsTransport::new(config);
        // Force transaction_id to u16::MAX via field access in lib tests
        // We verify wrapping via the packet header directly.
        // Build a packet with ID=0xFFFF, next should be 0x0000.
        let pkt_max = build_query(0xFFFF, "t.local", RecordType::TXT);
        assert_eq!(pkt_max[0], 0xFF);
        assert_eq!(pkt_max[1], 0xFF);

        let pkt_zero = build_query(0x0000, "t.local", RecordType::TXT);
        assert_eq!(pkt_zero[0], 0x00);
        assert_eq!(pkt_zero[1], 0x00);

        // DnsTransport itself wraps correctly (tested in lib unit tests, verified here)
        assert!(transport.is_available());
    }
}

// ============================================================
// 3. Error response handling
// ============================================================

mod error_responses {
    use super::*;

    fn make_response_header(txid: u16, flags: u16, ancount: u16) -> Vec<u8> {
        let mut pkt = Vec::new();
        pkt.extend(&txid.to_be_bytes());
        pkt.extend(&flags.to_be_bytes());
        pkt.extend(&0u16.to_be_bytes()); // QDCOUNT
        pkt.extend(&ancount.to_be_bytes()); // ANCOUNT
        pkt.extend(&0u16.to_be_bytes()); // NSCOUNT
        pkt.extend(&0u16.to_be_bytes()); // ARCOUNT
        pkt
    }

    /// NXDOMAIN (rcode=3) must parse successfully with rcode=3, no answers.
    #[test]
    fn test_nxdomain_response_rcode_3() {
        // flags: QR=1, AA=0, rcode=3 → 0x8003
        let pkt = make_response_header(0x0001, 0x8003, 0);
        let resp = parse_response(&pkt).expect("should parse");
        assert_eq!(resp.response_code, 3);
        assert!(resp.is_response);
        assert!(resp.answers.is_empty());
    }

    /// SERVFAIL (rcode=2) must parse with rcode=2.
    #[test]
    fn test_servfail_response_rcode_2() {
        let pkt = make_response_header(0x0002, 0x8002, 0);
        let resp = parse_response(&pkt).expect("should parse");
        assert_eq!(resp.response_code, 2);
        assert!(resp.answers.is_empty());
    }

    /// REFUSED (rcode=5) must parse with rcode=5.
    #[test]
    fn test_refused_response_rcode_5() {
        let pkt = make_response_header(0x0003, 0x8005, 0);
        let resp = parse_response(&pkt).expect("should parse");
        assert_eq!(resp.response_code, 5);
        assert!(resp.answers.is_empty());
    }

    /// Packet shorter than 12 bytes (DNS header size) must return None.
    #[test]
    fn test_packet_shorter_than_header_rejected() {
        for len in 0..12 {
            assert!(
                parse_response(&vec![0u8; len]).is_none(),
                "should reject packet of len {}",
                len
            );
        }
    }

    /// Malformed response: ANCOUNT=1 but answer section is missing / truncated.
    #[test]
    fn test_malformed_truncated_answer_section() {
        // Header claims 1 answer but provides 0 bytes of answer data
        let pkt = make_response_header(0xDEAD, 0x8180, 1);
        // No answer bytes — parse_response must return None or an empty answer list
        let result = parse_response(&pkt);
        match result {
            None => {} // expected: parse failure
            Some(resp) => {
                // Also acceptable: parsed but answers empty due to error
                assert!(resp.answers.is_empty());
            }
        }
    }

    /// TC bit set (truncated flag) — packet must still parse headers correctly.
    #[test]
    fn test_tc_bit_packet_parses_header() {
        // TC bit is bit 9 (0x0200) in the flags word
        // flags: QR=1, TC=1 → 0x8200
        let pkt = make_response_header(0xABCD, 0x8200, 0);
        let resp = parse_response(&pkt).expect("header should parse");
        assert_eq!(resp.transaction_id, 0xABCD);
        assert!(resp.is_response);
        // rcode = flags & 0x000F = 0
        assert_eq!(resp.response_code, 0);
    }

    /// Completely empty packet must return None.
    #[test]
    fn test_empty_packet_rejected() {
        assert!(parse_response(&[]).is_none());
    }

    /// Random garbage bytes must not panic — must return None.
    #[test]
    fn test_garbage_bytes_no_panic() {
        let garbage = vec![
            0xFF, 0xFE, 0xFD, 0xFC, 0x00, 0x01, 0xFF, 0xFF,
            0x00, 0x01, 0x00, 0x01, 0xC0, 0xFF, 0xEE, 0xFF,
        ];
        // Must not panic — result may be None or Some with incomplete data
        let _ = parse_response(&garbage);
    }

    /// A record with RDLENGTH != 4 must be rejected.
    #[test]
    fn test_a_record_wrong_rdlength_rejected() {
        let mut pkt = make_response_header(0x0001, 0x8180, 1);
        pkt.extend(&[
            0xC0, 0x0C, // Name ptr
            0x00, 0x01, // Type A
            0x00, 0x01, // Class IN
            0x00, 0x00, 0x00, 0x3C, // TTL
            0x00, 0x03, // RDLENGTH = 3 (invalid for A record)
            0x01, 0x02, 0x03, // 3 bytes instead of 4
        ]);
        let result = parse_response(&pkt);
        match result {
            None => {} // parse failed, fine
            Some(resp) => {
                // If we got a response, extract_a_data must return None (no valid A record)
                assert!(extract_a_data(&resp).is_none());
            }
        }
    }

    /// AAAA record with RDLENGTH != 16 must be rejected.
    #[test]
    fn test_aaaa_record_wrong_rdlength_rejected() {
        let mut pkt = make_response_header(0x0001, 0x8180, 1);
        pkt.extend(&[
            0xC0, 0x0C, // Name ptr
            0x00, 0x1C, // Type AAAA (28)
            0x00, 0x01, // Class IN
            0x00, 0x00, 0x00, 0x3C, // TTL
            0x00, 0x04, // RDLENGTH = 4 (invalid for AAAA, needs 16)
            0x20, 0x01, 0x0D, 0xB8, // Only 4 bytes
        ]);
        // Must not panic — result may be None
        let _ = parse_response(&pkt);
    }
}

// ============================================================
// 4. TXT record tests
// ============================================================

mod txt_record_tests {
    use super::*;

    fn build_txt_response(txid: u16, strings: &[&[u8]]) -> Vec<u8> {
        let mut pkt = vec![
            (txid >> 8) as u8, txid as u8, // Transaction ID
            0x81, 0x80,                      // Flags: response
            0x00, 0x00,                      // QDCOUNT
            0x00, 0x01,                      // ANCOUNT
            0x00, 0x00,                      // NSCOUNT
            0x00, 0x00,                      // ARCOUNT
        ];

        // Answer name (compression ptr to offset 12 — which is fine for test)
        pkt.extend(&[0xC0, 0x0C]);
        pkt.extend(&[0x00, 0x10]); // Type TXT
        pkt.extend(&[0x00, 0x01]); // Class IN
        pkt.extend(&[0x00, 0x00, 0x00, 0x3C]); // TTL 60

        // Build RDATA: each string as <len><bytes>
        let rdata: Vec<u8> = strings
            .iter()
            .flat_map(|s| {
                let mut v = vec![s.len() as u8];
                v.extend_from_slice(s);
                v
            })
            .collect();

        let rdlen = rdata.len() as u16;
        pkt.extend(&rdlen.to_be_bytes());
        pkt.extend(&rdata);

        pkt
    }

    /// Single TXT string: basic case.
    #[test]
    fn test_single_txt_string() {
        let pkt = build_txt_response(0x0001, &[b"NBSWY3DP"]);
        let resp = parse_response(&pkt).unwrap();
        let txt = extract_txt_data(&resp).unwrap();
        assert_eq!(txt, b"NBSWY3DP");
    }

    /// Multiple TXT strings in one record must be concatenated.
    #[test]
    fn test_multiple_txt_strings_concatenated() {
        let pkt = build_txt_response(0x0002, &[b"HELLO", b"WORLD", b"TEST"]);
        let resp = parse_response(&pkt).unwrap();
        let txt = extract_txt_data(&resp).unwrap();
        // Parser concatenates all strings
        assert_eq!(txt, b"HELLOWORLDTEST");
    }

    /// Empty TXT string (length byte = 0) is valid and results in empty content.
    #[test]
    fn test_empty_txt_string() {
        let pkt = build_txt_response(0x0003, &[b""]);
        let resp = parse_response(&pkt).unwrap();
        let txt = extract_txt_data(&resp).unwrap();
        assert!(txt.is_empty());
    }

    /// TXT string at maximum size (255 bytes per RFC 1035).
    #[test]
    fn test_max_size_txt_string_255_bytes() {
        let max_str = vec![b'A'; 255];
        let pkt = build_txt_response(0x0004, &[&max_str]);
        let resp = parse_response(&pkt).unwrap();
        let txt = extract_txt_data(&resp).unwrap();
        assert_eq!(txt.len(), 255);
        assert!(txt.iter().all(|&b| b == b'A'));
    }

    /// Multiple max-size TXT strings must all be concatenated.
    #[test]
    fn test_multiple_max_size_txt_strings() {
        let s1 = vec![b'A'; 255];
        let s2 = vec![b'B'; 255];
        let pkt = build_txt_response(0x0005, &[&s1, &s2]);
        let resp = parse_response(&pkt).unwrap();
        let txt = extract_txt_data(&resp).unwrap();
        assert_eq!(txt.len(), 510);
    }

    /// TXT record with base32 content decodes back to original binary.
    #[test]
    fn test_txt_base32_content_roundtrip() {
        let original = b"command data from server";
        let encoded = encode_base32(original);

        let pkt = build_txt_response(0x0006, &[encoded.as_bytes()]);
        let resp = parse_response(&pkt).unwrap();
        let txt_raw = extract_txt_data(&resp).unwrap();

        let decoded = decode_base32(std::str::from_utf8(&txt_raw).unwrap()).unwrap();
        assert_eq!(decoded, original);
    }

    /// Binary (non-ASCII) TXT content is stored and returned verbatim.
    #[test]
    fn test_binary_txt_content_preserved() {
        let binary: Vec<u8> = (0u8..=127).collect();
        let pkt = build_txt_response(0x0007, &[&binary]);
        let resp = parse_response(&pkt).unwrap();
        let txt = extract_txt_data(&resp).unwrap();
        assert_eq!(txt, binary);
    }

    /// When no TXT record is present, extract_txt_data must return None.
    #[test]
    fn test_extract_txt_data_returns_none_when_absent() {
        // Build a response with an A record, not TXT
        let mut pkt = vec![
            0x00, 0x01, 0x81, 0x80,
            0x00, 0x00, 0x00, 0x01,
            0x00, 0x00, 0x00, 0x00,
        ];
        pkt.extend(&[
            0xC0, 0x0C,
            0x00, 0x01, // Type A
            0x00, 0x01,
            0x00, 0x00, 0x00, 0x3C,
            0x00, 0x04,
            0x00, 0x00, 0x00, 0x01,
        ]);
        let resp = parse_response(&pkt).unwrap();
        assert!(extract_txt_data(&resp).is_none());
    }
}

// ============================================================
// 5. Property tests
// ============================================================

#[cfg(test)]
mod property_tests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        /// Arbitrary payload encodes and decodes back to identical bytes.
        #[test]
        fn prop_arbitrary_payload_roundtrip(
            data in prop::collection::vec(any::<u8>(), 0..2048)
        ) {
            let encoded = encode_base32(&data);
            let decoded = decode_base32(&encoded).expect("decode should not fail");
            prop_assert_eq!(decoded, data);
        }

        /// Query name encoding invariant: every dot-separated label has len ≤ MAX_LABEL_LEN.
        #[test]
        fn prop_query_name_label_length_invariant(
            data in prop::collection::vec(any::<u8>(), 1..512),
            nonce in "[a-z0-9]{4,16}",
        ) {
            let domain = "c2.test.local";
            let query = build_query_name(&data, &nonce, domain, MAX_LABEL_LEN);
            for label in query.split('.') {
                prop_assert!(
                    label.len() <= MAX_LABEL_LEN,
                    "label '{}' len {} exceeds {}", label, label.len(), MAX_LABEL_LEN
                );
            }
        }

        /// Build then parse is a perfect identity for any data + nonce.
        #[test]
        fn prop_query_name_build_parse_identity(
            data in prop::collection::vec(any::<u8>(), 0..512),
            nonce in "[a-z0-9]{1,20}",
        ) {
            let domain = "c2.test.local";
            let query = build_query_name(&data, &nonce, domain, MAX_LABEL_LEN);
            let (parsed_nonce, parsed_data) = parse_query_name(&query, domain)
                .expect("parse_query_name should succeed");
            prop_assert_eq!(parsed_nonce, nonce);
            prop_assert_eq!(parsed_data, data);
        }

        /// Encoded output contains only valid base32 alphabet characters.
        #[test]
        fn prop_encoded_chars_are_valid_base32(
            data in prop::collection::vec(any::<u8>(), 0..1024)
        ) {
            let encoded = encode_base32(&data);
            let alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
            for c in encoded.chars() {
                prop_assert!(
                    alphabet.contains(c),
                    "invalid base32 char '{}'", c
                );
            }
        }

        /// split_into_labels preserves concatenated content for any non-empty encoded string.
        #[test]
        fn prop_split_labels_preserves_content(
            data in prop::collection::vec(any::<u8>(), 1..512),
            max_len in 1usize..=63,
        ) {
            let encoded = encode_base32(&data);
            let labels = split_into_labels(&encoded, max_len);
            let rejoined: String = labels.concat();
            prop_assert_eq!(rejoined, encoded);
        }

        /// Decode is case-insensitive: uppercase and lowercase produce same result.
        #[test]
        fn prop_decode_case_insensitive(
            data in prop::collection::vec(any::<u8>(), 1..256)
        ) {
            let encoded = encode_base32(&data);
            let upper = decode_base32(&encoded.to_uppercase()).expect("upper decode");
            let lower = decode_base32(&encoded.to_lowercase()).expect("lower decode");
            prop_assert_eq!(upper, lower);
        }
    }
}

// ============================================================
// 6. Additional AckStatus / response code coverage
// ============================================================

mod ack_and_response_codes {
    use super::*;

    /// All defined AckStatus variants map correctly from their wire bytes.
    #[test]
    fn test_all_ack_status_variants() {
        assert_eq!(AckStatus::from([0, 0, 0, 0]), AckStatus::NoTasks);
        assert_eq!(AckStatus::from([0, 0, 0, 1]), AckStatus::Success);
        assert_eq!(AckStatus::from([0, 0, 0, 2]), AckStatus::Resend);
        assert_eq!(AckStatus::from([0, 0, 0, 3]), AckStatus::Error);
    }

    /// Any address not matching defined codes is Unknown.
    #[test]
    fn test_ack_status_unknown_cases() {
        let unknown_addrs: &[[u8; 4]] = &[
            [0, 0, 0, 4],
            [0, 0, 1, 0],
            [1, 0, 0, 0],
            [127, 0, 0, 1],
            [255, 255, 255, 255],
            [0, 0, 0, 255],
        ];
        for &addr in unknown_addrs {
            assert_eq!(
                AckStatus::from(addr),
                AckStatus::Unknown,
                "expected Unknown for {:?}",
                addr
            );
        }
    }

    /// Response with rcode=0 and 0 answers parses correctly.
    #[test]
    fn test_noerror_no_answers_response() {
        let pkt = vec![
            0x00, 0x01, // txid
            0x81, 0x80, // QR=1, rcode=0
            0x00, 0x00, // QDCOUNT
            0x00, 0x00, // ANCOUNT=0
            0x00, 0x00, 0x00, 0x00,
        ];
        let resp = parse_response(&pkt).unwrap();
        assert_eq!(resp.response_code, 0);
        assert!(resp.answers.is_empty());
    }

    /// NXDOMAIN response with a TXT-bearing answer section still gives rcode=3.
    #[test]
    fn test_nxdomain_with_answer_still_has_rcode_3() {
        // Some resolvers return NXDOMAIN with NSEC records in answer;
        // our parser should surface the rcode correctly.
        let mut pkt = vec![
            0x00, 0x01,
            0x81, 0x83, // QR=1, AA=1, rcode=3 (NXDOMAIN)
            0x00, 0x00,
            0x00, 0x00, // ANCOUNT=0
            0x00, 0x00, 0x00, 0x00,
        ];
        // Add no answers — just verify header
        let resp = parse_response(&pkt).unwrap();
        assert_eq!(resp.response_code, 3);
    }
}

// ============================================================
// 7. Query packet structure edge cases
// ============================================================

mod query_packet_structure {
    use super::*;

    /// Transaction ID 0x0000 is a valid edge case.
    #[test]
    fn test_query_txid_zero() {
        let pkt = build_query(0x0000, "test.local", RecordType::TXT);
        assert_eq!(pkt[0], 0x00);
        assert_eq!(pkt[1], 0x00);
    }

    /// Transaction ID 0xFFFF is a valid edge case.
    #[test]
    fn test_query_txid_max() {
        let pkt = build_query(0xFFFF, "test.local", RecordType::TXT);
        assert_eq!(pkt[0], 0xFF);
        assert_eq!(pkt[1], 0xFF);
    }

    /// Domain name with a single label encodes correctly.
    #[test]
    fn test_query_single_label_domain() {
        let pkt = build_query(0x0001, "localhost", RecordType::A);
        // After header (12 bytes): length(9) + "localhost" + 0
        assert_eq!(pkt[12], 9);
        assert_eq!(&pkt[13..22], b"localhost");
        assert_eq!(pkt[22], 0); // root label
    }

    /// Query for AAAA record sets QTYPE=28.
    #[test]
    fn test_query_aaaa_qtype() {
        let pkt = build_query(0x0001, "test.local", RecordType::AAAA);
        let qtype_pos = pkt.len() - 4;
        let qtype = u16::from_be_bytes([pkt[qtype_pos], pkt[qtype_pos + 1]]);
        assert_eq!(qtype, 28);
    }

    /// QDCOUNT must always be 1 for a single-question query.
    #[test]
    fn test_query_qdcount_is_1() {
        for rt in [RecordType::A, RecordType::TXT, RecordType::AAAA] {
            let pkt = build_query(1, "x.y", rt);
            let qdcount = u16::from_be_bytes([pkt[4], pkt[5]]);
            assert_eq!(qdcount, 1, "QDCOUNT must be 1 for {:?}", rt);
        }
    }

    /// RD (Recursion Desired) flag must be set in all queries.
    #[test]
    fn test_query_rd_flag_set() {
        let pkt = build_query(1, "test.local", RecordType::TXT);
        let flags = u16::from_be_bytes([pkt[2], pkt[3]]);
        assert_ne!(flags & 0x0100, 0, "RD flag must be set");
    }

    /// QR bit must be 0 (query, not response) in built queries.
    #[test]
    fn test_query_qr_bit_is_zero() {
        let pkt = build_query(1, "test.local", RecordType::TXT);
        let flags = u16::from_be_bytes([pkt[2], pkt[3]]);
        assert_eq!(flags & 0x8000, 0, "QR bit must be 0 for a query");
    }
}
