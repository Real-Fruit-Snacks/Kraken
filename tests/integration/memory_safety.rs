//! Memory safety tests — prevent DoS via malformed inputs.
//!
//! Following Sliver's envelope_reader_test.go pattern: craft frames that
//! declare enormous sizes or deeply-nested structures and verify the parser
//! rejects them without performing the implied allocation.
//!
//! Key invariant under test:
//!   `decode_with_length` must return an `Err` for any frame whose declared
//!   payload length exceeds the actual bytes supplied, **before** attempting
//!   to allocate a buffer of that declared size.

use protocol::{
    CheckIn, CheckInResponse, ImplantCommand, TaskResponse, Uuid,
    decode_with_length, encode_with_length,
};

// ---------------------------------------------------------------------------
// Shared constants
// ---------------------------------------------------------------------------

/// 64 MiB — a sane upper bound for any single protocol message.
/// Nothing in the Kraken protocol legitimately approaches this size; anything
/// larger is either a bug or an attempted amplification attack.
const MAX_ALLOWED_BYTES: usize = 64 * 1024 * 1024; // 64 MiB

// ---------------------------------------------------------------------------
// Helper: build a raw length-prefixed frame with an arbitrary declared length
// but only `body_bytes` of actual payload data.
// ---------------------------------------------------------------------------
fn crafted_frame(declared_len: u32, body_bytes: usize) -> Vec<u8> {
    let mut frame = Vec::with_capacity(4 + body_bytes);
    frame.extend_from_slice(&declared_len.to_be_bytes());
    // Fill body with innocuous zeroes — valid-ish protobuf filler.
    frame.extend(std::iter::repeat(0u8).take(body_bytes));
    frame
}

// ---------------------------------------------------------------------------
// Test 1: malformed frame with a huge declared size must fail fast
// ---------------------------------------------------------------------------

/// A frame that claims to carry ~8 GiB of payload but provides only 16 bytes
/// of actual data.  The decoder must detect the truncation and return an
/// error without attempting to allocate 8 GiB.
#[test]
fn test_malformed_frame_bounded_allocation() {
    // 0x0002_0000_0000 overflows u32; use u32::MAX (~4 GiB) as the ceiling.
    // In practice, declaring u32::MAX is sufficient to trigger the attack.
    let declared = u32::MAX; // ~4 GiB
    let frame = crafted_frame(declared, 16);

    let result: Result<(Uuid, usize), _> = decode_with_length(&frame);

    assert!(
        result.is_err(),
        "decoder must reject a frame whose declared length ({declared}) exceeds actual data"
    );

    let err = result.unwrap_err();
    let msg = format!("{err}");
    assert!(
        msg.contains("truncated") || msg.contains("too short") || msg.contains("decode error"),
        "error message should describe the truncation, got: {msg}"
    );
}

// ---------------------------------------------------------------------------
// Test 2: payloads exceeding MAX_ALLOWED_BYTES must be rejected
// ---------------------------------------------------------------------------

/// Verify that we can detect an oversized *declared* length before touching
/// any heap.  Even if the full bytes were present, a 64 MiB+ message should
/// be rejected at the framing layer.
///
/// This test encodes the expectation that callers validate the length prefix
/// against `MAX_ALLOWED_BYTES` before passing the frame to protobuf decode.
/// The helper below mirrors what a hardened `decode_with_length` wrapper would do.
#[test]
fn test_oversized_payload_rejected() {
    // Build a frame whose declared length is 1 byte over the ceiling.
    let oversized_declared = (MAX_ALLOWED_BYTES + 1) as u32;
    let frame = crafted_frame(oversized_declared, 0);

    // A policy-aware wrapper that enforces MAX_ALLOWED_BYTES before decode.
    let result = bounded_decode_with_length::<Uuid>(&frame, MAX_ALLOWED_BYTES);

    assert!(
        result.is_err(),
        "frames declaring more than {MAX_ALLOWED_BYTES} bytes must be rejected"
    );

    let err = result.unwrap_err();
    assert!(
        err.contains("exceeds") || err.contains("too large") || err.contains("limit"),
        "rejection message should explain the size limit, got: {err}"
    );
}

/// Length-prefix decoder with an explicit allocation ceiling.
///
/// Returns `Err(String)` if:
///   - the buffer is too short for the 4-byte length prefix, or
///   - the declared length exceeds `max_bytes`, or
///   - the actual payload is truncated, or
///   - protobuf decoding fails.
fn bounded_decode_with_length<M: prost::Message + Default>(
    bytes: &[u8],
    max_bytes: usize,
) -> Result<(M, usize), String> {
    if bytes.len() < 4 {
        return Err("buffer too short for length prefix".into());
    }
    let declared = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
    if declared > max_bytes {
        return Err(format!(
            "declared length {declared} exceeds limit of {max_bytes} bytes"
        ));
    }
    if bytes.len() < 4 + declared {
        return Err(format!(
            "payload truncated: expected {declared} bytes, got {}",
            bytes.len() - 4
        ));
    }
    M::decode(&bytes[4..4 + declared])
        .map(|msg| (msg, 4 + declared))
        .map_err(|e| format!("decode error: {e}"))
}

// ---------------------------------------------------------------------------
// Test 3: deeply nested message structures must not cause stack overflow
// ---------------------------------------------------------------------------

/// Build a `CheckInResponse` that carries `depth` layers of wrapping via
/// the `commands` list.  Each level adds an `ImplantCommand`, giving prost
/// something non-trivial to decode without actually requiring a recursive
/// message schema.
///
/// The goal is to confirm that parsing a message with a large number of
/// repeated fields (a common DoS vector) completes without panic or timeout.
#[test]
fn test_nested_message_depth_limit() {
    const DEPTH: usize = 1_000;

    // Build a CheckInResponse with DEPTH ImplantCommand entries.
    // Each SleepCommand carries a unique value so the compiler can't elide them.
    let commands: Vec<ImplantCommand> = (0u32..DEPTH as u32)
        .map(|i| ImplantCommand {
            command: Some(protocol::implant_command::Command::Sleep(
                protocol::SleepCommand {
                    duration_seconds: i,
                },
            )),
        })
        .collect();

    let response = CheckInResponse {
        tasks: vec![],
        new_checkin_interval: None,
        new_jitter_percent: None,
        commands,
    };

    // Encode then decode — must complete without stack overflow or panic.
    let encoded = encode_with_length(&response);
    let result: Result<(CheckInResponse, usize), _> = decode_with_length(&encoded);

    assert!(
        result.is_ok(),
        "deeply-nested (depth={DEPTH}) message should decode successfully: {:?}",
        result.err()
    );

    let (decoded, _) = result.unwrap();
    assert_eq!(
        decoded.commands.len(),
        DEPTH,
        "all {DEPTH} command entries must survive the encode/decode round-trip"
    );
}

// ---------------------------------------------------------------------------
// Test 4: many repeated TaskResponse entries (amplification vector)
// ---------------------------------------------------------------------------

/// A CheckIn carrying a very large number of TaskResponse entries should
/// either decode correctly or fail with a clear error — never panic or OOM.
#[test]
fn test_checkin_with_many_task_responses_survives() {
    const RESPONSE_COUNT: usize = 10_000;

    let task_responses: Vec<TaskResponse> = (0..RESPONSE_COUNT)
        .map(|_| TaskResponse {
            task_id: Some(Uuid { value: vec![0u8; 16] }),
            status: 0,
            result: None,
            completed_at: None,
        })
        .collect();

    let checkin = CheckIn {
        implant_id: Some(Uuid { value: vec![1u8; 16] }),
        local_time: None,
        task_responses,
        loaded_modules: vec![],
    };

    let encoded = encode_with_length(&checkin);

    // Must not panic; a size rejection is acceptable if MAX_ALLOWED_BYTES is enforced.
    let result_unbounded: Result<(CheckIn, usize), _> = decode_with_length(&encoded);
    // The unbounded decode should succeed (data is valid, just large).
    assert!(
        result_unbounded.is_ok(),
        "large-but-valid CheckIn must decode without error"
    );

    let (decoded, _) = result_unbounded.unwrap();
    assert_eq!(decoded.task_responses.len(), RESPONSE_COUNT);
}

// ---------------------------------------------------------------------------
// Test 5: empty / zero-length declared payload is handled gracefully
// ---------------------------------------------------------------------------

#[test]
fn test_zero_length_frame_decodes_to_default() {
    // A 4-byte length prefix of 0 with no body is valid protobuf (all-default message).
    let frame = crafted_frame(0, 0);
    let result: Result<(Uuid, usize), _> = decode_with_length(&frame);
    assert!(result.is_ok(), "zero-length frame must decode to default Uuid");
    let (decoded, consumed) = result.unwrap();
    assert_eq!(consumed, 4);
    assert_eq!(decoded.value, Vec::<u8>::new());
}
