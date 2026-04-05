//! Property-based tests for the protocol crate using proptest.

use proptest::prelude::*;

use crate::{
    decode, decode_with_length, encode, encode_with_length, Timestamp, Uuid,
};

// ---------------------------------------------------------------------------
// Strategies
// ---------------------------------------------------------------------------

fn arb_payload() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 0..65536)
}

fn arb_uuid_bytes() -> impl Strategy<Value = Vec<u8>> {
    // UUIDs are 16 bytes, but the field accepts any bytes length.
    prop::collection::vec(any::<u8>(), 0..=32)
}

fn arb_timestamp_millis() -> impl Strategy<Value = i64> {
    // Cover negative (before epoch), zero, and large positive values.
    prop_oneof![
        Just(0i64),
        (i64::MIN..=i64::MAX),
    ]
}

// ---------------------------------------------------------------------------
// Frame (length-prefixed) roundtrip tests
// ---------------------------------------------------------------------------

proptest! {
    /// Any `Uuid` payload survives encode → decode via bare protobuf.
    #[test]
    fn message_roundtrip(bytes in arb_uuid_bytes()) {
        let msg = Uuid { value: bytes.clone() };
        let encoded = encode(&msg);
        let decoded: Uuid = decode(&encoded).expect("decode should succeed");
        prop_assert_eq!(decoded.value, bytes);
    }

    /// encode_with_length / decode_with_length roundtrip preserves the payload.
    #[test]
    fn frame_encode_decode_roundtrip(bytes in arb_uuid_bytes()) {
        let msg = Uuid { value: bytes.clone() };
        let framed = encode_with_length(&msg);
        let (decoded, _consumed): (Uuid, _) =
            decode_with_length(&framed).expect("frame decode should succeed");
        prop_assert_eq!(decoded.value, bytes);
    }

    /// The 4-byte length prefix in an encoded frame equals the number of
    /// payload bytes that follow it.
    #[test]
    fn frame_length_matches(bytes in arb_uuid_bytes()) {
        let msg = Uuid { value: bytes };
        let framed = encode_with_length(&msg);

        prop_assert!(framed.len() >= 4, "framed length must be at least 4 bytes");

        let declared_len =
            u32::from_be_bytes([framed[0], framed[1], framed[2], framed[3]]) as usize;

        prop_assert_eq!(
            declared_len,
            framed.len() - 4,
            "declared length {} does not match actual payload length {}",
            declared_len,
            framed.len() - 4,
        );
    }

    /// `decode_with_length` returns the correct byte-consumption count so that
    /// a second message starting immediately after can still be parsed.
    #[test]
    fn envelope_roundtrip(
        bytes1 in arb_uuid_bytes(),
        millis in arb_timestamp_millis(),
    ) {
        // Wrap a Uuid followed by a Timestamp in a single buffer.
        let uuid_msg = Uuid { value: bytes1.clone() };
        let ts_msg = Timestamp { millis };

        let mut buf = encode_with_length(&uuid_msg);
        buf.extend(encode_with_length(&ts_msg));

        // Decode first envelope.
        let (decoded_uuid, consumed): (Uuid, _) =
            decode_with_length(&buf).expect("first frame decode should succeed");
        prop_assert_eq!(decoded_uuid.value, bytes1);

        // Decode second envelope starting at the consumed offset.
        let (decoded_ts, _): (Timestamp, _) =
            decode_with_length(&buf[consumed..]).expect("second frame decode should succeed");
        prop_assert_eq!(decoded_ts.millis, millis);
    }

    /// Arbitrary raw payloads survive encode_with_length / decode_with_length
    /// when wrapped in a Uuid (which accepts any bytes value field).
    #[test]
    fn frame_roundtrip(payload in arb_payload()) {
        let msg = Uuid { value: payload.clone() };
        let framed = encode_with_length(&msg);
        let (decoded, consumed): (Uuid, _) =
            decode_with_length(&framed).expect("decode should succeed");
        prop_assert_eq!(decoded.value, payload);
        prop_assert_eq!(consumed, framed.len());
    }

    /// Task message roundtrip - verifies arbitrary task data survives encode/decode.
    #[test]
    fn task_roundtrip(
        task_type in "[a-z_]{1,32}",
        task_data in arb_payload(),
    ) {
        use crate::Task;
        let task = Task {
            task_id: Some(Uuid { value: vec![0u8; 16] }),
            task_type,
            task_data: task_data.clone(),
            issued_at: None,
            operator_id: None,
        };
        let encoded = encode(&task);
        let decoded: Task = decode(&encoded).expect("task decode should succeed");
        prop_assert_eq!(decoded.task_data, task_data);
    }

    /// CheckIn message roundtrip - verifies module list survives encode/decode.
    #[test]
    fn checkin_roundtrip(
        modules in prop::collection::vec("[a-z-]{1,20}", 0..10),
    ) {
        use crate::CheckIn;
        let checkin = CheckIn {
            implant_id: Some(Uuid { value: vec![0u8; 16] }),
            local_time: Some(Timestamp { millis: 1234567890 }),
            task_responses: vec![],
            loaded_modules: modules.clone(),
        };
        let encoded = encode(&checkin);
        let decoded: CheckIn = decode(&encoded).expect("checkin decode should succeed");
        prop_assert_eq!(decoded.loaded_modules, modules);
    }

    /// TaskResponse with arbitrary result data survives roundtrip.
    #[test]
    fn task_response_roundtrip(result_data in arb_payload()) {
        use crate::{TaskResponse, TaskSuccess, TaskStatus, task_response};
        let response = TaskResponse {
            task_id: Some(Uuid { value: vec![0u8; 16] }),
            status: TaskStatus::Completed as i32,
            completed_at: Some(Timestamp { millis: 9876543210 }),
            result: Some(task_response::Result::Success(TaskSuccess {
                result_data: result_data.clone(),
            })),
        };
        let encoded = encode(&response);
        let decoded: TaskResponse = decode(&encoded).expect("response decode should succeed");
        if let Some(task_response::Result::Success(s)) = decoded.result {
            prop_assert_eq!(s.result_data, result_data);
        } else {
            prop_assert!(false, "expected Success variant");
        }
    }

    /// ShellResult with arbitrary output survives roundtrip.
    #[test]
    fn shell_result_roundtrip(
        stdout in "[\\x00-\\x7F]{0,100}",
        stderr in "[\\x00-\\x7F]{0,100}",
        exit_code in any::<i32>(),
        duration_ms in any::<u64>(),
    ) {
        use crate::ShellResult;
        let result = ShellResult {
            stdout: stdout.clone(),
            stderr: stderr.clone(),
            exit_code,
            duration_ms,
        };
        let encoded = encode(&result);
        let decoded: ShellResult = decode(&encoded).expect("shell result decode should succeed");
        prop_assert_eq!(decoded.stdout, stdout);
        prop_assert_eq!(decoded.stderr, stderr);
        prop_assert_eq!(decoded.exit_code, exit_code);
        prop_assert_eq!(decoded.duration_ms, duration_ms);
    }
}
