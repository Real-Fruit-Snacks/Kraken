#![no_main]
//! Structure-aware fuzz target for task sequences
//!
//! Tests that arbitrary sequences of well-formed operations
//! don't cause panics or undefined behavior in the protocol layer.

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

/// A structured operation that can be performed on the protocol layer.
/// Using Arbitrary derive enables structure-aware fuzzing.
#[derive(Arbitrary, Debug, Clone)]
enum ProtocolOperation {
    /// Encode a task with arbitrary data
    EncodeTask {
        task_type: TaskType,
        data_len: u8,
    },
    /// Decode raw bytes as a protocol frame
    DecodeFrame {
        len_prefix: u32,
        payload_len: u8,
    },
    /// Encode then decode roundtrip
    Roundtrip {
        task_type: TaskType,
        data_len: u8,
    },
}

/// Task types that can be generated
#[derive(Arbitrary, Debug, Clone, Copy)]
enum TaskType {
    Shell,
    FileList,
    FileRead,
    Sleep,
    Module,
}

impl TaskType {
    fn as_str(&self) -> &'static str {
        match self {
            TaskType::Shell => "shell",
            TaskType::FileList => "file_list",
            TaskType::FileRead => "file_read",
            TaskType::Sleep => "sleep",
            TaskType::Module => "module",
        }
    }
}

fuzz_target!(|ops: Vec<ProtocolOperation>| {
    use protocol::{encode, encode_with_length, decode_with_length, Task, Uuid};

    for op in ops.iter().take(100) { // Limit iterations per input
        match op {
            ProtocolOperation::EncodeTask { task_type, data_len } => {
                let task = Task {
                    task_id: Some(Uuid { value: vec![0u8; 16] }),
                    task_type: task_type.as_str().to_string(),
                    task_data: vec![0xAA; *data_len as usize],
                    issued_at: None,
                    operator_id: None,
                };
                let _ = encode(&task);
            }
            ProtocolOperation::DecodeFrame { len_prefix, payload_len } => {
                // Construct a potentially malformed frame
                let mut buf = len_prefix.to_be_bytes().to_vec();
                buf.extend(vec![0u8; *payload_len as usize]);
                // Should never panic, just return error
                let _: Result<(Uuid, usize), _> = decode_with_length(&buf);
            }
            ProtocolOperation::Roundtrip { task_type, data_len } => {
                let task = Task {
                    task_id: Some(Uuid { value: vec![0u8; 16] }),
                    task_type: task_type.as_str().to_string(),
                    task_data: vec![0xBB; *data_len as usize],
                    issued_at: None,
                    operator_id: None,
                };
                let encoded = encode_with_length(&task);
                if let Ok((decoded, _)) = decode_with_length::<Task>(&encoded) {
                    assert_eq!(decoded.task_type, task.task_type);
                    assert_eq!(decoded.task_data.len(), task.task_data.len());
                }
            }
        }
    }
});
