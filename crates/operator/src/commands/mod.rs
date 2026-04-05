//! Command parsing and dispatching

pub mod sessions;
pub mod jobs;
pub mod interact;
pub mod loot;
pub mod modules;
pub mod listeners;
pub mod tasks;
pub mod inject;
pub mod bof;
pub mod payload;
pub mod mesh;
pub mod operator;
pub mod socks;
pub mod collab;
pub mod operators;
pub mod report;

use anyhow::Result;
use crate::cli::CliState;
use crate::display::{print_error, print_info};

/// Command enum
#[derive(Debug, Clone)]
pub enum Command {
    // Global commands
    Sessions,
    SessionsWithTag(String),
    Session(SessionSubcommand),
    Use(String),
    Back,
    Help,
    Exit,
    Clear,

    // Session-context commands (require active session)
    Shell(String),
    Upload { local: String, remote: String },
    Download { remote: String, local: String },
    Cd(String),
    Pwd,
    Ls(Option<String>),
    Pushd(String),
    Popd,
    Dirs,
    Ps,
    PsTree(Option<String>),
    Sleep(u32),
    Burn,

    // Jobs
    Jobs(JobsSubcommand),

    // Tasks
    Tasks(TasksSubcommand),

    // Loot
    Loot(LootSubcommand),

    // Modules
    Modules(ModulesSubcommand),

    // Listeners
    Listeners(ListenersSubcommand),

    // Inject
    Inject(InjectSubcommand),

    // BOF
    Bof(BofSubcommand),

    // Payload
    Payload(PayloadSubcommand),

    // Advanced
    PortFwd(PortFwdSubcommand),
    Screenshot,
    Wifi,

    // Mesh
    Mesh(MeshSubcommand),

    // SOCKS Proxy
    Socks(SocksSubcommand),

    // Collaboration
    Collab(CollabSubcommand),

    // Operators
    Operators(OperatorsSubcommand),

    // Reports
    Report(ReportSubcommand),

    // Configuration
    Config(ConfigSubcommand),

    // Operator
    Whoami,

    // Unknown
    Unknown(String),
}

#[derive(Debug, Clone)]
pub enum ConfigSubcommand {
    Interval(u32),
    Jitter(u32),
}

#[derive(Debug, Clone)]
pub enum SessionSubcommand {
    Info(String),
    Retire(String),
    Delete(String),
    Burn(String),
    Tag { session_id: String, tag: String },
    Untag { session_id: String, tag: String },
}

#[derive(Debug, Clone)]
pub enum JobsSubcommand {
    List,
    Show(u32),
    Kill(u32),
    Output(u32),
    Clean,
}

#[derive(Debug, Clone)]
pub enum TasksSubcommand {
    List { all: bool },
    Show(String),
    Cancel(String),
}

#[derive(Debug, Clone)]
pub enum LootSubcommand {
    List,
    Search(String),
    Export(String),
    Show(String),
    Delete(String),
    ExportHashcat(String),
    ExportJtr(String),
    Stats,
}

#[derive(Debug, Clone)]
pub enum ModulesSubcommand {
    List,
    Load { name: String, version: Option<String> },
    Unload(String),
}

#[derive(Debug, Clone)]
pub enum InjectSubcommand {
    Shellcode {
        pid: u32,
        file: String,
        technique: Option<String>,
    },
    ListTechniques,
}

#[derive(Debug, Clone)]
pub enum BofSubcommand {
    List,
    Show(String),
    Execute { bof_id: String, args: Vec<String> },
    Validate(String),
    History { bof_id: Option<String>, limit: u32 },
    Upload(String),
    Delete(String),
}

#[derive(Debug, Clone)]
pub enum PayloadSubcommand {
    Generate {
        format: String,
        listener_id: String,
        output: String,
        os: Option<String>,
        arch: Option<String>,
    },
    List,
    Show(String),
    Delete(String),
}

#[derive(Debug, Clone)]
pub enum ListenersSubcommand {
    List,
    Start {
        listener_type: String,
        bind_host: String,
        bind_port: u32,
        profile: Option<String>,
        tls_cert: Option<String>,
        tls_key: Option<String>,
        dns_domain: Option<String>,
    },
    Stop(String),
}

#[derive(Debug, Clone)]
pub enum PortFwdSubcommand {
    Start { bind_port: u32, fwd_addr: String, reverse: bool },
    Stop(String),
    List,
}

#[derive(Debug, Clone)]
pub enum MeshSubcommand {
    Topology,
    Connect { peer_id: String, transport: String, address: String, port: u32 },
    Disconnect { peer_id: String },
    Role(String),
    Listen { port: u32, transport: String, bind_address: String },
    Route { from_id: String, to_id: String, max_paths: u32 },
}

#[derive(Debug, Clone)]
pub enum SocksSubcommand {
    Start { bind_host: String, bind_port: u32, version: String, reverse: bool },
    Stop(String),
    List,
    Stats(String),
}

#[derive(Debug, Clone)]
pub enum CollabSubcommand {
    Online,
    Lock { session_id: String, reason: Option<String> },
    Unlock(String),
    Locks,
    Chat { message: String, session_id: Option<String> },
    History { session_id: Option<String>, limit: u32 },
    Stats,
}

#[derive(Debug, Clone)]
pub enum OperatorsSubcommand {
    List,
    Create { username: String, password: String, role: String },
    Update { operator_id: String, role: Option<String>, disabled: Option<bool> },
    Delete(String),
}

#[derive(Debug, Clone)]
pub enum ReportSubcommand {
    Generate { title: String, report_type: String, format: String },
    List,
    Show(String),
    Delete(String),
}

/// Parse command string into Command enum
pub fn parse(input: &str) -> Command {
    let input = input.trim();
    if input.is_empty() {
        return Command::Unknown(String::new());
    }

    // Split using shellwords for proper quote handling
    let parts = match shellwords::split(input) {
        Ok(p) => p,
        Err(_) => {
            return Command::Unknown(input.to_string());
        }
    };

    if parts.is_empty() {
        return Command::Unknown(String::new());
    }

    let cmd = parts[0].as_str();
    let args = &parts[1..];

    match cmd {
        // Global commands
        "sessions" => {
            // Check for --tag flag
            if args.len() >= 2 && args[0] == "--tag" {
                Command::SessionsWithTag(args[1].clone())
            } else if args.is_empty() {
                Command::Sessions
            } else {
                Command::Unknown("sessions: unknown option (use --tag <tag>)".to_string())
            }
        }
        "session" => {
            if args.is_empty() {
                Command::Unknown("session requires a subcommand (info, retire, delete)".to_string())
            } else {
                match args[0].as_str() {
                    "info" => {
                        if args.len() < 2 {
                            Command::Unknown("session info requires <id>".to_string())
                        } else {
                            Command::Session(SessionSubcommand::Info(args[1].clone()))
                        }
                    }
                    "retire" => {
                        if args.len() < 2 {
                            Command::Unknown("session retire requires <id>".to_string())
                        } else {
                            Command::Session(SessionSubcommand::Retire(args[1].clone()))
                        }
                    }
                    "delete" => {
                        if args.len() < 2 {
                            Command::Unknown("session delete requires <id>".to_string())
                        } else {
                            Command::Session(SessionSubcommand::Delete(args[1].clone()))
                        }
                    }
                    "burn" => {
                        if args.len() < 2 {
                            Command::Unknown("session burn requires <id>".to_string())
                        } else {
                            Command::Session(SessionSubcommand::Burn(args[1].clone()))
                        }
                    }
                    "tag" => {
                        if args.len() < 3 {
                            Command::Unknown("session tag requires <id> <tag>".to_string())
                        } else {
                            Command::Session(SessionSubcommand::Tag {
                                session_id: args[1].clone(),
                                tag: args[2].clone(),
                            })
                        }
                    }
                    "untag" => {
                        if args.len() < 3 {
                            Command::Unknown("session untag requires <id> <tag>".to_string())
                        } else {
                            Command::Session(SessionSubcommand::Untag {
                                session_id: args[1].clone(),
                                tag: args[2].clone(),
                            })
                        }
                    }
                    _ => Command::Unknown(format!("unknown session subcommand: {}", args[0])),
                }
            }
        }
        "use" => {
            if args.is_empty() {
                Command::Unknown("use requires a session ID".to_string())
            } else {
                Command::Use(args[0].clone())
            }
        }
        "back" => Command::Back,
        "help" => Command::Help,
        "exit" | "quit" => Command::Exit,
        "clear" | "cls" => Command::Clear,

        // Session commands
        "shell" => {
            if args.is_empty() {
                Command::Unknown("shell requires a command".to_string())
            } else {
                Command::Shell(args.join(" "))
            }
        }
        "upload" => {
            if args.len() < 2 {
                Command::Unknown("upload requires <local> <remote>".to_string())
            } else {
                Command::Upload {
                    local: args[0].clone(),
                    remote: args[1].clone(),
                }
            }
        }
        "download" => {
            if args.len() < 2 {
                Command::Unknown("download requires <remote> <local>".to_string())
            } else {
                Command::Download {
                    remote: args[0].clone(),
                    local: args[1].clone(),
                }
            }
        }
        "cd" => {
            if args.is_empty() {
                Command::Unknown("cd requires a path".to_string())
            } else {
                Command::Cd(args[0].clone())
            }
        }
        "pwd" => Command::Pwd,
        "ls" => Command::Ls(args.first().cloned()),
        "pushd" => {
            if args.is_empty() {
                Command::Unknown("pushd requires a path".to_string())
            } else {
                Command::Pushd(args[0].clone())
            }
        }
        "popd" => Command::Popd,
        "dirs" => Command::Dirs,
        "ps" => {
            if args.len() > 0 && args[0] == "tree" {
                // "ps tree [filter]"
                Command::PsTree(args.get(1).cloned())
            } else {
                Command::Ps
            }
        }
        "pstree" => Command::PsTree(args.first().cloned()),
        "sleep" => {
            if args.is_empty() {
                Command::Unknown("sleep requires seconds".to_string())
            } else {
                match args[0].parse::<u32>() {
                    Ok(s) => Command::Sleep(s),
                    Err(_) => Command::Unknown("sleep requires a number".to_string()),
                }
            }
        }
        "burn" => Command::Burn,
        "screenshot" => Command::Screenshot,
        "wifi" => Command::Wifi,

        // Payload
        "payload" => {
            if args.is_empty() || args[0] == "list" {
                Command::Payload(PayloadSubcommand::List)
            } else {
                match args[0].as_str() {
                    "generate" => {
                        if args.len() < 4 {
                            Command::Unknown("payload generate requires <format> <listener-id> <output> [--os <os>] [--arch <arch>]".to_string())
                        } else {
                            let format = args[1].clone();
                            let listener_id = args[2].clone();
                            let output = args[3].clone();

                            // Parse optional flags
                            let mut os = None;
                            let mut arch = None;

                            let mut i = 4;
                            while i < args.len() {
                                match args[i].as_str() {
                                    "--os" => {
                                        if i + 1 < args.len() {
                                            os = Some(args[i + 1].clone());
                                            i += 2;
                                        } else {
                                            return Command::Unknown("--os requires a value".to_string());
                                        }
                                    }
                                    "--arch" => {
                                        if i + 1 < args.len() {
                                            arch = Some(args[i + 1].clone());
                                            i += 2;
                                        } else {
                                            return Command::Unknown("--arch requires a value".to_string());
                                        }
                                    }
                                    _ => {
                                        return Command::Unknown(format!("unknown flag: {}", args[i]));
                                    }
                                }
                            }

                            Command::Payload(PayloadSubcommand::Generate {
                                format,
                                listener_id,
                                output,
                                os,
                                arch,
                            })
                        }
                    }
                    "show" => {
                        if args.len() < 2 {
                            Command::Unknown("payload show requires <id>".to_string())
                        } else {
                            Command::Payload(PayloadSubcommand::Show(args[1].clone()))
                        }
                    }
                    "delete" => {
                        if args.len() < 2 {
                            Command::Unknown("payload delete requires <id>".to_string())
                        } else {
                            Command::Payload(PayloadSubcommand::Delete(args[1].clone()))
                        }
                    }
                    _ => Command::Unknown(format!("unknown payload subcommand: {}", args[0])),
                }
            }
        }

        // BOF
        "bof" => {
            if args.is_empty() || args[0] == "list" {
                Command::Bof(BofSubcommand::List)
            } else {
                match args[0].as_str() {
                    "show" => {
                        if args.len() < 2 {
                            Command::Unknown("bof show requires <bof_id>".to_string())
                        } else {
                            Command::Bof(BofSubcommand::Show(args[1].clone()))
                        }
                    }
                    "execute" | "exec" => {
                        if args.len() < 2 {
                            Command::Unknown("bof execute requires <bof_id> [args...]".to_string())
                        } else {
                            let bof_id = args[1].clone();
                            let bof_args = args[2..].to_vec();
                            Command::Bof(BofSubcommand::Execute { bof_id, args: bof_args })
                        }
                    }
                    "validate" => {
                        if args.len() < 2 {
                            Command::Unknown("bof validate requires <bof_id>".to_string())
                        } else {
                            Command::Bof(BofSubcommand::Validate(args[1].clone()))
                        }
                    }
                    "history" => {
                        let bof_id = args.get(1).cloned();
                        let limit = args.get(2).and_then(|s| s.parse::<u32>().ok()).unwrap_or(10);
                        Command::Bof(BofSubcommand::History { bof_id, limit })
                    }
                    "upload" => {
                        if args.len() < 2 {
                            Command::Unknown("bof upload requires <file>".to_string())
                        } else {
                            Command::Bof(BofSubcommand::Upload(args[1].clone()))
                        }
                    }
                    "delete" => {
                        if args.len() < 2 {
                            Command::Unknown("bof delete requires <bof_id>".to_string())
                        } else {
                            Command::Bof(BofSubcommand::Delete(args[1].clone()))
                        }
                    }
                    _ => Command::Unknown(format!("unknown bof subcommand: {}", args[0])),
                }
            }
        }

        // Inject
        "inject" => {
            if args.is_empty() {
                Command::Unknown("inject requires a subcommand. Use: shellcode, list-techniques".to_string())
            } else {
                match args[0].as_str() {
                    "shellcode" => {
                        if args.len() < 3 {
                            Command::Unknown("inject shellcode requires <pid> <file> [technique]".to_string())
                        } else {
                            match args[1].parse::<u32>() {
                                Ok(pid) => {
                                    let file = args[2].clone();
                                    let technique = args.get(3).cloned();
                                    Command::Inject(InjectSubcommand::Shellcode { pid, file, technique })
                                }
                                Err(_) => Command::Unknown("pid must be a number".to_string()),
                            }
                        }
                    }
                    "list-techniques" => Command::Inject(InjectSubcommand::ListTechniques),
                    _ => Command::Unknown(format!("unknown inject subcommand: {}", args[0])),
                }
            }
        }

        // Tasks
        "tasks" | "task" => {
            if args.is_empty() || args[0] == "list" {
                let all = args.get(1).map(|s| s == "all").unwrap_or(false);
                Command::Tasks(TasksSubcommand::List { all })
            } else {
                match args[0].as_str() {
                    "show" => {
                        if args.len() < 2 {
                            Command::Unknown("task show requires <task_id>".to_string())
                        } else {
                            Command::Tasks(TasksSubcommand::Show(args[1].clone()))
                        }
                    }
                    "cancel" => {
                        if args.len() < 2 {
                            Command::Unknown("task cancel requires <task_id>".to_string())
                        } else {
                            Command::Tasks(TasksSubcommand::Cancel(args[1].clone()))
                        }
                    }
                    _ => Command::Unknown(format!("unknown task subcommand: {}", args[0])),
                }
            }
        }

        // Jobs
        "jobs" => {
            if args.is_empty() {
                Command::Jobs(JobsSubcommand::List)
            } else {
                match args[0].as_str() {
                    "list" => Command::Jobs(JobsSubcommand::List),
                    "show" => {
                        if args.len() < 2 {
                            Command::Unknown("jobs show requires <job_id>".to_string())
                        } else {
                            match args[1].parse::<u32>() {
                                Ok(id) => Command::Jobs(JobsSubcommand::Show(id)),
                                Err(_) => Command::Unknown("job_id must be a number".to_string()),
                            }
                        }
                    }
                    "kill" => {
                        if args.len() < 2 {
                            Command::Unknown("jobs kill requires <job_id>".to_string())
                        } else {
                            match args[1].parse::<u32>() {
                                Ok(id) => Command::Jobs(JobsSubcommand::Kill(id)),
                                Err(_) => Command::Unknown("job_id must be a number".to_string()),
                            }
                        }
                    }
                    "output" => {
                        if args.len() < 2 {
                            Command::Unknown("jobs output requires <job_id>".to_string())
                        } else {
                            match args[1].parse::<u32>() {
                                Ok(id) => Command::Jobs(JobsSubcommand::Output(id)),
                                Err(_) => Command::Unknown("job_id must be a number".to_string()),
                            }
                        }
                    }
                    "clean" => Command::Jobs(JobsSubcommand::Clean),
                    _ => Command::Unknown(format!("unknown jobs subcommand: {}", args[0])),
                }
            }
        }

        // Loot
        "loot" => {
            if args.is_empty() {
                Command::Loot(LootSubcommand::List)
            } else {
                match args[0].as_str() {
                    "list" => Command::Loot(LootSubcommand::List),
                    "search" => {
                        if args.len() < 2 {
                            Command::Unknown("loot search requires <query>".to_string())
                        } else {
                            Command::Loot(LootSubcommand::Search(args[1].clone()))
                        }
                    }
                    "export" => {
                        if args.len() < 2 {
                            Command::Unknown("loot export requires <path>".to_string())
                        } else {
                            Command::Loot(LootSubcommand::Export(args[1].clone()))
                        }
                    }
                    "show" => {
                        if args.len() < 2 {
                            Command::Unknown("loot show requires <id>".to_string())
                        } else {
                            Command::Loot(LootSubcommand::Show(args[1].clone()))
                        }
                    }
                    "delete" => {
                        if args.len() < 2 {
                            Command::Unknown("loot delete requires <id>".to_string())
                        } else {
                            Command::Loot(LootSubcommand::Delete(args[1].clone()))
                        }
                    }
                    "export-hashcat" => {
                        if args.len() < 2 {
                            Command::Unknown("loot export-hashcat requires <path>".to_string())
                        } else {
                            Command::Loot(LootSubcommand::ExportHashcat(args[1].clone()))
                        }
                    }
                    "export-jtr" => {
                        if args.len() < 2 {
                            Command::Unknown("loot export-jtr requires <path>".to_string())
                        } else {
                            Command::Loot(LootSubcommand::ExportJtr(args[1].clone()))
                        }
                    }
                    "stats" => Command::Loot(LootSubcommand::Stats),
                    _ => Command::Unknown(format!("unknown loot subcommand: {}", args[0])),
                }
            }
        }

        // Modules
        "modules" => {
            if args.is_empty() {
                Command::Modules(ModulesSubcommand::List)
            } else {
                match args[0].as_str() {
                    "list" => Command::Modules(ModulesSubcommand::List),
                    "load" => {
                        if args.len() < 2 {
                            Command::Unknown("modules load requires <name>".to_string())
                        } else {
                            let version = args.get(2).cloned();
                            Command::Modules(ModulesSubcommand::Load {
                                name: args[1].clone(),
                                version,
                            })
                        }
                    }
                    "unload" => {
                        if args.len() < 2 {
                            Command::Unknown("modules unload requires <name>".to_string())
                        } else {
                            Command::Modules(ModulesSubcommand::Unload(args[1].clone()))
                        }
                    }
                    _ => Command::Unknown(format!("unknown modules subcommand: {}", args[0])),
                }
            }
        }

        // Listeners
        "listeners" | "listener" => {
            if args.is_empty() || args[0] == "list" {
                Command::Listeners(ListenersSubcommand::List)
            } else {
                match args[0].as_str() {
                    "start" => {
                        if args.len() < 4 {
                            Command::Unknown("listener start requires <type> <host> <port> [--profile <id>] [--cert <path>] [--key <path>] [--domain <name>]".to_string())
                        } else {
                            let listener_type = args[1].clone();
                            let bind_host = args[2].clone();
                            let bind_port = match args[3].parse::<u32>() {
                                Ok(p) => p,
                                Err(_) => return Command::Unknown("port must be a number".to_string()),
                            };

                            // Parse optional flags
                            let mut profile = None;
                            let mut tls_cert = None;
                            let mut tls_key = None;
                            let mut dns_domain = None;

                            let mut i = 4;
                            while i < args.len() {
                                match args[i].as_str() {
                                    "--profile" => {
                                        if i + 1 < args.len() {
                                            profile = Some(args[i + 1].clone());
                                            i += 2;
                                        } else {
                                            return Command::Unknown("--profile requires a value".to_string());
                                        }
                                    }
                                    "--cert" => {
                                        if i + 1 < args.len() {
                                            tls_cert = Some(args[i + 1].clone());
                                            i += 2;
                                        } else {
                                            return Command::Unknown("--cert requires a value".to_string());
                                        }
                                    }
                                    "--key" => {
                                        if i + 1 < args.len() {
                                            tls_key = Some(args[i + 1].clone());
                                            i += 2;
                                        } else {
                                            return Command::Unknown("--key requires a value".to_string());
                                        }
                                    }
                                    "--domain" => {
                                        if i + 1 < args.len() {
                                            dns_domain = Some(args[i + 1].clone());
                                            i += 2;
                                        } else {
                                            return Command::Unknown("--domain requires a value".to_string());
                                        }
                                    }
                                    _ => {
                                        return Command::Unknown(format!("unknown flag: {}", args[i]));
                                    }
                                }
                            }

                            Command::Listeners(ListenersSubcommand::Start {
                                listener_type,
                                bind_host,
                                bind_port,
                                profile,
                                tls_cert,
                                tls_key,
                                dns_domain,
                            })
                        }
                    }
                    "stop" => {
                        if args.len() < 2 {
                            Command::Unknown("listener stop requires <id>".to_string())
                        } else {
                            Command::Listeners(ListenersSubcommand::Stop(args[1].clone()))
                        }
                    }
                    _ => Command::Unknown(format!("unknown listener subcommand: {}", args[0])),
                }
            }
        }

        // Port forwarding
        "portfwd" => {
            if args.is_empty() {
                Command::PortFwd(PortFwdSubcommand::List)
            } else {
                match args[0].as_str() {
                    "list" => Command::PortFwd(PortFwdSubcommand::List),
                    "start" => {
                        if args.len() < 3 {
                            Command::Unknown("portfwd start requires <bind_port> <fwd_addr> [reverse]".to_string())
                        } else {
                            match args[1].parse::<u32>() {
                                Ok(port) => {
                                    let reverse = args.get(3).map(|s| s == "reverse").unwrap_or(false);
                                    Command::PortFwd(PortFwdSubcommand::Start {
                                        bind_port: port,
                                        fwd_addr: args[2].clone(),
                                        reverse,
                                    })
                                }
                                Err(_) => Command::Unknown("bind_port must be a number".to_string()),
                            }
                        }
                    }
                    "stop" => {
                        if args.len() < 2 {
                            Command::Unknown("portfwd stop requires <id>".to_string())
                        } else {
                            Command::PortFwd(PortFwdSubcommand::Stop(args[1].clone()))
                        }
                    }
                    _ => Command::Unknown(format!("unknown portfwd subcommand: {}", args[0])),
                }
            }
        }

        // Mesh
        "mesh" => {
            if args.is_empty() || args[0] == "topology" {
                Command::Mesh(MeshSubcommand::Topology)
            } else {
                match args[0].as_str() {
                    "connect" => {
                        if args.len() < 4 {
                            Command::Unknown("mesh connect requires <peer_id> <transport> <address> <port>".to_string())
                        } else {
                            match args[4].parse::<u32>() {
                                Ok(port) => Command::Mesh(MeshSubcommand::Connect {
                                    peer_id: args[1].clone(),
                                    transport: args[2].clone(),
                                    address: args[3].clone(),
                                    port,
                                }),
                                Err(_) => Command::Unknown("port must be a number".to_string()),
                            }
                        }
                    }
                    "disconnect" => {
                        if args.len() < 2 {
                            Command::Unknown("mesh disconnect requires <peer_id>".to_string())
                        } else {
                            Command::Mesh(MeshSubcommand::Disconnect {
                                peer_id: args[1].clone(),
                            })
                        }
                    }
                    "role" => {
                        if args.len() < 2 {
                            Command::Unknown("mesh role requires <role>".to_string())
                        } else {
                            Command::Mesh(MeshSubcommand::Role(args[1].clone()))
                        }
                    }
                    "listen" => {
                        if args.len() < 3 {
                            Command::Unknown("mesh listen requires <port> <transport> [bind_address]".to_string())
                        } else {
                            match args[1].parse::<u32>() {
                                Ok(port) => {
                                    let bind_address = args.get(3).unwrap_or(&"0.0.0.0".to_string()).clone();
                                    Command::Mesh(MeshSubcommand::Listen {
                                        port,
                                        transport: args[2].clone(),
                                        bind_address,
                                    })
                                }
                                Err(_) => Command::Unknown("port must be a number".to_string()),
                            }
                        }
                    }
                    "route" => {
                        if args.len() < 3 {
                            Command::Unknown("mesh route requires <from_id> <to_id> [max_paths]".to_string())
                        } else {
                            let max_paths = args.get(3).and_then(|s| s.parse::<u32>().ok()).unwrap_or(3);
                            Command::Mesh(MeshSubcommand::Route {
                                from_id: args[1].clone(),
                                to_id: args[2].clone(),
                                max_paths,
                            })
                        }
                    }
                    _ => Command::Unknown(format!("unknown mesh subcommand: {}", args[0])),
                }
            }
        }

        // SOCKS Proxy
        "socks" => {
            if args.is_empty() || args[0] == "list" {
                Command::Socks(SocksSubcommand::List)
            } else {
                match args[0].as_str() {
                    "start" => {
                        if args.len() < 3 {
                            Command::Unknown("socks start requires <bind_host> <bind_port> [version] [reverse]".to_string())
                        } else {
                            match args[2].parse::<u32>() {
                                Ok(port) => {
                                    let version = args.get(3).unwrap_or(&"5".to_string()).clone();
                                    let reverse = args.get(4).map(|s| s == "reverse").unwrap_or(false);
                                    Command::Socks(SocksSubcommand::Start {
                                        bind_host: args[1].clone(),
                                        bind_port: port,
                                        version,
                                        reverse,
                                    })
                                }
                                Err(_) => Command::Unknown("bind_port must be a number".to_string()),
                            }
                        }
                    }
                    "stop" => {
                        if args.len() < 2 {
                            Command::Unknown("socks stop requires <proxy_id>".to_string())
                        } else {
                            Command::Socks(SocksSubcommand::Stop(args[1].clone()))
                        }
                    }
                    "stats" => {
                        if args.len() < 2 {
                            Command::Unknown("socks stats requires <proxy_id>".to_string())
                        } else {
                            Command::Socks(SocksSubcommand::Stats(args[1].clone()))
                        }
                    }
                    _ => Command::Unknown(format!("unknown socks subcommand: {}", args[0])),
                }
            }
        }

        // Collaboration
        "collab" => {
            if args.is_empty() || args[0] == "online" {
                Command::Collab(CollabSubcommand::Online)
            } else {
                match args[0].as_str() {
                    "online" => Command::Collab(CollabSubcommand::Online),
                    "lock" => {
                        if args.len() < 2 {
                            Command::Unknown("collab lock requires <session_id> [reason]".to_string())
                        } else {
                            let reason = if args.len() > 2 {
                                Some(args[2..].join(" "))
                            } else {
                                None
                            };
                            Command::Collab(CollabSubcommand::Lock {
                                session_id: args[1].clone(),
                                reason,
                            })
                        }
                    }
                    "unlock" => {
                        if args.len() < 2 {
                            Command::Unknown("collab unlock requires <session_id>".to_string())
                        } else {
                            Command::Collab(CollabSubcommand::Unlock(args[1].clone()))
                        }
                    }
                    "locks" => Command::Collab(CollabSubcommand::Locks),
                    "chat" => {
                        if args.len() < 2 {
                            Command::Unknown("collab chat requires <message> [session_id]".to_string())
                        } else {
                            let session_id = args.last().and_then(|s| {
                                if s.len() == 8 && s.chars().all(|c| c.is_ascii_hexdigit()) {
                                    Some(s.clone())
                                } else {
                                    None
                                }
                            });
                            let message = if session_id.is_some() {
                                args[1..args.len()-1].join(" ")
                            } else {
                                args[1..].join(" ")
                            };
                            Command::Collab(CollabSubcommand::Chat { message, session_id })
                        }
                    }
                    "history" => {
                        let session_id = args.get(1).and_then(|s| {
                            if s.len() == 8 && s.chars().all(|c| c.is_ascii_hexdigit()) {
                                Some(s.clone())
                            } else {
                                None
                            }
                        });
                        let limit = if session_id.is_some() {
                            args.get(2).and_then(|s| s.parse::<u32>().ok()).unwrap_or(20)
                        } else {
                            args.get(1).and_then(|s| s.parse::<u32>().ok()).unwrap_or(20)
                        };
                        Command::Collab(CollabSubcommand::History { session_id, limit })
                    }
                    "stats" => Command::Collab(CollabSubcommand::Stats),
                    _ => Command::Unknown(format!("unknown collab subcommand: {}", args[0])),
                }
            }
        }

        // Operators
        "operators" => {
            if args.is_empty() || args[0] == "list" {
                Command::Operators(OperatorsSubcommand::List)
            } else {
                match args[0].as_str() {
                    "list" => Command::Operators(OperatorsSubcommand::List),
                    "create" => {
                        if args.len() < 4 {
                            Command::Unknown("operators create requires <username> <password> <role>".to_string())
                        } else {
                            Command::Operators(OperatorsSubcommand::Create {
                                username: args[1].clone(),
                                password: args[2].clone(),
                                role: args[3].clone(),
                            })
                        }
                    }
                    "update" => {
                        if args.len() < 2 {
                            Command::Unknown("operators update requires <operator_id> [role=<role>] [disabled=<true|false>]".to_string())
                        } else {
                            let operator_id = args[1].clone();
                            let mut role = None;
                            let mut disabled = None;

                            for arg in &args[2..] {
                                if arg.starts_with("role=") {
                                    role = Some(arg.strip_prefix("role=").unwrap().to_string());
                                } else if arg.starts_with("disabled=") {
                                    disabled = arg.strip_prefix("disabled=").unwrap().parse::<bool>().ok();
                                }
                            }

                            Command::Operators(OperatorsSubcommand::Update { operator_id, role, disabled })
                        }
                    }
                    "delete" => {
                        if args.len() < 2 {
                            Command::Unknown("operators delete requires <operator_id>".to_string())
                        } else {
                            Command::Operators(OperatorsSubcommand::Delete(args[1].clone()))
                        }
                    }
                    _ => Command::Unknown(format!("unknown operators subcommand: {}", args[0])),
                }
            }
        }

        // Reports
        "report" => {
            if args.is_empty() || args[0] == "list" {
                Command::Report(ReportSubcommand::List)
            } else {
                match args[0].as_str() {
                    "list" => Command::Report(ReportSubcommand::List),
                    "generate" => {
                        if args.len() < 4 {
                            Command::Unknown("report generate requires <title> <type> <format>".to_string())
                        } else {
                            Command::Report(ReportSubcommand::Generate {
                                title: args[1].clone(),
                                report_type: args[2].clone(),
                                format: args[3].clone(),
                            })
                        }
                    }
                    "show" => {
                        if args.len() < 2 {
                            Command::Unknown("report show requires <report_id>".to_string())
                        } else {
                            Command::Report(ReportSubcommand::Show(args[1].clone()))
                        }
                    }
                    "delete" => {
                        if args.len() < 2 {
                            Command::Unknown("report delete requires <report_id>".to_string())
                        } else {
                            Command::Report(ReportSubcommand::Delete(args[1].clone()))
                        }
                    }
                    _ => Command::Unknown(format!("unknown report subcommand: {}", args[0])),
                }
            }
        }

        // Configuration
        "config" => {
            if args.is_empty() {
                Command::Unknown("config requires a subcommand (interval, jitter)".to_string())
            } else {
                match args[0].as_str() {
                    "interval" => {
                        if args.len() < 2 {
                            Command::Unknown("config interval requires <seconds>".to_string())
                        } else {
                            match args[1].parse::<u32>() {
                                Ok(seconds) => Command::Config(ConfigSubcommand::Interval(seconds)),
                                Err(_) => Command::Unknown("interval must be a number".to_string()),
                            }
                        }
                    }
                    "jitter" => {
                        if args.len() < 2 {
                            Command::Unknown("config jitter requires <percent>".to_string())
                        } else {
                            match args[1].parse::<u32>() {
                                Ok(percent) => {
                                    if percent > 100 {
                                        Command::Unknown("jitter must be 0-100".to_string())
                                    } else {
                                        Command::Config(ConfigSubcommand::Jitter(percent))
                                    }
                                }
                                Err(_) => Command::Unknown("jitter must be a number".to_string()),
                            }
                        }
                    }
                    _ => Command::Unknown(format!("unknown config subcommand: {}", args[0])),
                }
            }
        }

        // Operator
        "whoami" => Command::Whoami,

        _ => Command::Unknown(input.to_string()),
    }
}

/// Dispatch command to appropriate handler
/// Returns Ok(true) to signal exit
pub async fn dispatch(cmd: Command, cli: &mut CliState) -> Result<bool> {
    match cmd {
        Command::Sessions => {
            sessions::list(cli).await?;
            Ok(false)
        }
        Command::SessionsWithTag(tag) => {
            sessions::list_by_tag(cli, &tag).await?;
            Ok(false)
        }
        Command::Session(subcmd) => {
            match subcmd {
                SessionSubcommand::Info(id) => sessions::info(cli, &id).await?,
                SessionSubcommand::Retire(id) => sessions::retire(cli, &id).await?,
                SessionSubcommand::Delete(id) => sessions::delete(cli, &id).await?,
                SessionSubcommand::Burn(id) => sessions::burn(cli, &id).await?,
                SessionSubcommand::Tag { session_id, tag } => sessions::tag(cli, &session_id, &tag).await?,
                SessionSubcommand::Untag { session_id, tag } => sessions::untag(cli, &session_id, &tag).await?,
            }
            Ok(false)
        }
        Command::Use(id) => {
            sessions::use_session(cli, &id).await?;
            Ok(false)
        }
        Command::Back => {
            sessions::back(cli);
            Ok(false)
        }
        Command::Help => {
            print_help();
            Ok(false)
        }
        Command::Exit => Ok(true),
        Command::Clear => {
            print!("\x1B[2J\x1B[1;1H");
            Ok(false)
        }

        // Session commands - require active session
        Command::Shell(cmd) => {
            if cli.active_session().is_none() {
                print_error("No session selected. Use 'use <id>' first.");
                return Ok(false);
            }
            interact::shell(cli, &cmd).await?;
            Ok(false)
        }
        Command::Upload { local, remote } => {
            if cli.active_session().is_none() {
                print_error("No session selected. Use 'use <id>' first.");
                return Ok(false);
            }
            interact::upload(cli, &local, &remote).await?;
            Ok(false)
        }
        Command::Download { remote, local } => {
            if cli.active_session().is_none() {
                print_error("No session selected. Use 'use <id>' first.");
                return Ok(false);
            }
            interact::download(cli, &remote, &local).await?;
            Ok(false)
        }
        Command::Cd(path) => {
            if cli.active_session().is_none() {
                print_error("No session selected. Use 'use <id>' first.");
                return Ok(false);
            }
            interact::cd(cli, &path).await?;
            Ok(false)
        }
        Command::Pwd => {
            if cli.active_session().is_none() {
                print_error("No session selected. Use 'use <id>' first.");
                return Ok(false);
            }
            interact::pwd(cli).await?;
            Ok(false)
        }
        Command::Ls(path) => {
            if cli.active_session().is_none() {
                print_error("No session selected. Use 'use <id>' first.");
                return Ok(false);
            }
            interact::ls(cli, path.as_deref()).await?;
            Ok(false)
        }
        Command::Pushd(path) => {
            if cli.active_session().is_none() {
                print_error("No session selected. Use 'use <id>' first.");
                return Ok(false);
            }
            interact::pushd(cli, &path).await?;
            Ok(false)
        }
        Command::Popd => {
            if cli.active_session().is_none() {
                print_error("No session selected. Use 'use <id>' first.");
                return Ok(false);
            }
            interact::popd(cli).await?;
            Ok(false)
        }
        Command::Dirs => {
            if cli.active_session().is_none() {
                print_error("No session selected. Use 'use <id>' first.");
                return Ok(false);
            }
            interact::dirs(cli);
            Ok(false)
        }
        Command::Ps => {
            if cli.active_session().is_none() {
                print_error("No session selected. Use 'use <id>' first.");
                return Ok(false);
            }
            interact::ps(cli).await?;
            Ok(false)
        }
        Command::PsTree(filter) => {
            if cli.active_session().is_none() {
                print_error("No session selected. Use 'use <id>' first.");
                return Ok(false);
            }
            interact::ps_tree(cli, filter.as_deref()).await?;
            Ok(false)
        }
        Command::Sleep(seconds) => {
            if cli.active_session().is_none() {
                print_error("No session selected. Use 'use <id>' first.");
                return Ok(false);
            }
            interact::sleep(cli, seconds).await?;
            Ok(false)
        }
        Command::Burn => {
            if cli.active_session().is_none() {
                print_error("No session selected. Use 'use <id>' first.");
                return Ok(false);
            }
            interact::burn(cli).await?;
            Ok(false)
        }
        Command::Screenshot => {
            if cli.active_session().is_none() {
                print_error("No session selected. Use 'use <id>' first.");
                return Ok(false);
            }
            interact::screenshot(cli).await?;
            Ok(false)
        }
        Command::Wifi => {
            if cli.active_session().is_none() {
                print_error("No session selected. Use 'use <id>' first.");
                return Ok(false);
            }
            interact::wifi(cli).await?;
            Ok(false)
        }

        // Payload
        Command::Payload(subcmd) => {
            match subcmd {
                PayloadSubcommand::Generate {
                    format,
                    listener_id,
                    output,
                    os,
                    arch,
                } => payload::generate(cli, format, listener_id, output, os, arch).await?,
                PayloadSubcommand::List => payload::list(cli).await?,
                PayloadSubcommand::Show(id) => payload::show(cli, id).await?,
                PayloadSubcommand::Delete(id) => payload::delete(cli, id).await?,
            }
            Ok(false)
        }

        // BOF
        Command::Bof(subcmd) => {
            match subcmd {
                BofSubcommand::List => bof::list(cli).await?,
                BofSubcommand::Show(bof_id) => bof::show(cli, bof_id).await?,
                BofSubcommand::Execute { bof_id, args } => {
                    if cli.active_session().is_none() {
                        print_error("No session selected. Use 'use <id>' first.");
                        return Ok(false);
                    }
                    bof::execute(cli, bof_id, args).await?
                }
                BofSubcommand::Validate(bof_id) => {
                    if cli.active_session().is_none() {
                        print_error("No session selected. Use 'use <id>' first.");
                        return Ok(false);
                    }
                    bof::validate(cli, bof_id).await?
                }
                BofSubcommand::History { bof_id, limit } => bof::history(cli, bof_id, limit).await?,
                BofSubcommand::Upload(file) => bof::upload(cli, file).await?,
                BofSubcommand::Delete(bof_id) => bof::delete(cli, bof_id).await?,
            }
            Ok(false)
        }

        // Inject
        Command::Inject(subcmd) => {
            match subcmd {
                InjectSubcommand::Shellcode { pid, file, technique } => {
                    if cli.active_session().is_none() {
                        print_error("No session selected. Use 'use <id>' first.");
                        return Ok(false);
                    }
                    inject::shellcode(cli, pid, file, technique).await?
                }
                InjectSubcommand::ListTechniques => inject::list_techniques(),
            }
            Ok(false)
        }

        // Tasks
        Command::Tasks(subcmd) => {
            match subcmd {
                TasksSubcommand::List { all } => tasks::list(cli, all).await?,
                TasksSubcommand::Show(id) => tasks::show(cli, id).await?,
                TasksSubcommand::Cancel(id) => tasks::cancel(cli, id).await?,
            }
            Ok(false)
        }

        // Jobs
        Command::Jobs(subcmd) => {
            match subcmd {
                JobsSubcommand::List => jobs::list(cli).await?,
                JobsSubcommand::Show(id) => jobs::show(cli, id).await?,
                JobsSubcommand::Kill(id) => jobs::kill(cli, id).await?,
                JobsSubcommand::Output(id) => jobs::output(cli, id).await?,
                JobsSubcommand::Clean => jobs::clean(cli).await?,
            }
            Ok(false)
        }

        // Loot
        Command::Loot(subcmd) => {
            match subcmd {
                LootSubcommand::List => loot::list(cli, None).await?,
                LootSubcommand::Search(query) => loot::search(cli, &query).await?,
                LootSubcommand::Export(path) => loot::export(cli, &path).await?,
                LootSubcommand::Show(id) => loot::show(cli, &id).await?,
                LootSubcommand::Delete(id) => loot::delete(cli, &id).await?,
                LootSubcommand::ExportHashcat(path) => loot::export_hashcat(cli, &path).await?,
                LootSubcommand::ExportJtr(path) => loot::export_jtr(cli, &path).await?,
                LootSubcommand::Stats => loot::stats(cli).await?,
            }
            Ok(false)
        }

        // Modules
        Command::Modules(subcmd) => {
            match subcmd {
                ModulesSubcommand::List => modules::list(cli).await?,
                ModulesSubcommand::Load { name, version } => {
                    if cli.active_session().is_none() {
                        print_error("No session selected. Use 'use <id>' first.");
                        return Ok(false);
                    }
                    modules::load(cli, &name, version.as_deref()).await?
                }
                ModulesSubcommand::Unload(name) => {
                    if cli.active_session().is_none() {
                        print_error("No session selected. Use 'use <id>' first.");
                        return Ok(false);
                    }
                    modules::unload(cli, &name).await?
                }
            }
            Ok(false)
        }

        // Listeners
        Command::Listeners(subcmd) => {
            match subcmd {
                ListenersSubcommand::List => listeners::list(cli).await?,
                ListenersSubcommand::Start {
                    listener_type,
                    bind_host,
                    bind_port,
                    profile,
                    tls_cert,
                    tls_key,
                    dns_domain,
                } => {
                    listeners::start(
                        cli,
                        listener_type,
                        bind_host,
                        bind_port,
                        profile,
                        tls_cert,
                        tls_key,
                        dns_domain,
                    )
                    .await?
                }
                ListenersSubcommand::Stop(id) => listeners::stop(cli, id).await?,
            }
            Ok(false)
        }

        // Port forwarding
        Command::PortFwd(subcmd) => {
            if cli.active_session().is_none() {
                print_error("No session selected. Use 'use <id>' first.");
                return Ok(false);
            }
            match subcmd {
                PortFwdSubcommand::List => interact::portfwd_list(cli).await?,
                PortFwdSubcommand::Start { bind_port, fwd_addr, reverse } => {
                    interact::portfwd_start(cli, bind_port, &fwd_addr, reverse).await?
                }
                PortFwdSubcommand::Stop(id) => interact::portfwd_stop(cli, &id).await?,
            }
            Ok(false)
        }

        // Mesh
        Command::Mesh(subcmd) => {
            match subcmd {
                MeshSubcommand::Topology => mesh::topology(cli).await?,
                MeshSubcommand::Connect { peer_id, transport, address, port } => {
                    if cli.active_session().is_none() {
                        print_error("No session selected. Use 'use <id>' first.");
                        return Ok(false);
                    }
                    mesh::connect(cli, peer_id, transport, address, port).await?
                }
                MeshSubcommand::Disconnect { peer_id } => {
                    if cli.active_session().is_none() {
                        print_error("No session selected. Use 'use <id>' first.");
                        return Ok(false);
                    }
                    mesh::disconnect(cli, peer_id).await?
                }
                MeshSubcommand::Role(role) => {
                    if cli.active_session().is_none() {
                        print_error("No session selected. Use 'use <id>' first.");
                        return Ok(false);
                    }
                    mesh::role(cli, role).await?
                }
                MeshSubcommand::Listen { port, transport, bind_address } => {
                    if cli.active_session().is_none() {
                        print_error("No session selected. Use 'use <id>' first.");
                        return Ok(false);
                    }
                    mesh::listen(cli, port, transport, bind_address).await?
                }
                MeshSubcommand::Route { from_id, to_id, max_paths } => {
                    mesh::route(cli, from_id, to_id, max_paths).await?
                }
            }
            Ok(false)
        }

        // SOCKS Proxy
        Command::Socks(subcmd) => {
            match subcmd {
                SocksSubcommand::List => socks::list(cli).await?,
                SocksSubcommand::Start { bind_host, bind_port, version, reverse } => {
                    if cli.active_session().is_none() {
                        print_error("No session selected. Use 'use <id>' first.");
                        return Ok(false);
                    }
                    socks::start(cli, bind_host, bind_port, version, reverse).await?
                }
                SocksSubcommand::Stop(proxy_id) => socks::stop(cli, proxy_id).await?,
                SocksSubcommand::Stats(proxy_id) => socks::stats(cli, proxy_id).await?,
            }
            Ok(false)
        }

        // Collaboration
        Command::Collab(subcmd) => {
            match subcmd {
                CollabSubcommand::Online => collab::online(cli).await?,
                CollabSubcommand::Lock { session_id, reason } => collab::lock(cli, session_id, reason).await?,
                CollabSubcommand::Unlock(session_id) => collab::unlock(cli, session_id).await?,
                CollabSubcommand::Locks => collab::locks(cli).await?,
                CollabSubcommand::Chat { message, session_id } => collab::chat(cli, message, session_id).await?,
                CollabSubcommand::History { session_id, limit } => collab::history(cli, session_id, limit).await?,
                CollabSubcommand::Stats => collab::stats(cli).await?,
            }
            Ok(false)
        }

        // Operators
        Command::Operators(subcmd) => {
            match subcmd {
                OperatorsSubcommand::List => operators::list(cli).await?,
                OperatorsSubcommand::Create { username, password, role } => {
                    operators::create(cli, username, password, role).await?
                }
                OperatorsSubcommand::Update { operator_id, role, disabled } => {
                    operators::update(cli, operator_id, role, disabled).await?
                }
                OperatorsSubcommand::Delete(operator_id) => operators::delete(cli, operator_id).await?,
            }
            Ok(false)
        }

        // Configuration
        Command::Config(subcmd) => {
            if cli.active_session().is_none() {
                print_error("No session selected. Use 'use <id>' first.");
                return Ok(false);
            }
            match subcmd {
                ConfigSubcommand::Interval(seconds) => interact::config_interval(cli, seconds).await?,
                ConfigSubcommand::Jitter(percent) => interact::config_jitter(cli, percent).await?,
            }
            Ok(false)
        }

        // Reports
        Command::Report(subcmd) => {
            match subcmd {
                ReportSubcommand::List => report::list(cli).await?,
                ReportSubcommand::Generate { title, report_type, format } => {
                    report::generate(cli, title, report_type, format).await?
                }
                ReportSubcommand::Show(report_id) => report::show(cli, report_id).await?,
                ReportSubcommand::Delete(report_id) => report::delete(cli, report_id).await?,
            }
            Ok(false)
        }

        // Operator
        Command::Whoami => {
            operator::whoami(cli).await?;
            Ok(false)
        }

        Command::Unknown(msg) => {
            if !msg.is_empty() {
                print_error(&format!("Unknown command: {}", msg));
                print_info("Type 'help' for available commands");
            }
            Ok(false)
        }
    }
}

/// Print help message
fn print_help() {
    use crate::theme::Theme;
    use console::style;

    if Theme::is_interactive() {
        println!("\n{}", style("GLOBAL COMMANDS").fg(crate::theme::colors::LAVENDER).bold());
        println!("  {}              List all sessions", style("sessions").fg(crate::theme::colors::TEAL));
        println!("  {} {}  List sessions with tag", style("sessions --tag").fg(crate::theme::colors::TEAL), style("<tag>").fg(crate::theme::colors::PEACH));
        println!("  {} {}       Select a session", style("use").fg(crate::theme::colors::TEAL), style("<id>").fg(crate::theme::colors::PEACH));
        println!("  {}                Background current session", style("back").fg(crate::theme::colors::TEAL));
        println!("  {} {}      Show session details", style("session info").fg(crate::theme::colors::TEAL), style("<id>").fg(crate::theme::colors::PEACH));
        println!("  {} {}   Retire session", style("session retire").fg(crate::theme::colors::TEAL), style("<id>").fg(crate::theme::colors::PEACH));
        println!("  {} {}   Delete session", style("session delete").fg(crate::theme::colors::TEAL), style("<id>").fg(crate::theme::colors::PEACH));
        println!("  {} {}     Burn session (destroy implant)", style("session burn").fg(crate::theme::colors::TEAL), style("<id>").fg(crate::theme::colors::PEACH));
        println!("  {} {}     Add tag to session", style("session tag").fg(crate::theme::colors::TEAL), style("<id> <tag>").fg(crate::theme::colors::PEACH));
        println!("  {} {}   Remove tag from session", style("session untag").fg(crate::theme::colors::TEAL), style("<id> <tag>").fg(crate::theme::colors::PEACH));
        println!("\n{}", style("CONFIGURATION").fg(crate::theme::colors::LAVENDER).bold());
        println!("  {} {}  Update checkin interval", style("config interval").fg(crate::theme::colors::TEAL), style("<sec>").fg(crate::theme::colors::PEACH));
        println!("  {} {}    Update jitter percent", style("config jitter").fg(crate::theme::colors::TEAL), style("<pct>").fg(crate::theme::colors::PEACH));

        println!("\n{}", style("GLOBAL").fg(crate::theme::colors::LAVENDER).bold());
        println!("  {}               Show current operator", style("whoami").fg(crate::theme::colors::TEAL));
        println!("  {}                Show this help", style("help").fg(crate::theme::colors::TEAL));
        println!("  {}                Exit the operator", style("exit").fg(crate::theme::colors::TEAL));
        println!("  {}               Clear screen", style("clear").fg(crate::theme::colors::TEAL));

        println!("\n{}", style("SESSION COMMANDS").fg(crate::theme::colors::LAVENDER).bold());
        println!("  {} {}      Execute shell command", style("shell").fg(crate::theme::colors::TEAL), style("<cmd>").fg(crate::theme::colors::PEACH));
        println!("  {} {} {}  Upload file to implant", style("upload").fg(crate::theme::colors::TEAL), style("<local>").fg(crate::theme::colors::PEACH), style("<remote>").fg(crate::theme::colors::PEACH));
        println!("  {} {} {}  Download file from implant", style("download").fg(crate::theme::colors::TEAL), style("<remote>").fg(crate::theme::colors::PEACH), style("<local>").fg(crate::theme::colors::PEACH));
        println!("  {} {}        Change directory", style("cd").fg(crate::theme::colors::TEAL), style("<path>").fg(crate::theme::colors::PEACH));
        println!("  {}                 Print working directory", style("pwd").fg(crate::theme::colors::TEAL));
        println!("  {} {}         List directory", style("ls").fg(crate::theme::colors::TEAL), style("[path]").fg(crate::theme::colors::PEACH));
        println!("  {} {}       Push directory onto stack", style("pushd").fg(crate::theme::colors::TEAL), style("<path>").fg(crate::theme::colors::PEACH));
        println!("  {}                Pop directory from stack", style("popd").fg(crate::theme::colors::TEAL));
        println!("  {}                Show directory stack", style("dirs").fg(crate::theme::colors::TEAL));
        println!("  {}                  List processes", style("ps").fg(crate::theme::colors::TEAL));
        println!("  {} {}       Process tree view", style("ps tree").fg(crate::theme::colors::TEAL), style("[filter]").fg(crate::theme::colors::PEACH));
        println!("  {} {}         Process tree view", style("pstree").fg(crate::theme::colors::TEAL), style("[filter]").fg(crate::theme::colors::PEACH));
        println!("  {} {}   Set callback interval (seconds)", style("sleep").fg(crate::theme::colors::TEAL), style("<sec>").fg(crate::theme::colors::PEACH));
        println!("  {}                Burn implant", style("burn").fg(crate::theme::colors::TEAL));
        println!("  {}          Take screenshot", style("screenshot").fg(crate::theme::colors::TEAL));

        println!("\n{}", style("INJECT").fg(crate::theme::colors::LAVENDER).bold());
        println!("  {} {} {} {}  Inject shellcode into process", style("inject shellcode").fg(crate::theme::colors::TEAL), style("<pid>").fg(crate::theme::colors::PEACH), style("<file>").fg(crate::theme::colors::PEACH), style("[tech]").fg(crate::theme::colors::PEACH));
        println!("  {}  List injection techniques", style("inject list-techniques").fg(crate::theme::colors::TEAL));

        println!("\n{}", style("BOF (Beacon Object Files)").fg(crate::theme::colors::LAVENDER).bold());
        println!("  {}                List BOFs in catalog", style("bof list").fg(crate::theme::colors::TEAL));
        println!("  {} {}         Show BOF details", style("bof show").fg(crate::theme::colors::TEAL), style("<id>").fg(crate::theme::colors::PEACH));
        println!("  {} {} {}   Execute BOF on session", style("bof execute").fg(crate::theme::colors::TEAL), style("<id>").fg(crate::theme::colors::PEACH), style("[args]").fg(crate::theme::colors::PEACH));
        println!("  {} {}    Validate compatibility", style("bof validate").fg(crate::theme::colors::TEAL), style("<id>").fg(crate::theme::colors::PEACH));
        println!("  {} {}     Execution history", style("bof history").fg(crate::theme::colors::TEAL), style("[id]").fg(crate::theme::colors::PEACH));
        println!("  {} {}       Delete BOF", style("bof delete").fg(crate::theme::colors::TEAL), style("<id>").fg(crate::theme::colors::PEACH));

        println!("\n{}", style("TASKS").fg(crate::theme::colors::LAVENDER).bold());
        println!("  {}              List tasks for session", style("tasks").fg(crate::theme::colors::TEAL));
        println!("  {}          List all tasks", style("tasks all").fg(crate::theme::colors::TEAL));
        println!("  {} {}     Show task details", style("task show").fg(crate::theme::colors::TEAL), style("<id>").fg(crate::theme::colors::PEACH));
        println!("  {} {}   Cancel task", style("task cancel").fg(crate::theme::colors::TEAL), style("<id>").fg(crate::theme::colors::PEACH));

        println!("\n{}", style("JOBS").fg(crate::theme::colors::LAVENDER).bold());
        println!("  {}              List jobs", style("jobs list").fg(crate::theme::colors::TEAL));
        println!("  {} {}      Show job details", style("jobs show").fg(crate::theme::colors::TEAL), style("<id>").fg(crate::theme::colors::PEACH));
        println!("  {} {}      Kill job", style("jobs kill").fg(crate::theme::colors::TEAL), style("<id>").fg(crate::theme::colors::PEACH));
        println!("  {} {}    Show job output", style("jobs output").fg(crate::theme::colors::TEAL), style("<id>").fg(crate::theme::colors::PEACH));
        println!("  {}             Clean completed jobs", style("jobs clean").fg(crate::theme::colors::TEAL));

        println!("\n{}", style("LOOT").fg(crate::theme::colors::LAVENDER).bold());
        println!("  {}                   List all loot", style("loot list").fg(crate::theme::colors::TEAL));
        println!("  {} {}         Search loot (server-side FTS5)", style("loot search").fg(crate::theme::colors::TEAL), style("<query>").fg(crate::theme::colors::PEACH));
        println!("  {} {}          Export loot (.json/.csv/.md)", style("loot export").fg(crate::theme::colors::TEAL), style("<path>").fg(crate::theme::colors::PEACH));
        println!("  {} {}  Export hashes (hashcat)", style("loot export-hashcat").fg(crate::theme::colors::TEAL), style("<path>").fg(crate::theme::colors::PEACH));
        println!("  {} {}     Export hashes (JtR)", style("loot export-jtr").fg(crate::theme::colors::TEAL), style("<path>").fg(crate::theme::colors::PEACH));
        println!("  {}                   Show loot statistics", style("loot stats").fg(crate::theme::colors::TEAL));
        println!("  {} {}            Show loot details", style("loot show").fg(crate::theme::colors::TEAL), style("<id>").fg(crate::theme::colors::PEACH));
        println!("  {} {}          Delete loot entry", style("loot delete").fg(crate::theme::colors::TEAL), style("<id>").fg(crate::theme::colors::PEACH));

        println!("\n{}", style("MODULES").fg(crate::theme::colors::LAVENDER).bold());
        println!("  {}           List available modules", style("modules list").fg(crate::theme::colors::TEAL));
        println!("  {} {}    Load module onto session", style("modules load").fg(crate::theme::colors::TEAL), style("<name>").fg(crate::theme::colors::PEACH));
        println!("  {} {}  Unload module from session", style("modules unload").fg(crate::theme::colors::PEACH), style("<name>").fg(crate::theme::colors::PEACH));

        println!("\n{}", style("LISTENERS").fg(crate::theme::colors::LAVENDER).bold());
        println!("  {}        List all listeners", style("listeners").fg(crate::theme::colors::TEAL));
        println!("  {} {} {} {}  Start listener", style("listener start").fg(crate::theme::colors::TEAL), style("<type>").fg(crate::theme::colors::PEACH), style("<host>").fg(crate::theme::colors::PEACH), style("<port>").fg(crate::theme::colors::PEACH));
        println!("  {} {}    Stop listener", style("listener stop").fg(crate::theme::colors::TEAL), style("<id>").fg(crate::theme::colors::PEACH));

        println!("\n{}", style("PAYLOAD").fg(crate::theme::colors::LAVENDER).bold());
        println!("  {}            List generated payloads", style("payload list").fg(crate::theme::colors::TEAL));
        println!("  {} {} {} {}  Generate payload", style("payload generate").fg(crate::theme::colors::TEAL), style("<format>").fg(crate::theme::colors::PEACH), style("<listener-id>").fg(crate::theme::colors::PEACH), style("<output>").fg(crate::theme::colors::PEACH));
        println!("  {} {}       Show payload details", style("payload show").fg(crate::theme::colors::TEAL), style("<id>").fg(crate::theme::colors::PEACH));
        println!("  {} {}     Delete payload", style("payload delete").fg(crate::theme::colors::TEAL), style("<id>").fg(crate::theme::colors::PEACH));

        println!("\n{}", style("PORT FORWARDING").fg(crate::theme::colors::LAVENDER).bold());
        println!("  {}           List port forwards", style("portfwd list").fg(crate::theme::colors::TEAL));
        println!("  {} {} {}  Start port forward", style("portfwd start").fg(crate::theme::colors::TEAL), style("<port>").fg(crate::theme::colors::PEACH), style("<addr>").fg(crate::theme::colors::PEACH));
        println!("  {} {}       Stop port forward", style("portfwd stop").fg(crate::theme::colors::TEAL), style("<id>").fg(crate::theme::colors::PEACH));

        println!("\n{}", style("MESH NETWORKING").fg(crate::theme::colors::LAVENDER).bold());
        println!("  {}         Show mesh topology", style("mesh topology").fg(crate::theme::colors::TEAL));
        println!("  {} {} {} {} {}  Connect to peer", style("mesh connect").fg(crate::theme::colors::TEAL), style("<peer>").fg(crate::theme::colors::PEACH), style("<transport>").fg(crate::theme::colors::PEACH), style("<addr>").fg(crate::theme::colors::PEACH), style("<port>").fg(crate::theme::colors::PEACH));
        println!("  {} {}   Disconnect from peer", style("mesh disconnect").fg(crate::theme::colors::TEAL), style("<peer>").fg(crate::theme::colors::PEACH));
        println!("  {} {}        Set mesh role", style("mesh role").fg(crate::theme::colors::TEAL), style("<role>").fg(crate::theme::colors::PEACH));
        println!("  {} {} {} {}  Start listener", style("mesh listen").fg(crate::theme::colors::TEAL), style("<port>").fg(crate::theme::colors::PEACH), style("<transport>").fg(crate::theme::colors::PEACH), style("[addr]").fg(crate::theme::colors::PEACH));
        println!("  {} {} {}   Compute route", style("mesh route").fg(crate::theme::colors::TEAL), style("<from>").fg(crate::theme::colors::PEACH), style("<to>").fg(crate::theme::colors::PEACH));

        println!("\n{}", style("SOCKS PROXY").fg(crate::theme::colors::LAVENDER).bold());
        println!("  {}              List SOCKS proxies", style("socks list").fg(crate::theme::colors::TEAL));
        println!("  {} {} {} {} {}  Start SOCKS proxy", style("socks start").fg(crate::theme::colors::TEAL), style("<host>").fg(crate::theme::colors::PEACH), style("<port>").fg(crate::theme::colors::PEACH), style("[ver]").fg(crate::theme::colors::PEACH), style("[rev]").fg(crate::theme::colors::PEACH));
        println!("  {} {}       Stop SOCKS proxy", style("socks stop").fg(crate::theme::colors::TEAL), style("<id>").fg(crate::theme::colors::PEACH));
        println!("  {} {}      Get proxy statistics", style("socks stats").fg(crate::theme::colors::TEAL), style("<id>").fg(crate::theme::colors::PEACH));

        println!("\n{}", style("COLLABORATION").fg(crate::theme::colors::LAVENDER).bold());
        println!("  {}            List online operators", style("collab online").fg(crate::theme::colors::TEAL));
        println!("  {} {} {}  Lock session", style("collab lock").fg(crate::theme::colors::TEAL), style("<id>").fg(crate::theme::colors::PEACH), style("[reason]").fg(crate::theme::colors::PEACH));
        println!("  {} {}      Unlock session", style("collab unlock").fg(crate::theme::colors::TEAL), style("<id>").fg(crate::theme::colors::PEACH));
        println!("  {}             List session locks", style("collab locks").fg(crate::theme::colors::TEAL));
        println!("  {} {}   Send chat message", style("collab chat").fg(crate::theme::colors::TEAL), style("<msg>").fg(crate::theme::colors::PEACH));
        println!("  {} {}   Get chat history", style("collab history").fg(crate::theme::colors::TEAL), style("[limit]").fg(crate::theme::colors::PEACH));
        println!("  {}             Collaboration stats", style("collab stats").fg(crate::theme::colors::TEAL));

        println!("\n{}", style("OPERATOR MANAGEMENT").fg(crate::theme::colors::LAVENDER).bold());
        println!("  {}          List all operators", style("operators list").fg(crate::theme::colors::TEAL));
        println!("  {} {} {} {}  Create operator", style("operators create").fg(crate::theme::colors::TEAL), style("<user>").fg(crate::theme::colors::PEACH), style("<pass>").fg(crate::theme::colors::PEACH), style("<role>").fg(crate::theme::colors::PEACH));
        println!("  {} {} {}  Update operator", style("operators update").fg(crate::theme::colors::TEAL), style("<id>").fg(crate::theme::colors::PEACH), style("[options]").fg(crate::theme::colors::PEACH));
        println!("  {} {}      Delete operator", style("operators delete").fg(crate::theme::colors::TEAL), style("<id>").fg(crate::theme::colors::PEACH));

        println!("\n{}", style("REPORTING").fg(crate::theme::colors::LAVENDER).bold());
        println!("  {}              List all reports", style("report list").fg(crate::theme::colors::TEAL));
        println!("  {} {} {} {}  Generate report", style("report generate").fg(crate::theme::colors::TEAL), style("<title>").fg(crate::theme::colors::PEACH), style("<type>").fg(crate::theme::colors::PEACH), style("<fmt>").fg(crate::theme::colors::PEACH));
        println!("  {} {}          Show report details", style("report show").fg(crate::theme::colors::TEAL), style("<id>").fg(crate::theme::colors::PEACH));
        println!("  {} {}        Delete report\n", style("report delete").fg(crate::theme::colors::TEAL), style("<id>").fg(crate::theme::colors::PEACH));
    } else {
        println!("\nGLOBAL COMMANDS");
        println!("  sessions              List all sessions");
        println!("  sessions --tag <tag>  List sessions with tag");
        println!("  use <id>              Select a session");
        println!("  back                  Background current session");
        println!("  session info <id>     Show session details");
        println!("  session retire <id>   Retire session");
        println!("  session delete <id>   Delete session");
        println!("  session burn <id>     Burn session (destroy implant)");
        println!("  session tag <id> <tag>    Add tag to session");
        println!("  session untag <id> <tag>  Remove tag from session");
        println!("  whoami                Show current operator");
        println!("  help                  Show this help");
        println!("  exit                  Exit the operator");
        println!("  clear                 Clear screen");

        println!("\nSESSION COMMANDS");
        println!("  shell <cmd>           Execute shell command");
        println!("  upload <local> <remote>   Upload file to implant (auto-chunks >10MB)");
        println!("  download <remote> <local> Download file from implant");
        println!("  cd <path>             Change directory");
        println!("  pwd                   Print working directory");
        println!("  ls [path]             List directory");
        println!("  ps                    List processes");
        println!("  sleep <sec>           Set callback interval (seconds, legacy)");
        println!("  config interval <sec> Update checkin interval");
        println!("  config jitter <pct>   Update jitter percent (0-100)");
        println!("  burn                  Burn implant");
        println!("  screenshot            Take screenshot");

        println!("\nINJECT");
        println!("  inject shellcode <pid> <file> [tech]  Inject shellcode");
        println!("  inject list-techniques                List techniques");

        println!("\nBOF (Beacon Object Files)");
        println!("  bof list                  List BOFs in catalog");
        println!("  bof show <id>             Show BOF details");
        println!("  bof execute <id> [args]   Execute BOF on session");
        println!("  bof validate <id>         Validate compatibility");
        println!("  bof history [id] [limit]  Execution history");
        println!("  bof delete <id>           Delete BOF");

        println!("\nTASKS");
        println!("  tasks                 List tasks for session");
        println!("  tasks all             List all tasks");
        println!("  task show <id>        Show task details");
        println!("  task cancel <id>      Cancel task");

        println!("\nJOBS");
        println!("  jobs list             List jobs");
        println!("  jobs show <id>        Show job details");
        println!("  jobs kill <id>        Kill job");
        println!("  jobs output <id>      Show job output");
        println!("  jobs clean            Clean completed jobs");

        println!("\nLOOT");
        println!("  loot list                  List all loot");
        println!("  loot search <query>        Search loot (server-side FTS5)");
        println!("  loot export <path>         Export loot (.json/.csv/.md)");
        println!("  loot export-hashcat <path> Export hashes (hashcat format)");
        println!("  loot export-jtr <path>     Export hashes (John the Ripper format)");
        println!("  loot stats                 Show loot statistics");
        println!("  loot show <id>             Show loot details");
        println!("  loot delete <id>           Delete loot entry");

        println!("\nMODULES");
        println!("  modules list          List available modules");
        println!("  modules load <name>   Load module onto session");
        println!("  modules unload <name> Unload module from session");

        println!("\nLISTENERS");
        println!("  listeners             List all listeners");
        println!("  listener start <type> <host> <port>  Start listener");
        println!("  listener stop <id>    Stop listener");

        println!("\nPAYLOAD");
        println!("  payload list          List generated payloads");
        println!("  payload generate <format> <listener-id> <output>  Generate payload");
        println!("  payload show <id>     Show payload details");
        println!("  payload delete <id>   Delete payload");

        println!("\nPORT FORWARDING");
        println!("  portfwd list          List port forwards");
        println!("  portfwd start <port> <addr>  Start port forward");
        println!("  portfwd stop <id>     Stop port forward");

        println!("\nMESH NETWORKING");
        println!("  mesh topology         Show mesh topology");
        println!("  mesh connect <peer> <transport> <addr> <port>  Connect to peer");
        println!("  mesh disconnect <peer>  Disconnect from peer");
        println!("  mesh role <role>      Set mesh role (leaf/relay/hub)");
        println!("  mesh listen <port> <transport> [addr]  Start listener");
        println!("  mesh route <from> <to>  Compute route");

        println!("\nSOCKS PROXY");
        println!("  socks list            List SOCKS proxies");
        println!("  socks start <host> <port> [ver] [rev]  Start SOCKS proxy");
        println!("  socks stop <id>       Stop SOCKS proxy");
        println!("  socks stats <id>      Get proxy statistics");

        println!("\nCOLLABORATION");
        println!("  collab online         List online operators");
        println!("  collab lock <id> [reason]  Lock session");
        println!("  collab unlock <id>    Unlock session");
        println!("  collab locks          List session locks");
        println!("  collab chat <msg>     Send chat message");
        println!("  collab history [limit]  Get chat history");
        println!("  collab stats          Collaboration stats");

        println!("\nOPERATOR MANAGEMENT");
        println!("  operators list        List all operators");
        println!("  operators create <user> <pass> <role>  Create operator");
        println!("  operators update <id> [options]  Update operator");
        println!("  operators delete <id>  Delete operator");

        println!("\nREPORTING");
        println!("  report list           List all reports");
        println!("  report generate <title> <type> <fmt>  Generate report");
        println!("  report show <id>      Show report details");
        println!("  report delete <id>    Delete report\n");
    }
}
