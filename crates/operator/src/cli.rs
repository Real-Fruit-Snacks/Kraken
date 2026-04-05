//! CLI state management and prompt rendering

use anyhow::Result;
use chrono::{DateTime, Utc};
use rustyline::completion::{Completer, FilenameCompleter, Pair};
use rustyline::highlight::Highlighter;
use rustyline::hint::Hinter;
use rustyline::validate::Validator;
use rustyline::{Context, Helper};
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, RwLock};

use crate::client::KrakenClient;
use crate::display::ImplantInfo;
use crate::file_browser::FileBrowserState;
use crate::history::History;
use crate::theme::Theme;

/// CLI state
pub struct CliState {
    pub client: KrakenClient,
    pub server_addr: String,
    active_session: Option<ImplantInfo>,
    known_implants: Vec<ImplantInfo>,
    pub history: History,
    file_browser: HashMap<Vec<u8>, FileBrowserState>,
}

impl CliState {
    /// Create new CLI state and connect to server
    pub async fn new(server_addr: &str) -> Result<Self> {
        let client = KrakenClient::connect(server_addr).await?;
        let history = History::new()?;

        Ok(Self {
            client,
            server_addr: server_addr.to_string(),
            active_session: None,
            known_implants: Vec::new(),
            history,
            file_browser: HashMap::new(),
        })
    }

    /// Get active session
    pub fn active_session(&self) -> Option<&ImplantInfo> {
        self.active_session.as_ref()
    }

    /// Set active session
    pub fn set_active_session(&mut self, session: ImplantInfo) {
        self.active_session = Some(session);
    }

    /// Clear active session
    pub fn clear_active_session(&mut self) {
        self.active_session = None;
    }

    /// Get known implants
    pub fn get_implants(&self) -> &[ImplantInfo] {
        &self.known_implants
    }

    /// Refresh implants cache from server
    pub async fn refresh_implants(&mut self) -> Result<()> {
        let implants = self.client.list_implants().await?;

        self.known_implants = implants
            .iter()
            .map(|imp| {
                // Extract short ID (first 4 bytes as hex)
                let short_id = if imp.id.is_some() {
                    let id_bytes = imp.id.as_ref().unwrap().value.as_slice();
                    if id_bytes.len() >= 4 {
                        hex::encode(&id_bytes[..4])
                    } else {
                        hex::encode(id_bytes)
                    }
                } else {
                    "unknown".to_string()
                };

                // Map state enum to string
                let state = match imp.state {
                    0 => "staging",
                    1 => "active",
                    2 => "lost",
                    3 => "burned",
                    4 => "retired",
                    _ => "unknown",
                };

                // Extract system info
                let (hostname, username, os) = if let Some(ref sysinfo) = imp.system_info {
                    (
                        sysinfo.hostname.clone(),
                        sysinfo.username.clone(),
                        sysinfo.os_name.clone(),
                    )
                } else {
                    ("unknown".to_string(), "unknown".to_string(), "unknown".to_string())
                };

                // Format last seen timestamp
                let last_seen = if let Some(ref ts) = imp.last_seen {
                    let secs = ts.millis / 1000;
                    if let Some(dt) = DateTime::<Utc>::from_timestamp(secs, 0) {
                        dt.format("%H:%M:%S").to_string()
                    } else {
                        "never".to_string()
                    }
                } else {
                    "never".to_string()
                };

                ImplantInfo {
                    id: short_id,
                    full_id: imp.id.as_ref().map(|id| id.value.clone()).unwrap_or_default(),
                    name: imp.name.clone(),
                    state: state.to_string(),
                    hostname,
                    username,
                    os,
                    last_seen,
                    tags: imp.tags.clone(),
                }
            })
            .collect();

        Ok(())
    }

    /// Get known implant IDs for tab completion
    pub fn known_implant_ids(&self) -> Vec<String> {
        self.known_implants.iter().map(|i| i.id.clone()).collect()
    }

    /// Get all unique tags from known implants
    pub fn known_tags(&self) -> Vec<String> {
        let mut tags: HashSet<String> = HashSet::new();
        for implant in &self.known_implants {
            for tag in &implant.tags {
                tags.insert(tag.clone());
            }
        }
        let mut tag_list: Vec<String> = tags.into_iter().collect();
        tag_list.sort();
        tag_list
    }

    /// Get or create file browser state for a session
    pub fn file_browser_state(&mut self, session_id: &[u8]) -> &mut FileBrowserState {
        self.file_browser.entry(session_id.to_vec()).or_default()
    }

    /// Generate prompt string
    pub fn prompt(&self) -> String {
        if Theme::is_interactive() {
            if let Some(ref session) = self.active_session {
                format!(
                    "{} ({}) {} ",
                    Theme::prompt().apply_to("kraken"),
                    Theme::prompt_session().apply_to(&session.id),
                    Theme::prompt_arrow().apply_to(">")
                )
            } else {
                format!(
                    "{} {} ",
                    Theme::prompt().apply_to("kraken"),
                    Theme::prompt_arrow().apply_to(">")
                )
            }
        } else {
            if self.active_session.is_some() {
                let session_id = &self.active_session.as_ref().unwrap().id;
                format!("kraken ({}) > ", session_id)
            } else {
                "kraken > ".to_string()
            }
        }
    }
}

/// Shared completion data updated from CLI state
#[derive(Clone, Default)]
pub struct CompletionData {
    pub session_ids: Vec<String>,
    pub tags: Vec<String>,
}

/// Rustyline helper for tab completion
pub struct KrakenHelper {
    file_completer: FilenameCompleter,
    commands: Vec<String>,
    session_commands: Vec<String>,
    completion_data: Arc<RwLock<CompletionData>>,
}

impl KrakenHelper {
    pub fn new() -> Self {
        let commands = vec![
            "sessions", "use", "back", "help", "exit", "quit", "clear", "cls",
            "jobs", "loot", "modules", "pstree", "pushd", "popd", "dirs",
        ]
        .into_iter()
        .map(String::from)
        .collect();

        let session_commands = vec![
            "shell", "upload", "download", "cd", "pwd", "ls", "ps",
            "sleep", "burn", "screenshot", "portfwd", "wifi", "inject",
        ]
        .into_iter()
        .map(String::from)
        .collect();

        Self {
            file_completer: FilenameCompleter::new(),
            commands,
            session_commands,
            completion_data: Arc::new(RwLock::new(CompletionData::default())),
        }
    }

    /// Get shared completion data handle for updates
    #[allow(dead_code)]
    pub fn completion_data(&self) -> Arc<RwLock<CompletionData>> {
        Arc::clone(&self.completion_data)
    }

    /// Update completion data from CLI state
    pub fn update_from_cli(&self, cli: &CliState) {
        if let Ok(mut data) = self.completion_data.write() {
            data.session_ids = cli.known_implant_ids();
            data.tags = cli.known_tags();
        }
    }

    /// Get all available commands (context-aware)
    #[allow(dead_code)]
    pub fn all_commands(&self, has_session: bool) -> Vec<String> {
        let mut all = self.commands.clone();
        if has_session {
            all.extend(self.session_commands.clone());
        }
        all.sort();
        all
    }
}

impl Completer for KrakenHelper {
    type Candidate = Pair;

    fn complete(
        &self,
        line: &str,
        pos: usize,
        _ctx: &Context,
    ) -> rustyline::Result<(usize, Vec<Self::Candidate>)> {
        let parts: Vec<&str> = line[..pos].split_whitespace().collect();

        if parts.is_empty() || (parts.len() == 1 && !line.ends_with(' ')) {
            // Complete command names
            let prefix = parts.first().copied().unwrap_or("");
            let candidates: Vec<Pair> = self
                .commands
                .iter()
                .chain(self.session_commands.iter())
                .filter(|cmd| cmd.starts_with(prefix))
                .map(|cmd| Pair {
                    display: cmd.clone(),
                    replacement: cmd.clone(),
                })
                .collect();

            Ok((pos - prefix.len(), candidates))
        } else if parts.len() >= 1 {
            // Complete subcommands or arguments
            match parts[0] {
                "use" if parts.len() == 1 || (parts.len() == 2 && !line.ends_with(' ')) => {
                    // Complete session IDs for "use" command
                    let prefix = parts.get(1).copied().unwrap_or("");
                    let data = self.completion_data.read().ok();
                    let candidates: Vec<Pair> = data
                        .as_ref()
                        .map(|d| {
                            d.session_ids
                                .iter()
                                .filter(|id| id.starts_with(prefix))
                                .map(|id| Pair {
                                    display: id.clone(),
                                    replacement: id.clone(),
                                })
                                .collect()
                        })
                        .unwrap_or_default();
                    Ok((pos - prefix.len(), candidates))
                }
                "sessions" if parts.len() >= 2 => {
                    // Handle sessions subcommands with additional arguments
                    match parts[1] {
                        "tag" if parts.len() == 3 || (parts.len() == 4 && !line.ends_with(' ')) => {
                            // sessions tag <session_id> <tag>
                            if parts.len() == 3 && !line.ends_with(' ') {
                                // Complete session ID
                                let prefix = parts.get(2).copied().unwrap_or("");
                                let data = self.completion_data.read().ok();
                                let candidates: Vec<Pair> = data
                                    .as_ref()
                                    .map(|d| {
                                        d.session_ids
                                            .iter()
                                            .filter(|id| id.starts_with(prefix))
                                            .map(|id| Pair {
                                                display: id.clone(),
                                                replacement: id.clone(),
                                            })
                                            .collect()
                                    })
                                    .unwrap_or_default();
                                Ok((pos - prefix.len(), candidates))
                            } else {
                                // Complete tag name (4th argument)
                                let prefix = parts.get(3).copied().unwrap_or("");
                                let data = self.completion_data.read().ok();
                                let candidates: Vec<Pair> = data
                                    .as_ref()
                                    .map(|d| {
                                        d.tags
                                            .iter()
                                            .filter(|tag| tag.starts_with(prefix))
                                            .map(|tag| Pair {
                                                display: tag.clone(),
                                                replacement: tag.clone(),
                                            })
                                            .collect()
                                    })
                                    .unwrap_or_default();
                                Ok((pos - prefix.len(), candidates))
                            }
                        }
                        "list-tag" if parts.len() == 2 || (parts.len() == 3 && !line.ends_with(' ')) => {
                            // sessions list-tag <tag>
                            let prefix = parts.get(2).copied().unwrap_or("");
                            let data = self.completion_data.read().ok();
                            let candidates: Vec<Pair> = data
                                .as_ref()
                                .map(|d| {
                                    d.tags
                                        .iter()
                                        .filter(|tag| tag.starts_with(prefix))
                                        .map(|tag| Pair {
                                            display: tag.clone(),
                                            replacement: tag.clone(),
                                        })
                                        .collect()
                                })
                                .unwrap_or_default();
                            Ok((pos - prefix.len(), candidates))
                        }
                        _ if parts.len() == 2 && !line.ends_with(' ') => {
                            // Complete sessions subcommands
                            let prefix = parts.get(1).copied().unwrap_or("");
                            let subcmds = vec!["list", "tag", "list-tag", "untag"];
                            let candidates: Vec<Pair> = subcmds
                                .into_iter()
                                .filter(|cmd| cmd.starts_with(prefix))
                                .map(|cmd| Pair {
                                    display: cmd.to_string(),
                                    replacement: cmd.to_string(),
                                })
                                .collect();
                            Ok((pos - prefix.len(), candidates))
                        }
                        _ => Ok((pos, vec![])),
                    }
                }
                "jobs" if parts.len() >= 2 => {
                    match parts[1] {
                        "show" | "kill" | "output"
                            if parts.len() == 2 || (parts.len() == 3 && !line.ends_with(' ')) =>
                        {
                            // Complete job IDs (mock data for now)
                            let prefix = parts.get(2).copied().unwrap_or("");
                            let job_ids = vec!["1", "2", "3"];
                            let candidates: Vec<Pair> = job_ids
                                .into_iter()
                                .filter(|id| id.starts_with(prefix))
                                .map(|id| Pair {
                                    display: id.to_string(),
                                    replacement: id.to_string(),
                                })
                                .collect();
                            Ok((pos - prefix.len(), candidates))
                        }
                        _ if parts.len() == 2 && !line.ends_with(' ') => {
                            // Complete jobs subcommands
                            let prefix = parts.get(1).copied().unwrap_or("");
                            let subcmds = vec!["list", "show", "kill", "output", "clean"];
                            let candidates: Vec<Pair> = subcmds
                                .into_iter()
                                .filter(|cmd| cmd.starts_with(prefix))
                                .map(|cmd| Pair {
                                    display: cmd.to_string(),
                                    replacement: cmd.to_string(),
                                })
                                .collect();
                            Ok((pos - prefix.len(), candidates))
                        }
                        _ => Ok((pos, vec![])),
                    }
                }
                "loot" if parts.len() == 1 || (parts.len() == 2 && !line.ends_with(' ')) => {
                    let prefix = parts.get(1).copied().unwrap_or("");
                    let subcmds = vec!["list", "search", "export", "hashcat", "jtr", "stats"];
                    let candidates: Vec<Pair> = subcmds
                        .into_iter()
                        .filter(|cmd| cmd.starts_with(prefix))
                        .map(|cmd| Pair {
                            display: cmd.to_string(),
                            replacement: cmd.to_string(),
                        })
                        .collect();
                    Ok((pos - prefix.len(), candidates))
                }
                "ps" if parts.len() == 1 || (parts.len() == 2 && !line.ends_with(' ')) => {
                    let prefix = parts.get(1).copied().unwrap_or("");
                    let subcmds = vec!["tree", "filter"];
                    let candidates: Vec<Pair> = subcmds
                        .into_iter()
                        .filter(|cmd| cmd.starts_with(prefix))
                        .map(|cmd| Pair {
                            display: cmd.to_string(),
                            replacement: cmd.to_string(),
                        })
                        .collect();
                    Ok((pos - prefix.len(), candidates))
                }
                "modules" if parts.len() == 1 || (parts.len() == 2 && !line.ends_with(' ')) => {
                    let prefix = parts.get(1).copied().unwrap_or("");
                    let subcmds = vec!["list", "load", "unload"];
                    let candidates: Vec<Pair> = subcmds
                        .into_iter()
                        .filter(|cmd| cmd.starts_with(prefix))
                        .map(|cmd| Pair {
                            display: cmd.to_string(),
                            replacement: cmd.to_string(),
                        })
                        .collect();
                    Ok((pos - prefix.len(), candidates))
                }
                "portfwd" if parts.len() == 1 || (parts.len() == 2 && !line.ends_with(' ')) => {
                    let prefix = parts.get(1).copied().unwrap_or("");
                    let subcmds = vec!["list", "start", "stop"];
                    let candidates: Vec<Pair> = subcmds
                        .into_iter()
                        .filter(|cmd| cmd.starts_with(prefix))
                        .map(|cmd| Pair {
                            display: cmd.to_string(),
                            replacement: cmd.to_string(),
                        })
                        .collect();
                    Ok((pos - prefix.len(), candidates))
                }
                "inject" if parts.len() == 1 || (parts.len() == 2 && !line.ends_with(' ')) => {
                    let prefix = parts.get(1).copied().unwrap_or("");
                    let subcmds = vec!["shellcode", "list-techniques"];
                    let candidates: Vec<Pair> = subcmds
                        .into_iter()
                        .filter(|cmd| cmd.starts_with(prefix))
                        .map(|cmd| Pair {
                            display: cmd.to_string(),
                            replacement: cmd.to_string(),
                        })
                        .collect();
                    Ok((pos - prefix.len(), candidates))
                }
                "upload" | "download" | "export" => {
                    // File path completion
                    self.file_completer.complete(line, pos, _ctx)
                }
                _ => Ok((pos, vec![])),
            }
        } else {
            Ok((pos, vec![]))
        }
    }
}

impl Hinter for KrakenHelper {
    type Hint = String;

    fn hint(&self, _line: &str, _pos: usize, _ctx: &Context) -> Option<Self::Hint> {
        None
    }
}

impl Highlighter for KrakenHelper {}

impl Validator for KrakenHelper {}

impl Helper for KrakenHelper {}
