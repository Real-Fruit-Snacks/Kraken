//! Report type definitions

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// A complete report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Report {
    pub id: Uuid,
    pub title: String,
    pub report_type: ReportType,
    pub generated_at: DateTime<Utc>,
    pub generated_by: String,
    pub sections: Vec<ReportSection>,
    pub metadata: ReportMetadata,
}

/// Type of report
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReportType {
    /// Full engagement report with all sessions
    Engagement,
    /// Single session timeline
    SessionTimeline,
    /// Credentials and secrets found
    LootSummary,
    /// Indicators of compromise for blue team
    Indicators,
    /// Executive summary (non-technical)
    Executive,
}

/// A section within a report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportSection {
    pub title: String,
    pub content: SectionContent,
}

/// Content types for report sections
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SectionContent {
    /// Markdown text
    Text { markdown: String },
    /// List of sessions
    SessionList { sessions: Vec<SessionSummary> },
    /// Timeline of events
    Timeline { events: Vec<TimelineEvent> },
    /// List of loot items
    LootList { items: Vec<LootItem> },
    /// Chart/graph
    Chart {
        chart_type: ChartType,
        data: Vec<ChartDataPoint>,
    },
    /// Attack path graph
    AttackGraph {
        nodes: Vec<AttackNode>,
        edges: Vec<AttackEdge>,
    },
    /// List of IOCs
    Iocs { indicators: Vec<Ioc> },
}

/// Report metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportMetadata {
    pub engagement_name: String,
    pub client_name: Option<String>,
    pub date_range: (DateTime<Utc>, DateTime<Utc>),
    pub session_count: u32,
    pub host_count: u32,
    pub credential_count: u32,
}

/// Summary of a session for reports
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionSummary {
    pub id: Uuid,
    pub hostname: String,
    pub username: String,
    pub external_ip: String,
    pub internal_ip: Option<String>,
    pub process_name: Option<String>,
    pub process_id: Option<u32>,
    pub first_seen: DateTime<Utc>,
    pub last_seen: Option<DateTime<Utc>>,
    pub state: String,
}

/// Summary of a task for reports
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskSummary {
    pub id: Uuid,
    pub session_id: Uuid,
    pub task_type: String,
    pub created_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
    pub success: bool,
    pub target_path: Option<String>,
}

/// A loot item for reports
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LootItem {
    pub id: Uuid,
    pub session_id: Uuid,
    pub loot_type: LootType,
    pub source: String,
    pub collected_at: DateTime<Utc>,
}

/// Type of loot
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum LootType {
    Credential {
        username: String,
        credential_type: String,
    },
    File {
        path: String,
        size: u64,
    },
    Screenshot {
        width: u32,
        height: u32,
    },
    Token {
        token_type: String,
    },
    Other {
        description: String,
    },
}

/// Timeline event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelineEvent {
    pub timestamp: DateTime<Utc>,
    pub event_type: String,
    pub description: String,
    pub session_id: Option<Uuid>,
}

/// Chart types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChartType {
    Pie,
    Bar,
    Line,
}

/// Data point for charts
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChartDataPoint {
    pub label: String,
    pub value: f64,
}

/// Attack graph node
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackNode {
    pub id: String,
    pub label: String,
    pub node_type: String,
}

/// Attack graph edge
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackEdge {
    pub from: String,
    pub to: String,
    pub label: String,
}

/// Indicator of Compromise
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ioc {
    pub ioc_type: IocType,
    pub value: String,
    pub context: String,
    pub first_seen: DateTime<Utc>,
}

/// Types of IOCs
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IocType {
    IpAddress,
    Domain,
    FilePath,
    FileHash,
    ProcessName,
    RegistryKey,
    PipeName,
    ServiceName,
}

impl std::fmt::Display for IocType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IocType::IpAddress => write!(f, "IP Address"),
            IocType::Domain => write!(f, "Domain"),
            IocType::FilePath => write!(f, "File Path"),
            IocType::FileHash => write!(f, "File Hash"),
            IocType::ProcessName => write!(f, "Process Name"),
            IocType::RegistryKey => write!(f, "Registry Key"),
            IocType::PipeName => write!(f, "Pipe Name"),
            IocType::ServiceName => write!(f, "Service Name"),
        }
    }
}

impl std::fmt::Display for ReportType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReportType::Engagement => write!(f, "Engagement Report"),
            ReportType::SessionTimeline => write!(f, "Session Timeline"),
            ReportType::LootSummary => write!(f, "Loot Summary"),
            ReportType::Indicators => write!(f, "Indicators of Compromise"),
            ReportType::Executive => write!(f, "Executive Summary"),
        }
    }
}
