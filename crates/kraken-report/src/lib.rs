//! Kraken Reporting Engine
//!
//! Provides report generation and export capabilities for engagements,
//! sessions, loot, and indicators of compromise (IOCs).

mod export;
mod types;

pub use export::{ExportError, HtmlExporter, JsonExporter, ReportExporter};
pub use types::*;

use chrono::{DateTime, Utc};
use std::collections::HashSet;
use uuid::Uuid;

/// Report generation error
#[derive(Debug, thiserror::Error)]
pub enum ReportError {
    #[error("no sessions in range")]
    NoSessions,
    #[error("invalid date range")]
    InvalidDateRange,
    #[error("export error: {0}")]
    Export(#[from] ExportError),
}

/// Options for generating an engagement report
#[derive(Debug, Clone)]
pub struct EngagementReportOptions {
    pub engagement_name: String,
    pub client_name: Option<String>,
    pub operator: String,
    pub start: DateTime<Utc>,
    pub end: DateTime<Utc>,
    pub include_attack_graph: bool,
}

/// Options for generating an IOC report
#[derive(Debug, Clone)]
pub struct IocReportOptions {
    pub engagement_name: String,
    pub operator: String,
    pub start: DateTime<Utc>,
    pub end: DateTime<Utc>,
}

/// Options for generating an executive summary
#[derive(Debug, Clone)]
pub struct ExecutiveReportOptions {
    pub engagement_name: String,
    pub client_name: Option<String>,
    pub operator: String,
    pub start: DateTime<Utc>,
    pub end: DateTime<Utc>,
}

/// Report generator - creates reports from session/task/loot data
pub struct ReportGenerator;

impl ReportGenerator {
    pub fn new() -> Self {
        Self
    }

    /// Generate an engagement report from provided data
    pub fn generate_engagement(
        &self,
        opts: EngagementReportOptions,
        sessions: Vec<SessionSummary>,
        tasks: Vec<TaskSummary>,
        loot: Vec<LootItem>,
    ) -> Result<Report, ReportError> {
        if opts.start >= opts.end {
            return Err(ReportError::InvalidDateRange);
        }

        let mut sections = vec![];

        // Executive summary
        sections.push(ReportSection {
            title: "Executive Summary".into(),
            content: SectionContent::Text {
                markdown: self.generate_executive_summary(&sessions, &tasks, &loot),
            },
        });

        // Session overview
        sections.push(ReportSection {
            title: "Session Overview".into(),
            content: SectionContent::SessionList {
                sessions: sessions.clone(),
            },
        });

        // Activity timeline
        sections.push(ReportSection {
            title: "Activity Timeline".into(),
            content: SectionContent::Timeline {
                events: self.build_timeline(&sessions, &tasks),
            },
        });

        // Loot summary
        if !loot.is_empty() {
            sections.push(ReportSection {
                title: "Credentials & Secrets".into(),
                content: SectionContent::LootList { items: loot.clone() },
            });
        }

        // Statistics
        sections.push(ReportSection {
            title: "Statistics".into(),
            content: SectionContent::Chart {
                chart_type: ChartType::Pie,
                data: self.build_task_distribution(&tasks),
            },
        });

        // Attack graph if requested
        if opts.include_attack_graph && !sessions.is_empty() {
            sections.push(ReportSection {
                title: "Attack Path".into(),
                content: SectionContent::AttackGraph {
                    nodes: self.build_attack_nodes(&sessions, &loot),
                    edges: self.build_attack_edges(&sessions, &tasks),
                },
            });
        }

        let unique_hosts: HashSet<_> = sessions.iter().map(|s| &s.hostname).collect();
        let credential_count = loot
            .iter()
            .filter(|l| matches!(l.loot_type, LootType::Credential { .. }))
            .count();

        Ok(Report {
            id: Uuid::new_v4(),
            title: format!("{} - Engagement Report", opts.engagement_name),
            report_type: ReportType::Engagement,
            generated_at: Utc::now(),
            generated_by: opts.operator,
            sections,
            metadata: ReportMetadata {
                engagement_name: opts.engagement_name,
                client_name: opts.client_name,
                date_range: (opts.start, opts.end),
                session_count: sessions.len() as u32,
                host_count: unique_hosts.len() as u32,
                credential_count: credential_count as u32,
            },
        })
    }

    /// Generate an IOC report for blue team
    pub fn generate_iocs(
        &self,
        opts: IocReportOptions,
        sessions: Vec<SessionSummary>,
        tasks: Vec<TaskSummary>,
    ) -> Result<Report, ReportError> {
        if opts.start >= opts.end {
            return Err(ReportError::InvalidDateRange);
        }

        let mut iocs = vec![];

        // Extract IOCs from sessions
        for session in &sessions {
            // Process names
            if let Some(ref process) = session.process_name {
                iocs.push(Ioc {
                    ioc_type: IocType::ProcessName,
                    value: process.clone(),
                    context: format!("Session on {}", session.hostname),
                    first_seen: session.first_seen,
                });
            }

            // External IPs
            iocs.push(Ioc {
                ioc_type: IocType::IpAddress,
                value: session.external_ip.clone(),
                context: format!("Implant callback from {}", session.hostname),
                first_seen: session.first_seen,
            });
        }

        // Extract IOCs from tasks (file paths, etc.)
        for task in &tasks {
            if let Some(ref path) = task.target_path {
                iocs.push(Ioc {
                    ioc_type: IocType::FilePath,
                    value: path.clone(),
                    context: format!("Task: {}", task.task_type),
                    first_seen: task.created_at,
                });
            }
        }

        // Deduplicate
        iocs.sort_by(|a, b| (&a.ioc_type, &a.value).cmp(&(&b.ioc_type, &b.value)));
        iocs.dedup_by(|a, b| a.ioc_type == b.ioc_type && a.value == b.value);

        let unique_hosts: HashSet<_> = sessions.iter().map(|s| &s.hostname).collect();

        Ok(Report {
            id: Uuid::new_v4(),
            title: format!("{} - Indicators of Compromise", opts.engagement_name),
            report_type: ReportType::Indicators,
            generated_at: Utc::now(),
            generated_by: opts.operator,
            sections: vec![ReportSection {
                title: "Indicators".into(),
                content: SectionContent::Iocs { indicators: iocs },
            }],
            metadata: ReportMetadata {
                engagement_name: opts.engagement_name,
                client_name: None,
                date_range: (opts.start, opts.end),
                session_count: sessions.len() as u32,
                host_count: unique_hosts.len() as u32,
                credential_count: 0,
            },
        })
    }

    /// Generate executive summary report
    pub fn generate_executive(
        &self,
        opts: ExecutiveReportOptions,
        sessions: Vec<SessionSummary>,
        tasks: Vec<TaskSummary>,
        loot: Vec<LootItem>,
    ) -> Result<Report, ReportError> {
        if opts.start >= opts.end {
            return Err(ReportError::InvalidDateRange);
        }

        let unique_hosts: HashSet<_> = sessions.iter().map(|s| &s.hostname).collect();
        let credential_count = loot
            .iter()
            .filter(|l| matches!(l.loot_type, LootType::Credential { .. }))
            .count();

        let summary = self.generate_executive_summary(&sessions, &tasks, &loot);

        Ok(Report {
            id: Uuid::new_v4(),
            title: format!("{} - Executive Summary", opts.engagement_name),
            report_type: ReportType::Executive,
            generated_at: Utc::now(),
            generated_by: opts.operator,
            sections: vec![ReportSection {
                title: "Summary".into(),
                content: SectionContent::Text { markdown: summary },
            }],
            metadata: ReportMetadata {
                engagement_name: opts.engagement_name,
                client_name: opts.client_name,
                date_range: (opts.start, opts.end),
                session_count: sessions.len() as u32,
                host_count: unique_hosts.len() as u32,
                credential_count: credential_count as u32,
            },
        })
    }

    fn generate_executive_summary(
        &self,
        sessions: &[SessionSummary],
        tasks: &[TaskSummary],
        loot: &[LootItem],
    ) -> String {
        let unique_hosts: HashSet<_> = sessions.iter().map(|s| &s.hostname).collect();
        let credential_count = loot
            .iter()
            .filter(|l| matches!(l.loot_type, LootType::Credential { .. }))
            .count();
        let successful_tasks = tasks.iter().filter(|t| t.success).count();

        format!(
            r#"## Overview

During this engagement, the team established **{} sessions** across **{} unique hosts**.

### Key Findings

- **Sessions**: {} implant sessions established
- **Commands Executed**: {} tasks ({} successful)
- **Credentials Recovered**: {}
- **Unique Hosts Compromised**: {}

### Summary

The engagement demonstrated the ability to gain and maintain access to target systems.
{}"#,
            sessions.len(),
            unique_hosts.len(),
            sessions.len(),
            tasks.len(),
            successful_tasks,
            credential_count,
            unique_hosts.len(),
            if credential_count > 0 {
                format!(
                    "A total of {} credentials were recovered during the assessment.",
                    credential_count
                )
            } else {
                "No credentials were recovered during this engagement.".to_string()
            }
        )
    }

    fn build_timeline(
        &self,
        sessions: &[SessionSummary],
        tasks: &[TaskSummary],
    ) -> Vec<TimelineEvent> {
        let mut events = vec![];

        for session in sessions {
            events.push(TimelineEvent {
                timestamp: session.first_seen,
                event_type: "session_start".to_string(),
                description: format!(
                    "Session established on {} ({})",
                    session.hostname, session.username
                ),
                session_id: Some(session.id),
            });

            if let Some(last) = session.last_seen {
                if session.state == "dead" || session.state == "burned" {
                    events.push(TimelineEvent {
                        timestamp: last,
                        event_type: "session_end".to_string(),
                        description: format!("Session ended on {}", session.hostname),
                        session_id: Some(session.id),
                    });
                }
            }
        }

        for task in tasks {
            events.push(TimelineEvent {
                timestamp: task.created_at,
                event_type: "task".to_string(),
                description: format!(
                    "{}: {}",
                    task.task_type,
                    if task.success { "success" } else { "failed" }
                ),
                session_id: Some(task.session_id),
            });
        }

        events.sort_by_key(|e| e.timestamp);
        events
    }

    fn build_task_distribution(&self, tasks: &[TaskSummary]) -> Vec<ChartDataPoint> {
        use std::collections::HashMap;

        let mut counts: HashMap<String, u32> = HashMap::new();
        for task in tasks {
            *counts.entry(task.task_type.clone()).or_insert(0) += 1;
        }

        counts
            .into_iter()
            .map(|(label, value)| ChartDataPoint {
                label,
                value: value as f64,
            })
            .collect()
    }

    fn build_attack_nodes(
        &self,
        sessions: &[SessionSummary],
        loot: &[LootItem],
    ) -> Vec<AttackNode> {
        let mut nodes = vec![];

        // Add host nodes
        let mut seen_hosts = HashSet::new();
        for session in sessions {
            if seen_hosts.insert(&session.hostname) {
                nodes.push(AttackNode {
                    id: format!("host_{}", session.hostname),
                    label: session.hostname.clone(),
                    node_type: "host".to_string(),
                });
            }
        }

        // Add credential nodes
        for item in loot {
            if let LootType::Credential { username, .. } = &item.loot_type {
                nodes.push(AttackNode {
                    id: format!("cred_{}", item.id),
                    label: username.clone(),
                    node_type: "credential".to_string(),
                });
            }
        }

        nodes
    }

    fn build_attack_edges(
        &self,
        sessions: &[SessionSummary],
        _tasks: &[TaskSummary],
    ) -> Vec<AttackEdge> {
        let mut edges = vec![];

        // Connect sessions to hosts
        for session in sessions {
            edges.push(AttackEdge {
                from: format!("host_{}", session.hostname),
                to: format!("session_{}", session.id),
                label: "compromised".to_string(),
            });
        }

        edges
    }
}

impl Default for ReportGenerator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_sessions() -> Vec<SessionSummary> {
        vec![
            SessionSummary {
                id: Uuid::new_v4(),
                hostname: "WORKSTATION01".to_string(),
                username: "jdoe".to_string(),
                external_ip: "192.168.1.100".to_string(),
                internal_ip: Some("10.0.0.50".to_string()),
                process_name: Some("explorer.exe".to_string()),
                process_id: Some(1234),
                first_seen: Utc::now() - chrono::Duration::hours(2),
                last_seen: Some(Utc::now()),
                state: "active".to_string(),
            },
            SessionSummary {
                id: Uuid::new_v4(),
                hostname: "SERVER01".to_string(),
                username: "admin".to_string(),
                external_ip: "192.168.1.10".to_string(),
                internal_ip: Some("10.0.0.10".to_string()),
                process_name: Some("svchost.exe".to_string()),
                process_id: Some(5678),
                first_seen: Utc::now() - chrono::Duration::hours(1),
                last_seen: Some(Utc::now()),
                state: "active".to_string(),
            },
        ]
    }

    fn sample_tasks() -> Vec<TaskSummary> {
        vec![
            TaskSummary {
                id: Uuid::new_v4(),
                session_id: Uuid::new_v4(),
                task_type: "shell".to_string(),
                created_at: Utc::now() - chrono::Duration::minutes(30),
                completed_at: Some(Utc::now() - chrono::Duration::minutes(29)),
                success: true,
                target_path: None,
            },
            TaskSummary {
                id: Uuid::new_v4(),
                session_id: Uuid::new_v4(),
                task_type: "file_download".to_string(),
                created_at: Utc::now() - chrono::Duration::minutes(20),
                completed_at: Some(Utc::now() - chrono::Duration::minutes(19)),
                success: true,
                target_path: Some("C:\\Users\\admin\\secrets.txt".to_string()),
            },
        ]
    }

    fn sample_loot() -> Vec<LootItem> {
        vec![LootItem {
            id: Uuid::new_v4(),
            session_id: Uuid::new_v4(),
            loot_type: LootType::Credential {
                username: "admin".to_string(),
                credential_type: "NTLM".to_string(),
            },
            source: "mimikatz".to_string(),
            collected_at: Utc::now() - chrono::Duration::minutes(15),
        }]
    }

    #[test]
    fn test_generate_engagement_report() {
        let gen = ReportGenerator::new();
        let opts = EngagementReportOptions {
            engagement_name: "Test Engagement".to_string(),
            client_name: Some("Acme Corp".to_string()),
            operator: "operator1".to_string(),
            start: Utc::now() - chrono::Duration::days(1),
            end: Utc::now() + chrono::Duration::hours(1),
            include_attack_graph: true,
        };

        let report = gen
            .generate_engagement(opts, sample_sessions(), sample_tasks(), sample_loot())
            .unwrap();

        assert_eq!(report.report_type, ReportType::Engagement);
        assert!(!report.sections.is_empty());
        assert_eq!(report.metadata.session_count, 2);
        assert_eq!(report.metadata.host_count, 2);
        assert_eq!(report.metadata.credential_count, 1);
    }

    #[test]
    fn test_generate_ioc_report() {
        let gen = ReportGenerator::new();
        let opts = IocReportOptions {
            engagement_name: "Test Engagement".to_string(),
            operator: "operator1".to_string(),
            start: Utc::now() - chrono::Duration::days(1),
            end: Utc::now() + chrono::Duration::hours(1),
        };

        let report = gen
            .generate_iocs(opts, sample_sessions(), sample_tasks())
            .unwrap();

        assert_eq!(report.report_type, ReportType::Indicators);
        assert_eq!(report.sections.len(), 1);

        if let SectionContent::Iocs { indicators } = &report.sections[0].content {
            assert!(!indicators.is_empty());
        } else {
            panic!("expected IOC section");
        }
    }

    #[test]
    fn test_generate_executive_report() {
        let gen = ReportGenerator::new();
        let opts = ExecutiveReportOptions {
            engagement_name: "Test Engagement".to_string(),
            client_name: Some("Acme Corp".to_string()),
            operator: "operator1".to_string(),
            start: Utc::now() - chrono::Duration::days(1),
            end: Utc::now() + chrono::Duration::hours(1),
        };

        let report = gen
            .generate_executive(opts, sample_sessions(), sample_tasks(), sample_loot())
            .unwrap();

        assert_eq!(report.report_type, ReportType::Executive);
    }

    #[test]
    fn test_invalid_date_range() {
        let gen = ReportGenerator::new();
        let opts = EngagementReportOptions {
            engagement_name: "Test".to_string(),
            client_name: None,
            operator: "op".to_string(),
            start: Utc::now(),
            end: Utc::now() - chrono::Duration::hours(1), // Invalid: end before start
            include_attack_graph: false,
        };

        let result = gen.generate_engagement(opts, vec![], vec![], vec![]);
        assert!(matches!(result, Err(ReportError::InvalidDateRange)));
    }

    #[test]
    fn test_timeline_ordering() {
        let gen = ReportGenerator::new();
        let sessions = sample_sessions();
        let tasks = sample_tasks();

        let timeline = gen.build_timeline(&sessions, &tasks);

        // Verify events are sorted by timestamp
        for window in timeline.windows(2) {
            assert!(window[0].timestamp <= window[1].timestamp);
        }
    }
}
