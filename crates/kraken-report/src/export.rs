//! Report export formats

use crate::{ChartType, Ioc, LootItem, LootType, Report, ReportSection, SectionContent, SessionSummary};

/// Export error
#[derive(Debug, thiserror::Error)]
pub enum ExportError {
    #[error("JSON serialization failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error("template error: {0}")]
    Template(String),
}

/// Trait for report exporters
pub trait ReportExporter {
    /// Export a report to bytes
    fn export(&self, report: &Report) -> Result<Vec<u8>, ExportError>;
    /// MIME content type
    fn content_type(&self) -> &'static str;
    /// File extension
    fn file_extension(&self) -> &'static str;
}

/// JSON exporter
pub struct JsonExporter;

impl ReportExporter for JsonExporter {
    fn export(&self, report: &Report) -> Result<Vec<u8>, ExportError> {
        serde_json::to_vec_pretty(report).map_err(ExportError::Json)
    }

    fn content_type(&self) -> &'static str {
        "application/json"
    }

    fn file_extension(&self) -> &'static str {
        "json"
    }
}

/// HTML exporter with embedded template
pub struct HtmlExporter {
    template: String,
}

impl HtmlExporter {
    pub fn new() -> Self {
        Self {
            template: DEFAULT_HTML_TEMPLATE.to_string(),
        }
    }

    pub fn with_template(template: String) -> Self {
        Self { template }
    }

    fn render_section(&self, section: &ReportSection) -> String {
        let mut html = format!(
            "<section class=\"report-section\">\n<h2>{}</h2>\n",
            html_escape(&section.title)
        );

        html.push_str(&match &section.content {
            SectionContent::Text { markdown } => {
                format!("<div class=\"markdown\">{}</div>", render_markdown(markdown))
            }
            SectionContent::SessionList { sessions } => self.render_session_table(sessions),
            SectionContent::Timeline { events } => {
                let mut timeline_html = String::from("<div class=\"timeline\">\n");
                for event in events {
                    timeline_html.push_str(&format!(
                        "<div class=\"timeline-event\">\n\
                         <span class=\"time\">{}</span>\n\
                         <span class=\"type\">{}</span>\n\
                         <span class=\"desc\">{}</span>\n\
                         </div>\n",
                        event.timestamp.format("%Y-%m-%d %H:%M:%S"),
                        html_escape(&event.event_type),
                        html_escape(&event.description)
                    ));
                }
                timeline_html.push_str("</div>");
                timeline_html
            }
            SectionContent::LootList { items } => self.render_loot_table(items),
            SectionContent::Chart { chart_type, data } => {
                let mut chart_html = format!(
                    "<div class=\"chart\" data-type=\"{}\">\n<table class=\"chart-data\">\n",
                    match chart_type {
                        ChartType::Pie => "pie",
                        ChartType::Bar => "bar",
                        ChartType::Line => "line",
                    }
                );
                for point in data {
                    chart_html.push_str(&format!(
                        "<tr><td>{}</td><td>{}</td></tr>\n",
                        html_escape(&point.label),
                        point.value
                    ));
                }
                chart_html.push_str("</table>\n</div>");
                chart_html
            }
            SectionContent::AttackGraph { nodes, edges } => {
                let mut graph_html = String::from("<div class=\"attack-graph\">\n");
                graph_html.push_str("<h3>Nodes</h3>\n<ul>\n");
                for node in nodes {
                    graph_html.push_str(&format!(
                        "<li><strong>{}</strong>: {} ({})</li>\n",
                        html_escape(&node.id),
                        html_escape(&node.label),
                        html_escape(&node.node_type)
                    ));
                }
                graph_html.push_str("</ul>\n<h3>Edges</h3>\n<ul>\n");
                for edge in edges {
                    graph_html.push_str(&format!(
                        "<li>{} --[{}]--> {}</li>\n",
                        html_escape(&edge.from),
                        html_escape(&edge.label),
                        html_escape(&edge.to)
                    ));
                }
                graph_html.push_str("</ul>\n</div>");
                graph_html
            }
            SectionContent::Iocs { indicators } => self.render_ioc_table(indicators),
        });

        html.push_str("</section>\n");
        html
    }

    fn render_session_table(&self, sessions: &[SessionSummary]) -> String {
        let mut html = String::from(
            "<table class=\"data-table sessions\">\n\
             <thead><tr>\
             <th>Hostname</th>\
             <th>Username</th>\
             <th>External IP</th>\
             <th>Process</th>\
             <th>First Seen</th>\
             <th>State</th>\
             </tr></thead>\n<tbody>\n",
        );

        for session in sessions {
            html.push_str(&format!(
                "<tr>\
                 <td>{}</td>\
                 <td>{}</td>\
                 <td>{}</td>\
                 <td>{}</td>\
                 <td>{}</td>\
                 <td class=\"state-{}\">{}</td>\
                 </tr>\n",
                html_escape(&session.hostname),
                html_escape(&session.username),
                html_escape(&session.external_ip),
                session
                    .process_name
                    .as_ref()
                    .map(|p| html_escape(p))
                    .unwrap_or_default(),
                session.first_seen.format("%Y-%m-%d %H:%M:%S"),
                session.state.to_lowercase(),
                html_escape(&session.state)
            ));
        }

        html.push_str("</tbody></table>");
        html
    }

    fn render_loot_table(&self, items: &[LootItem]) -> String {
        let mut html = String::from(
            "<table class=\"data-table loot\">\n\
             <thead><tr>\
             <th>Type</th>\
             <th>Details</th>\
             <th>Source</th>\
             <th>Collected</th>\
             </tr></thead>\n<tbody>\n",
        );

        for item in items {
            let (type_str, details) = match &item.loot_type {
                LootType::Credential {
                    username,
                    credential_type,
                } => ("Credential", format!("{} ({})", username, credential_type)),
                LootType::File { path, size } => {
                    ("File", format!("{} ({} bytes)", path, size))
                }
                LootType::Screenshot { width, height } => {
                    ("Screenshot", format!("{}x{}", width, height))
                }
                LootType::Token { token_type } => ("Token", token_type.clone()),
                LootType::Other { description } => ("Other", description.clone()),
            };

            html.push_str(&format!(
                "<tr>\
                 <td>{}</td>\
                 <td>{}</td>\
                 <td>{}</td>\
                 <td>{}</td>\
                 </tr>\n",
                type_str,
                html_escape(&details),
                html_escape(&item.source),
                item.collected_at.format("%Y-%m-%d %H:%M:%S")
            ));
        }

        html.push_str("</tbody></table>");
        html
    }

    fn render_ioc_table(&self, indicators: &[Ioc]) -> String {
        let mut html = String::from(
            "<table class=\"data-table iocs\">\n\
             <thead><tr>\
             <th>Type</th>\
             <th>Value</th>\
             <th>Context</th>\
             <th>First Seen</th>\
             </tr></thead>\n<tbody>\n",
        );

        for ioc in indicators {
            html.push_str(&format!(
                "<tr>\
                 <td>{}</td>\
                 <td><code>{}</code></td>\
                 <td>{}</td>\
                 <td>{}</td>\
                 </tr>\n",
                ioc.ioc_type,
                html_escape(&ioc.value),
                html_escape(&ioc.context),
                ioc.first_seen.format("%Y-%m-%d %H:%M:%S")
            ));
        }

        html.push_str("</tbody></table>");
        html
    }
}

impl Default for HtmlExporter {
    fn default() -> Self {
        Self::new()
    }
}

impl ReportExporter for HtmlExporter {
    fn export(&self, report: &Report) -> Result<Vec<u8>, ExportError> {
        let mut html = self.template.clone();

        // Replace placeholders
        html = html.replace("{{title}}", &html_escape(&report.title));
        html = html.replace("{{generated_at}}", &report.generated_at.to_rfc3339());
        html = html.replace("{{generated_by}}", &html_escape(&report.generated_by));
        html = html.replace(
            "{{engagement_name}}",
            &html_escape(&report.metadata.engagement_name),
        );
        html = html.replace(
            "{{session_count}}",
            &report.metadata.session_count.to_string(),
        );
        html = html.replace("{{host_count}}", &report.metadata.host_count.to_string());
        html = html.replace(
            "{{credential_count}}",
            &report.metadata.credential_count.to_string(),
        );

        // Render sections
        let mut sections_html = String::new();
        for section in &report.sections {
            sections_html.push_str(&self.render_section(section));
        }
        html = html.replace("{{sections}}", &sections_html);

        Ok(html.into_bytes())
    }

    fn content_type(&self) -> &'static str {
        "text/html"
    }

    fn file_extension(&self) -> &'static str {
        "html"
    }
}

/// Simple HTML escaping
fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#x27;")
}

/// Simple markdown to HTML (basic support)
fn render_markdown(md: &str) -> String {
    let mut html = String::new();
    let mut in_list = false;

    for line in md.lines() {
        let trimmed = line.trim();

        if trimmed.is_empty() {
            if in_list {
                html.push_str("</ul>\n");
                in_list = false;
            }
            continue;
        }

        // Headers
        if let Some(rest) = trimmed.strip_prefix("### ") {
            if in_list {
                html.push_str("</ul>\n");
                in_list = false;
            }
            html.push_str(&format!("<h4>{}</h4>\n", html_escape(rest)));
        } else if let Some(rest) = trimmed.strip_prefix("## ") {
            if in_list {
                html.push_str("</ul>\n");
                in_list = false;
            }
            html.push_str(&format!("<h3>{}</h3>\n", html_escape(rest)));
        } else if let Some(rest) = trimmed.strip_prefix("# ") {
            if in_list {
                html.push_str("</ul>\n");
                in_list = false;
            }
            html.push_str(&format!("<h2>{}</h2>\n", html_escape(rest)));
        }
        // List items
        else if let Some(rest) = trimmed.strip_prefix("- ") {
            if !in_list {
                html.push_str("<ul>\n");
                in_list = true;
            }
            html.push_str(&format!("<li>{}</li>\n", render_inline_markdown(rest)));
        }
        // Paragraphs
        else {
            if in_list {
                html.push_str("</ul>\n");
                in_list = false;
            }
            html.push_str(&format!("<p>{}</p>\n", render_inline_markdown(trimmed)));
        }
    }

    if in_list {
        html.push_str("</ul>\n");
    }

    html
}

/// Render inline markdown (bold, etc.)
fn render_inline_markdown(text: &str) -> String {
    let mut result = html_escape(text);

    // Bold: **text**
    while let Some(start) = result.find("**") {
        if let Some(end) = result[start + 2..].find("**") {
            let before = &result[..start];
            let bold = &result[start + 2..start + 2 + end];
            let after = &result[start + 2 + end + 2..];
            result = format!("{}<strong>{}</strong>{}", before, bold, after);
        } else {
            break;
        }
    }

    result
}

/// Default HTML template
const DEFAULT_HTML_TEMPLATE: &str = r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{title}}</title>
    <style>
        :root {
            --bg-primary: #1a1a2e;
            --bg-secondary: #16213e;
            --text-primary: #eee;
            --text-secondary: #aaa;
            --accent: #e94560;
            --success: #4ade80;
            --warning: #fbbf24;
        }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            line-height: 1.6;
            margin: 0;
            padding: 2rem;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
        }
        header {
            border-bottom: 2px solid var(--accent);
            padding-bottom: 1rem;
            margin-bottom: 2rem;
        }
        h1 { color: var(--accent); margin: 0; }
        .meta { color: var(--text-secondary); font-size: 0.9rem; }
        .report-section {
            background: var(--bg-secondary);
            border-radius: 8px;
            padding: 1.5rem;
            margin-bottom: 1.5rem;
        }
        .report-section h2 {
            color: var(--accent);
            margin-top: 0;
            border-bottom: 1px solid var(--accent);
            padding-bottom: 0.5rem;
        }
        .data-table {
            width: 100%;
            border-collapse: collapse;
            margin: 1rem 0;
        }
        .data-table th, .data-table td {
            padding: 0.75rem;
            text-align: left;
            border-bottom: 1px solid #333;
        }
        .data-table th {
            background: var(--bg-primary);
            color: var(--accent);
        }
        .data-table tr:hover {
            background: rgba(233, 69, 96, 0.1);
        }
        .state-active { color: var(--success); }
        .state-dead { color: var(--text-secondary); }
        .state-burned { color: var(--accent); }
        .timeline {
            border-left: 2px solid var(--accent);
            padding-left: 1rem;
            margin-left: 1rem;
        }
        .timeline-event {
            padding: 0.5rem 0;
            position: relative;
        }
        .timeline-event::before {
            content: '';
            position: absolute;
            left: -1.35rem;
            top: 0.75rem;
            width: 10px;
            height: 10px;
            background: var(--accent);
            border-radius: 50%;
        }
        .timeline-event .time {
            color: var(--text-secondary);
            font-size: 0.8rem;
            display: block;
        }
        .timeline-event .type {
            background: var(--accent);
            color: white;
            padding: 0.1rem 0.5rem;
            border-radius: 3px;
            font-size: 0.8rem;
            margin-right: 0.5rem;
        }
        code {
            background: var(--bg-primary);
            padding: 0.2rem 0.4rem;
            border-radius: 3px;
            font-family: 'Monaco', 'Consolas', monospace;
        }
        .stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 1rem;
            margin-bottom: 2rem;
        }
        .stat-card {
            background: var(--bg-secondary);
            padding: 1rem;
            border-radius: 8px;
            text-align: center;
        }
        .stat-card .value {
            font-size: 2rem;
            font-weight: bold;
            color: var(--accent);
        }
        .stat-card .label {
            color: var(--text-secondary);
            font-size: 0.9rem;
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>{{title}}</h1>
            <div class="meta">
                <p>Generated: {{generated_at}} by {{generated_by}}</p>
            </div>
        </header>

        <div class="stats">
            <div class="stat-card">
                <div class="value">{{session_count}}</div>
                <div class="label">Sessions</div>
            </div>
            <div class="stat-card">
                <div class="value">{{host_count}}</div>
                <div class="label">Hosts</div>
            </div>
            <div class="stat-card">
                <div class="value">{{credential_count}}</div>
                <div class="label">Credentials</div>
            </div>
        </div>

        {{sections}}
    </div>
</body>
</html>
"#;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ReportMetadata, ReportType};
    use chrono::Utc;
    use uuid::Uuid;

    fn sample_report() -> Report {
        Report {
            id: Uuid::new_v4(),
            title: "Test Report".to_string(),
            report_type: ReportType::Engagement,
            generated_at: Utc::now(),
            generated_by: "tester".to_string(),
            sections: vec![ReportSection {
                title: "Summary".to_string(),
                content: SectionContent::Text {
                    markdown: "## Overview\n\nThis is a **test** report.".to_string(),
                },
            }],
            metadata: ReportMetadata {
                engagement_name: "Test Engagement".to_string(),
                client_name: Some("Acme Corp".to_string()),
                date_range: (Utc::now(), Utc::now()),
                session_count: 5,
                host_count: 3,
                credential_count: 2,
            },
        }
    }

    #[test]
    fn test_json_export() {
        let report = sample_report();
        let exporter = JsonExporter;

        let data = exporter.export(&report).unwrap();
        assert!(!data.is_empty());

        // Verify it's valid JSON
        let parsed: serde_json::Value = serde_json::from_slice(&data).unwrap();
        assert_eq!(parsed["title"], "Test Report");
        assert_eq!(exporter.content_type(), "application/json");
        assert_eq!(exporter.file_extension(), "json");
    }

    #[test]
    fn test_html_export() {
        let report = sample_report();
        let exporter = HtmlExporter::new();

        let data = exporter.export(&report).unwrap();
        let html = String::from_utf8(data).unwrap();

        assert!(html.contains("<!DOCTYPE html>"));
        assert!(html.contains("Test Report"));
        assert!(html.contains("Summary"));
        assert_eq!(exporter.content_type(), "text/html");
        assert_eq!(exporter.file_extension(), "html");
    }

    #[test]
    fn test_html_escape() {
        assert_eq!(html_escape("<script>"), "&lt;script&gt;");
        assert_eq!(html_escape("a & b"), "a &amp; b");
        assert_eq!(html_escape("\"quoted\""), "&quot;quoted&quot;");
    }

    #[test]
    fn test_render_markdown() {
        let md = "## Header\n\nSome **bold** text.\n\n- Item 1\n- Item 2";
        let html = render_markdown(md);

        assert!(html.contains("<h3>Header</h3>"));
        assert!(html.contains("<strong>bold</strong>"));
        assert!(html.contains("<li>Item 1</li>"));
    }
}
