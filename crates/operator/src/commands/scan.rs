//! Network scanning commands

use anyhow::Result;
use common::ImplantId;
use prost::Message;

use crate::cli::CliState;
use crate::display::{print_info, print_success};

/// Parse a port specification string like "22,80,443" or "1-1024" into a list of individual ports
fn parse_ports(ports_str: &str) -> (Vec<u32>, Option<u32>, Option<u32>) {
    let mut individual_ports = Vec::new();
    let mut start_port = None;
    let mut end_port = None;

    for part in ports_str.split(',') {
        let part = part.trim();
        if let Some((start, end)) = part.split_once('-') {
            start_port = start.trim().parse().ok();
            end_port = end.trim().parse().ok();
        } else if let Ok(p) = part.parse::<u32>() {
            individual_ports.push(p);
        }
    }

    (individual_ports, start_port, end_port)
}

/// Scan TCP/UDP ports on a target host
///
/// `ports` is a comma- or range-separated list (e.g. "22,80,443" or "1-1024").
/// `threads` and `timeout_ms` are optional and default to implant-side values when omitted.
pub async fn ports(
    cli: &CliState,
    target: &str,
    ports: &str,
    threads: Option<u32>,
    timeout_ms: Option<u32>,
) -> Result<()> {
    let session = cli.active_session().unwrap();
    let implant_id = ImplantId::from_bytes(&session.full_id)?;

    print_info(&format!("Scanning ports {} on {}", ports, target));

    let (individual_ports, start_port, end_port) = parse_ports(ports);
    let task = protocol::ScanTask {
        operation: Some(protocol::scan_task::Operation::PortScan(protocol::PortScan {
            target: target.to_string(),
            ports: individual_ports,
            start_port,
            end_port,
            timeout_ms,
            threads,
        })),
    };
    let task_data = task.encode_to_vec();

    let task_id = cli.client.dispatch_task(implant_id, "scan", task_data).await?;
    print_success(&format!("Port scan task dispatched: {}", hex::encode(task_id.as_bytes())));
    print_info("Output will be available via 'jobs output'");

    Ok(())
}

/// Ping sweep a subnet to discover live hosts (e.g. "192.168.1.0/24")
///
/// `timeout_ms` is optional and defaults to the implant-side value when omitted.
pub async fn ping(cli: &CliState, subnet: &str, timeout_ms: Option<u32>) -> Result<()> {
    let session = cli.active_session().unwrap();
    let implant_id = ImplantId::from_bytes(&session.full_id)?;

    print_info(&format!("Ping sweeping subnet: {}", subnet));

    let task = protocol::ScanTask {
        operation: Some(protocol::scan_task::Operation::PingSweep(protocol::PingSweep {
            subnet: subnet.to_string(),
            timeout_ms,
            threads: None,
        })),
    };
    let task_data = task.encode_to_vec();

    let task_id = cli.client.dispatch_task(implant_id, "scan", task_data).await?;
    print_success(&format!("Ping sweep task dispatched: {}", hex::encode(task_id.as_bytes())));
    print_info("Output will be available via 'jobs output'");

    Ok(())
}

/// Enumerate SMB shares accessible on the target host
pub async fn shares(cli: &CliState, target: &str) -> Result<()> {
    let session = cli.active_session().unwrap();
    let implant_id = ImplantId::from_bytes(&session.full_id)?;

    print_info(&format!("Enumerating SMB shares on: {}", target));

    let task = protocol::ScanTask {
        operation: Some(protocol::scan_task::Operation::ShareEnum(protocol::ShareEnum {
            target: target.to_string(),
        })),
    };
    let task_data = task.encode_to_vec();

    let task_id = cli.client.dispatch_task(implant_id, "scan", task_data).await?;
    print_success(&format!("Share enumeration task dispatched: {}", hex::encode(task_id.as_bytes())));
    print_info("Output will be available via 'jobs output'");

    Ok(())
}
