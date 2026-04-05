//! TCP connect port scanning

use common::{KrakenError, PortScanOutput, OpenPortInfo};
use protocol::PortScan;
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::time::Duration;
use tracing::debug;

/// Well-known service names for common ports
fn service_name(port: u16) -> &'static str {
    match port {
        21 => "ftp",
        22 => "ssh",
        23 => "telnet",
        25 => "smtp",
        53 => "dns",
        80 => "http",
        110 => "pop3",
        135 => "msrpc",
        139 => "netbios-ssn",
        143 => "imap",
        389 => "ldap",
        443 => "https",
        445 => "microsoft-ds",
        465 => "smtps",
        587 => "submission",
        636 => "ldaps",
        993 => "imaps",
        995 => "pop3s",
        1433 => "mssql",
        1521 => "oracle",
        3306 => "mysql",
        3389 => "rdp",
        5432 => "postgresql",
        5900 => "vnc",
        6379 => "redis",
        8080 => "http-alt",
        8443 => "https-alt",
        27017 => "mongodb",
        _ => "",
    }
}

/// Attempt a TCP connect to determine if a port is open.
/// Returns Some(banner) if open, None if closed/filtered.
fn try_connect(addr: SocketAddr, timeout: Duration) -> Option<String> {
    match TcpStream::connect_timeout(&addr, timeout) {
        Ok(_stream) => {
            // Port is open; banner grabbing omitted for simplicity
            Some(String::new())
        }
        Err(_) => None,
    }
}

pub fn scan(req: &PortScan) -> Result<PortScanOutput, KrakenError> {
    let timeout_ms = req.timeout_ms.unwrap_or(1000);
    let timeout = Duration::from_millis(timeout_ms as u64);

    // Resolve target to an IP
    let target = req.target.trim().to_string();
    let addr: IpAddr = target
        .parse()
        .or_else(|_| {
            use std::net::ToSocketAddrs;
            format!("{}:0", target)
                .to_socket_addrs()
                .ok()
                .and_then(|mut it| it.next())
                .map(|sa| sa.ip())
                .ok_or_else(|| std::net::AddrParseError::from(
                    "0.0.0.0".parse::<IpAddr>().unwrap_err()
                ))
        })
        .map_err(|_| KrakenError::Internal(format!("failed to resolve target: {}", target)))?;

    // Build port list
    let mut ports: Vec<u16> = req.ports.iter().map(|&p| p as u16).collect();

    if ports.is_empty() {
        let start = req.start_port.unwrap_or(1) as u16;
        let end = req.end_port.unwrap_or(1024) as u16;
        ports = (start..=end).collect();
    }

    let _max_threads = req.threads.unwrap_or(64) as usize;

    let mut open_ports: Vec<OpenPortInfo> = Vec::new();

    for port in ports {
        let sock_addr = SocketAddr::new(addr, port);
        if let Some(banner) = try_connect(sock_addr, timeout) {
            let service = service_name(port).to_string();
            debug!("open port {}:{} ({})", target, port, service);
            open_ports.push(OpenPortInfo {
                port: port as u32,
                service,
                banner,
            });
        }
    }

    Ok(PortScanOutput {
        target,
        open_ports,
    })
}
