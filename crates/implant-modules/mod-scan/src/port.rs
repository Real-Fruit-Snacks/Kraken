//! TCP connect port scanning

use common::{KrakenError, PortScanOutput, OpenPortInfo};
use protocol::PortScan;
use std::net::{IpAddr, SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::mpsc;
use std::time::Duration;
use tracing::debug;

/// DNS resolution timeout
const DNS_TIMEOUT: Duration = Duration::from_secs(5);

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

/// Resolve a hostname to an IP address with a timeout.
/// Spawns a thread to perform the blocking DNS lookup and waits at most
/// `DNS_TIMEOUT` before returning an error.
fn resolve_with_timeout(host: &str) -> Result<IpAddr, KrakenError> {
    // Fast path: already an IP literal
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(ip);
    }

    let host_owned = format!("{}:0", host);
    let (tx, rx) = mpsc::channel();

    std::thread::spawn(move || {
        let result = host_owned
            .to_socket_addrs()
            .ok()
            .and_then(|mut it| it.next())
            .map(|sa| sa.ip());
        // Ignore send error — receiver may have timed out
        let _ = tx.send(result);
    });

    match rx.recv_timeout(DNS_TIMEOUT) {
        Ok(Some(ip)) => Ok(ip),
        Ok(None) => Err(KrakenError::Internal(format!(
            "failed to resolve target: {}",
            host
        ))),
        Err(_) => Err(KrakenError::Internal(format!(
            "DNS resolution timed out for target: {}",
            host
        ))),
    }
}

pub fn scan(req: &PortScan) -> Result<PortScanOutput, KrakenError> {
    let timeout_ms = req.timeout_ms.unwrap_or(1000);
    let timeout = Duration::from_millis(timeout_ms as u64);

    // Resolve target to an IP with a bounded timeout
    let target = req.target.trim().to_string();
    let addr = resolve_with_timeout(&target)?;

    // Build port list
    let mut ports: Vec<u16> = Vec::new();

    if req.ports.is_empty() {
        let start = req.start_port.unwrap_or(1);
        let end = req.end_port.unwrap_or(1024);

        // Validate range
        if start == 0 || start > 65535 {
            return Err(KrakenError::Internal(format!(
                "start_port {} out of valid range 1-65535",
                start
            )));
        }
        if end == 0 || end > 65535 {
            return Err(KrakenError::Internal(format!(
                "end_port {} out of valid range 1-65535",
                end
            )));
        }

        ports = (start as u16..=end as u16).collect();
    } else {
        for &p in &req.ports {
            if p == 0 || p > 65535 {
                return Err(KrakenError::Internal(format!(
                    "port {} out of valid range 1-65535",
                    p
                )));
            }
            ports.push(p as u16);
        }
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
