//! Ping sweep - TCP-based host discovery
//!
//! Uses TCP connect to common ports as a fallback since raw ICMP requires
//! elevated privileges. Tries ports 80, 443, 22, 445 to detect live hosts.

use common::{KrakenError, PingSweepOutput};
use protocol::PingSweep;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream};
use std::time::Duration;
use tracing::debug;

/// Probe ports used for TCP-ping host detection
const PROBE_PORTS: &[u16] = &[80, 443, 22, 445, 3389, 8080];

fn is_host_alive(ip: IpAddr, timeout: Duration) -> bool {
    for &port in PROBE_PORTS {
        let addr = SocketAddr::new(ip, port);
        if TcpStream::connect_timeout(&addr, timeout).is_ok() {
            return true;
        }
    }
    false
}

/// Parse CIDR notation like "192.168.1.0/24" into a list of host IPs.
fn parse_cidr(subnet: &str) -> Result<Vec<Ipv4Addr>, KrakenError> {
    let parts: Vec<&str> = subnet.split('/').collect();
    if parts.len() != 2 {
        return Err(KrakenError::Internal(format!(
            "invalid subnet: {} (expected CIDR notation)",
            subnet
        )));
    }

    let base: Ipv4Addr = parts[0]
        .parse()
        .map_err(|_| KrakenError::Internal(format!("invalid IP: {}", parts[0])))?;

    let prefix_len: u32 = parts[1]
        .parse()
        .map_err(|_| KrakenError::Internal(format!("invalid prefix length: {}", parts[1])))?;

    if prefix_len > 32 {
        return Err(KrakenError::Internal(format!(
            "prefix length {} out of range",
            prefix_len
        )));
    }

    let mask: u32 = if prefix_len == 0 {
        0
    } else {
        !0u32 << (32 - prefix_len)
    };

    let base_u32 = u32::from(base) & mask;
    let host_count = 1u32 << (32 - prefix_len);

    // Skip network address (first) and broadcast (last) for /24 and smaller
    let (start, end) = if prefix_len >= 31 {
        (0, host_count)
    } else {
        (1, host_count - 1)
    };

    let mut hosts = Vec::with_capacity(end as usize);
    for i in start..end {
        hosts.push(Ipv4Addr::from(base_u32 + i));
    }

    Ok(hosts)
}

pub fn sweep(req: &PingSweep) -> Result<PingSweepOutput, KrakenError> {
    let timeout_ms = req.timeout_ms.unwrap_or(500);
    let timeout = Duration::from_millis(timeout_ms as u64);

    let hosts = parse_cidr(req.subnet.trim())?;
    let total_scanned = hosts.len() as u32;

    let mut live_hosts: Vec<String> = Vec::new();

    for ip in hosts {
        let ip_addr = IpAddr::V4(ip);
        if is_host_alive(ip_addr, timeout) {
            debug!("live host: {}", ip);
            live_hosts.push(ip.to_string());
        }
    }

    Ok(PingSweepOutput {
        live_hosts,
        total_scanned,
    })
}
