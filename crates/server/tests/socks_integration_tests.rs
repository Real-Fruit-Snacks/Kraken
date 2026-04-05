//! SOCKS Proxy Integration Tests
//!
//! Tests the server-side SOCKS5 proxy functionality including:
//! - SOCKS5 protocol handshake
//! - Connection establishment
//! - Data relay through channels
//! - Multiple concurrent connections
//! - Statistics tracking
//! - Error handling and timeouts

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use common::ImplantId;

// SOCKS5 protocol constants
const SOCKS5_VERSION: u8 = 0x05;
const SOCKS5_AUTH_NONE: u8 = 0x00;
const SOCKS5_CMD_CONNECT: u8 = 0x01;
const SOCKS5_ATYP_IPV4: u8 = 0x01;
const SOCKS5_ATYP_DOMAIN: u8 = 0x03;
const SOCKS5_REP_SUCCESS: u8 = 0x00;

// ---------------------------------------------------------------------------
// Helper: Start a simple echo server for testing
// ---------------------------------------------------------------------------

fn start_echo_server() -> (TcpListener, u16) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind echo server");
    let port = listener.local_addr().unwrap().port();

    let listener_clone = listener.try_clone().unwrap();
    thread::spawn(move || {
        for stream in listener_clone.incoming() {
            if let Ok(mut conn) = stream {
                thread::spawn(move || {
                    let mut buf = [0u8; 4096];
                    while let Ok(n) = conn.read(&mut buf) {
                        if n == 0 { break; }
                        if conn.write_all(&buf[..n]).is_err() { break; }
                    }
                });
            }
        }
    });

    (listener, port)
}

// ---------------------------------------------------------------------------
// Helper: SOCKS5 client handshake
// ---------------------------------------------------------------------------

fn socks5_handshake(stream: &mut TcpStream) -> std::io::Result<()> {
    // Send greeting: version + 1 method (no auth)
    stream.write_all(&[SOCKS5_VERSION, 0x01, SOCKS5_AUTH_NONE])?;

    // Read response
    let mut resp = [0u8; 2];
    stream.read_exact(&mut resp)?;

    if resp[0] != SOCKS5_VERSION || resp[1] != SOCKS5_AUTH_NONE {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "invalid handshake response",
        ));
    }

    Ok(())
}

fn socks5_connect_ipv4(stream: &mut TcpStream, ip: [u8; 4], port: u16) -> std::io::Result<()> {
    // CONNECT request: VER CMD RSV ATYP ADDR PORT
    let mut req = vec![SOCKS5_VERSION, SOCKS5_CMD_CONNECT, 0x00, SOCKS5_ATYP_IPV4];
    req.extend_from_slice(&ip);
    req.extend_from_slice(&port.to_be_bytes());
    stream.write_all(&req)?;

    // Read response (minimum 10 bytes for IPv4)
    let mut resp = [0u8; 10];
    stream.read_exact(&mut resp)?;

    if resp[0] != SOCKS5_VERSION {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "invalid version in response",
        ));
    }

    if resp[1] != SOCKS5_REP_SUCCESS {
        return Err(std::io::Error::new(
            std::io::ErrorKind::ConnectionRefused,
            format!("SOCKS connect failed: reply code {}", resp[1]),
        ));
    }

    Ok(())
}

fn socks5_connect_domain(stream: &mut TcpStream, domain: &str, port: u16) -> std::io::Result<()> {
    // CONNECT request with domain name
    let mut req = vec![SOCKS5_VERSION, SOCKS5_CMD_CONNECT, 0x00, SOCKS5_ATYP_DOMAIN];
    req.push(domain.len() as u8);
    req.extend_from_slice(domain.as_bytes());
    req.extend_from_slice(&port.to_be_bytes());
    stream.write_all(&req)?;

    // Read response header
    let mut resp = [0u8; 4];
    stream.read_exact(&mut resp)?;

    if resp[0] != SOCKS5_VERSION {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "invalid version in response",
        ));
    }

    // Read rest based on address type
    match resp[3] {
        SOCKS5_ATYP_IPV4 => {
            let mut addr_port = [0u8; 6];
            stream.read_exact(&mut addr_port)?;
        }
        SOCKS5_ATYP_DOMAIN => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len)?;
            let mut domain_buf = vec![0u8; len[0] as usize + 2];
            stream.read_exact(&mut domain_buf)?;
        }
        0x04 => { // IPv6
            let mut addr_port = [0u8; 18];
            stream.read_exact(&mut addr_port)?;
        }
        _ => {}
    }

    if resp[1] != SOCKS5_REP_SUCCESS {
        return Err(std::io::Error::new(
            std::io::ErrorKind::ConnectionRefused,
            format!("SOCKS connect failed: reply code {}", resp[1]),
        ));
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Unit Tests for SOCKS Protocol Helpers
// ---------------------------------------------------------------------------

#[test]
fn test_socks5_constants() {
    assert_eq!(SOCKS5_VERSION, 0x05);
    assert_eq!(SOCKS5_AUTH_NONE, 0x00);
    assert_eq!(SOCKS5_CMD_CONNECT, 0x01);
}

// ---------------------------------------------------------------------------
// SocksProxyManager Tests (direct API testing)
// ---------------------------------------------------------------------------

mod manager_tests {
    use super::*;
    use server::socks_server::{SocksProxyManager, SocksVersion};

    #[test]
    fn test_manager_creation() {
        let manager = SocksProxyManager::new();
        let proxies = manager.list(None);
        assert!(proxies.is_empty());
    }

    #[test]
    fn test_start_and_stop_proxy() {
        let manager = SocksProxyManager::new();
        let implant_id = ImplantId::new();

        let connect_count = Arc::new(AtomicU32::new(0));
        let data_count = Arc::new(AtomicU32::new(0));

        let cc = Arc::clone(&connect_count);
        let dc = Arc::clone(&data_count);

        let result = manager.start_proxy(
            implant_id,
            "127.0.0.1",
            0, // random port
            SocksVersion::Socks5,
            move |_req| { cc.fetch_add(1, Ordering::SeqCst); },
            move |_id, _data| { dc.fetch_add(1, Ordering::SeqCst); },
        );

        assert!(result.is_ok());
        let proxy_id = result.unwrap();

        // Proxy should be in the list
        let proxies = manager.list(None);
        assert_eq!(proxies.len(), 1);

        // Should be able to get it by ID
        assert!(manager.get(proxy_id).is_some());

        // Stop the proxy
        assert!(manager.stop_proxy(proxy_id));

        // Should no longer be in the list
        assert!(manager.get(proxy_id).is_none());
    }

    #[test]
    fn test_multiple_proxies() {
        let manager = SocksProxyManager::new();
        let implant1 = ImplantId::new();
        let implant2 = ImplantId::new();

        let id1 = manager.start_proxy(
            implant1,
            "127.0.0.1", 0,
            SocksVersion::Socks5,
            |_| {}, |_, _| {},
        ).unwrap();

        let id2 = manager.start_proxy(
            implant2,
            "127.0.0.1", 0,
            SocksVersion::Socks5,
            |_| {}, |_, _| {},
        ).unwrap();

        // Both should exist
        assert!(manager.get(id1).is_some());
        assert!(manager.get(id2).is_some());

        // List all
        let all = manager.list(None);
        assert_eq!(all.len(), 2);

        // Filter by implant
        let filtered1 = manager.list(Some(implant1));
        assert_eq!(filtered1.len(), 1);

        let filtered2 = manager.list(Some(implant2));
        assert_eq!(filtered2.len(), 1);

        // Clean up
        manager.stop_proxy(id1);
        manager.stop_proxy(id2);
    }

    #[test]
    fn test_proxy_stats_initial() {
        let manager = SocksProxyManager::new();
        let implant_id = ImplantId::new();

        let proxy_id = manager.start_proxy(
            implant_id,
            "127.0.0.1", 0,
            SocksVersion::Socks5,
            |_| {}, |_, _| {},
        ).unwrap();

        let instance = manager.get(proxy_id).unwrap();
        let (bytes_in, bytes_out, active, total) = instance.get_stats();

        assert_eq!(bytes_in, 0);
        assert_eq!(bytes_out, 0);
        assert_eq!(active, 0);
        assert_eq!(total, 0);

        manager.stop_proxy(proxy_id);
    }
}

// ---------------------------------------------------------------------------
// SocksProxyInstance Tests
// ---------------------------------------------------------------------------

mod instance_tests {
    use super::*;
    use server::socks_server::{SocksProxyInstance, SocksVersion};

    #[test]
    fn test_instance_creation() {
        let result = SocksProxyInstance::new(
            ImplantId::new(),
            "127.0.0.1",
            0,
            SocksVersion::Socks5,
        );
        assert!(result.is_ok());

        let (instance, listener) = result.unwrap();
        assert!(instance.is_running());
        assert!(listener.local_addr().is_ok());
    }

    #[test]
    fn test_channel_management() {
        let (instance, _listener) = SocksProxyInstance::new(
            ImplantId::new(),
            "127.0.0.1",
            0,
            SocksVersion::Socks5,
        ).unwrap();

        let channel_id = instance.next_channel_id();

        // Register a channel
        let _rx = instance.register_channel(
            channel_id,
            "example.com".into(),
            80,
            "127.0.0.1:54321".into(),
        );

        // Check stats
        let (_, _, active, total) = instance.get_stats();
        assert_eq!(active, 1);
        assert_eq!(total, 1);

        // Get connections list
        let connections = instance.get_connections();
        assert_eq!(connections.len(), 1);
        assert_eq!(connections[0].channel_id, channel_id);
        assert_eq!(connections[0].target_addr, "example.com:80");

        // Mark connected
        instance.mark_connected(channel_id);

        // Remove channel
        instance.remove_channel(channel_id);
        let (_, _, active_after, _) = instance.get_stats();
        assert_eq!(active_after, 0);
    }

    #[test]
    fn test_instance_stop() {
        let (instance, _listener) = SocksProxyInstance::new(
            ImplantId::new(),
            "127.0.0.1",
            0,
            SocksVersion::Socks5,
        ).unwrap();

        assert!(instance.is_running());
        instance.stop();
        assert!(!instance.is_running());
    }

    #[test]
    fn test_deliver_data() {
        let (instance, _listener) = SocksProxyInstance::new(
            ImplantId::new(),
            "127.0.0.1",
            0,
            SocksVersion::Socks5,
        ).unwrap();

        let channel_id = instance.next_channel_id();
        let mut rx = instance.register_channel(
            channel_id,
            "test.local".into(),
            8080,
            "127.0.0.1:12345".into(),
        );

        // Deliver data
        instance.deliver_data(channel_id, b"hello world".to_vec());

        // Receive in async context
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        let data = rt.block_on(async {
            tokio::time::timeout(Duration::from_millis(100), rx.recv()).await
        });

        assert!(data.is_ok());
        assert_eq!(data.unwrap().unwrap(), b"hello world");

        instance.stop();
    }
}

// ---------------------------------------------------------------------------
// Connection Tests (full SOCKS5 flow with real sockets)
// ---------------------------------------------------------------------------

mod connection_tests {
    use super::*;
    use server::socks_server::{SocksProxyManager, SocksVersion, ProxyData, SocksConnectRequest};
    use std::sync::Mutex;

    #[test]
    fn test_socks5_handshake_basic() {
        let manager = SocksProxyManager::new();
        let implant_id = ImplantId::new();

        let connect_requests: Arc<Mutex<Vec<SocksConnectRequest>>> = Arc::new(Mutex::new(vec![]));
        let cr = Arc::clone(&connect_requests);

        let proxy_id = manager.start_proxy(
            implant_id,
            "127.0.0.1", 0,
            SocksVersion::Socks5,
            move |req| { cr.lock().unwrap().push(req); },
            |_, _| {},
        ).unwrap();

        let instance = manager.get(proxy_id).unwrap();
        let port = instance.bind_addr.port();

        // Give server time to start
        thread::sleep(Duration::from_millis(50));

        // Connect as SOCKS5 client
        let mut client = TcpStream::connect(format!("127.0.0.1:{}", port)).unwrap();
        client.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        client.set_write_timeout(Some(Duration::from_secs(2))).unwrap();

        // Perform handshake
        let result = socks5_handshake(&mut client);
        assert!(result.is_ok(), "handshake failed: {:?}", result.err());

        manager.stop_proxy(proxy_id);
    }

    #[test]
    fn test_socks5_connect_request() {
        let manager = SocksProxyManager::new();
        let implant_id = ImplantId::new();

        let connect_requests: Arc<Mutex<Vec<SocksConnectRequest>>> = Arc::new(Mutex::new(vec![]));
        let cr = Arc::clone(&connect_requests);

        let proxy_id = manager.start_proxy(
            implant_id,
            "127.0.0.1", 0,
            SocksVersion::Socks5,
            move |req| { cr.lock().unwrap().push(req); },
            |_, _| {},
        ).unwrap();

        let instance = manager.get(proxy_id).unwrap();
        let port = instance.bind_addr.port();

        thread::sleep(Duration::from_millis(50));

        let mut client = TcpStream::connect(format!("127.0.0.1:{}", port)).unwrap();
        client.set_read_timeout(Some(Duration::from_secs(2))).unwrap();

        // Handshake
        socks5_handshake(&mut client).unwrap();

        // Connect to 192.168.1.1:80
        let result = socks5_connect_ipv4(&mut client, [192, 168, 1, 1], 80);
        assert!(result.is_ok());

        // Verify connect request was captured
        thread::sleep(Duration::from_millis(50));
        let requests = connect_requests.lock().unwrap();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].target_host, "192.168.1.1");
        assert_eq!(requests[0].target_port, 80);

        manager.stop_proxy(proxy_id);
    }

    #[test]
    fn test_socks5_connect_domain() {
        let manager = SocksProxyManager::new();
        let implant_id = ImplantId::new();

        let connect_requests: Arc<Mutex<Vec<SocksConnectRequest>>> = Arc::new(Mutex::new(vec![]));
        let cr = Arc::clone(&connect_requests);

        let proxy_id = manager.start_proxy(
            implant_id,
            "127.0.0.1", 0,
            SocksVersion::Socks5,
            move |req| { cr.lock().unwrap().push(req); },
            |_, _| {},
        ).unwrap();

        let instance = manager.get(proxy_id).unwrap();
        let port = instance.bind_addr.port();

        thread::sleep(Duration::from_millis(50));

        let mut client = TcpStream::connect(format!("127.0.0.1:{}", port)).unwrap();
        client.set_read_timeout(Some(Duration::from_secs(2))).unwrap();

        socks5_handshake(&mut client).unwrap();

        // Connect with domain name
        let result = socks5_connect_domain(&mut client, "example.com", 443);
        assert!(result.is_ok());

        thread::sleep(Duration::from_millis(50));
        let requests = connect_requests.lock().unwrap();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].target_host, "example.com");
        assert_eq!(requests[0].target_port, 443);

        manager.stop_proxy(proxy_id);
    }

    #[test]
    fn test_concurrent_connections() {
        let manager = SocksProxyManager::new();
        let implant_id = ImplantId::new();

        let connect_count = Arc::new(AtomicU32::new(0));
        let cc = Arc::clone(&connect_count);

        let proxy_id = manager.start_proxy(
            implant_id,
            "127.0.0.1", 0,
            SocksVersion::Socks5,
            move |_| { cc.fetch_add(1, Ordering::SeqCst); },
            |_, _| {},
        ).unwrap();

        let instance = manager.get(proxy_id).unwrap();
        let port = instance.bind_addr.port();

        thread::sleep(Duration::from_millis(50));

        // Spawn 5 concurrent clients
        let handles: Vec<_> = (0..5).map(|i| {
            let port = port;
            thread::spawn(move || {
                let mut client = TcpStream::connect(format!("127.0.0.1:{}", port)).unwrap();
                client.set_read_timeout(Some(Duration::from_secs(2))).unwrap();

                socks5_handshake(&mut client).unwrap();
                socks5_connect_ipv4(&mut client, [10, 0, 0, i as u8], 8080).unwrap();

                // Keep connection open briefly
                thread::sleep(Duration::from_millis(100));
            })
        }).collect();

        // Wait for all to complete
        for h in handles {
            h.join().unwrap();
        }

        // Verify all connect requests received
        thread::sleep(Duration::from_millis(50));
        assert_eq!(connect_count.load(Ordering::SeqCst), 5);

        manager.stop_proxy(proxy_id);
    }

    #[test]
    fn test_data_relay() {
        let manager = Arc::new(SocksProxyManager::new());
        let implant_id = ImplantId::new();

        let data_received: Arc<Mutex<Vec<ProxyData>>> = Arc::new(Mutex::new(vec![]));
        let dr = Arc::clone(&data_received);

        let manager_for_cb = Arc::clone(&manager);

        let proxy_id = manager.start_proxy(
            implant_id,
            "127.0.0.1", 0,
            SocksVersion::Socks5,
            |_| {},
            move |proxy_id, data| {
                dr.lock().unwrap().push(data.clone());
                // Echo data back (simulating implant response)
                if !data.eof && !data.data.is_empty() {
                    manager_for_cb.deliver_implant_data(proxy_id, data.channel_id, data.data);
                }
            },
        ).unwrap();

        let instance = manager.get(proxy_id).unwrap();
        let port = instance.bind_addr.port();

        thread::sleep(Duration::from_millis(50));

        let mut client = TcpStream::connect(format!("127.0.0.1:{}", port)).unwrap();
        client.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        client.set_write_timeout(Some(Duration::from_secs(2))).unwrap();

        socks5_handshake(&mut client).unwrap();
        socks5_connect_ipv4(&mut client, [127, 0, 0, 1], 9999).unwrap();

        // Send data through the proxy
        let test_data = b"Hello through SOCKS proxy!";
        client.write_all(test_data).unwrap();

        // Give time for data to flow
        thread::sleep(Duration::from_millis(200));

        // Read echoed response
        let mut response = [0u8; 1024];
        let n = client.read(&mut response).unwrap_or(0);

        // Verify data was captured
        let received = data_received.lock().unwrap();
        assert!(!received.is_empty(), "no data received");
        assert_eq!(&received[0].data, test_data);

        // Verify echo response
        assert_eq!(n, test_data.len());
        assert_eq!(&response[..n], test_data);

        manager.stop_proxy(proxy_id);
    }

    #[test]
    fn test_invalid_socks_version() {
        let manager = SocksProxyManager::new();
        let implant_id = ImplantId::new();

        let proxy_id = manager.start_proxy(
            implant_id,
            "127.0.0.1", 0,
            SocksVersion::Socks5,
            |_| {},
            |_, _| {},
        ).unwrap();

        let instance = manager.get(proxy_id).unwrap();
        let port = instance.bind_addr.port();

        thread::sleep(Duration::from_millis(50));

        let mut client = TcpStream::connect(format!("127.0.0.1:{}", port)).unwrap();
        client.set_read_timeout(Some(Duration::from_secs(1))).unwrap();

        // Send invalid SOCKS4 greeting to SOCKS5 server
        client.write_all(&[0x04, 0x01]).unwrap();

        // Should get disconnected or error
        let mut buf = [0u8; 10];
        let result = client.read(&mut buf);
        // Connection should fail or close
        assert!(result.is_err() || result.unwrap() == 0);

        manager.stop_proxy(proxy_id);
    }

    #[test]
    fn test_stats_tracking() {
        let manager = Arc::new(SocksProxyManager::new());
        let implant_id = ImplantId::new();

        let manager_for_cb = Arc::clone(&manager);

        let proxy_id = manager.start_proxy(
            implant_id,
            "127.0.0.1", 0,
            SocksVersion::Socks5,
            |_| {},
            move |proxy_id, data| {
                // Echo back
                if !data.eof && !data.data.is_empty() {
                    manager_for_cb.deliver_implant_data(proxy_id, data.channel_id, data.data);
                }
            },
        ).unwrap();

        let instance = manager.get(proxy_id).unwrap();
        let port = instance.bind_addr.port();

        thread::sleep(Duration::from_millis(50));

        let mut client = TcpStream::connect(format!("127.0.0.1:{}", port)).unwrap();
        client.set_read_timeout(Some(Duration::from_secs(2))).unwrap();

        socks5_handshake(&mut client).unwrap();
        socks5_connect_ipv4(&mut client, [127, 0, 0, 1], 8080).unwrap();

        // Send some data
        client.write_all(b"test data 123").unwrap();
        thread::sleep(Duration::from_millis(100));

        // Check stats
        let (bytes_in, bytes_out, active, total) = instance.get_stats();

        // bytes_out should have data we sent
        assert!(bytes_out > 0, "bytes_out should be > 0");
        // total connections should be 1
        assert_eq!(total, 1);
        // active should be 1
        assert_eq!(active, 1);

        // Explicitly shutdown to signal EOF
        let _ = client.shutdown(std::net::Shutdown::Both);
        drop(client);

        // Note: Connection cleanup is async and may not complete immediately
        // The important thing is that data relay worked correctly
        // Stopping the proxy will force cleanup
        manager.stop_proxy(proxy_id);
    }
}

// ---------------------------------------------------------------------------
// Error Handling Tests
// ---------------------------------------------------------------------------

mod error_tests {
    use super::*;
    use server::socks_server::{SocksProxyInstance, SocksVersion};

    #[test]
    fn test_bind_port_already_in_use() {
        // Bind a port first
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();

        // Try to create proxy on same port
        let result = SocksProxyInstance::new(
            ImplantId::new(),
            "127.0.0.1",
            port,
            SocksVersion::Socks5,
        );

        assert!(result.is_err());
    }

    #[test]
    fn test_remove_nonexistent_channel() {
        let (instance, _listener) = SocksProxyInstance::new(
            ImplantId::new(),
            "127.0.0.1",
            0,
            SocksVersion::Socks5,
        ).unwrap();

        // Removing nonexistent channel should be safe
        instance.remove_channel(99999);

        let (_, _, active, _) = instance.get_stats();
        assert_eq!(active, 0);
    }

    #[test]
    fn test_deliver_to_nonexistent_channel() {
        let (instance, _listener) = SocksProxyInstance::new(
            ImplantId::new(),
            "127.0.0.1",
            0,
            SocksVersion::Socks5,
        ).unwrap();

        // Should not panic
        instance.deliver_data(99999, b"test".to_vec());
    }
}

// ---------------------------------------------------------------------------
// ProxyId Tests
// ---------------------------------------------------------------------------

mod proxy_id_tests {
    use server::socks_server::ProxyInstanceId;

    #[test]
    fn test_proxy_id_uniqueness() {
        let id1 = ProxyInstanceId::new();
        let id2 = ProxyInstanceId::new();
        let id3 = ProxyInstanceId::new();

        assert_ne!(id1, id2);
        assert_ne!(id2, id3);
        assert_ne!(id1, id3);
    }

    #[test]
    fn test_proxy_id_bytes() {
        let id = ProxyInstanceId::new();
        let bytes = id.as_bytes();
        assert_eq!(bytes.len(), 16);
    }

    #[test]
    fn test_proxy_id_default() {
        let id1 = ProxyInstanceId::default();
        let id2 = ProxyInstanceId::default();
        assert_ne!(id1, id2);
    }
}
