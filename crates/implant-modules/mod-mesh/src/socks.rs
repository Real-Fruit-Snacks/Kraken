//! SOCKS5 proxy implementation for mesh tunneling
//!
//! Provides a SOCKS5 server that tunnels connections through mesh peers.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream, SocketAddr, ToSocketAddrs};
use std::sync::{RwLock, OnceLock, atomic::AtomicU32};
use std::thread;
use std::time::Duration;

use common::KrakenError;

// Channel ID counter
#[allow(dead_code)]
static CHANNEL_COUNTER: AtomicU32 = AtomicU32::new(1);

// Active SOCKS channels: channel_id -> (local_stream, remote_stream)
#[allow(dead_code)]
static CHANNELS: OnceLock<RwLock<HashMap<u32, SocksChannel>>> = OnceLock::new();

#[allow(dead_code)]
fn channels() -> &'static RwLock<HashMap<u32, SocksChannel>> {
    CHANNELS.get_or_init(|| RwLock::new(HashMap::new()))
}

pub struct SocksChannel {
    pub local_stream: TcpStream,
    pub remote_stream: Option<TcpStream>,
}

/// SOCKS5 constants
const SOCKS5_VERSION: u8 = 0x05;
const SOCKS5_AUTH_NONE: u8 = 0x00;
const SOCKS5_CMD_CONNECT: u8 = 0x01;
const SOCKS5_ATYP_IPV4: u8 = 0x01;
const SOCKS5_ATYP_DOMAIN: u8 = 0x03;
const SOCKS5_ATYP_IPV6: u8 = 0x04;
const SOCKS5_REP_SUCCESS: u8 = 0x00;
const SOCKS5_REP_FAILURE: u8 = 0x01;
const SOCKS5_REP_CONN_REFUSED: u8 = 0x05;

/// Start a SOCKS5 proxy server that tunnels through mesh
pub fn start_socks_server(bind_addr: &str, port: u16) -> Result<SocksServer, KrakenError> {
    let addr = format!("{}:{}", bind_addr, port);
    let listener = TcpListener::bind(addr)
        .map_err(|e| KrakenError::Transport(format!("SOCKS bind failed: {}", e)))?;

    Ok(SocksServer { listener })
}

pub struct SocksServer {
    listener: TcpListener,
}

impl SocksServer {
    /// Accept and handle SOCKS5 connections (direct mode - connects directly to target)
    pub fn run_direct(&self) {
        loop {
            match self.listener.accept() {
                Ok((stream, peer)) => {
                    thread::spawn(move || {
                        if let Err(e) = handle_socks_client_direct(stream, peer) {
                            eprintln!("[-] SOCKS client error: {}", e);
                        }
                    });
                }
                Err(e) => {
                    eprintln!("[-] SOCKS accept error: {}", e);
                }
            }
        }
    }

    /// Get local address
    pub fn local_addr(&self) -> Result<SocketAddr, KrakenError> {
        self.listener.local_addr()
            .map_err(|e| KrakenError::Transport(format!("failed to get local addr: {}", e)))
    }
}

/// Handle a SOCKS5 client connection (direct mode)
fn handle_socks_client_direct(mut client: TcpStream, peer: SocketAddr) -> Result<(), KrakenError> {
    client.set_read_timeout(Some(Duration::from_secs(30)))?;
    client.set_write_timeout(Some(Duration::from_secs(30)))?;

    // SOCKS5 handshake - client sends version + auth methods
    let mut buf = [0u8; 258];
    let n = client.read(&mut buf[..2])?;
    if n < 2 || buf[0] != SOCKS5_VERSION {
        return Err(KrakenError::Protocol("invalid SOCKS5 handshake".into()));
    }

    let nmethods = buf[1] as usize;
    client.read_exact(&mut buf[..nmethods])?;

    // We only support no-auth
    client.write_all(&[SOCKS5_VERSION, SOCKS5_AUTH_NONE])?;

    // Read connect request
    let mut req = [0u8; 4];
    client.read_exact(&mut req)?;

    if req[0] != SOCKS5_VERSION || req[1] != SOCKS5_CMD_CONNECT {
        // Only CONNECT supported
        client.write_all(&[SOCKS5_VERSION, SOCKS5_REP_FAILURE, 0, SOCKS5_ATYP_IPV4, 0,0,0,0, 0,0])?;
        return Err(KrakenError::Protocol("only CONNECT supported".into()));
    }

    // Parse destination address
    let (target_host, target_port) = parse_socks_address(&mut client, req[3])?;

    println!("[*] SOCKS CONNECT {}:{} from {}", target_host, target_port, peer);

    // Connect to target directly
    let target_addr = format!("{}:{}", target_host, target_port);
    match TcpStream::connect_timeout(
        &target_addr.to_socket_addrs()
            .map_err(|e| KrakenError::Transport(format!("DNS resolve failed: {}", e)))?
            .next()
            .ok_or_else(|| KrakenError::Transport("no addresses found".into()))?,
        Duration::from_secs(10)
    ) {
        Ok(target) => {
            target.set_nodelay(true)?;

            // Send success response
            let local = target.local_addr().unwrap_or_else(|_| "0.0.0.0:0".parse().unwrap());
            let response = build_socks_response(SOCKS5_REP_SUCCESS, &local);
            client.write_all(&response)?;

            println!("[+] SOCKS connected to {}:{}", target_host, target_port);

            // Relay data bidirectionally
            relay_streams(client, target)?;
        }
        Err(e) => {
            println!("[-] SOCKS connect failed: {}", e);
            client.write_all(&[SOCKS5_VERSION, SOCKS5_REP_CONN_REFUSED, 0, SOCKS5_ATYP_IPV4, 0,0,0,0, 0,0])?;
            return Err(KrakenError::Transport(format!("connect failed: {}", e)));
        }
    }

    Ok(())
}

/// Parse SOCKS5 address from stream
fn parse_socks_address(stream: &mut TcpStream, atyp: u8) -> Result<(String, u16), KrakenError> {
    let host = match atyp {
        SOCKS5_ATYP_IPV4 => {
            let mut addr = [0u8; 4];
            stream.read_exact(&mut addr)?;
            format!("{}.{}.{}.{}", addr[0], addr[1], addr[2], addr[3])
        }
        SOCKS5_ATYP_DOMAIN => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len)?;
            let mut domain = vec![0u8; len[0] as usize];
            stream.read_exact(&mut domain)?;
            String::from_utf8(domain)
                .map_err(|_| KrakenError::Protocol("invalid domain".into()))?
        }
        SOCKS5_ATYP_IPV6 => {
            let mut addr = [0u8; 16];
            stream.read_exact(&mut addr)?;
            // Format IPv6
            let mut parts = Vec::new();
            for i in 0..8 {
                parts.push(format!("{:x}", u16::from_be_bytes([addr[i*2], addr[i*2+1]])));
            }
            parts.join(":")
        }
        _ => return Err(KrakenError::Protocol("unsupported address type".into())),
    };

    let mut port_buf = [0u8; 2];
    stream.read_exact(&mut port_buf)?;
    let port = u16::from_be_bytes(port_buf);

    Ok((host, port))
}

/// Build SOCKS5 response
fn build_socks_response(rep: u8, bound: &SocketAddr) -> Vec<u8> {
    let mut resp = vec![SOCKS5_VERSION, rep, 0x00];

    match bound {
        SocketAddr::V4(addr) => {
            resp.push(SOCKS5_ATYP_IPV4);
            resp.extend_from_slice(&addr.ip().octets());
            resp.extend_from_slice(&addr.port().to_be_bytes());
        }
        SocketAddr::V6(addr) => {
            resp.push(SOCKS5_ATYP_IPV6);
            resp.extend_from_slice(&addr.ip().octets());
            resp.extend_from_slice(&addr.port().to_be_bytes());
        }
    }

    resp
}

/// Relay data between two streams bidirectionally
fn relay_streams(mut client: TcpStream, mut target: TcpStream) -> Result<(), KrakenError> {
    let mut client_clone = client.try_clone()?;
    let mut target_clone = target.try_clone()?;

    // Client -> Target
    let h1 = thread::spawn(move || {
        let mut buf = [0u8; 8192];
        loop {
            match client.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    if target.write_all(&buf[..n]).is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        let _ = target.shutdown(std::net::Shutdown::Write);
    });

    // Target -> Client
    let h2 = thread::spawn(move || {
        let mut buf = [0u8; 8192];
        loop {
            match target_clone.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    if client_clone.write_all(&buf[..n]).is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        let _ = client_clone.shutdown(std::net::Shutdown::Write);
    });

    h1.join().ok();
    h2.join().ok();

    Ok(())
}

/// Handle incoming SOCKS connect request on peer side (makes actual connection)
pub fn handle_socks_connect(target_host: &str, target_port: u16) -> Result<TcpStream, KrakenError> {
    let addr = format!("{}:{}", target_host, target_port);
    let socket_addr = addr.to_socket_addrs()
        .map_err(|e| KrakenError::Transport(format!("DNS failed: {}", e)))?
        .next()
        .ok_or_else(|| KrakenError::Transport("no address".into()))?;

    TcpStream::connect_timeout(&socket_addr, Duration::from_secs(10))
        .map_err(|e| KrakenError::Transport(format!("connect failed: {}", e)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Barrier};

    #[test]
    fn test_socks_server_bind() {
        let server = start_socks_server("127.0.0.1", 0).unwrap();
        let addr = server.local_addr().unwrap();
        assert!(addr.port() > 0);
    }

    #[test]
    fn test_build_socks_response() {
        let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        let resp = build_socks_response(SOCKS5_REP_SUCCESS, &addr);
        assert_eq!(resp[0], SOCKS5_VERSION);
        assert_eq!(resp[1], SOCKS5_REP_SUCCESS);
        assert_eq!(resp[3], SOCKS5_ATYP_IPV4);
    }

    /// Stress test: 20 concurrent clients all perform the SOCKS5 auth negotiation.
    /// The server must handle every connection without panicking or dropping a client.
    #[test]
    fn test_socks_server_concurrent_connections() {
        const NUM_CLIENTS: usize = 20;

        // Bind on port 0 so the OS assigns a free port.
        let server = start_socks_server("127.0.0.1", 0).unwrap();
        let server_addr = server.local_addr().unwrap();

        // Spawn the server accept loop in a background thread.
        // run_direct loops forever, so we rely on the listener being dropped when
        // the test process exits, or simply let the thread be abandoned after the
        // test assertion completes.
        thread::spawn(move || {
            server.run_direct();
        });

        // Give the server thread a moment to enter accept().
        thread::sleep(Duration::from_millis(50));

        // Barrier so all client threads fire simultaneously.
        let barrier = Arc::new(Barrier::new(NUM_CLIENTS));
        let mut handles = Vec::with_capacity(NUM_CLIENTS);

        for _ in 0..NUM_CLIENTS {
            let barrier = Arc::clone(&barrier);
            let addr = server_addr;

            handles.push(thread::spawn(move || -> bool {
                // Wait until every client thread is ready.
                barrier.wait();

                let mut stream = match TcpStream::connect_timeout(&addr, Duration::from_secs(5)) {
                    Ok(s) => s,
                    Err(_) => return false,
                };
                stream.set_read_timeout(Some(Duration::from_secs(5))).ok();
                stream.set_write_timeout(Some(Duration::from_secs(5))).ok();

                // SOCKS5 greeting: version=5, nmethods=1, method=no-auth(0x00)
                if stream.write_all(&[0x05, 0x01, 0x00]).is_err() {
                    return false;
                }

                // Expected server response: [0x05, 0x00]
                let mut resp = [0u8; 2];
                if stream.read_exact(&mut resp).is_err() {
                    return false;
                }

                resp[0] == 0x05 && resp[1] == 0x00
            }));
        }

        // Collect results; every client must have succeeded.
        let results: Vec<bool> = handles
            .into_iter()
            .map(|h| h.join().unwrap_or(false))
            .collect();

        let success_count = results.iter().filter(|&&ok| ok).count();
        assert_eq!(
            success_count, NUM_CLIENTS,
            "{} / {} clients completed SOCKS5 auth negotiation successfully",
            success_count, NUM_CLIENTS
        );
    }

    /// Throughput test: send varying data sizes (1 KB, 10 KB, 100 KB) through a
    /// loopback TCP target that echoes everything back, then verify integrity.
    ///
    /// Architecture:
    ///   test client  →  SOCKS5 server (run_direct)  →  echo server
    ///
    /// Because run_direct makes a real outbound TCP connection we spin up a tiny
    /// echo server that accepts one connection per size variant.
    #[test]
    fn test_socks_server_throughput() {
        // ── echo server ────────────────────────────────────────────────────────
        let echo_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let echo_addr = echo_listener.local_addr().unwrap();

        thread::spawn(move || {
            // Handle one connection per data-size variant (3 total).
            for _ in 0..3usize {
                if let Ok((mut conn, _)) = echo_listener.accept() {
                    conn.set_read_timeout(Some(Duration::from_secs(10))).ok();
                    conn.set_write_timeout(Some(Duration::from_secs(10))).ok();
                    let mut buf = vec![0u8; 128 * 1024];
                    loop {
                        match conn.read(&mut buf) {
                            Ok(0) | Err(_) => break,
                            Ok(n) => {
                                if conn.write_all(&buf[..n]).is_err() {
                                    break;
                                }
                            }
                        }
                    }
                }
            }
        });

        // ── SOCKS5 server ──────────────────────────────────────────────────────
        let socks = start_socks_server("127.0.0.1", 0).unwrap();
        let socks_addr = socks.local_addr().unwrap();

        thread::spawn(move || {
            socks.run_direct();
        });

        thread::sleep(Duration::from_millis(50));

        // ── helper: perform one SOCKS5 CONNECT + send/recv payload ─────────────
        let run_transfer = |payload_size: usize| -> bool {
            let mut stream = TcpStream::connect_timeout(&socks_addr, Duration::from_secs(5))
                .expect("connect to SOCKS server");
            stream.set_read_timeout(Some(Duration::from_secs(10))).ok();
            stream.set_write_timeout(Some(Duration::from_secs(10))).ok();

            // Auth negotiation
            stream.write_all(&[0x05, 0x01, 0x00]).unwrap();
            let mut auth_resp = [0u8; 2];
            stream.read_exact(&mut auth_resp).unwrap();
            if auth_resp != [0x05, 0x00] {
                return false;
            }

            // CONNECT request targeting the echo server (IPv4)
            let ip = match echo_addr.ip() {
                std::net::IpAddr::V4(v4) => v4.octets(),
                _ => panic!("expected IPv4 echo addr"),
            };
            let port = echo_addr.port().to_be_bytes();
            let mut connect_req = vec![
                0x05, // version
                0x01, // CMD CONNECT
                0x00, // reserved
                0x01, // ATYP IPv4
            ];
            connect_req.extend_from_slice(&ip);
            connect_req.extend_from_slice(&port);
            stream.write_all(&connect_req).unwrap();

            // Read CONNECT response (at least 10 bytes for IPv4 BND.ADDR)
            let mut conn_resp = [0u8; 10];
            if stream.read_exact(&mut conn_resp).is_err() {
                return false;
            }
            if conn_resp[0] != 0x05 || conn_resp[1] != SOCKS5_REP_SUCCESS {
                return false;
            }

            // Send payload and read it back from the echo server
            let payload: Vec<u8> = (0..payload_size).map(|i| (i & 0xFF) as u8).collect();
            stream.write_all(&payload).unwrap();
            // Signal EOF so echo server can stop reading
            stream.shutdown(std::net::Shutdown::Write).ok();

            let mut received = Vec::with_capacity(payload_size);
            let mut buf = [0u8; 8192];
            loop {
                match stream.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => received.extend_from_slice(&buf[..n]),
                }
            }

            received == payload
        };

        for &size in &[1_024usize, 10_240, 102_400] {
            assert!(
                run_transfer(size),
                "throughput test failed for payload size {} bytes",
                size
            );
        }
    }

    /// E2E test: verifies that data sent through the SOCKS5 tunnel is correctly
    /// relayed to a real TCP echo server and returned unmodified.
    ///
    /// Flow:
    ///   test client  ->  SocksServer (run_direct)  ->  echo server
    #[test]
    fn test_socks_server_e2e_connection() {
        // ── 1. Echo server ────────────────────────────────────────────────────
        let echo_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let echo_addr = echo_listener.local_addr().unwrap();

        thread::spawn(move || {
            if let Ok((mut conn, _)) = echo_listener.accept() {
                conn.set_read_timeout(Some(Duration::from_secs(10))).ok();
                conn.set_write_timeout(Some(Duration::from_secs(10))).ok();
                let mut buf = [0u8; 4096];
                loop {
                    match conn.read(&mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if conn.write_all(&buf[..n]).is_err() {
                                break;
                            }
                        }
                    }
                }
            }
        });

        // ── 2. SOCKS5 server ─────────────────────────────────────────────────
        let server = start_socks_server("127.0.0.1", 0).unwrap();
        let socks_addr = server.local_addr().unwrap();

        thread::spawn(move || {
            server.run_direct();
        });

        // Give both servers a moment to enter accept().
        thread::sleep(Duration::from_millis(50));

        // ── 3. TCP client connects to SOCKS5 server ───────────────────────────
        let mut client = TcpStream::connect_timeout(&socks_addr, Duration::from_secs(5))
            .expect("connect to SOCKS5 server");
        client.set_read_timeout(Some(Duration::from_secs(10))).ok();
        client.set_write_timeout(Some(Duration::from_secs(10))).ok();

        // ── 4. SOCKS5 handshake: version=5, nmethods=1, method=no-auth ────────
        client.write_all(&[0x05, 0x01, 0x00]).unwrap();

        // ── 5. Receive handshake response: [0x05, 0x00] ───────────────────────
        let mut auth_resp = [0u8; 2];
        client.read_exact(&mut auth_resp).unwrap();
        assert_eq!(auth_resp, [0x05, 0x00], "SOCKS5 auth negotiation failed");

        // ── 6. SOCKS5 CONNECT request (IPv4) to echo server ───────────────────
        let ip = match echo_addr.ip() {
            std::net::IpAddr::V4(v4) => v4.octets(),
            _ => panic!("expected IPv4 echo address"),
        };
        let port_bytes = echo_addr.port().to_be_bytes();
        let mut connect_req = vec![
            0x05, // VER
            0x01, // CMD CONNECT
            0x00, // RSV
            0x01, // ATYP IPv4
        ];
        connect_req.extend_from_slice(&ip);
        connect_req.extend_from_slice(&port_bytes);
        client.write_all(&connect_req).unwrap();

        // ── 7. Receive CONNECT success response (10 bytes for IPv4 BND.ADDR) ──
        let mut conn_resp = [0u8; 10];
        client
            .read_exact(&mut conn_resp)
            .expect("read CONNECT response");
        assert_eq!(conn_resp[0], 0x05, "response VER mismatch");
        assert_eq!(
            conn_resp[1], SOCKS5_REP_SUCCESS,
            "SOCKS5 CONNECT did not succeed (rep=0x{:02x})",
            conn_resp[1]
        );

        // ── 8. Send test data through the tunnel ─────────────────────────────
        let test_data = b"hello socks5 tunnel";
        client.write_all(test_data).unwrap();
        // Signal EOF so the echo server stops blocking on read.
        client.shutdown(std::net::Shutdown::Write).unwrap();

        // ── 9. Verify echo server returns the same data ───────────────────────
        let mut received = Vec::new();
        let mut buf = [0u8; 256];
        loop {
            match client.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => received.extend_from_slice(&buf[..n]),
            }
        }

        assert_eq!(
            received, test_data,
            "echoed data does not match sent data"
        );
    }
}
