//! Standalone mesh test binary
//!
//! Usage:
//!   mesh_test listen <port>           - Start listener (hub mode)
//!   mesh_test connect <host> <port>   - Connect to hub
//!   mesh_test socks <port>            - Start SOCKS5 proxy (direct mode)
//!   mesh_test socks-peer <mesh-port> <socks-port> - SOCKS5 via mesh peer

use std::env;
use std::net::TcpStream;
use std::thread;
use std::time::Duration;

use mod_mesh::handshake::Transport;  // For send/recv methods

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        eprintln!("Usage: mesh_test listen <port>              - TCP mesh listener");
        eprintln!("       mesh_test connect <host> <port>      - TCP mesh connect");
        eprintln!("       mesh_test socks <port>               - SOCKS5 proxy (direct)");
        eprintln!("       mesh_test smb-listen [pipe_name]     - SMB pipe listener (Windows)");
        eprintln!("       mesh_test smb-connect <host> [pipe]  - SMB pipe connect (Windows)");
        std::process::exit(1);
    }

    match args[1].as_str() {
        "listen" => {
            let port: u16 = args.get(2)
                .expect("port required")
                .parse()
                .expect("invalid port");
            run_listener(port);
        }
        "connect" => {
            let host = args.get(2).expect("host required");
            let port: u16 = args.get(3)
                .expect("port required")
                .parse()
                .expect("invalid port");
            run_connector(host, port);
        }
        "socks" => {
            let port: u16 = args.get(2)
                .expect("port required")
                .parse()
                .expect("invalid port");
            run_socks_server(port);
        }
        "smb-listen" => {
            let pipe_name = args.get(2).map(|s| s.as_str()).unwrap_or("kraken-mesh");
            run_smb_listener(pipe_name);
        }
        "smb-connect" => {
            let host = args.get(2).expect("host required");
            let pipe_name = args.get(3).map(|s| s.as_str()).unwrap_or("kraken-mesh");
            run_smb_connector(host, pipe_name);
        }
        _ => {
            eprintln!("Unknown command: {}", args[1]);
            std::process::exit(1);
        }
    }
}

fn run_listener(port: u16) {
    println!("[+] Starting mesh listener on 0.0.0.0:{}", port);

    let server = mod_mesh::tcp::TcpServer::bind("0.0.0.0", port)
        .expect("Failed to bind");

    println!("[+] Listening... waiting for connections");

    loop {
        match server.accept() {
            Ok(Some(stream)) => {
                let peer_addr = stream.peer_addr()
                    .map(|a| a.to_string())
                    .unwrap_or_else(|_| "unknown".to_string());
                println!("[+] Incoming connection from {}", peer_addr);

                thread::spawn(move || {
                    handle_connection(stream);
                });
            }
            Ok(None) => {
                thread::sleep(Duration::from_millis(100));
            }
            Err(e) => {
                eprintln!("[-] Accept error: {}", e);
                break;
            }
        }
    }
}

fn handle_connection(stream: TcpStream) {
    let peer_addr = stream.peer_addr()
        .map(|a| a.to_string())
        .unwrap_or_else(|_| "unknown".to_string());

    println!("[*] Handling connection from {}", peer_addr);

    // Wrap stream
    let mut conn = match mod_mesh::tcp::TcpConnection::new(stream) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("[-] Connection setup failed: {}", e);
            return;
        }
    };

    // Generate keypair
    let keypair = match crypto::generate_keypair() {
        Ok(k) => k,
        Err(e) => {
            eprintln!("[-] Keypair generation failed: {}", e);
            return;
        }
    };

    // Responder handshake
    match mod_mesh::respond_handshake(&mut conn, &keypair) {
        Ok(result) => {
            let peer_pubkey_hex = hex::encode(result.peer_public_key.as_bytes());
            println!("[+] Handshake SUCCESS with {}", peer_addr);
            println!("    Peer pubkey: {}...", &peer_pubkey_hex[..16]);
            println!("    Session key derived: {} bytes", result.session_key.as_bytes().len());

            // Wrap connection with encryption (responder = not initiator)
            let mut enc_conn = mod_mesh::EncryptedConnection::new(conn, result.session_key, false);

            // Test encrypted communication
            println!("[*] Testing encrypted channel...");
            match enc_conn.recv() {
                Ok(msg) => {
                    println!("[+] Received encrypted: {:?}", String::from_utf8_lossy(&msg));
                    // Echo back
                    let response = b"ENCRYPTED_ACK";
                    if let Err(e) = enc_conn.send(response) {
                        eprintln!("[-] Send failed: {}", e);
                    } else {
                        println!("[+] Sent encrypted response");
                    }
                }
                Err(e) => {
                    eprintln!("[-] Recv failed: {}", e);
                }
            }

            // Derive peer ID
            let hash = crypto::sha256(result.peer_public_key.as_bytes());
            let peer_id = common::ImplantId::from_bytes(&hash[..16]).unwrap();
            println!("    Peer ID: {}", peer_id);
            println!("[+] Encrypted mesh link established!");
        }
        Err(e) => {
            eprintln!("[-] Handshake FAILED: {}", e);
        }
    }
}

fn run_connector(host: &str, port: u16) {
    println!("[+] Connecting to {}:{}", host, port);

    let mut conn = match mod_mesh::tcp::connect(host, port) {
        Ok(c) => {
            println!("[+] TCP connection established");
            c
        }
        Err(e) => {
            eprintln!("[-] Connection failed: {}", e);
            std::process::exit(1);
        }
    };

    // Generate keypair
    let keypair = crypto::generate_keypair().expect("keypair generation failed");
    println!("[*] Generated ephemeral keypair");

    // Initiator handshake
    match mod_mesh::initiate_handshake(&mut conn, &keypair, None) {
        Ok(result) => {
            let peer_pubkey_hex = hex::encode(result.peer_public_key.as_bytes());
            println!("[+] Handshake SUCCESS!");
            println!("    Peer pubkey: {}...", &peer_pubkey_hex[..16]);
            println!("    Session key derived: {} bytes", result.session_key.as_bytes().len());

            // Wrap connection with encryption (initiator = true)
            let mut enc_conn = mod_mesh::EncryptedConnection::new(conn, result.session_key, true);

            // Test encrypted communication
            println!("[*] Testing encrypted channel...");
            let test_msg = b"ENCRYPTED_HELLO";
            if let Err(e) = enc_conn.send(test_msg) {
                eprintln!("[-] Send failed: {}", e);
                std::process::exit(1);
            }
            println!("[+] Sent encrypted: {:?}", String::from_utf8_lossy(test_msg));

            match enc_conn.recv() {
                Ok(response) => {
                    println!("[+] Received encrypted: {:?}", String::from_utf8_lossy(&response));
                }
                Err(e) => {
                    eprintln!("[-] Recv failed: {}", e);
                }
            }

            println!("[+] Encrypted mesh link established!");
        }
        Err(e) => {
            eprintln!("[-] Handshake FAILED: {}", e);
            std::process::exit(1);
        }
    }
}

fn run_socks_server(port: u16) {
    println!("[+] Starting SOCKS5 proxy on 0.0.0.0:{}", port);

    let server = match mod_mesh::start_socks_server("0.0.0.0", port) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[-] Failed to start SOCKS server: {}", e);
            std::process::exit(1);
        }
    };

    let addr = server.local_addr().unwrap();
    println!("[+] SOCKS5 server listening on {}", addr);
    println!("[*] Configure proxychains: socks5 127.0.0.1 {}", addr.port());
    println!("[*] Waiting for connections...");

    // Run in direct mode (connects directly to targets)
    server.run_direct();
}

#[cfg(windows)]
fn run_smb_listener(pipe_name: &str) {
    println!("[+] Starting SMB mesh listener on \\\\.\\pipe\\{}", pipe_name);

    let server = match mod_mesh::smb::SmbServer::bind(pipe_name) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[-] Failed to create named pipe: {}", e);
            std::process::exit(1);
        }
    };

    println!("[+] Listening... waiting for connections");

    loop {
        match server.accept() {
            Ok(mut conn) => {
                println!("[+] Incoming SMB connection");

                let keypair = match crypto::generate_keypair() {
                    Ok(k) => k,
                    Err(e) => {
                        eprintln!("[-] Keypair generation failed: {}", e);
                        continue;
                    }
                };

                match mod_mesh::respond_handshake(&mut conn, &keypair) {
                    Ok(result) => {
                        let peer_pubkey_hex = hex::encode(result.peer_public_key.as_bytes());
                        println!("[+] SMB Handshake SUCCESS!");
                        println!("    Peer pubkey: {}...", &peer_pubkey_hex[..16]);
                        println!("    Session key derived: {} bytes", result.session_key.as_bytes().len());

                        // Test encrypted communication
                        let mut enc_conn = mod_mesh::EncryptedConnection::new(conn, result.session_key, false);
                        match enc_conn.recv() {
                            Ok(msg) => {
                                println!("[+] Received encrypted: {:?}", String::from_utf8_lossy(&msg));
                                let _ = enc_conn.send(b"SMB_ENCRYPTED_ACK");
                                println!("[+] Sent encrypted response");
                            }
                            Err(e) => eprintln!("[-] Recv failed: {}", e),
                        }

                        let hash = crypto::sha256(result.peer_public_key.as_bytes());
                        let peer_id = common::ImplantId::from_bytes(&hash[..16]).unwrap();
                        println!("    Peer ID: {}", peer_id);
                        println!("[+] Encrypted SMB mesh link established!");
                    }
                    Err(e) => {
                        eprintln!("[-] SMB Handshake FAILED: {}", e);
                    }
                }
            }
            Err(e) => {
                eprintln!("[-] Accept error: {}", e);
                thread::sleep(Duration::from_millis(100));
            }
        }
    }
}

#[cfg(not(windows))]
fn run_smb_listener(_pipe_name: &str) {
    eprintln!("[-] SMB listener only supported on Windows");
    std::process::exit(1);
}

#[cfg(windows)]
fn run_smb_connector(host: &str, pipe_name: &str) {
    println!("[+] Connecting to \\\\{}\\pipe\\{}", host, pipe_name);

    let mut conn = match mod_mesh::smb::connect(host, pipe_name) {
        Ok(c) => {
            println!("[+] SMB connection established");
            c
        }
        Err(e) => {
            eprintln!("[-] Connection failed: {}", e);
            std::process::exit(1);
        }
    };

    let keypair = crypto::generate_keypair().expect("keypair generation failed");
    println!("[*] Generated ephemeral keypair");

    match mod_mesh::initiate_handshake(&mut conn, &keypair, None) {
        Ok(result) => {
            let peer_pubkey_hex = hex::encode(result.peer_public_key.as_bytes());
            println!("[+] SMB Handshake SUCCESS!");
            println!("    Peer pubkey: {}...", &peer_pubkey_hex[..16]);
            println!("    Session key derived: {} bytes", result.session_key.as_bytes().len());

            let mut enc_conn = mod_mesh::EncryptedConnection::new(conn, result.session_key, true);
            let test_msg = b"SMB_ENCRYPTED_HELLO";
            if let Err(e) = enc_conn.send(test_msg) {
                eprintln!("[-] Send failed: {}", e);
                std::process::exit(1);
            }
            println!("[+] Sent encrypted: {:?}", String::from_utf8_lossy(test_msg));

            match enc_conn.recv() {
                Ok(response) => {
                    println!("[+] Received encrypted: {:?}", String::from_utf8_lossy(&response));
                }
                Err(e) => {
                    eprintln!("[-] Recv failed: {}", e);
                }
            }

            println!("[+] Encrypted SMB mesh link established!");
        }
        Err(e) => {
            eprintln!("[-] SMB Handshake FAILED: {}", e);
            std::process::exit(1);
        }
    }
}

#[cfg(not(windows))]
fn run_smb_connector(_host: &str, _pipe_name: &str) {
    eprintln!("[-] SMB connector only supported on Windows");
    std::process::exit(1);
}
