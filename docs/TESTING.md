# Kraken Testing Guide

## Unit Tests

Kraken maintains **400+ automated tests** across all crates.

### Quick Start

```bash
# Run all unit tests
cargo test --workspace

# Run with verbose output
cargo test --workspace -- --nocapture
```

### Test Summary

| Crate | Tests | Description |
|-------|-------|-------------|
| implant-core | 93+ | Task modules (shell, mesh, file, bof, module_loader) |
| server | 77 | Auth, state, HTTP handlers, gRPC integration |
| mod-mesh | 50 | Networking, encryption, relay, SOCKS |
| protocol | 45 | Encode/decode, ID conversions |
| loot | 43 | Loot types and serialization |
| obfuscation | 30 | Macro tests |
| crypto | 27 | Cryptographic operations |
| mesh | 13 | Dijkstra routing |
| db | 13 | Database operations |

### Feature-Gated Tests

```bash
# Mesh networking tests
cargo test -p implant-core --features mod-mesh -- mesh

# File module tests
cargo test -p implant-core --features mod-file -- file

# BOF module tests
cargo test -p implant-core --features mod-bof -- bof

# Full mesh stack (single-threaded for keepalive)
cargo test -p mod-mesh --features "protocol/grpc" -- --test-threads=1
```

### Stress Tests

```bash
# 100 concurrent TCP connections
cargo test -p mod-mesh -- test_tcp_100_concurrent

# High volume message relay
cargo test -p mod-mesh -- test_relay_high_volume

# Concurrent handshakes
cargo test -p mod-mesh -- test_handshake_concurrent
```

See [wiki/reference/test-coverage.md](../wiki/reference/test-coverage.md) for complete documentation.

---

## Test Environments

### Linux (Primary Development)
- Run smoke test: `./scripts/smoke-test.sh`
- Build: `cargo build --release -p server -p implant-core`
- Run server: `./target/release/kraken-server --insecure`
- Run implant: `KRAKEN_SERVER="http://127.0.0.1:8080" ./target/release/implant`

### Windows VM (Cross-Platform Testing)

**Connection Info:**
```bash
# RDP
xfreerdp /u:labuser /p:'Password123!' /v:192.168.247.132 /dynamic-resolution

# SSH
ssh labuser@192.168.247.132

# WinRM
evil-winrm -i 192.168.247.132 -u labuser -p 'Password123!'

# SMB
smbclient -L //192.168.247.132 -U labuser

# Scan open ports
nmap -sV -p 22,445,3389,5985 192.168.247.132
```

**Credentials:**
- Username: `labuser`
- Password: `Password123!`
- IP: `192.168.247.132`

## Cross-Platform Testing Workflow

### 1. Build Windows Implant
```bash
cargo build --release -p implant-core --target x86_64-pc-windows-gnu
```

### 2. Copy to Windows VM
```bash
scp target/x86_64-pc-windows-gnu/release/implant.exe labuser@192.168.247.132:C:/Users/labuser/Desktop/
```

### 3. Start Server (Linux)
```bash
# Get Linux IP
ip addr show | grep "inet " | grep -v 127.0.0.1

# Start server (bind to all interfaces)
KRAKEN_HTTP_ADDR="0.0.0.0:8080" KRAKEN_GRPC_ADDR="0.0.0.0:50051" ./target/release/kraken-server --insecure
```

### 4. Run Implant (Windows)
```powershell
# Set server address to Linux host IP
$env:KRAKEN_SERVER = "http://<LINUX_IP>:8080"
.\implant.exe
```

### 5. Verify Registration
Check server logs for successful implant registration with Windows hostname/user.

## Binary Size Verification

| Platform | Target | Max Size | Command |
|----------|--------|----------|---------|
| Linux x64 | `x86_64-unknown-linux-gnu` | <3MB | `ls -lh target/release/implant` |
| Windows x64 | `x86_64-pc-windows-gnu` | <1.5MB | `ls -lh target/x86_64-pc-windows-gnu/release/implant.exe` |

## Phase-Specific Tests

### Phase 1-2: Core C2 Loop + Modules
```bash
cargo test --workspace
./scripts/smoke-test.sh
```

### Phase 3: Dynamic Module Loading
```bash
cargo test -p implant-loader -p module-store

# Test module compilation (requires release-implant profile)
cargo build --profile release-implant -p mod-shell --target x86_64-unknown-linux-gnu
```

## Troubleshooting

### Implant Can't Connect
- Check firewall: `ufw allow 8080/tcp`
- Verify server is listening: `ss -tlnp | grep 8080`
- Test connectivity: `curl http://<SERVER_IP>:8080/health`

### Windows Build Fails
- Ensure MinGW installed: `apt install mingw-w64`
- Check target: `rustup target add x86_64-pc-windows-gnu`
