# Kraken C2 Framework

**A Rust-based Command & Control framework for authorized security research and red team operations.**

Version: 0.1.0 | Phase: Foundation

[![Coverage](https://codecov.io/gh/YOUR_ORG/kraken/branch/main/graph/badge.svg)](https://codecov.io/gh/YOUR_ORG/kraken)

---

## Table of Contents

1. [Overview](#overview)
2. [Features](#features)
3. [Architecture](#architecture)
4. [Prerequisites](#prerequisites)
5. [Building from Source](#building-from-source)
6. [Running the Framework](#running-the-framework)
7. [Testing with the Implant Simulator](#testing-with-the-implant-simulator)
8. [Project Structure](#project-structure)
9. [Security Considerations](#security-considerations)
10. [Development](#development)
11. [License](#license)

---

## Overview

Kraken is a research-grade, open-source C2 framework built in Rust. It synthesizes lessons from industry C2 frameworks (Cobalt Strike, Havoc, Brute Ratel, Mythic, Covenant, and others) into a cohesive, OPSEC-first design.

### What Kraken Is

- **Rust-native** with syscall-level control and no runtime artifacts
- **Modular implant** with a minimal hardened core and runtime-loadable signed modules
- **Mesh-capable** for implant relay networks and peer-to-peer communications
- **Operator-focused** with a professional TUI (ratatui with Catppuccin Mocha theming)
- **Professionally structured** Cargo workspace with explicit API boundaries
- **Auditable** with append-only structured logging
- **OPSEC-aware** showing operators what defenders see

### Intended Use

Kraken is designed for:

- **Authorized security testing** in controlled environments
- **Red team operations** with proper rules of engagement
- **Security research** and framework development
- **Educational purposes** for understanding C2 architecture

**Legal Notice**: Kraken is provided for authorized security testing and research only. Unauthorized access to computer systems is illegal. Users are responsible for ensuring compliance with all applicable laws and regulations.

---

## Features

### Core Framework

- **Encrypted Communications**: X25519 ECDH key exchange with AES-256-GCM encryption
- **Multi-Transport**: HTTP/HTTPS, TCP, SMB, and DNS support with automatic fallback chains
- **gRPC Server**: Operator-to-server communication using tonic/protobuf
- **TUI Operator Interface**: Real-time ratatui-based terminal UI with interactive command dispatch
- **SQLite Database**: Structured data storage for implants, tasks, results, and logs
- **Audit Logging**: Append-only structured logs for all operations and implant events

### Implant Capabilities

- **Compile-time Configuration**: All C2 addresses, intervals, and keys baked at build time
- **Task Dispatch**: Flexible task system with typed results (not raw bytes)
- **Module System**: Minimal core with capability modules loaded at runtime or compile-time
- **Mesh Networking**: Peer discovery, relaying, and topology computation
- **OPSEC-First Design**: Minimal runtime signatures, indirect syscalls, sleep masking
- **BOF Compatibility**: Rust COFF loader for existing Beacon Object File ecosystem

### Operator Features

- **Interactive TUI**: Real-time implant interaction with keybinding-based navigation
- **Task Management**: Queue, dispatch, and track tasks across implant network
- **Multi-Implant Control**: Manage multiple implants with grouped operations
- **Structured Results**: Rendered task output with search and export capabilities
- **Session Management**: Clean session tracking with graceful cleanup

---

## Architecture

### High-Level Diagram

```
┌─────────────────────────────────────────────────────────────┐
│                      Operator Workstation                   │
│                                                              │
│  ┌──────────────────────────────────────────────────────┐  │
│  │            Kraken Operator (TUI)                      │  │
│  │  ┌────────────────────────────────────────────────┐  │  │
│  │  │  ratatui UI (Catppuccin Mocha)                 │  │  │
│  │  │  • Implant list & status                       │  │  │
│  │  │  • Task queue & results                        │  │  │
│  │  │  • Interactive command interface               │  │  │
│  │  └────────────────────────────────────────────────┘  │  │
│  └────────────────┬─────────────────────────────────────┘  │
│                   │ gRPC (encrypted TLS)                    │
└───────────────────┼──────────────────────────────────────────┘
                    │
                    │
┌───────────────────▼──────────────────────────────────────────┐
│                   Kraken Teamserver                           │
│                                                               │
│  ┌────────────────────────────────────────────────────────┐  │
│  │ gRPC Service (tonic)                                   │  │
│  │ • Operator RPC handlers                                │  │
│  │ • RBAC & session management                            │  │
│  │ • Audit event emission                                 │  │
│  └────────────────────────────────────────────────────────┘  │
│                                                               │
│  ┌────────────────────────────────────────────────────────┐  │
│  │ HTTP/HTTPS Listener (axum)                             │  │
│  │ • Implant registration & check-in                      │  │
│  │ • Encrypted payload delivery                           │  │
│  │ • Multi-transport routing                              │  │
│  └────────────────────────────────────────────────────────┘  │
│                                                               │
│  ┌────────────────────────────────────────────────────────┐  │
│  │ Database (SQLite)                                      │  │
│  │ • Implant registry & state                             │  │
│  │ • Task queue & results                                 │  │
│  │ • Audit logs (append-only)                             │  │
│  │ • Credentials & loot                                   │  │
│  └────────────────────────────────────────────────────────┘  │
│                                                               │
└──────────────────┬─────────────────────────────────────────┬─┘
                   │ HTTP/HTTPS                              │
                   │ (Encrypted: X25519 + AES-256-GCM)      │
                   │                                         │
        ┌──────────▼────────────┐         ┌──────────────────▼───┐
        │                       │         │                      │
        │   Compromised Host 1  │         │  Compromised Host 2  │
        │   (Windows/Linux)     │         │  (Windows/Linux)     │
        │                       │         │                      │
        │ ┌─────────────────┐   │         │ ┌──────────────────┐ │
        │ │ Kraken Implant  │   │         │ │ Kraken Implant   │ │
        │ │ ┌─────────────┐ │   │         │ │ ┌──────────────┐ │ │
        │ │ │ Core Kernel │ │   │         │ │ │ Core Kernel  │ │ │
        │ │ │ • Check-in  │ │   │         │ │ │ • Check-in   │ │ │
        │ │ │ • Dispatch  │ │   │         │ │ │ • Dispatch   │ │ │
        │ │ │ • Transport │ │   │         │ │ │ • Transport  │ │ │
        │ │ └──────┬──────┘ │   │         │ │ └──────┬───────┘ │ │
        │ │        │        │   │         │ │        │         │ │
        │ │ ┌──────▼──────┐ │   │         │ │ ┌──────▼──────┐ │ │
        │ │ │   Modules   │ │   │         │ │ │   Modules  │ │ │
        │ │ │ • shell     │ │   │         │ │ │ • file     │ │ │
        │ │ │ • file      │ │   │         │ │ │ • socks    │ │ │
        │ │ │ • bof       │ │   │         │ │ │ • mesh     │ │ │
        │ │ │ • mesh      │ │   │         │ │ └────────────┘ │ │
        │ │ └─────────────┘ │   │         │ │                │ │
        │ └─────────────────┘   │         │ └────────────────┘ │
        │                       │         │                    │
        └───────────────────────┘         └────────────────────┘
```

### Crate Structure

The Kraken workspace consists of 9 Rust crates, each with a single responsibility:

| Crate | Purpose |
|-------|---------|
| **common** | Shared traits (`Module`, `Transport`, `CryptoProvider`), ID types, error types, `TaskResult` enum |
| **crypto** | Cryptographic primitives: X25519 ECDH, AES-256-GCM, HKDF-SHA256, Ed25519, secure random |
| **protocol** | Generated protobuf types and serialization helpers for all messages |
| **config** | Compile-time configuration baking for implant settings |
| **db** | Database abstraction layer using sqlx with SQLite (PostgreSQL migration path available) |
| **server** | Teamserver binary: gRPC services, HTTP listeners, state management, audit logging |
| **operator** | Operator TUI: ratatui UI, keybindings, real-time event rendering |
| **implant-core** | Minimal implant kernel: registration, check-in loop, task dispatch, transport chains |
| **implant-sim** | Implant simulator for testing server functionality without real targets |

### Communication Protocols

**Operator ↔ Server**: gRPC over TLS
- Service definitions in `proto/kraken.proto`
- tonic framework for async RPC handling
- Per-operator session management and RBAC

**Implant ↔ Server**: HTTP/HTTPS with encrypted payload
- Registration: ephemeral X25519 keypair generation
- Check-in: encrypted messages using derived AES-256-GCM keys
- Task delivery: server sends encrypted task list
- Response upload: encrypted task results

**Encryption Details**:
- **Key Exchange**: X25519 ECDH with server public key (baked at implant compile time)
- **Derived Keys**: HKDF-SHA256 from shared secret
- **Bulk Encryption**: AES-256-GCM with per-message nonces
- **Nonce Replay Protection**: Server tracks seen nonces to prevent replay attacks

---

## Prerequisites

### Required

- **Rust 1.75+** ([Install from rustup.rs](https://rustup.rs/))
- **Protoc 3.20+** for protobuf code generation
- **SQLite development libraries** (usually included with build-essential)

### Optional (for cross-compilation)

- **Windows MinGW target** (for Windows implant builds)
- **Linux target** (for Linux implant builds)

### System Dependencies

#### Ubuntu/Debian

```bash
sudo apt-get update
sudo apt-get install -y \
    build-essential \
    protobuf-compiler \
    libsqlite3-dev \
    pkg-config \
    libssl-dev
```

#### macOS

```bash
brew install protobuf sqlite3
```

#### Windows

Use MSVC build tools or install via Chocolatey:

```powershell
choco install protoc
```

---

## Building from Source

### 1. Clone the Repository

```bash
git clone https://github.com/kraken-c2/kraken.git
cd kraken
```

### 2. Setup Development Environment

```bash
# Install development targets for cross-compilation
just setup

# Or manually:
rustup target add x86_64-pc-windows-gnu
rustup target add x86_64-unknown-linux-gnu
cargo install just
```

### 3. Generate Protocol Code

```bash
just proto

# Or manually:
cargo build -p protocol
```

### 4. Build All Components

```bash
# Full release build
just build

# Or build individual components:
just server          # Teamserver
just operator        # Operator TUI
just implant-linux-x64
just implant-windows-x64
just sim             # Implant simulator
```

### Build Output

After compilation, binaries are located in:

- **Server**: `target/release/server`
- **Operator**: `target/release/operator` (or `kraken-operator`)
- **Implant (Linux)**: `target/x86_64-unknown-linux-gnu/release-implant/implant-core`
- **Implant (Windows)**: `target/x86_64-pc-windows-gnu/release-implant/implant-core.exe`
- **Simulator**: `target/release/implant-sim`

---

## Running the Framework

### Step 1: Start the Teamserver

```bash
# Using just:
just server

# Or directly:
cargo run -p server --release

# With custom ports:
./target/release/server --grpc-port 50051 --http-port 8080

# With logging:
RUST_LOG=debug cargo run -p server --release
```

The server initializes:
1. SQLite database (creates if not exists)
2. gRPC listener on port 50051 (default)
3. HTTP listener on port 8080 (default)
4. Event loop for task dispatch

**Output**:
```
2024-03-28T10:15:30Z INFO server: Kraken Teamserver starting
2024-03-28T10:15:30Z INFO server: gRPC listener: 127.0.0.1:50051
2024-03-28T10:15:30Z INFO server: HTTP listener: 0.0.0.0:8080
2024-03-28T10:15:30Z INFO server: Database initialized
```

### Step 2: Start the Operator TUI

In a new terminal:

```bash
# Using just:
just operator

# Or directly:
cargo run -p operator --release

# With custom server address:
./target/release/kraken-operator --server http://localhost:50051

# With logging:
RUST_LOG=info ./target/release/kraken-operator --server http://localhost:50051
```

The operator will:
1. Connect to the teamserver gRPC endpoint
2. Initialize the TUI interface
3. Display implant list and status
4. Wait for interactive commands

**Keybindings** (reference):
- `Ctrl+C` or `Ctrl+Q`: Exit
- `Tab`: Navigate between panels
- `Enter`: Select/Execute command
- Arrow keys: Navigate implants/tasks
- See logs in `logs/operator.log` for detailed activity

### Step 3: Register an Implant

With the simulator:

```bash
# In a third terminal:
just sim

# Or directly:
cargo run -p implant-sim
```

The simulator:
1. Generates an ephemeral X25519 keypair
2. Sends registration to server on `http://localhost:8080`
3. Receives implant ID and server key
4. Starts check-in loop (every 5 seconds by default)
5. Simulates task execution and result upload

**Output**:
```
[INFO] Connecting to http://localhost:8080
[INFO] Generated ephemeral keypair
[INFO] Registering implant...
[INFO] Registered as implant ID: 550e8400-e29b-41d4-a716-446655440000
[INFO] First check-in in 5 seconds...
```

Once registered, you should see the implant appear in the operator TUI.

---

## Testing with the Implant Simulator

The `implant-sim` crate provides a simulated implant for development and testing:

### Features

- **HTTP-based communication** matching the real implant protocol
- **Encrypted registration** using X25519 + AES-256-GCM
- **Task simulation** with configurable response times
- **No actual code execution** (simulates safely)

### Basic Workflow

1. **Terminal 1** - Start server:
   ```bash
   just server
   ```

2. **Terminal 2** - Start operator:
   ```bash
   just operator
   ```

3. **Terminal 3** - Start simulator(s):
   ```bash
   # Single simulator
   just sim

   # Or run multiple simulators (spawns multiple implants)
   for i in {1..5}; do cargo run -p implant-sim &; done
   ```

4. **In Operator TUI**:
   - View implants in the list
   - Select implant with arrow keys
   - Dispatch tasks using menu commands
   - View results in real-time

### Testing Task Dispatch

From the operator TUI, you can:

1. **Queue a task**: Select implant → `New Task` → Choose module
2. **Set parameters**: Fill in command details
3. **Dispatch**: Server sends encrypted task to implant
4. **Receive result**: Simulator responds with mock data
5. **View result**: TUI renders typed result with proper formatting

### Testing Multiple Implants

```bash
# Spawn 5 simulators with different configs
RUST_LOG=info cargo run -p implant-sim -- --instances 5
```

Each simulator:
- Registers independently
- Maintains its own check-in loop
- Can receive tasks in parallel
- Simulates realistic network jitter

---

## Project Structure

### Directory Layout

```
kraken/
├── README.md                      # This file
├── Cargo.toml                     # Workspace configuration
├── Justfile                       # Build automation (just task runner)
├── proto/
│   └── kraken.proto              # Protocol buffer definitions
│
├── crates/
│   ├── common/                    # Shared types & traits
│   │   ├── src/
│   │   │   ├── lib.rs
│   │   │   ├── traits.rs         # Transport, Module, CryptoProvider
│   │   │   ├── error.rs          # KrakenError type
│   │   │   └── types.rs          # TaskResult, ImplantId, etc.
│   │   └── Cargo.toml
│   │
│   ├── crypto/                    # Cryptographic primitives
│   │   ├── src/
│   │   │   ├── lib.rs
│   │   │   ├── x25519.rs         # ECDH key exchange
│   │   │   ├── aes_gcm.rs        # Symmetric encryption
│   │   │   └── hkdf.rs           # Key derivation
│   │   └── Cargo.toml
│   │
│   ├── protocol/                  # Protobuf generated types
│   │   ├── src/
│   │   │   ├── lib.rs
│   │   │   └── generated.rs      # (auto-generated by build.rs)
│   │   └── Cargo.toml
│   │
│   ├── config/                    # Compile-time configuration
│   │   ├── src/
│   │   │   └── lib.rs
│   │   └── Cargo.toml
│   │
│   ├── db/                        # Database layer
│   │   ├── src/
│   │   │   ├── lib.rs
│   │   │   ├── repositories/     # CRUD operations
│   │   │   └── migrations/       # SQL migrations
│   │   └── Cargo.toml
│   │
│   ├── server/                    # Teamserver binary
│   │   ├── src/
│   │   │   ├── main.rs          # Entry point
│   │   │   ├── lib.rs
│   │   │   ├── grpc/            # gRPC service handlers
│   │   │   ├── http/            # HTTP listener (axum)
│   │   │   └── state.rs         # Server state management
│   │   └── Cargo.toml
│   │
│   ├── operator/                  # Operator TUI
│   │   ├── src/
│   │   │   ├── main.rs          # Entry point
│   │   │   ├── lib.rs
│   │   │   ├── app.rs           # App state & event loop
│   │   │   ├── client.rs        # gRPC client wrapper
│   │   │   ├── theme.rs         # Catppuccin Mocha colors
│   │   │   └── views/           # TUI components
│   │   └── Cargo.toml
│   │
│   ├── implant-core/              # Implant kernel
│   │   ├── src/
│   │   │   ├── main.rs          # Entry point (Windows/Linux)
│   │   │   ├── lib.rs
│   │   │   ├── checkin.rs       # Registration & check-in loop
│   │   │   ├── transport.rs     # HTTP/HTTPS connector
│   │   │   ├── config.rs        # Baked configuration
│   │   │   └── registry.rs      # Module registry
│   │   └── Cargo.toml
│   │
│   └── implant-sim/               # Implant simulator
│       ├── src/
│       │   ├── main.rs
│       │   └── lib.rs
│       └── Cargo.toml
│
├── kraken-spec/                   # Phase specifications
│   ├── KRAKEN.md                 # Architecture & design (Phase 0)
│   ├── KRAKEN-PHASE1.md          # MVP implementation
│   ├── KRAKEN-PHASE2.md          # Modules & capabilities
│   ├── KRAKEN-PHASE3.md          # Dynamic loading
│   ├── KRAKEN-PHASE4.md          # OPSEC hardening
│   ├── KRAKEN-PHASE5.md          # Mesh networking
│   ├── KRAKEN-PHASE6.md          # Operations & RBAC
│   └── KRAKEN-PHASE7.md          # Advanced features
│
└── target/                        # Build artifacts (git-ignored)
    └── release/                   # Compiled binaries
```

---

## Security Considerations

### Cryptographic Security

**Key Exchange**: X25519 elliptic-curve Diffie-Hellman
- Baked server public key prevents MITM at registration
- Ephemeral implant keypair per-session
- No key reuse across sessions

**Symmetric Encryption**: AES-256-GCM
- 256-bit keys derived from shared secret via HKDF-SHA256
- Authenticated encryption (GCM provides both confidentiality and authenticity)
- Per-message nonces to prevent reuse
- Nonce replay protection on server

**Module Signing** (Phase 3): Ed25519 signatures
- Server signs module binaries
- Implant verifies signature before loading
- Tampering detection

**Hash Algorithm**: SHA-256 for:
- Nonce derivation
- Key derivation (HKDF)
- Config integrity verification

### Operational Security

**Implant**:
- All configuration baked at compile time
- No command-line arguments (prevents parent process inspection)
- No environment variable lookups
- Minimal process footprint
- Optional sleep masking (defeats timing analysis)

**Server**:
- No hardcoded credentials (database encrypted at rest via OS)
- TLS for gRPC (operator communication)
- Audit logging for all operations (append-only)
- Operator RBAC (Phase 6)
- Session timeouts

**Operator**:
- TLS connection to teamserver
- No credential caching
- Logs to file (not stdout) by default
- Clean shutdown (no artifact leftover)

### Threat Model

Kraken assumes:

**In Scope**:
- EDR (endpoint detection/response) evasion
- Network defensive (NDR, DPI, TLS interception)
- SIEM correlation attacks
- Sandbox detection and anti-analysis
- Manual blue team investigation

**Out of Scope**:
- Nation-state kernel exploits
- Hypervisor access
- Firmware/UEFI persistence
- Cryptographic breaks (assumes AES-256-GCM, X25519, SHA-256 are secure)
- Compromised build environment
- Physical access attacks

### For Authorized Operations Only

**Legal**: Kraken is provided for authorized security testing and research. Unauthorized access to computer systems is illegal.

**Technical Scope Enforcement**: The framework does not include:
- Ransomware/wiper/destructive capabilities
- Supply chain attack tooling
- Automated mass exploitation

Users are responsible for:
- Obtaining proper authorization before testing
- Maintaining audit logs for compliance
- Using in isolated test environments
- Securing operator infrastructure
- Managing implant artifacts

---

## Development

### Adding a New Module

Modules extend implant capability. Example: adding `mod-shell` for command execution

1. **Create the module crate**:
   ```bash
   mkdir -p crates/implant-modules/mod-shell/src
   cargo init --lib crates/implant-modules/mod-shell
   ```

2. **Implement the `Module` trait** from `common`:
   ```rust
   use common::{Module, TaskResult};

   pub struct ShellModule;

   #[async_trait::async_trait]
   impl Module for ShellModule {
       async fn execute(&self, task: &Task) -> Result<TaskResult, KrakenError> {
           // Command execution logic
       }
   }
   ```

3. **Add to implant registry** in `implant-core/src/registry.rs`:
   ```rust
   #[cfg(feature = "mod-shell")]
   mod_shell::ShellModule,
   ```

4. **Add protobuf messages** to `proto/kraken.proto`:
   ```protobuf
   message ShellTask {
       string command = 1;
       uint32 timeout_seconds = 2;
   }
   ```

5. **Write tests** in `mod-shell/tests/`:
   ```rust
   #[tokio::test]
   async fn test_shell_execution() {
       // Test logic
   }
   ```

### Running Tests

```bash
# All tests
just test

# Specific crate
cargo test -p common
cargo test -p crypto
cargo test -p server

# With output
cargo test -- --nocapture

# Integration tests
cargo test --test '*'
```

### Code Quality

```bash
# Format code
just fmt

# Lint with clippy
just lint

# Check compilation
just check
```

### Adding a New Transport

Transports define how implants communicate with the server.

1. **Implement the `Transport` trait** from `common`:
   ```rust
   pub trait Transport: Send + Sync {
       async fn send(&self, data: &[u8]) -> Result<Vec<u8>, TransportError>;
   }
   ```

2. **Add listener in server**:
   ```rust
   pub struct CustomListener {
       // Protocol-specific state
   }

   impl Listener for CustomListener {
       async fn accept(&mut self) -> Result<Connection, ListenerError> {
           // Accept incoming connections
       }
   }
   ```

3. **Integrate in implant** transport chain in `implant-core/src/transport.rs`

4. **Add tests** for encoding/decoding, error handling, timeout behavior

### Database Migrations

```bash
# Run migrations
just db-migrate

# Or manually
cargo run -p db --bin migrate

# Add new migration
# Create file: crates/db/migrations/001_schema.sql
```

### Debugging

**Tracing Logs**:
```bash
# High verbosity
RUST_LOG=trace cargo run -p server

# Selective modules
RUST_LOG=server=debug,crypto=debug cargo run -p server

# Write to file
RUST_LOG=debug cargo run -p server 2>&1 | tee debug.log
```

**GDB (Linux)**:
```bash
# Debug implant
cargo build -p implant-core --target x86_64-unknown-linux-gnu
gdb target/x86_64-unknown-linux-gnu/debug/implant-core
```

---

## Common Tasks

### Build Windows Implant (from Linux)

```bash
# One-off build
just implant-windows-x64

# Or with custom config
cargo build \
    --profile release-implant \
    -p implant-core \
    --target x86_64-pc-windows-gnu \
    --release
```

Requires MinGW toolchain installed (see Prerequisites).

### Build Linux Implant (from macOS/Windows)

```bash
just implant-linux-x64
```

### Customize Implant Configuration

Edit `crates/implant-core/src/config.rs` to bake settings:

```rust
const CHECKIN_INTERVAL: u32 = 5;           // seconds
const JITTER_PERCENT: u32 = 20;            // 0-100
const SERVER_URL: &str = "http://c2.example.com:8080";
const SERVER_PUBLIC_KEY: &[u8; 32] = b"..."; // X25519 public key
```

Rebuild implant to apply changes.

### Run Multiple Implants

```bash
# Spawn 10 simulators
for i in {1..10}; do
    (sleep $((RANDOM % 5)) && cargo run -p implant-sim) &
done
wait
```

### Monitor Server Activity

```bash
# Follow server logs in real-time
RUST_LOG=debug cargo run -p server 2>&1 | grep -E "register|checkin|task"

# Or from a file
tail -f logs/server.log | grep ERROR
```

---

## Troubleshooting

### "protoc not found"

Install protobuf compiler:
```bash
# Ubuntu/Debian
sudo apt-get install protobuf-compiler

# macOS
brew install protobuf

# Or build from source
git clone https://github.com/protocolbuffers/protobuf.git
cd protobuf && ./configure && make && sudo make install
```

### "sqlite3 development libraries not found"

```bash
# Ubuntu/Debian
sudo apt-get install libsqlite3-dev

# macOS
brew install sqlite3

# Or use bundled sqlite3
cargo build -p db --features bundled
```

### Implant won't connect to server

1. **Check server is running**: `netstat -tlnp | grep 8080`
2. **Verify network connectivity**: `curl http://localhost:8080/health`
3. **Check logs**: `RUST_LOG=debug cargo run -p implant-sim`
4. **Verify firewall**: `sudo ufw allow 8080` (if using UFW)

### "too many open files" error

Increase file descriptor limit:
```bash
# Temporarily
ulimit -n 4096

# Permanently (Linux)
echo "* soft nofile 4096" | sudo tee -a /etc/security/limits.conf
```

### TUI operator won't connect

```bash
# Verify gRPC port
netstat -tlnp | grep 50051

# Test gRPC directly
grpcurl -plaintext localhost:50051 list

# Check server logs
RUST_LOG=debug cargo run -p server 2>&1 | grep grpc
```

---

## Performance Tuning

### Implant Size Optimization

Release build optimizations are enabled by default in `Cargo.toml`:

```toml
[profile.release]
opt-level = "z"        # Optimize for size
lto = true             # Link-time optimization
codegen-units = 1      # Increase optimization
panic = "abort"        # Reduce panic handler size
strip = true           # Strip symbols
```

To further reduce size:

```bash
# Check binary size
ls -lh target/release-implant/*/implant-core*

# Strip additional symbols
strip --strip-all target/release-implant/*/implant-core
```

### Server Throughput

Increase concurrency in `server/Cargo.toml`:

```toml
tokio = { version = "1.35", features = ["full"] }  # Multi-threaded runtime
```

Tune in `crates/server/src/main.rs`:

```rust
// Increase gRPC connection limit
let max_connections = 10000;

// Increase database pool size
let pool = sqlx::pool::PoolOptions::new()
    .max_connections(50)
    .connect(database_url)
    .await?;
```

---

## Documentation & Resources

### Official Documentation

- **Architecture**: `kraken-spec/KRAKEN.md` (Phase 0)
- **MVP Guide**: `kraken-spec/KRAKEN-PHASE1.md`
- **Modules**: `kraken-spec/KRAKEN-PHASE2.md`
- **OPSEC**: `kraken-spec/KRAKEN-PHASE4.md`
- **Mesh Networking**: `kraken-spec/KRAKEN-PHASE5.md`

### Key Files

- Protocol definitions: `proto/kraken.proto`
- Common types: `crates/common/src/lib.rs`
- Crypto primitives: `crates/crypto/src/lib.rs`

### External References

- [Tonic gRPC Framework](https://github.com/hyperium/tonic)
- [Ratatui TUI Library](https://github.com/ratatui-org/ratatui)
- [Ring Cryptography](https://github.com/briansmith/ring)
- [Tokio Async Runtime](https://tokio.rs/)

---

## Contributing

Contributions are welcome. Areas for contribution:

- Module implementations (shell, file, SOCKS, BOF loader, etc.)
- Transport implementations (DNS, TCP, SMB mesh)
- Operator TUI enhancements
- OPSEC improvements (sleep masking, syscall obfuscation)
- Documentation and examples
- Security audits and bug reports

Please follow the code style conventions documented in `kraken-spec/CLAUDE.md`.

---

## License

Kraken is released under the **MIT License**. See LICENSE file for details.

```
MIT License

Copyright (c) 2024 Kraken Contributors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
```

---

## Legal Notice

**IMPORTANT**: This software is provided for authorized security testing and research only.

- **Unauthorized access** to computer systems without proper authorization is **illegal**.
- Users are responsible for ensuring compliance with all applicable laws and regulations.
- This framework should only be used in controlled test environments with explicit permission.
- Operators must maintain proper audit logs for compliance and incident reconstruction.

By using Kraken, you acknowledge that you are solely responsible for complying with all applicable laws and regulations regarding its use.

---

## Support & Contact

For questions, bug reports, or security vulnerabilities:

1. **Bugs/Features**: Create an issue on GitHub
2. **Security Issues**: Please email security@kraken-c2.dev (do not disclose in public issues)
3. **Documentation**: Check `kraken-spec/` directory

---

**Last Updated**: March 28, 2024
**Version**: 0.1.0-draft
**Status**: Foundation Phase (Phase 0)
