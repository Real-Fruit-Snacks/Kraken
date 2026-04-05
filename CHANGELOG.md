# Changelog

All notable changes to Kraken will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [0.1.0] - 2026-04-05

### Added
- Initial release
- Nine-crate Cargo workspace (common, crypto, protocol, config, db, server, operator, implant-core, implant-sim)
- X25519 ECDH key exchange with AES-256-GCM encryption
- Multi-transport support (HTTP/HTTPS, TCP, SMB, DNS)
- gRPC teamserver with operator authentication
- ratatui TUI operator interface
- Modular implant with runtime-loadable capabilities
- Mesh networking with peer discovery and relay routing
- BOF compatibility via Rust COFF loader
- Implant simulator for development testing
- Append-only audit logging
