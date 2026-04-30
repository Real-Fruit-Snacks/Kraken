<picture>
  <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/Real-Fruit-Snacks/Kraken/main/docs/assets/logo-dark.svg">
  <source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/Real-Fruit-Snacks/Kraken/main/docs/assets/logo-light.svg">
  <img alt="Kraken" src="https://raw.githubusercontent.com/Real-Fruit-Snacks/Kraken/main/docs/assets/logo-dark.svg" width="100%">
</picture>

> [!IMPORTANT]
> **OPSEC-first Rust C2** — modular implant under 50 KB, four transports with live fallback, BOF-compatible. **Under active development; not yet operational.** APIs, protocols, and module surfaces will change.

> *The implant doesn't need to be small for performance. It needs to be small because that's how few bytes a defender has to forensically attribute back to you.*

---

## §1 / Premise

Most open-source C2 frameworks were written when "evade EDR" meant "use a domain that doesn't appear on a public blocklist." That premise no longer holds. Modern endpoint telemetry watches the syscall layer, not just the network — which means the implant's behavior on disk and in memory matters more than whatever it does over the wire.

Kraken is designed against a working assumption that **every byte the implant writes will be logged** by something. That constraint is what motivates the architecture below: minimal hardened core, runtime-loaded capability modules, signed-traffic profiles, no fallback to plaintext.

---

## §2 / Specs

| KEY      | VALUE                                                                       |
|----------|-----------------------------------------------------------------------------|
| CRYPTO   | X25519 ECDH · HKDF-SHA256 · AES-256-GCM · Ed25519 — no plaintext fallback   |
| XPORTS   | HTTPS · TCP · SMB · DNS — automatic fallback chains, compile- or runtime-selected |
| CORE     | Minimal hardened implant **~50 KB** — capabilities loaded at runtime        |
| MESH     | Peer-to-peer routing (TCP/SMB) — implants relay when direct C2 is blocked   |
| BOF      | Rust COFF loader runs **Cobalt Strike Beacon Object Files** unmodified      |
| STACK    | 9-crate Cargo workspace · gRPC (tonic) · SQLite (sqlx) · CLI + React Web UI |

Full architecture decisions in [`docs/DECISIONS.md`](docs/DECISIONS.md). Operator workflow in [`docs/OPERATOR.md`](docs/OPERATOR.md).

---

## §3 / Quickstart

```bash
# Prereqs: Rust 1.81+, protoc 3.20+, SQLite dev libs

git clone https://github.com/Real-Fruit-Snacks/Kraken.git
cd Kraken
just setup && just proto && just build

# Start the team server (gRPC :50051 · HTTPS :443)
just server

# Operator CLI (in another terminal)
just operator -- --server 127.0.0.1:50051

# Test without real implants
just sim -- --server https://127.0.0.1:443 --interval 5
```

---

## §4 / Reference

```
USAGE
  kraken <subcommand>      # via just / cargo run -p <crate>

OPERATOR COMMANDS
  shell <cmd>             Execute a shell command on the implant
  cd · pwd · ls           Directory navigation
  upload <src> <dst>      Push a file to the implant (chunked >10 MB)
  download <path>         Pull a file from the implant
  env                     System info, network, env vars, whoami
  ps                      Process listing and tree view
  scan                    Port scan, ping sweep, share enumeration
  ad                      AD enumeration · Kerberoasting · AS-REP
  reg · svc               Windows registry & service ops
  creds                   SAM · LSASS · LSA secrets · DPAPI · vault
  browser                 Browser passwords, cookies, history
  token                   Token theft · impersonation · privilege enable
  keylog · clipboard      Input capture
  screenshot[-stream]     Single capture or continuous stream
  audio · webcam · usb    Multimedia & device monitoring
  lateral                 PSExec · WMI · DCOM · WinRM · schtasks
  persist                 7 persistence methods
  inject                  9 process-injection techniques
  rdp · ntlm-relay        Session hijacking · NTLM relay setup
  mesh                    Peer-to-peer mesh routing
  socks · portfwd         SOCKS5 proxy · forward/reverse port forwarding
  bof <path>              Load and execute a Cobalt Strike BOF
  modules                 Runtime module load/unload
  task queue / status     Async task dispatch with structured results

BUILD TARGETS                                              # Justfile
  just setup              Install toolchain components
  just proto              Generate protobuf code
  just build              Build all workspace crates
  just server             Run the team server
  just operator           Run the operator CLI
  just sim                Run the implant simulator
  just implant-linux-x64  Build Linux x86_64 implant
  just implant-windows-x64  Build Windows x86_64 (MinGW cross)
  just implant-aarch64    Build Linux ARM64 implant
  just test               cargo test across workspace
  just fmt · lint         Format · clippy

CRATES
  common · crypto · protocol · config · db
  server · operator · implant-core · implant-sim
```

All implant configuration bakes at compile time — no runtime args, no environment lookups, no secrets on disk.

---

## §5 / Authorization

Built for engagements that are scoped, written, and signed. Read the threat model before the install instructions. Vulnerabilities go through [private security advisories](https://github.com/Real-Fruit-Snacks/Kraken/security/advisories/new), never public issues.

Kraken does **not** include ransomware, wiper, supply-chain attack tooling, or automated mass exploitation — and never will.

---

[License: MIT](LICENSE) · [Security policy](SECURITY.md) · [Contributing](CONTRIBUTING.md) · [Changelog](CHANGELOG.md) · Part of [Real-Fruit-Snacks](https://github.com/Real-Fruit-Snacks) — building offensive security tools, one wave at a time.
