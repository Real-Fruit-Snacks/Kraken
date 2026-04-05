# Kraken Architecture Decisions

This document records significant architectural decisions and their rationale.

---

## ADR-001: TUI Freeze — Web UI as Primary Interface

**Date**: 2026-03-30
**Status**: Accepted
**Deciders**: Project maintainers

### Context

Kraken has two user interfaces:
- **TUI** (`crates/operator`) — Rust/ratatui terminal interface, ships in Phase 1
- **Web UI** (`kraken-web`) — React/TypeScript, ships in Phase 6

Both interfaces consume the same gRPC API. Maintaining feature parity requires duplicate development effort across different technology stacks (Rust vs TypeScript).

### Decision

**Freeze TUI development. Web UI becomes the primary interface.**

Specifically:
- TUI remains functional with current features (Sessions, Interact, Events, Loot, Modules, Defender, Mesh, Help)
- Bug fixes only — no new views or features
- All new feature development targets Web UI
- Defender View and Mesh Topology will be implemented in Web UI, not backported to TUI
- TUI serves as "emergency SSH access mode" for field operators

### Rationale

1. **Resource efficiency**: Single codebase to maintain
2. **Target audience**: Kraken's research/education focus benefits from accessible Web UI
3. **Industry trend**: Modern C2s (Mythic, Covenant) are web-first
4. **Collaboration**: Web naturally supports multi-operator features
5. **Accessibility**: Lower barrier to entry for students/researchers

### Consequences

**Positive**:
- Faster feature development
- Consistent UX across all features
- Better documentation (Web is more inspectable)
- Easier onboarding for new contributors (TypeScript > Rust for UI)

**Negative**:
- Terminal purists may prefer TUI
- SSH-only access requires port forwarding for Web
- Slightly higher attack surface (web server)

**Mitigations**:
- TUI still works for operators who need it
- Web UI can be accessed via SSH tunnel
- Web server binds to localhost by default

### Alternatives Considered

1. **Keep both active**: Rejected due to maintenance burden
2. **Drop TUI entirely**: Rejected — existing functionality has value
3. **TUI-first, Web-secondary**: Rejected — conflicts with education focus

---

## ADR-002: Professional Features Implementation Order

**Date**: 2026-03-30
**Status**: Accepted

### Decision

Implement three professional features in this order:

| Priority | Feature | Rationale |
|----------|---------|-----------|
| 1 | Mesh Topology View | Visual differentiator, enables pivot chain understanding |
| 2 | Defender Dashboard | Unique value prop, no other C2 has full YARA/Sigma/IOC view |
| 3 | Collaboration Panel | Team operations, requires WebSocket infrastructure |

### Technical Choices

| Component | Technology | Rationale |
|-----------|------------|-----------|
| Graph rendering | @xyflow/react | Used by Mythic, native React, good perf |
| Graph layout | elkjs | Industry standard, supports hierarchical + force |
| Real-time transport | WebSocket | Bidirectional, better than SSE for presence |
| State management | Zustand | Already in use, lightweight |
| Event virtualization | @tanstack/virtual | Best for dynamic row heights |

---

## ADR-003: OPSEC Gate Severity Model

**Date**: 2026-03-30
**Status**: Proposed

### Decision

Implement three-tier OPSEC gate system:

| Tier | Color | Behavior | Use Case |
|------|-------|----------|----------|
| INFO | Blue | Log only, inline note | Low-risk operations |
| ADVISORY | Amber | Toast notification, dismissible | Medium-risk, operator awareness |
| BLOCKING | Red | Modal + blur, requires bypass | High-risk, potential burn |

### Rationale

No existing C2 has a visual severity-tiered OPSEC system. Mythic has the most sophisticated gates but uses binary blocking. Our model provides graduated feedback while maintaining auditability.

---
