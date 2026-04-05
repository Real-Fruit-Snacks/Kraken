# Security Policy

## Reporting a Vulnerability

Report vulnerabilities via [GitHub Security Advisories](https://github.com/Real-Fruit-Snacks/Kraken/security/advisories).

**Do not open a public issue for security vulnerabilities.**

### What to Include

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

### Response Timeline

- **Acknowledgment**: Within 48 hours
- **Assessment**: Within 7 days
- **Fix timeline**: Based on severity
- **Disclosure**: 90-day coordinated disclosure

## Scope

Kraken is a C2 framework designed for authorized security testing. Security reports should focus on:

- Cryptographic weaknesses in the X25519/AES-256-GCM implementation
- Authentication or authorization bypasses in the gRPC server
- Memory safety issues in the implant core
- Information disclosure through protocol analysis

## Out of Scope

- Social engineering attacks
- Denial of service against the teamserver
- Issues requiring physical access
