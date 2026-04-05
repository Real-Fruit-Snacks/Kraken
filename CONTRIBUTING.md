# Contributing to Kraken

## Development Setup

```bash
# Clone and setup
git clone https://github.com/Real-Fruit-Snacks/Kraken.git
cd Kraken
just setup

# Build everything
just build

# Run tests
just test
```

## Code Style

- Run `cargo fmt` before committing
- Run `cargo clippy -- -D warnings` for lint checks
- All public APIs must have doc comments
- Unsafe code requires a `// SAFETY:` comment

## Pull Request Process

1. Fork the repository
2. Create a feature branch from `main`
3. Write tests for new functionality
4. Ensure `just ci` passes (fmt + clippy + test)
5. Submit a PR with a clear description

## Commit Messages

Use conventional commits: `feat:`, `fix:`, `docs:`, `refactor:`, `test:`, `chore:`

## Architecture Guidelines

- Each crate has a single responsibility
- Public traits live in `common`
- Crypto operations go through `CryptoProvider` trait
- All implant modules implement the `Module` trait
- Database access through the `db` crate's abstraction layer

## Testing

```bash
just test          # Unit + integration tests
just test-crypto   # Crypto-specific tests
just sim           # Run implant simulator
just fuzz          # Fuzz testing
```

## Security

If you discover a security vulnerability, please report it via [GitHub Security Advisories](https://github.com/Real-Fruit-Snacks/Kraken/security/advisories) instead of opening a public issue.
