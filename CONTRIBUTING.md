# Contributing to TunnelCraft

Thank you for your interest in contributing to TunnelCraft!

## Development Setup

### Prerequisites

```bash
# Rust 1.75+
rustup update stable

# Node.js 18+ (for desktop app)
node --version

# macOS: Xcode CLI tools
xcode-select --install

# Linux: Build essentials
sudo apt install build-essential pkg-config libssl-dev
```

### Build

```bash
# Clone
git clone https://github.com/craftec/tunnelcraft.git
cd tunnelcraft

# Build all crates
cargo build

# Run tests
cargo test
```

## Project Structure

```
crates/
├── core/       # Types, errors (low-level)
├── crypto/     # Keys, signatures (depends on core)
├── erasure/    # Reed-Solomon (depends on core)
├── network/    # P2P, libp2p (depends on crypto)
├── relay/      # Relay logic (depends on network)
├── exit/       # Exit logic (depends on relay)
├── settlement/ # Solana (depends on crypto)
├── client/     # Client SDK (depends on *)
├── daemon/     # Background service (depends on client)
└── uniffi/     # Mobile bindings (depends on client)
```

## Git Workflow

### Branch Naming

```
feature/description   # New features
fix/description       # Bug fixes
docs/description      # Documentation
crypto/description    # Cryptographic changes
```

### Commit Messages

Use conventional commits:

```
feat: add NAT traversal support
fix: correct chain signature verification
docs: update protocol specification
crypto: improve key derivation
test: add relay verification tests
```

### Pull Request Process

1. Create feature branch from `main`
2. Make changes with tests
3. Ensure `cargo test` and `cargo clippy` pass
4. Submit PR with clear description
5. Address review feedback

## Code Guidelines

### Rust

```bash
# Format
cargo fmt

# Lint
cargo clippy -- -D warnings

# Test
cargo test
```

### Security-Critical Code

The following are security-sensitive:
- `crates/crypto/` - Key derivation, signatures
- `crates/relay/src/handler.rs` - Destination verification
- `crates/erasure/` - Reed-Solomon encoding

Changes require careful review.

### Tests

```bash
# All tests
cargo test

# Specific crate
cargo test -p tunnelcraft-relay

# With logging
RUST_LOG=debug cargo test
```

## Security

Please report security vulnerabilities privately to security@craft.ec.

**Critical areas:**
- Destination verification (prevents redirect attacks)
- Chain signature validation
- Key management

## Building for Platforms

See [BUILDING.md](./BUILDING.md) for:
- Desktop (Electron) builds
- iOS builds (Network Extension)
- Windows/Linux cross-compilation

## License

By contributing, you agree your contributions will be licensed under MIT.
