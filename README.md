# TunnelCraft

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Rust](https://img.shields.io/badge/Rust-1.75+-orange.svg)](https://www.rust-lang.org/)
[![Solana](https://img.shields.io/badge/Solana-Devnet-blueviolet)](https://solana.com/)

Decentralized, trustless P2P VPN with cryptographic verification at every step.

## Overview

TunnelCraft is a privacy-focused VPN network where no single node needs to be trusted. Privacy is achieved through:

- **Fragmentation**: Requests split into 5 shards, each taking a random path
- **Erasure Coding**: Only 3 of 5 shards needed to reconstruct
- **Trustless Verification**: Relays verify response destinations match request origins
- **On-chain Settlement**: Solana-based payment and work verification

## Features

- 🔒 **Privacy**: No single node sees full traffic
- 🌐 **Decentralized**: Anyone can run relay/exit nodes
- ✅ **Trustless**: Cryptographic proofs for all operations
- 💰 **Incentivized**: Earn tokens by running nodes
- 📱 **Cross-platform**: Desktop, iOS, Android (planned)

## Quick Start

### Desktop (Electron)

```bash
# Build Rust daemon
cargo build --release

# Start desktop app
cd apps/desktop
npm install
npm run dev
```

### CLI

```bash
cargo build --release -p tunnelcraft-cli
./target/release/tunnelcraft-cli connect --hops 2
```

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│  Desktop/Mobile UI (Electron / React Native)                │
├─────────────────────────────────────────────────────────────┤
│  Rust Daemon (P2P networking, tunneling)                    │
├─────────────────────────────────────────────────────────────┤
│  libp2p (DHT, NAT traversal)                                │
├─────────────────────────────────────────────────────────────┤
│  Solana (Credits, Settlement, Rewards)                      │
└─────────────────────────────────────────────────────────────┘
```

## Privacy Model

| Hop Mode | Latency | Privacy Level |
|----------|---------|---------------|
| 0 hops | ~30ms | Exit sees IP |
| 1 hop | ~60ms | 1 relay hides IP |
| 2 hops | ~90ms | Good privacy |
| 3 hops | ~120ms | Maximum privacy |

## Project Structure

```
tunnelcraft/
├── crates/
│   ├── core/           # Shared types and errors
│   ├── crypto/         # Keys, signatures, encryption
│   ├── erasure/        # Reed-Solomon encoding (5/3)
│   ├── network/        # libp2p integration
│   ├── relay/          # Relay node logic
│   ├── exit/           # Exit node + HTTP fetch
│   ├── settlement/     # Solana client
│   ├── client/         # Client SDK
│   ├── daemon/         # Background service
│   └── uniffi/         # Mobile bindings
└── apps/
    ├── cli/            # CLI application
    ├── desktop/        # Electron app
    └── mobile/         # React Native app
```

## Documentation

- [Building](./BUILDING.md) - Build instructions for all platforms
- [Design](./docs/DESIGN.md) - System architecture and protocols
- [Technical](./docs/TECHNICAL.md) - Implementation details
- [Status](./docs/STATUS.md) - Current development status

## How It Works

### Request Flow

1. **User** creates request, splits into 5 shards
2. **Each shard** takes random path through relays
3. **Relays** cache `request_id → user_pubkey`
4. **Exit** reconstructs, fetches from internet
5. **Response** splits into shards, random return paths
6. **Relays** verify destination matches cached origin
7. **Last relay** delivers to user, gets TCP ACK

### Trustless Verification

```
Request: User (ABC) → Relay → Exit
         Relay caches: request_id → ABC

Response: Exit → Relay → User
          Relay checks: destination == ABC?
          Mismatch → DROP (prevents redirect attacks)
```

## Development

```bash
# Build all crates
cargo build

# Run tests
cargo test

# Run specific crate tests
cargo test -p tunnelcraft-core

# Format and lint
cargo fmt && cargo clippy
```

## License

MIT
