# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

TunnelCraft is a decentralized, trustless P2P VPN with a Rust backend and TypeScript frontend. It uses cryptographic verification at every step to achieve anonymity without requiring trust in any single node.

**Core Innovation**: Privacy through fragmentation + trustless verification via relay destination checks.

## Technology Stack

### Backend (Rust)
- **Language**: Rust 1.75+
- **Async Runtime**: Tokio
- **P2P**: libp2p (Kademlia DHT, NAT traversal)
- **Erasure Coding**: reed-solomon-erasure (5/3)
- **Cryptography**: dalek ecosystem (ed25519-dalek, x25519-dalek, chacha20poly1305)
- **Settlement**: Solana + Anchor

### Frontend (TypeScript/Node.js)
- **Desktop**: Electron (macOS, Windows, Linux)
- **Mobile**: React Native (iOS, Android)
- **IPC**: Unix socket / Named pipe to Rust daemon

### Mobile VPN Layer (Native)
- **iOS**: Swift Network Extension → Rust FFI (uniffi)
- **Android**: Kotlin VpnService → Rust JNI (uniffi)

## Target Platforms

| Platform | UI | VPN Tunnel | Notes |
|----------|-----|------------|-------|
| macOS | Electron | Rust daemon | launchd service |
| Windows | Electron | Rust daemon | Windows service |
| Linux | Electron | Rust daemon | systemd service |
| iOS | React Native | Swift + Rust FFI | Network Extension |
| Android | React Native | Kotlin + Rust JNI | VpnService |

## Build Commands

```bash
# Backend (Rust)
cargo build                      # Build all crates
cargo build --release            # Release build
cargo test                       # Run all tests
cargo test -p tunnelcraft-core   # Test specific crate
cargo clippy                     # Lint
cargo fmt                        # Format

# Generate mobile bindings
cargo run -p tunnelcraft-uniffi --release

# Desktop Frontend (Electron)
cd apps/desktop
npm install
npm run dev                      # Development
npm run build                    # Production build

# Mobile Frontend (React Native)
cd apps/mobile
npm install
npx react-native run-ios         # iOS simulator
npx react-native run-android     # Android emulator

# iOS VPN Extension
cd apps/mobile/ios
xcodebuild -scheme TunnelCraftVPN -configuration Release

# Android VPN Service
cd apps/mobile/android
./gradlew assembleRelease
```

## Architecture

```
tunnelcraft/
├── crates/
│   ├── core/           # Types: Shard, ChainEntry, errors
│   ├── crypto/         # Keys, signatures, encryption
│   ├── erasure/        # Reed-Solomon encoding (5/3)
│   ├── network/        # libp2p integration
│   ├── relay/          # Relay logic + destination verification
│   ├── exit/           # Exit node + HTTP fetch + settlement
│   ├── settlement/     # Solana client
│   ├── client/         # Client SDK
│   ├── daemon/         # Background service (IPC server)
│   └── uniffi/         # Mobile bindings (iOS/Android)
└── apps/
    ├── cli/            # CLI application
    ├── desktop/        # Electron app
    └── mobile/         # React Native app
        ├── ios/        # Swift Network Extension
        └── android/    # Kotlin VpnService
```

## Component Communication

```
┌─────────────────────────────────────────────────────────────┐
│  Desktop                                                     │
│  ┌──────────────┐      IPC Socket      ┌──────────────────┐ │
│  │   Electron   │ ◄──────────────────► │   Rust Daemon    │ │
│  │   (UI/UX)    │                      │   (VPN Core)     │ │
│  └──────────────┘                      └──────────────────┘ │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│  Mobile                                                      │
│  ┌──────────────┐                      ┌──────────────────┐ │
│  │ React Native │ ◄─── RN Bridge ────► │  Native Module   │ │
│  │   (UI/UX)    │                      │ (Swift/Kotlin)   │ │
│  └──────────────┘                      └────────┬─────────┘ │
│                                                 │ FFI/JNI   │
│                                        ┌────────▼─────────┐ │
│                                        │   Rust Library   │ │
│                                        │   (VPN Core)     │ │
│                                        └──────────────────┘ │
└─────────────────────────────────────────────────────────────┘
```

## Key Concepts

### Trustless Verification
Relays cache `request_id → user_pubkey` and verify that response destinations match. This prevents exit nodes from redirecting responses to colluding parties.

### Two-Phase Settlement
1. **Phase 1 (PENDING)**: Exit submits request settlement with `credit_secret` and locks `user_pubkey`
2. **Phase 2 (COMPLETE)**: Last relay submits response settlement with TCP ACK; chain verifies `destination == user_pubkey`

### Chain Signatures
Each shard accumulates signatures as it traverses the network. These prove work done and enable claims.

### Erasure Coding
Requests/responses are split into 5 shards; only 3 needed for reconstruction. Each shard takes a random path.

## Critical Implementation

The trustless verification in `crates/relay/src/handler.rs` is the most security-critical code:

```rust
// Response handling - MUST verify destination
if let Some(expected_user) = self.cache.get(&shard.request_id) {
    if shard.destination != *expected_user {
        return Err(Error::DestinationMismatch);  // DROP
    }
}
```

## Solana Contract Instructions

- `purchase_credit` - Buy credits with credit_hash
- `settle_request` - Exit settles, stores user_pubkey (PENDING)
- `settle_response` - Last relay settles with TCP ACK (COMPLETE)
- `claim_work` - Relays claim points from completed requests
- `withdraw` - Withdraw epoch rewards

## Work Style

When asked to "wire up everything", "fix all gaps", or similar comprehensive tasks:

### Surviving context compaction
Audit results and work lists MUST be written to `.claude/audit-gaps.md` (not held in memory). Context compaction loses in-memory lists. The file on disk is the source of truth.

### Update the document as you go
After EVERY batch of fixes, IMMEDIATELY mark items `[x]` in `.claude/audit-gaps.md` before moving to the next batch. This is not optional — it prevents double work when context compacts and a new session re-reads the file. A stale audit file with unchecked items that are already fixed wastes time rechecking. The file must always reflect the true current state.

### Execution order
1. **Audit first**: Spawn parallel Explore subagents (backend, desktop, mobile, config) to find ALL gaps. Write every gap to `.claude/audit-gaps.md` with checkboxes.
2. **Fix by priority**: Work through the file top-to-bottom. After fixing each batch, mark items `[x]` in the file and `cargo check`/`tsc --noEmit` to verify.
3. **Never skip**: Do not cherry-pick easy items. Work through the list sequentially. If an item is intentionally skipped (e.g. design choice), mark it `[x] SKIPPED: reason` — never silently drop it.
4. **Re-audit when done**: After all items are checked, spawn fresh Explore agents to verify nothing was missed. If new gaps appear, append them to the file and fix them.
5. **Never declare done after one pass**: The cycle is audit → fix → verify → re-audit. Only stop when the re-audit finds zero new actionable gaps.

### Batch size
Fix items in batches of 10-20, verify compilation after each batch, then continue. This prevents large broken states.

## IPC Protocol

Desktop frontend communicates with Rust daemon via JSON-RPC over Unix socket (macOS/Linux) or Named Pipe (Windows):

```json
{"jsonrpc":"2.0","method":"connect","params":{"hops":2},"id":1}
{"jsonrpc":"2.0","method":"disconnect","id":2}
{"jsonrpc":"2.0","method":"status","id":3}
{"jsonrpc":"2.0","method":"purchase_credits","params":{"amount":100},"id":4}
```
