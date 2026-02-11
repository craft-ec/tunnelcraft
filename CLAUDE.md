# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

TunnelCraft is a decentralized, trustless P2P VPN with a Rust backend and TypeScript frontend. It operates at L4 (TCP tunnel via SOCKS5 proxy) for end-to-end TLS privacy, with an L7 HTTP mode for simpler use cases. The design is **private but not anonymous** — no single node sees the full picture, but routing metadata (pseudonymous pubkeys) is visible to relays.

**Core Innovation**: Privacy through fragmentation + trustless verification via relay destination checks + decentralized relay operators (no single trust point).

## Technology Stack

### Backend (Rust)
- **Language**: Rust 1.75+
- **Async Runtime**: Tokio
- **P2P**: libp2p (Kademlia DHT, NAT traversal, gossipsub)
- **Erasure Coding**: reed-solomon-erasure (5/3, chunked at 3KB)
- **Cryptography**: dalek ecosystem (ed25519-dalek, x25519-dalek, chacha20poly1305)
- **Settlement**: Solana + Anchor

### Frontend (TypeScript/Node.js)
- **Desktop**: Electron (macOS, Windows, Linux)
- **Mobile**: React Native (iOS, Android)
- **IPC**: Unix socket / Named pipe to Rust daemon

### Mobile VPN Layer (Native)
- **iOS**: Swift Network Extension → tun2socks → SOCKS5 → Rust FFI (uniffi)
- **Android**: Kotlin VpnService → tun2socks → SOCKS5 → Rust JNI (uniffi)

## Target Platforms

| Platform | UI | VPN Tunnel | Notes |
|----------|-----|------------|-------|
| macOS | Electron | Rust daemon + SOCKS5 | launchd service |
| Windows | Electron | Rust daemon + SOCKS5 | Windows service |
| Linux | Electron | Rust daemon + SOCKS5 | systemd service |
| iOS | React Native | TUN → tun2socks → SOCKS5 | Network Extension |
| Android | React Native | TUN → tun2socks → SOCKS5 | VpnService |

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
│   ├── core/           # Types: Shard, ForwardReceipt, TunnelMetadata, errors
│   ├── crypto/         # Keys, signatures, encryption
│   ├── erasure/        # Reed-Solomon encoding (5/3, 3KB chunks)
│   ├── network/        # libp2p integration
│   ├── relay/          # Relay logic + destination verification
│   ├── exit/           # Exit node + HTTP fetch + TCP tunnel handler
│   ├── settlement/     # Solana client
│   ├── client/         # Client SDK + SOCKS5 proxy + tunnel builder
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
│  │   (UI/UX)    │                      │ (VPN + SOCKS5)   │ │
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
│                        TUN interface → │  tun2socks       │ │
│                                        │  → SOCKS5 proxy  │ │
│                                        │  → Rust Library   │ │
│                                        └──────────────────┘ │
└─────────────────────────────────────────────────────────────┘
```

## Key Concepts

### Two Operating Modes

**TCP Tunnel Mode (L4, primary)** — SOCKS5 proxy on localhost. Browser/app connects via SOCKS5, exit opens raw TCP connection to destination, pipes bytes. TLS is end-to-end between client and destination. Exit sees only `host:port` + ciphertext. Payload prefix: `0x01`.

**HTTP Mode (L7, legacy)** — Exit reconstructs full HTTP request and fetches it. Exit sees URLs, headers, bodies. For HTTPS, exit terminates TLS. Payload prefix: `0x00` (default).

### Privacy Model

**Private but not anonymous.** Relays see pseudonymous routing metadata (`user_pubkey`, exit pubkey) but not content (TLS end-to-end via SOCKS5). No single entity sees the full picture — relay operators are independent. This is sufficient for production (better than centralized VPNs, tradeoff vs Tor/Nym is speed).

### Best-Effort Routing with Minimum Relay Count

User selects privacy level via `HopMode` which sets a minimum relay count (`min_relays`). Shards carry a decrementing `hops_remaining` counter:
- Counter > 0: relay MUST forward to another relay, decrements counter
- Counter = 0: relay forwards toward exit via best-effort fastest path
- Shards are never dropped due to missing relays — fallback to any connected peer

| Mode | Min relays | Privacy |
|------|-----------|---------|
| Direct | 0 | Exit sees client IP |
| Light | 1 | 1 relay hides IP from exit |
| Standard | 2 | No single node sees both client and exit |
| Paranoid | 3 | Maximum privacy |

### Trustless Verification

Relays cache `request_id → user_pubkey` and verify that response destinations match. This prevents exit nodes from redirecting responses to colluding parties.

### Erasure Coding (Chunked)

Data is split into 3KB chunks. Each chunk is Reed-Solomon encoded into 5 shards (3 data + 2 parity). Only 3 of 5 shards needed per chunk for reconstruction. Each shard carries `chunk_index` and `total_chunks` for multi-chunk reassembly.

### Settlement: Per-Epoch Pools + Off-Chain Proofs + On-Chain Merkle Claims

- Users subscribe on-chain per epoch (30 days). USDC payment goes into a per-epoch pool PDA (`SubscriptionAccount`).
- Each relay earns ForwardReceipts locally as proof of forwarding (signed by next hop). Receipts include `payload_size` for bandwidth-weighted settlement.
- Relays batch receipts into Merkle trees and publish ZK-proven summaries (`ProofMessage`) via gossipsub. Receipts never go on-chain.
- An aggregator collects proof summaries, builds a per-pool Merkle distribution (relay_pubkey, cumulative_bytes), and posts the distribution root on-chain after the grace period (epoch expiry + 1 day).
- Relays claim proportional payout by submitting a Merkle inclusion proof on-chain: `(relay_bytes / total_bytes) * pool_balance`.
- Double-claim prevention via Light Protocol compressed accounts — non-inclusion proof fails if relay already claimed for that epoch.
- Per-user per-epoch pool prevents cross-user and cross-epoch dilution.
- No on-chain receipt submission, no bitmap, no credit indexes, no NodeAccount accumulation.

### Subscription Verification via Gossip
- Active subscriptions propagated via gossipsub (zero RPC).
- Relays maintain local cache of subscribed user_pubkeys.
- Random audit: relays spot-check subscriptions on-chain periodically.
- Fakers are reported for abuse. Subscribed users get priority; unsubscribed get best-effort.

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

The tunnel mode dispatch in `crates/exit/src/handler.rs`:

```rust
// Check payload mode prefix byte
if !request_data.is_empty() && request_data[0] == PAYLOAD_MODE_TUNNEL {
    // TCP tunnel: parse TunnelMetadata, pipe bytes to destination
} else {
    // HTTP mode: parse and fetch HTTP request
}
```

## Solana Contract Instructions

Program: `2QQvVc5QmYkLEAFyoVd3hira43NE9qrhjRcuT1hmfMTH` (Anchor, deployed on devnet)

- `subscribe` - User subscribes for an epoch. Creates `UserMeta` PDA (tracks next_epoch) + per-epoch `SubscriptionAccount` PDA. Transfers USDC from payer to pool token account (ATA owned by subscription PDA).
- `post_distribution` - Aggregator posts Merkle root of (relay_pubkey, cumulative_bytes) entries after grace period (epoch expiry + 1 day). First-writer-wins; saves original pool balance for proportional claims.
- `claim` - Relay submits Merkle inclusion proof to claim proportional share: `(relay_bytes / total_bytes) * pool_balance`. Double-claim prevented via Light Protocol compressed `ClaimReceipt` account (non-inclusion proof fails if address exists). PDA-signed USDC transfer from pool to relay wallet.

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
{"jsonrpc":"2.0","method":"subscribe","params":{"tier":"standard"},"id":4}
{"jsonrpc":"2.0","method":"start_proxy","params":{"port":1080},"id":5}
{"jsonrpc":"2.0","method":"stop_proxy","id":6}
{"jsonrpc":"2.0","method":"proxy_status","id":7}
```
