# CLAUDE.md

This file provides guidance specific to the CraftNet repository. See `../CLAUDE.md` for ecosystem-level context (craftec-core, identity, settlement, IPC conventions).

## Project Overview

CraftNet is the transport layer of the Craftec ecosystem — a decentralized, trustless P2P VPN. It operates at L4 (TCP tunnel via SOCKS5 proxy) for end-to-end TLS privacy, with an L7 HTTP mode for simpler use cases. The design is **anonymous** — onion routing hides client IP from exits, erasure coding splits payloads across paths, and ephemeral pool keys prevent session correlation.

**Core Innovation**: Privacy through fragmentation + trustless verification via relay destination checks + decentralized relay operators (no single trust point).

## Technology Stack

- **Async Runtime**: Tokio
- **P2P**: libp2p (via craftec-network)
- **Erasure Coding**: Reed-Solomon 5/3, chunked at 3KB (via craftec-erasure)
- **Onion Routing**: X25519-ECDH + ChaCha20-Poly1305, per-layer ephemeral keys
- **Identity**: craftec-identity (DID, cross-craft reputation, social recovery)
- **Settlement**: craftec-settlement (ForwardReceipt implements ContributionReceipt)
- **Desktop**: Via CraftStudio (Tauri) — CraftNet is consumed as a library
- **Mobile**: React Native (iOS, Android)
- **Mobile VPN**: iOS Network Extension / Android VpnService → tun2socks → SOCKS5 → Rust FFI (uniffi)

## Build Commands

```bash
# Backend (Rust)
cargo build                      # Build all crates
cargo build --release            # Release build
cargo test                       # Run all tests
cargo test -p craftnet-core   # Test specific crate
cargo clippy                     # Lint
cargo fmt                        # Format

# Generate mobile bindings
cargo run -p craftnet-uniffi --release

# CLI
cargo build -p craftnet-cli --release

# Mobile Frontend (React Native)
cd apps/mobile
npm install
npx react-native run-ios         # iOS simulator
npx react-native run-android     # Android emulator

# iOS VPN Extension
cd apps/mobile/ios
xcodebuild -scheme CraftNetVPN -configuration Release

# Android VPN Service
cd apps/mobile/android
./gradlew assembleRelease
```

Note: Desktop UI is provided by CraftStudio (Tauri). See `../craftstudio/`.

## Architecture

```
craftnet/
├── crates/
│   ├── core/           Shard, ForwardReceipt, TunnelMetadata, HopMode, Capabilities
│   ├── crypto/         Onion routing, sign_forward_receipt()
│   ├── network/        Tunnel protocol handlers on shared craftec-network swarm
│   ├── erasure/        Shard-specific 5/3 encoding wrappers
│   ├── relay/          Relay logic + destination verification
│   ├── exit/           Exit node: TCP tunnel + HTTP handler
│   ├── aggregator/     ForwardReceipt aggregation for settlement
│   ├── client/         Client SDK: SOCKS5 proxy, tunnel builder, UnifiedNode
│   ├── daemon/         Background service (IPC via craftec-ipc)
│   └── uniffi/         Mobile bindings (iOS/Android via UniFFI)
├── apps/
│   ├── cli/            Command-line interface
│   └── mobile/         React Native app
│       ├── ios/        Swift Network Extension
│       └── android/    Kotlin VpnService
└── tests/              E2E tests
```

### craftec-core Dependencies

| Tunnel crate | craftec-core dependencies |
|--------------|--------------------------|
| `core` | craftec-core, craftec-crypto |
| `crypto` | craftec-crypto |
| `network` | craftec-network |
| `erasure` | craftec-erasure |
| `relay` | craftec-identity (reputation for priority routing) |
| `aggregator` | craftec-settlement, craftec-prover |
| `daemon` | craftec-app, craftec-ipc, craftec-identity |

## Component Communication

```
┌─────────────────────────────────────────────────────────────┐
│  Desktop (via CraftStudio)                                   │
│  ┌──────────────┐     WebSocket       ┌──────────────────┐ │
│  │ Tauri Shell  │ ◄────────────────► │ craftstudio-daemon│ │
│  │ (System      │                     │ ├─ craftnet    │ │
│  │  WebView)    │                     │ ├─ SOCKS5 proxy   │ │
│  └──────────────┘                     │ └─ TUN interface  │ │
│                                        └──────────────────┘ │
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

**Anonymous.** Onion routing ensures no single relay sees both client and destination (with 2+ hops). Erasure coding splits payloads across multiple paths. Ephemeral pool keys prevent session correlation. Content is protected end-to-end via TLS (SOCKS5 mode). Relay operators are independent — no single trust point.

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

## IPC Protocol

CraftNet's daemon uses `craftec-ipc` for the shared `IpcHandler` trait and protocol types. The `DaemonService` implements `craftec_ipc::server::IpcHandler`, making it compatible with `ServerBuilder` namespace routing in CraftStudio (`tunnel.*` prefix).

CLI and local tools communicate with the Rust daemon via JSON-RPC over Unix socket (macOS/Linux) or Named Pipe (Windows). The Tauri/browser UI connects via WebSocket (same JSON-RPC protocol). When running standalone (not via CraftStudio), methods have no namespace prefix:

```json
{"jsonrpc":"2.0","method":"connect","params":{"hops":2},"id":1}
{"jsonrpc":"2.0","method":"disconnect","id":2}
{"jsonrpc":"2.0","method":"status","id":3}
{"jsonrpc":"2.0","method":"subscribe","params":{"tier":"standard"},"id":4}
{"jsonrpc":"2.0","method":"start_proxy","params":{"port":1080},"id":5}
{"jsonrpc":"2.0","method":"stop_proxy","id":6}
{"jsonrpc":"2.0","method":"proxy_status","id":7}
```
