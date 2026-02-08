# Feature Implementation Tracker

Updated: 2026-02-08

---

## CURRENT BATCH — Fix All (2026-02-08)

### 1. Exit User-Agent
- [x] Add default User-Agent header to reqwest client in exit handler

### 2. Subscription Verification (gossip + cache + priority)
- [x] Add SUBSCRIPTION_TOPIC gossipsub topic
- [x] Add SubscriptionAnnouncement message type (user pubkey, tier, expires_at, signature)
- [x] Add subscribe/publish methods to TunnelCraftBehaviour
- [x] Add subscription cache to Node (pubkey → SubscriptionEntry{tier, expires_at, verified})
- [x] Client announces subscription on connect (gossipsub publish)
- [x] Relays handle subscription announcements → insert into cache
- [x] Periodic batch on-chain verification of recently-seen users (settlement.is_subscribed)
- [x] Priority routing in process_incoming_shard: subscribers get priority, non-subscribers best-effort when busy
- [x] Wire PoolType from subscription cache into request_user tracking

### 3. Settlement Production Readiness
- [x] Sign ProofMessage with relay's ed25519 keypair before gossip publish
- [x] Aggregator: verify ProofMessage signature before accepting
- [x] Daemon: read TUNNELCRAFT_PROGRAM_ID + TUNNELCRAFT_NETWORK env vars to select devnet/mainnet config

### 4. Dead Code Cleanup
- [x] Remove unused `info` import in aggregator
- [x] Suppress `last_updated` warning in ProofClaim (used for writes, future read)
- [x] Remove unused `tracing::debug` import in relay handler
- [x] Suppress `config` warning in RelayHandler (public API, will be wired)

---

## FEATURE IMPLEMENTATION STATE

### FULLY WORKING (Real implementation, tested)

| Feature | Where | Evidence |
|---------|-------|---------|
| P2P Networking | `crates/network/` | Full libp2p swarm with Kademlia DHT, mDNS, gossipsub, NAT traversal (dcutr + relay) |
| Erasure Coding (5/3) | `crates/erasure/src/lib.rs` | Reed-Solomon encode/decode with 20+ passing tests, handles up to 2 lost shards |
| Multi-hop Relay Routing | `crates/relay/`, `crates/client/src/node.rs` | Privacy levels control hop count; each relay decrements hops and signs shards |
| Chain Signatures | `crates/core/src/shard.rs`, `crates/relay/src/handler.rs` | Each relay appends signature to shard chain; accumulates proof-of-work |
| Trustless Relay Verification | `crates/relay/src/handler.rs:180-200` | Destination-mismatch check prevents exit node redirection attacks |
| Exit Node HTTP Fetch | `crates/exit/src/handler.rs` | Full GET/POST/PUT/DELETE/PATCH/HEAD via reqwest with User-Agent; shards and encodes response |
| Raw VPN Packet Tunneling | `crates/exit/src/handler.rs` (handle_raw_packet) | IPv4 TCP/UDP forwarding with IP header reconstruction at exit nodes |
| Response Reconstruction | `crates/erasure/src/lib.rs`, `crates/client/` | Client reassembles shards via erasure decoding after relay traversal |
| Gossipsub Exit Announcements | `crates/network/src/status.rs`, `crates/network/src/node.rs` | Exit nodes broadcast heartbeats with load/throughput/uptime via gossipsub |
| Domain Blocking (Exit) | `crates/exit/src/handler.rs` | Blocked domain list enforced at exit handler; tested |
| Desktop Electron App | `apps/desktop/` | Full JSON-RPC IPC to daemon; all commands wired; event forwarding works |
| CLI | `apps/cli/src/main.rs` | 20+ commands fully connected to daemon via IPC client |
| Settings Persistence | `crates/settings/src/config.rs` | JSON config load/save |
| Key Management | `crates/keystore/` | ED25519 generate/store/load; encrypted export/import with ChaCha20-Poly1305 |
| Anchor Settlement Program | `programs/tunnelcraft-settlement/` | Deployed to devnet |
| 2-hop + 3-hop routing | `crates/client/src/node.rs` | Unified destination resolution, cross-shard fan-out, proactive client DHT lookup |
| Subscription Verification | `crates/network/src/subscription.rs`, `crates/client/src/node.rs` | Gossipsub announcements, relay cache, periodic on-chain batch verification, priority routing |
| Settlement Signing | `crates/client/src/node.rs`, `crates/aggregator/src/lib.rs` | ProofMessage signed with relay ed25519 keypair; aggregator verifies before accepting |
| Devnet/Mainnet Config | `crates/daemon/src/service.rs` | TUNNELCRAFT_PROGRAM_ID + TUNNELCRAFT_NETWORK env vars select settlement target |

### Settlement Pipeline Redesign + risc0 ZK Proofs (2026-02-08)

#### Phase A: Pipeline Fixes (no risc0 dependency)
- [x] A0: Add sender_pubkey to ForwardReceipt (anti-Sybil receipt binding)
- [x] A1: Fix pool routing — use user_pubkey not user_proof
- [x] A2: Key proof_queue and pool_roots by (user_pubkey, PoolType)
- [x] A3: Fix try_prove() to use proof output bytes
- [x] A6: Aggregator accepts Prover, pool key update, ZK verification
- [x] A4: Proof state persistence (save/load pool_roots + pending receipts)
- [x] A4b: Chain recovery via aggregator query (ProofStateQuery/Response, apply_chain_recovery)
- [x] A5: First-writer-wins for distribution posting (DistributionAlreadyPosted error)

#### Phase B: risc0 ZK Proofs
- [x] B1: prover-guest-types crate (no_std shared types: GuestReceipt, GuestInput, GuestOutput)
- [x] B2: prover-guest crate (risc0 guest: sig verify, Merkle tree, sender binding)
- [x] B3: risc0 feature in prover crate (Risc0Prover, build.rs, conditional export)
- [x] B4: Wire prover selection in client (cfg-gated StubProver vs Risc0Prover)
- [x] B5: Workspace config (prover-guest-types in members, prover-guest in exclude, risc0 workspace deps)

**Status**: All code written. Workspace compiles and all tests pass without risc0 feature.
risc0 feature requires `rzup` toolchain installed to compile (`cargo check --features risc0`).

### Production Blockers (what prevents this from being a real VPN)

1. ~~**Settlement defaults to mock** — Anchor program is on devnet; daemon needs config~~ FIXED
2. ~~**No subscription enforcement** — all traffic treated as Free tier~~ FIXED
3. **Android VPN is mocked** — returns fake data, no real tunnel
4. **iOS untested on device** — UniFFI bindings compile but never ran on hardware
5. **No payment flow** — no way for users to actually purchase credits
