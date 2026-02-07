# Feature Implementation Tracker

Updated: 2026-02-07 (Final)

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
| Exit Node HTTP Fetch | `crates/exit/src/handler.rs` | Full GET/POST/PUT/DELETE/PATCH/HEAD via reqwest; shards and encodes response |
| Raw VPN Packet Tunneling | `crates/exit/src/handler.rs` (handle_raw_packet) | IPv4 TCP/UDP forwarding with IP header reconstruction at exit nodes |
| Response Reconstruction | `crates/erasure/src/lib.rs`, `crates/client/` | Client reassembles shards via erasure decoding after relay traversal |
| Gossipsub Exit Announcements | `crates/network/src/status.rs`, `crates/network/src/node.rs` | Exit nodes broadcast heartbeats with load/throughput/uptime via gossipsub |
| Domain Blocking (Exit) | `crates/exit/src/handler.rs` | Blocked domain list enforced at exit handler; tested |
| Local Discovery Toggle | `crates/client/src/node.rs` | mDNS peers skipped when `local_discovery_enabled = false` |
| Desktop Electron App | `apps/desktop/` | Full JSON-RPC IPC to daemon; all commands wired; event forwarding works |
| CLI | `apps/cli/src/main.rs` | 20+ commands fully connected to daemon via IPC client (history, earnings, speedtest, bandwidth, key export/import) |
| Settings Persistence | `crates/settings/src/config.rs` | JSON config load/save to `~/.tunnelcraft/settings.json` |
| Key Management | `crates/keystore/` | ED25519 generate/store/load; encrypted export/import with ChaCha20-Poly1305 |
| Custom Headers Passthrough | `crates/client/src/node.rs`, `crates/daemon/src/service.rs` | Headers flow from IPC → daemon → node.fetch() → RequestBuilder |
| Anchor Settlement Program | `programs/tunnelcraft-settlement/` | Deployed to devnet as `2QQvVc5QmYkLEAFyoVd3hira43NE9qrhjRcuT1hmfMTH`; 5 instructions (purchase, settle_request, settle_response, claim_work, withdraw) |
| Connection History | `crates/daemon/src/service.rs` | Daemon tracks connect/disconnect events; capped at 100 entries; IPC + CLI + desktop wired |
| Earnings History | `crates/daemon/src/service.rs` | Daemon tracks settlement events; capped at 100 entries; IPC + CLI + desktop wired |
| Speed Test | `crates/daemon/src/service.rs` | Estimates throughput from node byte counters; stores last 10 results; IPC + CLI + desktop wired |
| Bandwidth Limiting | `crates/client/src/node.rs`, `crates/daemon/src/service.rs` | `bandwidth_limit_kbps` field on node; IPC + CLI + desktop wired |
| Key Export/Import | `crates/keystore/`, `crates/daemon/src/service.rs` | ChaCha20-Poly1305 encrypted export/import; IPC + CLI + desktop wired |
| Exit Geo Enforcement | `crates/client/src/node.rs` | `set_exit_preference()` filters exits by region/country/city; warns when no match |
| Bootstrap Mode | `apps/cli/src/main.rs` | `tunnelcraft daemon --bootstrap` runs relay-only node on configurable port; prints multiaddr |

### PARTIAL (Some parts work, gaps remain)

| Feature | What works | What doesn't |
|---------|-----------|--------------|
| iOS VPN Network Extension | 563-line PacketTunnelProvider with split tunneling; UniFFI bindings compile | Never integration-tested on a real device |
| iOS Native Module | 574-line Swift module (connect/disconnect/status/exits/request) | Dev mode returns mocks; production UniFFI path untested on device |
| Node Earnings (Live) | Anchor program deployed to devnet; settlement client has devnet config | Daemon defaults to mock settlement unless `TUNNELCRAFT_PROGRAM_ID` env var is set |
| Windows IPC | Named pipe server + client both compile | Never tested on actual Windows |
| NAT Traversal | libp2p dcutr + relay protocol configured in swarm | Never tested in real NAT scenarios |

### REMAINING WORK

- [x] **Anchor Program**: Deployed to devnet as `2QQvVc5QmYkLEAFyoVd3hira43NE9qrhjRcuT1hmfMTH`
- [x] **Wire Program ID**: Settlement client has `DEVNET_PROGRAM_ID` + `devnet_default()`, daemon uses env var
- [x] **Bootstrap Infrastructure**: `tunnelcraft daemon --bootstrap` runs relay-only node, prints peer ID
- [x] **Connection History**: Daemon handler + IPC method + storage (capped at 100)
- [x] **Earnings History**: Daemon handler + IPC method + storage (capped at 100)
- [x] **Speed Test**: Daemon handler + IPC method + measurement via node stats
- [x] **Bandwidth Limiting**: Node field + daemon handler + IPC
- [x] **Key Export/Import**: ChaCha20-Poly1305 encrypted export/import via keystore
- [x] **Desktop Frontend Wiring**: IPC handlers for all new features
- [x] **CLI Subcommands**: Commands for history, earnings, speedtest, bandwidth, key export/import
- [x] **Exit Geo Enforcement**: `set_exit_preference()` filters by region/country/city; warns on no match
- [x] **Update Audit**: Final verification pass — `cargo test` all pass, `tsc --noEmit` clean

---

### Production Blockers (what prevents this from being a real VPN)

1. ~~**No bootstrap nodes deployed**~~ — Bootstrap node live at `64.225.12.79:9000` (peer `12D3KooWMHxq3CkQ1YogRBuCUJJPoSgFSdi3pshqv3zfLxMHS9hq`), hardcoded as default
2. ~~**No exit nodes deployed**~~ — Exit node live at `64.225.12.79:9001` (peer `12D3KooWPrNiqw9AVYfhBfWhZnt2hDdpJcV2ctS6bqdTCwBqr5DE`), bootstraps from local node
3. **Settlement defaults to mock** — Anchor program is on devnet; daemon needs `TUNNELCRAFT_PROGRAM_ID` env var to use it
4. **Android VPN is mocked** — returns fake data, no real tunnel
5. **iOS untested on device** — UniFFI bindings compile but never ran on hardware
6. **No payment flow** — no way for users to actually purchase credits (needs Apple IAP / Stripe)
