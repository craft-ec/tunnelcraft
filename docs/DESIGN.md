# TunnelCraft: P2P Incentivized VPN

## Executive Summary

TunnelCraft is a decentralized, trustless VPN network that provides strong privacy through fragmentation. The design achieves practical anonymity with cryptographic verification at every step.

**Key Innovation**: Privacy through fragmentation. Trustless through verification.

---

## Core Philosophy

```
Every node is equal. No dedicated servers.
No trust required. Only cryptographic verification.
Random routing. Network decides path.
User controls privacy level. Network handles routing.
```

---

## Architecture Overview

### Two Layers

```
┌─────────────────────────────────────────────────────────────┐
│                                                              │
│   LIBP2P KADEMLIA DHT                                        │
│   • Peer discovery                                           │
│   • Exit lookup                                              │
│   • One-time pubkey announcement                             │
│   • NAT traversal                                            │
│                                                              │
│   SOLANA                                                     │
│   • Credits                                                  │
│   • Settlement                                               │
│   • Claims                                                   │
│   • Rewards                                                  │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

### Components

| Layer | Technology | Purpose |
|-------|------------|---------|
| P2P | libp2p Kademlia DHT | Discovery, NAT traversal |
| Coding | Reed-Solomon (5/3) | Resilience, fragmentation |
| Routing | Random (network decides) | Anonymity, load distribution |
| Proof | Chain signatures | Work verification |
| Settlement | Solana | Rewards, credits |

---

## Routing Model

### User Controls Privacy, Network Controls Path

```
┌─────────────────────────────────────────────────────────────┐
│                                                              │
│   USER DECIDES                                               │
│   • Hop count (0, 1, 2, 3)                                   │
│   • Which exits to use                                       │
│                                                              │
│   NETWORK DECIDES                                            │
│   • Actual path (random per shard)                           │
│   • Which relays                                             │
│                                                              │
│   RESULT                                                     │
│   • Each shard takes different route                         │
│   • No bottleneck                                            │
│   • Maximum anonymity                                        │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

### Hop Modes

```
┌─────────────────────────────────────────────────────────────┐
│                                                              │
│   0 HOP                                                      │
│   User → Exit                                                │
│   Fast, less private                                         │
│                                                              │
│   1+ HOP                                                     │
│   User → [random relays] → Exit                              │
│   Shard: hops_remaining = N                                  │
│   Each relay: pick random next, decrement, sign              │
│   When hops_remaining = 0: forward to exit                   │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

| Mode | Hops | Latency | Privacy |
|------|------|---------|---------|
| Direct | 0 | ~30ms | Exit sees IP |
| Light | 1 | ~60ms | 1 relay hides IP |
| Standard | 2 | ~90ms | Good privacy |
| Paranoid | 3 | ~120ms | Maximum privacy |

---

## Chain Signatures

### Each Shard Has Own Chain

```
┌─────────────────────────────────────────────────────────────┐
│                                                              │
│   SHARD TRAVELS: User → A → B → Exit                         │
│                                                              │
│   At User:  chain = []                                       │
│   At A:     chain = [A_sig]                                  │
│   At B:     chain = [A_sig, B_sig]                           │
│   At Exit:  chain = [A_sig, B_sig, Exit_sig]                 │
│                                                              │
│   Each relay keeps own chain as proof                        │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

### Response Has Own Chain

```
┌─────────────────────────────────────────────────────────────┐
│                                                              │
│   RESPONSE: Exit → X → Y → User                              │
│                                                              │
│   At Exit: chain = [Exit_sig]                                │
│   At X:    chain = [Exit_sig, X_sig]                         │
│   At Y:    chain = [Exit_sig, X_sig, Y_sig]                  │
│                                                              │
│   Different path than request                                │
│   Each chunk different path                                  │
│   No bottleneck                                              │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

---

## Trustless Verification

### The Key Insight

```
┌─────────────────────────────────────────────────────────────┐
│                                                              │
│   RELAYS VERIFY DESTINATION                                  │
│                                                              │
│   Request comes through:                                     │
│   Relay sees: {request_id, user_pubkey: ABC}                 │
│   Relay caches: request_id → user ABC                        │
│                                                              │
│   Response comes through:                                    │
│   Relay sees: {request_id, destination: XYZ}                 │
│   Relay checks: XYZ == ABC?                                  │
│   No → Drop. Won't forward.                                  │
│                                                              │
│   EXIT CAN'T REDIRECT                                        │
│   Relays enforce destination = origin                        │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

### Every Step Verified

```
┌─────────────────────────────────────────────────────────────┐
│                                                              │
│   USER                                                       │
│   Verified by: hash(credit_secret) on-chain                  │
│                                                              │
│   RELAY                                                      │
│   Verified by: Chain signature                               │
│   Validates: destination == origin                           │
│                                                              │
│   EXIT                                                       │
│   Verified by: Has credit_secret                             │
│   Constrained by: Relays check destination                   │
│                                                              │
│   LAST RELAY                                                 │
│   Verified by: TCP ACK from user                             │
│                                                              │
│   TRUST REQUIRED: None                                       │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

---

## Settlement Flow

### Two-Phase Settlement

```
┌─────────────────────────────────────────────────────────────┐
│                                                              │
│   PHASE 1: EXIT SETTLES REQUEST                              │
│                                                              │
│   Exit receives request shards                               │
│   Exit decrypts, gets credit_secret                          │
│   Exit submits:                                              │
│   {                                                          │
│     request_id,                                              │
│     credit_secret,                                           │
│     user_pubkey,           // Locked for response            │
│     request_chains         // From all shards                │
│   }                                                          │
│   Status: PENDING                                            │
│                                                              │
│   ─────────────────────────────────────────────────          │
│                                                              │
│   PHASE 2: LAST RELAY SETTLES RESPONSE                       │
│                                                              │
│   Last relay delivers to user                                │
│   Gets TCP ACK                                               │
│   Submits:                                                   │
│   {                                                          │
│     request_id,                                              │
│     response_chain,                                          │
│     tcp_ack                                                  │
│   }                                                          │
│   Chain checks: destination == stored user_pubkey            │
│   Status: COMPLETE                                           │
│                                                              │
│   ─────────────────────────────────────────────────          │
│                                                              │
│   ALL CLAIMS ENABLED AFTER COMPLETE                          │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

### Points Distribution

```
┌─────────────────────────────────────────────────────────────┐
│                                                              │
│   REQUEST PATH: User → A → B → Exit                          │
│                                                              │
│   A: 1 point                                                 │
│   B: 1 point                                                 │
│   Exit: 1 point                                              │
│                                                              │
│   RESPONSE PATH: Exit → X → Y → User                         │
│                                                              │
│   Exit: 2 points (fetch work)                                │
│   X: 1 point                                                 │
│   Y: 1 point (+ settles with TCP ACK)                        │
│                                                              │
│   Exit total: 3 points (request + response)                  │
│   Response more valuable (bigger payload)                    │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

---

## Shard Structure

### Request Shard

```
┌─────────────────────────────────────────────────────────────┐
│                                                              │
│   {                                                          │
│     shard_id: bytes32,                                       │
│     request_id: bytes32,                                     │
│     credit_hash: bytes32,                                    │
│     user_pubkey: pubkey,                                     │
│     destination: exit_pubkey,                                │
│     hops_remaining: u8,                                      │
│     chain: [...],                                            │
│     payload: encrypted  // Contains credit_secret            │
│   }                                                          │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

### Response Shard

```
┌─────────────────────────────────────────────────────────────┐
│                                                              │
│   {                                                          │
│     shard_id: bytes32,                                       │
│     request_id: bytes32,                                     │
│     destination: user_pubkey,    // Must match request       │
│     hops_remaining: u8,                                      │
│     chain: [Exit_sig, ...],      // Starts with exit         │
│     payload: encrypted                                       │
│   }                                                          │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

---

## Attack Resistance

### All Attacks Blocked

```
┌─────────────────────────────────────────────────────────────┐
│                                                              │
│   ATTACK: Exit redirects response to colluding user         │
│                                                              │
│   1. Real user (ABC) sends request                           │
│   2. Exit tries response to colluder (XYZ)                   │
│   3. First relay checks: XYZ == ABC?                         │
│   4. No → Drop                                               │
│   5. Attack dies at first relay                              │
│                                                              │
│   ─────────────────────────────────────────────────          │
│                                                              │
│   ATTACK: Exit settles but never sends response              │
│                                                              │
│   1. Exit submits request settlement                         │
│   2. Status: PENDING                                         │
│   3. No response → No TCP ACK → No response settlement       │
│   4. Timeout → Credits refunded                              │
│   5. Exit gets nothing                                       │
│                                                              │
│   ─────────────────────────────────────────────────          │
│                                                              │
│   ATTACK: Fake response without credit_secret                │
│                                                              │
│   1. Attacker creates fake response                          │
│   2. No valid request settlement exists                      │
│   3. Response settlement rejected                            │
│   4. No payment                                              │
│                                                              │
│   ─────────────────────────────────────────────────          │
│                                                              │
│   ATTACK: Relay shortens chain                               │
│                                                              │
│   1. Relay tries to skip other relays                        │
│   2. Chain signature proves actual path                      │
│   3. Can't forge other relays' signatures                    │
│   4. Can't claim for work not done                           │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

### Defense Layers

| Layer | Defender | Checks |
|-------|----------|--------|
| Routing | Relays | destination == origin |
| Settlement | Chain | credit_secret valid |
| Settlement | Chain | user_pubkey matches |
| Claims | Chain | signatures valid |
| Delivery | Last relay | TCP ACK |

---

## Erasure Coding

### Parameters

```
Total shards: 5
Required for reconstruction: 3
Redundancy ratio: 1.67x
```

### Per Request

```
┌─────────────────────────────────────────────────────────────┐
│                                                              │
│   3 EXITS × 5 SHARDS = 15 SHARDS                             │
│                                                              │
│   Each shard: Random path                                    │
│   Each chunk: Random path                                    │
│   First exit to complete wins                                │
│                                                              │
│   No two shards take same route                              │
│   Maximum distribution                                       │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

---

## Privacy Model

### What's Private

| Property | Protected By |
|----------|--------------|
| Content | E2E encryption |
| User identity | One-time keys per request |
| Wallet linkage | Bearer credits |
| Traffic patterns | Random routing |
| Request/response correlation | Different paths |

### Privacy Matrix

| Party | Knows User IP | Knows Content | Can Correlate |
|-------|---------------|---------------|---------------|
| First relay | Partial (1 of 15) | No | No |
| Middle relay | No | No | No |
| Exit | No | Yes | No |
| Last relay | No | No | No |

---

## Service Quality

### Not Security, Just Quality

```
┌─────────────────────────────────────────────────────────────┐
│                                                              │
│   CRYPTOGRAPHICALLY VERIFIED                                 │
│   • Payment valid                                            │
│   • Work done                                                │
│   • Delivery complete                                        │
│   • No redirect possible                                     │
│                                                              │
│   MARKET DETERMINED                                          │
│   • Response quality (garbage or real?)                      │
│   • Speed                                                    │
│   • Reliability                                              │
│                                                              │
│   Bad exit sends garbage?                                    │
│   • Can't steal credits (verified)                           │
│   • Can't redirect (blocked by relays)                       │
│   • User picks different exit next time                      │
│   • Market punishment                                        │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

---

## Full Flow

```
┌─────────────────────────────────────────────────────────────┐
│                                                              │
│   1. USER                                                    │
│      • Has credit_secret (purchased)                         │
│      • Picks exits, sets hop count                           │
│      • Creates request shards                                │
│      • Sends to random first relays                          │
│                                                              │
│   2. REQUEST ROUTING                                         │
│      • Each relay: random next, sign, forward                │
│      • Relays cache: request_id → user_pubkey                │
│      • hops_remaining = 0: forward to exit                   │
│                                                              │
│   3. EXIT RECEIVES                                           │
│      • Reconstructs from 3+ shards                           │
│      • Decrypts, gets credit_secret                          │
│      • Settles request on-chain → PENDING                    │
│      • Fetches from internet                                 │
│                                                              │
│   4. RESPONSE ROUTING                                        │
│      • Exit creates response shards                          │
│      • Each shard: random path                               │
│      • Relays check: destination == cached user_pubkey       │
│      • Mismatch → Drop                                       │
│                                                              │
│   5. DELIVERY                                                │
│      • Last relay delivers to user                           │
│      • Gets TCP ACK                                          │
│      • Settles response on-chain → COMPLETE                  │
│                                                              │
│   6. CLAIMS                                                  │
│      • All relays claim from settled request                 │
│      • Pool distribution based on points                     │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

---

## Summary

```
┌─────────────────────────────────────────────────────────────┐
│                                                              │
│   DISCOVERY:  DHT (exits, relays, pubkeys)                   │
│   ROUTING:    Random (network decides)                       │
│   PRIVACY:    User sets hop count                            │
│   PROOF:      Chain signatures per shard                     │
│   SECURITY:   Relays verify destination = origin             │
│   SETTLEMENT: Two-phase (exit + last relay)                  │
│   TRUST:      None required                                  │
│                                                              │
│   ─────────────────────────────────────────────────          │
│                                                              │
│   Every step verified cryptographically.                     │
│   No actor can cheat.                                        │
│   Market handles service quality.                            │
│                                                              │
│   TRUSTLESS VPN.                                             │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```
