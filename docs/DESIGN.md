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
│   • Subscription gossip                                      │
│                                                              │
│   SOLANA                                                     │
│   • Subscriptions                                            │
│   • Per-user reward pools                                    │
│   • Receipt submission + claims                              │
│   • Rewards                                                  │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

### Components

| Layer | Technology | Purpose |
|-------|------------|---------|
| P2P | libp2p Kademlia DHT | Discovery, NAT traversal, subscription gossip |
| Coding | Reed-Solomon (5/3) | Resilience, fragmentation |
| Routing | Destination-based with DHT | Anonymity, load distribution |
| Proof | ForwardReceipts (ed25519) | Proof of forwarding |
| Settlement | Solana (per-user pool) | Subscription + proportional claiming |

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

## ForwardReceipts

### Proof of Forwarding

```
┌─────────────────────────────────────────────────────────────┐
│                                                              │
│   SHARD TRAVELS: User → A → B → Exit                         │
│                                                              │
│   User sends to A                                            │
│   A forwards to B → B signs receipt for A                    │
│   B forwards to Exit → Exit signs receipt for B              │
│                                                              │
│   Each receipt proves: "I received this shard"               │
│   Receipt includes: request_id, shard_index,                 │
│                     receiver_pubkey, timestamp, sig          │
│                                                              │
│   Receipts are the ONLY settlement primitive.                │
│   No credit indexes, no bitmap, no sequencer.                │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

### Response Path Receipts

```
┌─────────────────────────────────────────────────────────────┐
│                                                              │
│   RESPONSE: Exit → X → Y → User                              │
│                                                              │
│   Exit sends to X → X signs receipt for Exit                 │
│   X sends to Y → Y signs receipt for X                       │
│   Y sends to User → User signs receipt for Y                 │
│                                                              │
│   Every node (including User) signs receipts                 │
│   Only the first relay on request path doesn't receive one   │
│   (User is the payer, not a claimable hop)                   │
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
│   Verified by: On-chain SubscriptionPDA (active tier)        │
│                                                              │
│   RELAY                                                      │
│   Verified by: ForwardReceipt from next hop                  │
│   Validates: destination == origin (response path)           │
│   Settlement: Submits receipts to user's pool                │
│                                                              │
│   EXIT                                                       │
│   Verified by: ForwardReceipt from first response relay      │
│   Constrained by: Relays check destination                   │
│   Settlement: Submits receipts to user's pool                │
│                                                              │
│   CLIENT (on response)                                       │
│   Signs receipts so last relay can settle                    │
│                                                              │
│   TRUST REQUIRED: None                                       │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

---

## Subscription + Per-User Pool Model

### Overview

```
┌─────────────────────────────────────────────────────────────┐
│                                                              │
│   1. USER SUBSCRIBES                                         │
│      On-chain: SubscriptionPDA { tier, expires_at }          │
│      Payment goes into UserPoolPDA { balance }               │
│                                                              │
│   2. RELAYS FORWARD SHARDS                                   │
│      Collect ForwardReceipts as proof of work                │
│      Subscribed users get priority processing                │
│      Non-subscribed users get best-effort                    │
│                                                              │
│   3. RELAYS SUBMIT RECEIPTS                                  │
│      submit_receipts(user_pool, receipts[])                  │
│      Deduped by (request_id, shard_index, receiver_pubkey)   │
│      Increments relay's receipt count for that pool          │
│                                                              │
│   4. END OF CYCLE: CLAIM REWARDS                             │
│      relay_share = relay_receipts / total_receipts           │
│      relay_payout = relay_share * pool_balance               │
│      Pull-based: relay claims its weighted share             │
│                                                              │
│   5. POOL RESETS                                             │
│      Remaining balance carries over or refunds               │
│      Subscription renews or expires                          │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

### Subscription Tiers

| Tier | Price/month | Bandwidth | Pool contribution |
|------|------------|-----------|-------------------|
| Basic | 5 USDC | 10 GB | 5 USDC |
| Standard | 15 USDC | 100 GB | 15 USDC |
| Premium | 40 USDC | 1 TB + best-effort beyond | 40 USDC |

Premium users who exhaust their pool still get service at lower
priority (subsidized by network goodwill / best-effort).

### Why Per-User Pool (Not Global Pool)

```
┌─────────────────────────────────────────────────────────────┐
│                                                              │
│   GLOBAL POOL (BROKEN)                                       │
│   • Abuser + colluding exit spam traffic                     │
│   • Exit earns massive share of ENTIRE pool                  │
│   • Honest relays' earnings diluted                          │
│   • One bad actor breaks economics for everyone              │
│   → Pool inflation attack                                    │
│                                                              │
│   PER-USER POOL (CORRECT)                                    │
│   • Abuser spams traffic                                     │
│   • More receipts against THEIR OWN pool only                │
│   • Per-receipt value drops (40 USDC / 10000 receipts)       │
│   • Relays detect low yield → stop serving that user         │
│   • Honest users unaffected                                  │
│   → Abuse is self-correcting                                 │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

---

## Subscription Verification

### Gossip-Based (Zero RPC)

```
┌─────────────────────────────────────────────────────────────┐
│                                                              │
│   1. User subscribes on-chain                                │
│   2. Listener node detects event                             │
│   3. Gossips subscription to network via gossipsub           │
│   4. All relays update local cache:                          │
│      cache[user_pubkey] = { tier, expires_at }               │
│                                                              │
│   RELAY RECEIVES SHARD:                                      │
│   • Check local cache for user_pubkey                        │
│   • Cache hit + not expired → priority queue                 │
│   • Cache miss → best-effort queue                           │
│                                                              │
│   RANDOM AUDIT:                                              │
│   • Relay spot-checks random users on-chain periodically     │
│   • Catches fake gossip messages                             │
│   • Fakers reported for abuse                                │
│                                                              │
│   CACHING BEHAVIOR:                                          │
│   • Every relay caches independently                         │
│   • First request through a relay: cache miss → best-effort  │
│   • Subsequent requests: cache hit → instant priority        │
│   • Active subscriptions cached until expires_at             │
│   • Natural latency penalty for non-subscribers              │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

### No Relay Attestation

```
┌─────────────────────────────────────────────────────────────┐
│                                                              │
│   WHY NOT "FIRST RELAY ATTESTS, REST SKIP CHECK"?            │
│                                                              │
│   Attack: User runs custom first relay                       │
│   → Forges "subscribed" attestation                          │
│   → Gets priority service for free at all subsequent hops    │
│                                                              │
│   Solution: Every relay verifies independently (via cache)   │
│   No relay trusts another relay's attestation.               │
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
│     user_pubkey: pubkey,                                     │
│     destination: exit_pubkey,                                │
│     hops_remaining: u8,                                      │
│     chain: [ChainEntry],     // Signature chain              │
│     payload: encrypted,                                      │
│     shard_index: u8,                                         │
│     total_shards: u8,                                        │
│   }                                                          │
│                                                              │
│   No credit_hash, no credit_indexes, no credit_auth.         │
│   Payment is handled by the subscription pool model.         │
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
│     user_pubkey: pubkey,                                     │
│     destination: user_pubkey,   // Must match request        │
│     hops_remaining: u8,                                      │
│     chain: [ChainEntry],                                     │
│     payload: encrypted,                                      │
│     shard_index: u8,                                         │
│     total_shards: u8,                                        │
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
│   ATTACK: Relay submits same receipt twice                   │
│                                                              │
│   1. Receipt deduped by (request_id, shard_index,            │
│      receiver_pubkey) on-chain                               │
│   2. Second submission rejected                              │
│                                                              │
│   ─────────────────────────────────────────────────          │
│                                                              │
│   ATTACK: Relay forges a ForwardReceipt                      │
│                                                              │
│   1. Receipt is ed25519 signed by receiver                   │
│   2. Can't forge without receiver's private key              │
│   3. On-chain verifies signature                             │
│                                                              │
│   ─────────────────────────────────────────────────          │
│                                                              │
│   ATTACK: Relay doesn't forward, claims receipt              │
│                                                              │
│   1. No forwarding → no receipt from next hop                │
│   2. Can't claim without receipt                             │
│                                                              │
│   ─────────────────────────────────────────────────          │
│                                                              │
│   ATTACK: User spams overlapping requests (abuse)            │
│                                                              │
│   1. More receipts against user's pool                       │
│   2. Per-receipt value drops                                 │
│   3. Relays detect low yield per receipt                     │
│   4. Relays stop serving that user                           │
│   5. Abuse is self-correcting and self-contained             │
│   6. Other users' pools unaffected                           │
│                                                              │
│   ─────────────────────────────────────────────────          │
│                                                              │
│   ATTACK: Pool inflation via colluding exit                  │
│                                                              │
│   1. Per-user pool: colluding exit only inflates             │
│      receipts against the abuser's OWN pool                  │
│   2. Exit's per-receipt yield drops                          │
│   3. No dilution of honest users' pools                      │
│   4. No global pool to drain                                 │
│                                                              │
│   ─────────────────────────────────────────────────          │
│                                                              │
│   ATTACK: Fake subscription via gossip                       │
│                                                              │
│   1. Malicious node gossips "user X is subscribed"           │
│   2. Random audit: relay spot-checks on-chain                │
│   3. Fake caught → user reported for abuse                   │
│   4. Bounded damage: free priority for a few minutes         │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

### Defense Layers

| Layer | Defender | Checks |
|-------|----------|--------|
| Routing | Relays | destination == origin |
| Subscription | Gossip + random audit | Active subscription verified |
| Proof of work | On-chain | ForwardReceipt signature valid |
| Anti-double-claim | On-chain | Receipt deduped by unique tuple |
| Anti-abuse | Per-user pool | Abuse dilutes abuser's own pool only |
| Priority | Relays | Subscribed → priority, else best-effort |

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
│   3 EXITS x 5 SHARDS = 15 SHARDS                             │
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
| Wallet linkage | Subscription (not per-request payment) |
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
│   • Subscription valid (gossip + random audit)               │
│   • Work done (ForwardReceipt)                               │
│   • Delivery complete                                        │
│   • No redirect possible                                     │
│                                                              │
│   MARKET DETERMINED                                          │
│   • Response quality (garbage or real?)                      │
│   • Speed                                                    │
│   • Reliability                                              │
│                                                              │
│   Bad exit sends garbage?                                    │
│   • Can't steal from pool (receipts prove work)              │
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
│   1. USER SUBSCRIBES                                         │
│      • Buys subscription on-chain (tier)                     │
│      • Payment deposited to user's own pool PDA              │
│      • Subscription event gossiped to network                │
│                                                              │
│   2. REQUEST ROUTING                                         │
│      • User creates request shards, sends to first relays    │
│      • Each relay: checks subscription (cache), forwards     │
│      • Next hop signs ForwardReceipt for sender              │
│      • Sender stores receipt for later claiming               │
│      • Relays cache: request_id → user_pubkey                │
│      • hops_remaining = 0: forward to exit                   │
│                                                              │
│   3. EXIT RECEIVES                                           │
│      • Reconstructs from 3+ shards                           │
│      • Fetches from internet                                 │
│      • Stores receipts from first response relays             │
│                                                              │
│   4. RESPONSE ROUTING                                        │
│      • Exit creates response shards                          │
│      • Relays check: destination == cached user_pubkey       │
│      • Each relay gets receipt from next hop, stores it      │
│                                                              │
│   5. DELIVERY                                                │
│      • Last relay delivers to user                           │
│      • User signs ForwardReceipt for last relay              │
│                                                              │
│   6. SETTLEMENT                                              │
│      • Relays submit receipts to user's pool on-chain        │
│      • Deduped by (request_id, shard_index, receiver_pubkey) │
│      • End of cycle: relay claims proportional share         │
│      • relay_payout = (relay_receipts / total) * pool        │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

---

## Summary

```
┌─────────────────────────────────────────────────────────────┐
│                                                              │
│   DISCOVERY:  DHT (exits, relays, pubkeys)                   │
│   ROUTING:    Destination-based with DHT peer lookup          │
│   PRIVACY:    User sets hop count                            │
│   PROOF:      ForwardReceipts (signed proof of delivery)     │
│   SECURITY:   Relays verify destination = origin             │
│   PAYMENT:    Subscription → per-user pool                   │
│   CLAIMING:   Proportional (receipts / total * pool)         │
│   GOSSIP:     Subscription status + random audit             │
│   TRUST:      None required                                  │
│                                                              │
│   ─────────────────────────────────────────────────          │
│                                                              │
│   Every step verified cryptographically.                     │
│   Abuse is self-correcting (per-user pool).                  │
│   No bitmap. No sequencer. No credit indexes.                │
│   ForwardReceipt is the only settlement primitive.           │
│   Market handles service quality.                            │
│                                                              │
│   TRUSTLESS VPN.                                             │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```
