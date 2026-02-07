# TunnelCraft: Technical Specification

## Technology Stack

| Component | Technology | Purpose |
|-----------|------------|---------|
| Language | Rust 1.75+ | Core implementation |
| Runtime | Tokio | Async runtime |
| P2P | libp2p | Discovery, NAT traversal, gossip |
| Erasure | reed-solomon-erasure | Shard encoding |
| Crypto | dalek ecosystem (ed25519-dalek, x25519-dalek, chacha20poly1305) | Encryption, signatures |
| Settlement | Solana + Anchor | Subscriptions, pools, rewards |

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                       CLIENT                                 │
│  • Subscription management                                   │
│  • One-time key generation                                   │
│  • Erasure encoding                                          │
│  • Exit selection                                            │
│  • Hop count setting                                         │
└───────────────────────────┬─────────────────────────────────┘
                            │
┌───────────────────────────┼─────────────────────────────────┐
│                      NETWORK                                 │
│  ┌────────────────────────────────────────────────────┐     │
│  │                 libp2p Kademlia DHT                 │     │
│  │  • Peer discovery                                   │     │
│  │  • Exit lookup                                      │     │
│  │  • Subscription gossip                              │     │
│  └────────────────────────────────────────────────────┘     │
│                           │                                  │
│  ┌────────────────────────────────────────────────────┐     │
│  │                    Relay                            │     │
│  │  • Random next hop selection                        │     │
│  │  • Chain signing                                    │     │
│  │  • Destination verification                         │     │
│  │  • Request-origin caching                           │     │
│  │  • Subscription check (gossip cache)                │     │
│  └────────────────────────────────────────────────────┘     │
│                           │                                  │
│  ┌────────────────────────────────────────────────────┐     │
│  │                    Exit                             │     │
│  │  • Request reconstruction                           │     │
│  │  • HTTP fetch                                       │     │
│  │  • Response creation                                │     │
│  └────────────────────────────────────────────────────┘     │
└─────────────────────────────────────────────────────────────┘
                            │
┌───────────────────────────┼─────────────────────────────────┐
│                     SETTLEMENT                               │
│  ┌────────────────────────────────────────────────────┐     │
│  │                    Solana                           │     │
│  │  • SubscriptionPDA (tier, expiry)                   │     │
│  │  • UserPoolPDA (per-user reward pool)               │     │
│  │  • PoolReceiptsPDA (receipt counts per relay)       │     │
│  │  • NodeAccount (relay earnings)                     │     │
│  └────────────────────────────────────────────────────┘     │
└─────────────────────────────────────────────────────────────┘
```

---

## Core Types

### Shard

```rust
pub struct Shard {
    pub shard_id: [u8; 32],
    pub request_id: [u8; 32],
    pub user_pubkey: PublicKey,
    pub destination: PublicKey,        // Exit for request, User for response
    pub hops_remaining: u8,
    pub chain: Vec<ChainEntry>,        // Signature chain
    pub payload: Vec<u8>,
    pub shard_type: ShardType,         // Request or Response
    pub shard_index: u8,
    pub total_shards: u8,
}
```

No credit_hash, no credit_indexes, no credit_auth.
Payment handled by subscription pool model.

### ForwardReceipt

```rust
pub struct ForwardReceipt {
    pub request_id: [u8; 32],
    pub shard_index: u8,
    pub receiver_pubkey: [u8; 32],     // Signs this receipt
    pub timestamp: u64,
    pub signature: [u8; 64],          // ed25519 over all fields above
}
```

The only settlement primitive. Proves a node received a shard.
Deduped on-chain by (request_id, shard_index, receiver_pubkey).

### Relay Cache

```rust
pub struct RelayCache {
    // Maps request_id → user who originated it
    requests: HashMap<[u8; 32], PublicKey>,
    // Maps user_pubkey → subscription status (from gossip)
    subscriptions: HashMap<PublicKey, SubscriptionInfo>,
}

pub struct SubscriptionInfo {
    pub tier: SubscriptionTier,
    pub expires_at: u64,
}
```

---

## Relay Logic

### Request Handling

```rust
impl Relay {
    pub async fn handle_request(&self, mut shard: Shard) -> Result<()> {
        // 1. Cache request origin
        self.cache.record_request(shard.request_id, shard.user_pubkey);

        // 2. Check subscription (gossip cache) for priority
        let priority = self.cache.is_subscribed(&shard.user_pubkey);

        // 3. Decrement hops
        shard.hops_remaining -= 1;

        // 4. Forward to next hop (exit or another relay)
        let next = if shard.hops_remaining == 0 {
            shard.destination  // Exit
        } else {
            self.random_peer()
        };
        let receipt = self.send_shard(next, shard).await?;

        // 5. Store receipt for later submission to user's pool
        self.receipt_store.add(shard.user_pubkey, receipt);

        Ok(())
    }
}
```

### Response Handling (Trustless Verification)

```rust
impl Relay {
    pub async fn handle_response(&self, mut shard: Shard) -> Result<()> {
        // 1. CRITICAL: Verify destination matches cached origin
        if let Some(expected_user) = self.cache.get(&shard.request_id) {
            if shard.destination != *expected_user {
                // EXIT TRIED TO REDIRECT - DROP
                return Err(Error::DestinationMismatch);
            }
        }

        // 2. Sign ForwardReceipt for the sender (proves we received it)
        let receipt = self.sign_receipt(&shard);
        // Return receipt to sender via ShardResponse::Accepted(Some(receipt))

        // 3. Decrement and forward
        shard.hops_remaining -= 1;

        let next = if shard.hops_remaining == 0 {
            shard.destination  // User
        } else {
            self.random_peer()
        };
        let next_receipt = self.send_shard(next, shard).await?;

        // 4. Store receipt for later claiming
        self.receipt_store.add(shard.user_pubkey, next_receipt);

        Ok(())
    }
}
```

---

## Exit Logic

```rust
impl ExitNode {
    pub async fn handle_request(&self, shards: Vec<Shard>) -> Result<()> {
        // 1. Reconstruct from 3+ shards
        let request_data = self.encoder.decode(&shards)?;
        let http_request = self.decrypt(&request_data)?;

        // 2. Fetch from internet
        let response = self.http_client.execute(http_request).await?;

        // 3. Create response shards
        let response_shards = self.create_response_shards(
            &shards[0], &response,
        );

        // 4. Send response shards, collect receipts
        for shard in response_shards {
            let first_relay = self.random_peer();
            let receipt = self.send_shard(first_relay, shard).await?;
            // Store receipt for later claiming from user's pool
            self.receipt_store.add(shard.user_pubkey, receipt);
        }

        Ok(())
    }

    fn create_response_shards(
        &self, request: &Shard, response: &[u8],
    ) -> Vec<Shard> {
        let encoded = self.encoder.encode(response);
        let hops = request.hops_remaining;

        encoded.into_iter().enumerate().map(|(i, payload)| {
            Shard {
                shard_id: /* derive */,
                request_id: request.request_id,
                user_pubkey: request.user_pubkey,
                destination: request.user_pubkey,
                hops_remaining: hops,
                chain: vec![/* exit chain entry */],
                payload,
                shard_type: ShardType::Response,
                shard_index: i as u8,
                total_shards: encoded.len() as u8,
            }
        }).collect()
    }
}
```

---

## Settlement Contracts (Solana)

### Account Structures

```rust
/// User's subscription
/// PDA: ["subscription", user_pubkey]
#[account]
pub struct SubscriptionPDA {
    pub user_pubkey: [u8; 32],
    pub tier: u8,              // 0=Basic, 1=Standard, 2=Premium
    pub expires_at: i64,       // Unix timestamp
    pub bump: u8,
}

/// User's reward pool (funded by subscription payment)
/// PDA: ["pool", user_pubkey, cycle_id]
#[account]
pub struct UserPoolPDA {
    pub user_pubkey: [u8; 32],
    pub cycle_id: u64,         // Monthly cycle number
    pub balance: u64,          // Pool balance (subscription payment)
    pub total_receipts: u64,   // Total receipts submitted against this pool
    pub claimed: bool,         // Whether distribution has occurred
    pub bump: u8,
}

/// Relay's receipt count for a specific user pool
/// PDA: ["receipts", pool_pda, relay_pubkey]
#[account]
pub struct PoolReceiptsPDA {
    pub pool: [u8; 32],        // UserPoolPDA address
    pub relay_pubkey: [u8; 32],
    pub receipt_count: u64,    // Number of valid receipts from this relay
    pub claimed: bool,         // Whether relay has claimed its share
    pub bump: u8,
}

/// Node's accumulated earnings
/// PDA: ["node", node_pubkey]
#[account]
pub struct NodeAccount {
    pub node_pubkey: [u8; 32],
    pub total_earned: u64,
    pub bump: u8,
}
```

### Receipt Deduplication

Receipts are deduped by their unique tuple: `(request_id, shard_index, receiver_pubkey)`.

On-chain, this can be tracked via a hash set or by deriving a PDA per receipt:
```
receipt_pda = PDA(["receipt", pool_pda, SHA256(request_id || shard_index || receiver_pubkey)])
```

If the PDA already exists, the receipt is a duplicate and is rejected.

### Instructions

```rust
#[program]
pub mod tunnelcraft {
    /// Subscribe — create/renew subscription + fund user pool
    pub fn subscribe(
        ctx: Context<Subscribe>,
        tier: u8,
        payment_amount: u64,
    ) -> Result<()> {
        // Create/update SubscriptionPDA with tier and expiry
        // Create UserPoolPDA for current cycle
        // Transfer payment_amount to pool balance
    }

    /// Submit receipts — relay submits ForwardReceipts against user's pool
    pub fn submit_receipts(
        ctx: Context<SubmitReceipts>,
        receipts: Vec<ForwardReceipt>,
    ) -> Result<()> {
        // For each receipt:
        //   Verify: ed25519 signature valid
        //   Verify: not a duplicate (check receipt PDA doesn't exist)
        //   Create receipt PDA (marks as submitted)
        //   Increment PoolReceiptsPDA.receipt_count for this relay
        //   Increment UserPoolPDA.total_receipts
    }

    /// Claim rewards — relay claims proportional share of user's pool
    pub fn claim_rewards(
        ctx: Context<ClaimRewards>,
    ) -> Result<()> {
        // Verify: cycle has ended (or pool is in distribution phase)
        // Calculate: relay_share = receipt_count / total_receipts
        // Calculate: payout = relay_share * pool_balance
        // Transfer payout to NodeAccount.total_earned
        // Mark PoolReceiptsPDA.claimed = true
    }

    /// Withdraw accumulated earnings
    pub fn withdraw(
        ctx: Context<Withdraw>,
        amount: u64,
    ) -> Result<()>;
}
```

### Claim Rewards Logic

```rust
pub fn claim_rewards(
    ctx: Context<ClaimRewards>,
) -> Result<()> {
    let pool = &mut ctx.accounts.user_pool;
    let relay_receipts = &mut ctx.accounts.pool_receipts;
    let node = &mut ctx.accounts.node_account;

    // Must not have already claimed
    require!(!relay_receipts.claimed, Error::AlreadyClaimed);

    // Calculate proportional share
    let relay_share = relay_receipts.receipt_count as u128
        * pool.balance as u128
        / pool.total_receipts as u128;

    let payout = relay_share as u64;

    // Award to node
    node.total_earned += payout;
    relay_receipts.claimed = true;

    Ok(())
}
```

### Protection Model

| Mechanism | Protects against | How |
|-----------|-----------------|-----|
| Per-user pool | Pool inflation attack | Abuse only dilutes abuser's own pool |
| Receipt dedup | Relay double-claiming | Same receipt can't be submitted twice |
| Receipt signature | Forged receipts | ed25519 — can't forge without private key |
| Proportional claiming | Over-extraction | Relay gets exactly its share, no more |
| Gossip + random audit | Fake subscriptions | Spot-check catches fakers |
| Priority queuing | Free-riding | Non-subscribers get best-effort only |

Abuse is self-correcting: spamming a user's own pool dilutes per-receipt
value, causing relays to stop serving that user. No external enforcement needed.

---

## Subscription Gossip Protocol

### Gossipsub Topic: `tunnelcraft/subscriptions`

```rust
/// Gossiped when a subscription is detected on-chain
pub struct SubscriptionGossip {
    pub user_pubkey: [u8; 32],
    pub tier: u8,
    pub expires_at: u64,
    pub tx_signature: [u8; 64],  // Solana tx sig (for lazy verification)
}
```

### Relay Cache Logic

```rust
impl SubscriptionCache {
    pub fn on_gossip(&mut self, msg: SubscriptionGossip) {
        self.cache.insert(msg.user_pubkey, SubscriptionInfo {
            tier: msg.tier.into(),
            expires_at: msg.expires_at,
        });
    }

    pub fn is_subscribed(&self, user: &PublicKey) -> bool {
        match self.cache.get(user) {
            Some(info) => info.expires_at > current_timestamp(),
            None => false,
        }
    }

    /// Random audit: spot-check a random cached user against on-chain state
    pub async fn random_audit(&self, rpc: &RpcClient) {
        let user = self.cache.random_key();
        let on_chain = rpc.get_subscription(user).await;
        if on_chain.is_none() || on_chain.unwrap().expires_at < current_timestamp() {
            // Fake gossip detected — remove from cache, report
            self.cache.remove(user);
            self.report_abuse(user);
        }
    }
}
```

---

## Wire Format

### Shard Packet

```
┌────────────────────────────────────────────────────────────┐
│  HEADER                                                    │
├────────────────────────────────────────────────────────────┤
│  magic:          4 bytes   [0x54, 0x43, 0x53, 0x48]        │
│  version:        1 byte                                    │
│  type:           1 byte    (0=request, 1=response)         │
├────────────────────────────────────────────────────────────┤
│  shard_id:       32 bytes                                  │
│  request_id:     32 bytes                                  │
│  user_pubkey:    32 bytes                                  │
│  destination:    32 bytes                                  │
│  hops_remaining: 1 byte                                    │
│  shard_index:    1 byte                                    │
│  total_shards:   1 byte                                    │
├────────────────────────────────────────────────────────────┤
│  chain_count:    1 byte                                    │
│  chain_entries:  chain_count × (32 + 64 + 1) bytes         │
├────────────────────────────────────────────────────────────┤
│  payload_len:    4 bytes                                   │
│  payload:        variable                                  │
└────────────────────────────────────────────────────────────┘
```

### ShardResponse

```
┌────────────────────────────────────────────────────────────┐
│  type: 1 byte                                              │
│    0 = Accepted (no receipt)                                │
│    1 = Rejected (+ reason string)                          │
│    2 = Accepted with ForwardReceipt (bincode serialized)   │
└────────────────────────────────────────────────────────────┘
```

---

## Crate Structure

```
tunnelcraft/
├── Cargo.toml
├── crates/
│   ├── core/              # Types, traits
│   │   ├── shard.rs
│   │   ├── types.rs
│   │   └── error.rs
│   │
│   ├── crypto/            # Encryption, signatures
│   │   ├── keys.rs
│   │   └── sign.rs
│   │
│   ├── erasure/           # Reed-Solomon
│   │   └── encoder.rs
│   │
│   ├── network/           # libp2p
│   │   ├── swarm.rs
│   │   └── discovery.rs
│   │
│   ├── relay/             # Relay logic
│   │   ├── handler.rs
│   │   ├── cache.rs       # Request-origin + subscription cache
│   │   └── verify.rs      # Destination verification
│   │
│   ├── exit/              # Exit node
│   │   ├── handler.rs
│   │   └── http.rs
│   │
│   ├── settlement/        # Solana
│   │   ├── client.rs
│   │   └── types.rs
│   │
│   └── client/            # User client
│       ├── request.rs
│       └── identity.rs
│
├── programs/              # Solana programs
│   └── tunnelcraft-settlement/
│
└── apps/
    ├── cli/
    ├── desktop/
    └── mobile/
```

---

## Security Properties

### Cryptographic Guarantees

```
┌─────────────────────────────────────────────────────────────┐
│                                                              │
│   SUBSCRIPTION VALID                                         │
│   Proof: On-chain SubscriptionPDA                            │
│   Verification: Gossip cache + random audit                  │
│                                                              │
│   WORK DONE                                                  │
│   Proof: ForwardReceipt signed by next-hop receiver          │
│                                                              │
│   NO DOUBLE CLAIM                                            │
│   Proof: Receipts deduped by (request_id, shard_index,       │
│          receiver_pubkey) — PDA exists = duplicate            │
│                                                              │
│   NO REDIRECT POSSIBLE                                       │
│   Proof: Relays verify destination == origin                 │
│                                                              │
│   NO POOL INFLATION                                          │
│   Proof: Per-user pool — abuse dilutes abuser only           │
│                                                              │
│   TRUST REQUIRED: None                                       │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

---

## Summary

```
┌─────────────────────────────────────────────────────────────┐
│                                                              │
│   TRUSTLESS VERIFICATION                                     │
│                                                              │
│   Relays:                                                    │
│   • Cache request_id → user_pubkey                           │
│   • Verify response destination matches                      │
│   • Drop mismatches                                          │
│   • Check subscription via gossip cache                      │
│                                                              │
│   Settlement:                                                │
│   • Subscription → per-user pool                             │
│   • ForwardReceipts prove work done                          │
│   • Proportional claiming (receipts / total * pool)          │
│   • Receipt dedup prevents double-claiming                   │
│                                                              │
│   No bitmap. No sequencer. No credit indexes.                │
│   ForwardReceipt is the only settlement primitive.           │
│                                                              │
│   No trust. Just math.                                       │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```
