# TunnelCraft: Technical Specification

## Technology Stack

| Component | Technology | Purpose |
|-----------|------------|---------|
| Language | Rust 1.75+ | Core implementation |
| Runtime | Tokio | Async runtime |
| P2P | libp2p | Discovery, NAT traversal |
| Erasure | reed-solomon-erasure | Shard encoding |
| Crypto | dalek ecosystem (ed25519-dalek, x25519-dalek, chacha20poly1305) | Encryption, signatures |
| Settlement | Solana + Anchor | Credits, rewards |

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                       CLIENT                                 │
│  • Credit management                                         │
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
│  │  • One-time pubkey announcement                     │     │
│  └────────────────────────────────────────────────────┘     │
│                           │                                  │
│  ┌────────────────────────────────────────────────────┐     │
│  │                    Relay                            │     │
│  │  • Random next hop selection                        │     │
│  │  • Chain signing                                    │     │
│  │  • Destination verification                         │     │
│  │  • Request-origin caching                           │     │
│  └────────────────────────────────────────────────────┘     │
│                           │                                  │
│  ┌────────────────────────────────────────────────────┐     │
│  │                    Exit                             │     │
│  │  • Request reconstruction                           │     │
│  │  • HTTP fetch                                       │     │
│  │  • Request settlement                               │     │
│  │  • Response creation                                │     │
│  └────────────────────────────────────────────────────┘     │
└─────────────────────────────────────────────────────────────┘
                            │
┌───────────────────────────┼─────────────────────────────────┐
│                     SETTLEMENT                               │
│  ┌────────────────────────────────────────────────────┐     │
│  │                    Solana                           │     │
│  │  • Credit accounts                                  │     │
│  │  • Request settlement (PENDING)                     │     │
│  │  • Response settlement (COMPLETE)                   │     │
│  │  • Claims + rewards                                 │     │
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
    pub credit_hash: [u8; 32],
    pub user_pubkey: PublicKey,
    pub destination: PublicKey,        // Exit for request, User for response
    pub destination_addr: Address,
    pub hops_remaining: u8,
    pub chain: Vec<ChainEntry>,
    pub payload: Vec<u8>,
}

pub struct ChainEntry {
    pub pubkey: PublicKey,
    pub signature: Signature,
}
```

### Relay Cache

```rust
pub struct RelayCache {
    // Maps request_id → user who originated it
    requests: HashMap<[u8; 32], PublicKey>,
}

impl RelayCache {
    pub fn record_request(&mut self, request_id: [u8; 32], user_pubkey: PublicKey) {
        self.requests.insert(request_id, user_pubkey);
    }
    
    pub fn verify_response(&self, request_id: &[u8; 32], destination: &PublicKey) -> bool {
        match self.requests.get(request_id) {
            Some(user) => user == destination,
            None => false  // Unknown request, might be ok if we didn't see it
        }
    }
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
        
        // 2. Add my signature to chain
        let sig = self.sign(&shard);
        shard.chain.push(ChainEntry {
            pubkey: self.pubkey,
            signature: sig,
        });
        
        // 3. Decrement hops
        shard.hops_remaining -= 1;
        
        // 4. Route
        if shard.hops_remaining == 0 {
            // Send to exit
            self.send_to(shard.destination_addr, shard).await
        } else {
            // Random next hop
            let next = self.random_peer();
            self.send_to(next, shard).await
        }
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
        // Note: If we didn't see the request, we can't verify
        // But other relays will catch it
        
        // 2. Verify exit signature (first in chain)
        if !self.verify_exit_sig(&shard) {
            return Err(Error::InvalidExitSignature);
        }
        
        // 3. Add my signature
        let sig = self.sign(&shard);
        shard.chain.push(ChainEntry {
            pubkey: self.pubkey,
            signature: sig,
        });
        
        // 4. Decrement and route
        shard.hops_remaining -= 1;
        
        if shard.hops_remaining == 0 {
            // Last hop - deliver to user
            self.deliver_to_user(shard).await
        } else {
            let next = self.random_peer();
            self.send_to(next, shard).await
        }
    }
}
```

### Last Hop Delivery

```rust
impl Relay {
    pub async fn deliver_to_user(&self, shard: Shard) -> Result<()> {
        // 1. Lookup user address via DHT
        let user_addr = self.dht.lookup(shard.destination).await?;
        
        // 2. Send shard
        let ack = self.send_with_ack(user_addr, &shard).await?;
        
        // 3. Settle response on-chain
        self.settle_response(Settlement {
            request_id: shard.request_id,
            response_chain: shard.chain,
            tcp_ack: ack,
        }).await
    }
}
```

---

## Exit Logic

```rust
pub struct ExitNode {
    http_client: Client,
    encoder: Encoder,
}

impl ExitNode {
    pub async fn handle_request(&self, shards: Vec<Shard>) -> Result<()> {
        // 1. Reconstruct from 3+ shards
        let request_data = self.encoder.decode(&shards)?;
        
        // 2. Decrypt, get credit_secret
        let decrypted = self.decrypt(&request_data)?;
        let credit_secret = decrypted.credit_secret;
        let http_request = decrypted.request;
        
        // 3. Collect request chains
        let request_chains: Vec<Vec<ChainEntry>> = shards
            .iter()
            .map(|s| s.chain.clone())
            .collect();
        
        // 4. SETTLE REQUEST (Phase 1)
        self.settle_request(RequestSettlement {
            request_id: shards[0].request_id,
            credit_secret,
            user_pubkey: shards[0].user_pubkey,  // Locked for response
            request_chains,
        }).await?;
        
        // 5. Fetch from internet
        let response = self.http_client.execute(http_request).await?;
        
        // 6. Create response shards
        let response_shards = self.create_response_shards(
            &shards[0],
            &response,
        );
        
        // 7. Send response shards (random first hops)
        for shard in response_shards {
            let first_relay = self.random_peer();
            self.send_to(first_relay, shard).await?;
        }
        
        Ok(())
    }
    
    fn create_response_shards(&self, request: &Shard, response: &[u8]) -> Vec<Shard> {
        // Erasure encode response
        let encoded = self.encoder.encode(response);
        
        encoded.into_iter().enumerate().map(|(i, payload)| {
            let shard_id = hash(&[request.request_id.as_slice(), b"resp", &[i as u8]].concat());
            
            // Sign this shard
            let my_sig = self.sign(&shard_id, &request.request_id, &request.user_pubkey);
            
            Shard {
                shard_id,
                request_id: request.request_id,
                credit_hash: request.credit_hash,
                user_pubkey: request.user_pubkey,
                destination: request.user_pubkey,      // Response goes to user
                destination_addr: Address::default(),  // Resolved via DHT
                hops_remaining: request.hops_remaining, // Same hop count
                chain: vec![ChainEntry {
                    pubkey: self.pubkey,
                    signature: my_sig,
                }],
                payload,
            }
        }).collect()
    }
}
```

---

## Settlement Contracts (Solana)

### Account Structures

```rust
#[account]
pub struct Credit {
    pub credit_hash: [u8; 32],    // hash(credit_secret)
    pub amount: u64,
    pub used: u64,
    pub bump: u8,
}

#[account]
pub struct RequestRecord {
    pub request_id: [u8; 32],
    pub credit_hash: [u8; 32],
    pub user_pubkey: [u8; 32],     // Locked - response must go here
    pub status: RequestStatus,
    pub request_chains: Vec<Vec<ChainEntry>>,
    pub response_chains: Vec<Vec<ChainEntry>>,
    pub settled_at: i64,
    pub completed_at: Option<i64>,
    pub bump: u8,
}

#[derive(Clone, Copy, PartialEq)]
pub enum RequestStatus {
    Pending,    // Exit settled request
    Complete,   // Last relay settled response
    Expired,    // Timeout, credits refunded
}

#[account]
pub struct EpochClaim {
    pub node: Pubkey,
    pub epoch: u64,
    pub points: u64,
    pub withdrawn: bool,
    pub bump: u8,
}
```

### Instructions

```rust
#[program]
pub mod tunnelcraft {
    // Purchase credits
    pub fn purchase_credit(
        ctx: Context<PurchaseCredit>,
        credit_hash: [u8; 32],
        amount: u64,
    ) -> Result<()>;
    
    // Exit settles request (Phase 1)
    pub fn settle_request(
        ctx: Context<SettleRequest>,
        request_id: [u8; 32],
        credit_secret: [u8; 32],
        user_pubkey: [u8; 32],
        request_chains: Vec<Vec<ChainEntry>>,
    ) -> Result<()> {
        // Verify: hash(credit_secret) == credit_hash
        // Store: user_pubkey (locked for response)
        // Status: PENDING
    }
    
    // Last relay settles response (Phase 2)
    pub fn settle_response(
        ctx: Context<SettleResponse>,
        request_id: [u8; 32],
        response_chain: Vec<ChainEntry>,
        tcp_ack: TcpAck,
    ) -> Result<()> {
        // Verify: request exists and PENDING
        // Verify: response destination == stored user_pubkey
        // Verify: chain signatures valid
        // Status: COMPLETE
    }
    
    // Relay claims points
    pub fn claim_work(
        ctx: Context<ClaimWork>,
        request_id: [u8; 32],
    ) -> Result<()> {
        // Verify: request is COMPLETE
        // Verify: I'm in one of the chains
        // Add points based on role
    }
    
    // Withdraw epoch rewards
    pub fn withdraw(
        ctx: Context<Withdraw>,
        epoch: u64,
    ) -> Result<()>;
}
```

### Verification Logic

```rust
pub fn settle_response(
    ctx: Context<SettleResponse>,
    request_id: [u8; 32],
    response_chain: Vec<ChainEntry>,
    tcp_ack: TcpAck,
) -> Result<()> {
    let request = &mut ctx.accounts.request_record;
    
    // Must be PENDING
    require!(request.status == RequestStatus::Pending, Error::NotPending);
    
    // CRITICAL: Destination must match stored user_pubkey
    let chain_destination = extract_destination(&response_chain)?;
    require!(
        chain_destination == request.user_pubkey,
        Error::DestinationMismatch
    );
    
    // Verify chain signatures
    verify_chain(&response_chain)?;
    
    // Verify TCP ACK
    verify_ack(&tcp_ack)?;
    
    // Complete
    request.status = RequestStatus::Complete;
    request.response_chains.push(response_chain);
    request.completed_at = Some(Clock::get()?.unix_timestamp);
    
    Ok(())
}
```

---

## Points Distribution

```rust
pub fn claim_work(
    ctx: Context<ClaimWork>,
    request_id: [u8; 32],
) -> Result<()> {
    let request = &ctx.accounts.request_record;
    let claimer = &ctx.accounts.claimer;
    
    // Must be COMPLETE
    require!(request.status == RequestStatus::Complete, Error::NotComplete);
    
    let mut points = 0u64;
    
    // Check request chains
    for chain in &request.request_chains {
        if chain.iter().any(|e| e.pubkey == claimer.key()) {
            points += 1;
        }
    }
    
    // Check response chains
    for chain in &request.response_chains {
        if chain.iter().any(|e| e.pubkey == claimer.key()) {
            // First entry is exit - gets 2 points
            if chain[0].pubkey == claimer.key() {
                points += 2;  // Exit bonus for fetch work
            } else {
                points += 1;
            }
        }
    }
    
    // Add to epoch claim
    ctx.accounts.epoch_claim.points += points;
    
    Ok(())
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
│  credit_hash:    32 bytes                                  │
│  user_pubkey:    32 bytes                                  │
│  destination:    32 bytes                                  │
│  hops_remaining: 1 byte                                    │
├────────────────────────────────────────────────────────────┤
│  chain_len:      1 byte                                    │
│  chain:          chain_len × 96 bytes (32 pubkey + 64 sig) │
├────────────────────────────────────────────────────────────┤
│  payload_len:    2 bytes                                   │
│  payload:        variable                                  │
└────────────────────────────────────────────────────────────┘

Overhead (3 hops): ~6 + 161 + 1 + 288 + 2 = ~458 bytes
Payload: ~940 bytes (fits MTU)
```

---

## Crate Structure

```
tunnelcraft/
├── Cargo.toml
├── crates/
│   ├── core/              # Types, traits
│   │   ├── shard.rs
│   │   ├── chain.rs
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
│   │   ├── cache.rs       # Request-origin cache
│   │   └── verify.rs      # Destination verification
│   │
│   ├── exit/              # Exit node
│   │   ├── handler.rs
│   │   ├── http.rs
│   │   └── settle.rs
│   │
│   ├── settlement/        # Solana
│   │   ├── client.rs
│   │   └── instructions.rs
│   │
│   └── client/            # User client
│       ├── request.rs
│       └── identity.rs
│
├── contracts/             # Solana programs
│   └── programs/
│       └── tunnelcraft/
│
└── apps/
    ├── cli/
    ├── node/
    └── desktop/
```

---

## Security Properties

### Cryptographic Guarantees

```
┌─────────────────────────────────────────────────────────────┐
│                                                              │
│   PAYMENT VALID                                              │
│   Proof: hash(credit_secret) == credit_hash on-chain         │
│                                                              │
│   WORK DONE                                                  │
│   Proof: Valid chain signatures                              │
│                                                              │
│   DELIVERY COMPLETE                                          │
│   Proof: TCP ACK from user                                   │
│                                                              │
│   NO REDIRECT POSSIBLE                                       │
│   Proof: Relays verify destination == origin                 │
│   Proof: Chain verifies destination == stored user_pubkey    │
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
│                                                              │
│   Chain:                                                     │
│   • Verify credit_secret                                     │
│   • Lock user_pubkey at request settlement                   │
│   • Verify destination at response settlement                │
│                                                              │
│   No trust. Just math.                                       │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```
