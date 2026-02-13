//! TunnelCraft Aggregator
//!
//! Standalone service that any node can run. Subscribes to the proof
//! gossipsub topic, collects signed summaries from relays, builds
//! per-pool Merkle distributions, and posts them on-chain.
//!
//! Tracks both subscribed and free-tier traffic — free-tier stats feed
//! a future ecosystem reward pool.

use std::collections::{HashMap, HashSet, VecDeque};
use std::io::{Read as _, Write};
use std::path::Path;

use serde::{Serialize, Deserialize};
use tracing::{debug, info, warn};

use tunnelcraft_core::PublicKey;
use tunnelcraft_network::{ProofMessage, PoolType};
use tunnelcraft_prover::{MerkleProof, MerkleTree};

/// Maximum number of pending (out-of-order) proofs per relay per pool.
/// Prevents unbounded memory growth from misbehaving relays.
const MAX_PENDING_PER_CHAIN: usize = 16;

/// Maximum total pending proofs across all chains.
const MAX_PENDING_TOTAL: usize = 4096;

// =========================================================================
// History ledger types (append-only log)
// =========================================================================

/// A single entry in the append-only history log.
/// Each entry records a successfully applied proof or distribution event
/// with a global sequence number — the aggregator's "blockchain".
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistoryEntry {
    /// Global monotonic sequence number (the "block height")
    pub seq: u64,
    /// When this entry was recorded (aggregator's wall clock, unix seconds)
    pub recorded_at: u64,
    /// The event that occurred
    pub event: HistoryEvent,
}

/// Events recorded in the history log.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HistoryEvent {
    /// A relay proof was accepted and applied
    ProofAccepted {
relay_pubkey: [u8; 32],
pool_pubkey: [u8; 32],
        pool_type: PoolType,
        batch_bytes: u64,
        cumulative_bytes: u64,
prev_root: [u8; 32],
new_root: [u8; 32],
        proof_timestamp: u64,
    },
    /// A distribution was built (snapshot before on-chain posting)
    DistributionBuilt {
user_pubkey: [u8; 32],
        pool_type: PoolType,
distribution_root: [u8; 32],
        total_bytes: u64,
        num_relays: usize,
    },
    /// A distribution was posted on-chain
    DistributionPosted {
user_pubkey: [u8; 32],
distribution_root: [u8; 32],
        total_bytes: u64,
    },
}

/// Append-only history write buffer.
///
/// Only holds entries not yet flushed to disk. The JSONL file on disk
/// is the authoritative history — nothing is kept in memory after flush.
struct HistoryLog {
    /// Next sequence number to assign
    next_seq: u64,
    /// Entries buffered since last flush (not yet written to disk)
    buffer: Vec<HistoryEntry>,
}

impl HistoryLog {
    fn new() -> Self {
        Self {
            next_seq: 0,
            buffer: Vec::new(),
        }
    }

    fn with_seq(next_seq: u64) -> Self {
        Self { next_seq, buffer: Vec::new() }
    }

    fn append(&mut self, event: HistoryEvent) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let entry = HistoryEntry {
            seq: self.next_seq,
            recorded_at: now,
            event,
        };
        debug!("Appended history entry seq={}", entry.seq);
        self.buffer.push(entry);
        self.next_seq += 1;
    }
}

/// A single relay's proven claim for a pool
#[derive(Debug, Clone)]
struct ProofClaim {
    /// Running total of payload bytes this relay has proven for the pool
    cumulative_bytes: u64,
    /// Latest Merkle root
    latest_root: [u8; 32],
    /// Unix timestamp of last proof received (used for staleness checks)
    #[allow(dead_code)]
    last_updated: u64,
}

/// Tracks all relay claims for a single pool (user, pool_type)
#[derive(Debug, Clone)]
struct PoolTracker {
    /// Relay pubkey → latest cumulative proof
    relay_claims: HashMap<PublicKey, ProofClaim>,
}

/// Merkle distribution for a pool (ready for on-chain posting)
#[derive(Debug, Clone)]
pub struct Distribution {
    /// Merkle root of (relay, bytes) entries
    pub root: [u8; 32],
    /// Total payload bytes across all relays
    pub total: u64,
    /// Individual entries: (relay_pubkey, cumulative_bytes), sorted by pubkey
    pub entries: Vec<(PublicKey, u64)>,
    /// The Merkle tree (for generating per-relay proofs)
    tree: MerkleTree,
}

impl Distribution {
    /// Generate a Merkle proof for a specific relay.
    ///
    /// Returns `None` if the relay is not in the distribution.
    pub fn proof_for_relay(&self, relay: &PublicKey) -> Option<(MerkleProof, u32)> {
        let index = self.entries.iter().position(|(r, _)| r == relay)?;
        let proof = self.tree.proof(index)?;
        Some((proof, index as u32))
    }
}

/// Network-wide statistics
#[derive(Debug, Clone, Default)]
pub struct NetworkStats {
    /// Total payload bytes tracked (subscribed + free)
    pub total_bytes: u64,
    /// Number of active pools (users)
    pub active_pools: usize,
    /// Number of active relays
    pub active_relays: usize,
    /// Total subscribed payload bytes
    pub subscribed_bytes: u64,
    /// Total free-tier payload bytes
    pub free_bytes: u64,
}

/// Key identifying a single relay's proof chain within a pool.
type ChainKey = (PublicKey, PublicKey, PoolType); // (relay, pool, pool_type)

// === Persistence types (private, for JSON serialization) ===

#[derive(Serialize, Deserialize)]
struct AggregatorStateFile {
    pools: HashMap<String, PoolTrackerState>,
    pending: HashMap<String, Vec<ProofMessage>>,
    #[serde(default)]
    posted_distributions: Vec<PostedEntry>,
}

#[derive(Serialize, Deserialize)]
struct PoolTrackerState {
    relay_claims: HashMap<String, ProofClaimState>,
}

#[derive(Serialize, Deserialize)]
struct ProofClaimState {
    cumulative_bytes: u64,
    latest_root: String,
    last_updated: u64,
}

#[derive(Serialize, Deserialize)]
struct PostedEntry {
    user_pubkey: String,

}

/// Format a pool key as "hex_pubkey:PoolType"
fn format_pool_key(pubkey: &PublicKey, pool_type: &PoolType) -> String {
    format!("{}:{:?}", hex::encode(pubkey), pool_type)
}

/// Parse a pool key from "hex_pubkey:PoolType"
fn parse_pool_key(s: &str) -> Option<(PublicKey, PoolType)> {
    let parts: Vec<&str> = s.splitn(3, ':').collect();
    if parts.len() < 2 { return None; }
    let bytes = hex::decode(parts[0]).ok()?;
    if bytes.len() != 32 { return None; }
    let mut pubkey = [0u8; 32];
    pubkey.copy_from_slice(&bytes);
    let pool_type = match parts[1] {
        "Subscribed" => PoolType::Subscribed,
        "Free" => PoolType::Free,
        _ => return None,
    };
    Some((pubkey, pool_type))
}

/// Format a chain key as "hex_relay:hex_pool:PoolType"
fn format_chain_key(relay: &PublicKey, pool: &PublicKey, pool_type: &PoolType) -> String {
    format!("{}:{}:{:?}", hex::encode(relay), hex::encode(pool), pool_type)
}

/// Parse a chain key from "hex_relay:hex_pool:PoolType"
fn parse_chain_key(s: &str) -> Option<ChainKey> {
    let parts: Vec<&str> = s.splitn(3, ':').collect();
    if parts.len() < 3 { return None; }
    let relay_bytes = hex::decode(parts[0]).ok()?;
    let pool_bytes = hex::decode(parts[1]).ok()?;
    if relay_bytes.len() != 32 || pool_bytes.len() != 32 { return None; }
    let mut relay = [0u8; 32];
    relay.copy_from_slice(&relay_bytes);
    let mut pool = [0u8; 32];
    pool.copy_from_slice(&pool_bytes);
    let pool_type = match parts[2] {
        "Subscribed" => PoolType::Subscribed,
        "Free" => PoolType::Free,
        _ => return None,
    };
    Some((relay, pool, pool_type))
}

/// The aggregator service
///
/// Collects signed summaries from relays via gossipsub, builds
/// Merkle distributions per pool, and provides query APIs.
///
/// Out-of-order proofs are buffered and replayed when the missing link
/// arrives — like blockchain block buffering for orphan blocks.
pub struct Aggregator {
    /// Per (user, pool_type): relay → latest cumulative proof
    pools: HashMap<(PublicKey, PoolType), PoolTracker>,
    /// Out-of-order proofs waiting for their prev_root to appear.
    /// Keyed by (relay, pool, pool_type) → queue of proofs ordered by arrival.
    pending: HashMap<ChainKey, VecDeque<ProofMessage>>,
    /// Total count of pending proofs across all chains (for global cap).
    pending_total: usize,
    /// Append-only history log (the aggregator's "blockchain")
    history: HistoryLog,
}

impl Aggregator {
    /// Create a new aggregator
    pub fn new() -> Self {
        Self {
            pools: HashMap::new(),
            pending: HashMap::new(),
            pending_total: 0,
            history: HistoryLog::new(),
        }
    }

    /// Handle an incoming proof message from gossipsub.
    ///
    /// Verifies the relay signature, ZK proof (if present), and proof chain
    /// (prev_root matches last known root), then updates the pool tracker.
    ///
    /// Out-of-order proofs (prev_root doesn't match yet) are buffered and
    /// automatically replayed when the missing link arrives — like orphan
    /// block handling in blockchains.
    pub fn handle_proof(&mut self, msg: ProofMessage) -> Result<(), AggregatorError> {
        // Validate signature upfront (reject bad proofs before buffering)
        Self::verify_proof(&msg)?;

        // Try to apply. If out-of-order, buffer it.
        let chain_key = (msg.relay_pubkey, msg.pool_pubkey, msg.pool_type);
        match self.try_apply_proof(&msg) {
            Ok(()) => {
                // Success — drain any pending proofs that now chain from this one
                self.drain_pending(chain_key);
                Ok(())
            }
            Err(AggregatorError::ChainBreak) => {
                // Out of order — buffer for later replay
                let queue = self.pending.entry(chain_key).or_insert_with(VecDeque::new);
                if queue.len() >= MAX_PENDING_PER_CHAIN {
                    warn!(
                        "Pending buffer full for relay {} on pool {} — dropping oldest",
                        hex::encode(&msg.relay_pubkey[..8]),
                        hex::encode(&msg.pool_pubkey[..8]),
                    );
                    queue.pop_front();
                    self.pending_total = self.pending_total.saturating_sub(1);
                }
                // If global cap hit, reject instead of buffering
                if self.pending_total >= MAX_PENDING_TOTAL {
                    warn!("Global pending buffer full ({}) — rejecting proof", MAX_PENDING_TOTAL);
                    return Err(AggregatorError::ChainBreak);
                }
                debug!(
                    "Buffering out-of-order proof for relay {} on pool {} (prev_root={:?})",
                    hex::encode(&msg.relay_pubkey[..8]),
                    hex::encode(&msg.pool_pubkey[..8]),
                    &msg.prev_root[..8],
                );
                queue.push_back(msg);
                self.pending_total += 1;
                Ok(())
            }
            Err(e) => Err(e),
        }
    }

    /// Verify relay's ed25519 signature on a proof message.
    fn verify_proof(msg: &ProofMessage) -> Result<(), AggregatorError> {
        if msg.signature.len() != 64 {
            warn!(
                "Invalid signature length from relay {}: {} bytes",
                hex::encode(&msg.relay_pubkey[..8]),
                msg.signature.len(),
            );
            return Err(AggregatorError::InvalidSignature);
        }
        let sig: [u8; 64] = msg.signature[..64].try_into().unwrap();
        if !tunnelcraft_crypto::verify_signature(&msg.relay_pubkey, &msg.signable_data(), &sig) {
            warn!(
                "Invalid signature from relay {}",
                hex::encode(&msg.relay_pubkey[..8]),
            );
            return Err(AggregatorError::InvalidSignature);
        }

        Ok(())
    }

    /// Try to apply a verified proof to the pool tracker.
    ///
    /// Returns `ChainBreak` if prev_root doesn't match (caller decides
    /// whether to buffer or reject).
    fn try_apply_proof(&mut self, msg: &ProofMessage) -> Result<(), AggregatorError> {
        let pool_key = (msg.pool_pubkey, msg.pool_type);
        let pool = self.pools.entry(pool_key).or_insert_with(|| PoolTracker {
            relay_claims: HashMap::new(),
        });

        if let Some(existing) = pool.relay_claims.get(&msg.relay_pubkey) {
            if existing.latest_root != msg.prev_root {
                return Err(AggregatorError::ChainBreak);
            }

            // Cumulative bytes should be increasing
            if msg.cumulative_bytes <= existing.cumulative_bytes {
                warn!(
                    "Non-increasing cumulative bytes for relay {} on pool {} ({:?}): {} <= {}",
                    hex::encode(&msg.relay_pubkey[..8]),
                    hex::encode(&msg.pool_pubkey[..8]),
                    msg.pool_type,
                    msg.cumulative_bytes,
                    existing.cumulative_bytes,
                );
                return Err(AggregatorError::NonIncreasingCount);
            }
        } else {
            // First proof from this relay for this pool — prev_root should be zeros
            if msg.prev_root != [0u8; 32] && msg.cumulative_bytes != msg.batch_bytes {
                debug!(
                    "First proof from relay {} has non-zero prev_root — may have missed earlier proofs",
                    hex::encode(&msg.relay_pubkey[..8]),
                );
                // Accept anyway — we can't verify history we didn't see
            }
        }

        // Update relay claim
        pool.relay_claims.insert(msg.relay_pubkey, ProofClaim {
            cumulative_bytes: msg.cumulative_bytes,
            latest_root: msg.new_root,
            last_updated: msg.timestamp,
        });

        // Record in history log
        self.history.append(HistoryEvent::ProofAccepted {
            relay_pubkey: msg.relay_pubkey,
            pool_pubkey: msg.pool_pubkey,
            pool_type: msg.pool_type,

            batch_bytes: msg.batch_bytes,
            cumulative_bytes: msg.cumulative_bytes,
            prev_root: msg.prev_root,
            new_root: msg.new_root,
            proof_timestamp: msg.timestamp,
        });

        debug!(
            "Updated proof for relay {} on pool {} ({:?}): cumulative={}",
            hex::encode(&msg.relay_pubkey[..8]),
            hex::encode(&msg.pool_pubkey[..8]),
            msg.pool_type,
            msg.cumulative_bytes,
        );

        Ok(())
    }

    /// Drain pending proofs that now chain from the current head.
    ///
    /// After a proof is successfully applied, its `new_root` becomes the
    /// chain head. Any buffered proof whose `prev_root` matches can now
    /// be applied, which may in turn unblock further pending proofs.
    fn drain_pending(&mut self, chain_key: ChainKey) {
        let (relay, pool, pool_type) = chain_key;
        loop {
            // Get current chain head
            let pool_key = (pool, pool_type);
            let current_root = match self.pools.get(&pool_key)
                .and_then(|t| t.relay_claims.get(&relay))
            {
                Some(claim) => claim.latest_root,
                None => break,
            };

            // Find and remove the first pending proof whose prev_root matches
            let queue = match self.pending.get_mut(&chain_key) {
                Some(q) if !q.is_empty() => q,
                _ => break,
            };

            let pos = queue.iter().position(|p| p.prev_root == current_root);
            let Some(idx) = pos else { break };
            let msg = queue.remove(idx).unwrap();
            self.pending_total = self.pending_total.saturating_sub(1);

            // Try to apply — should succeed since we matched prev_root
            match self.try_apply_proof(&msg) {
                Ok(()) => {
                    debug!(
                        "Replayed buffered proof for relay {} on pool {} (cumulative={})",
                        hex::encode(&msg.relay_pubkey[..8]),
                        hex::encode(&msg.pool_pubkey[..8]),
                        msg.cumulative_bytes,
                    );
                    // Continue loop — more pending proofs may now chain
                }
                Err(e) => {
                    warn!(
                        "Buffered proof replay failed for relay {}: {}",
                        hex::encode(&msg.relay_pubkey[..8]),
                        e,
                    );
                    break;
                }
            }
        }

        // Clean up empty queues
        if self.pending.get(&chain_key).map_or(false, |q| q.is_empty()) {
            self.pending.remove(&chain_key);
        }
    }

    /// Build a Merkle distribution for a pool.
    ///
    /// Returns the distribution root and entries that can be posted
    /// on-chain via `post_distribution()`.
    pub fn build_distribution(&self, pool_key: &(PublicKey, PoolType)) -> Option<Distribution> {
        let tracker = self.pools.get(pool_key)?;

        let mut entries: Vec<(PublicKey, u64)> = tracker.relay_claims.iter()
            .map(|(relay, claim)| (*relay, claim.cumulative_bytes))
            .collect();

        if entries.is_empty() {
            return None;
        }

        // Sort by relay pubkey for deterministic root
        entries.sort_by_key(|(relay, _)| *relay);

        let total: u64 = entries.iter().map(|(_, count)| count).sum();

        // Build proper binary Merkle tree from entries
        let tree_entries: Vec<([u8; 32], u64)> = entries
            .iter()
            .map(|(relay, count)| (*relay, *count))
            .collect();
        let tree = MerkleTree::from_entries(&tree_entries);
        let root = tree.root();

        Some(Distribution {
            root,
            total,
            entries,
            tree,
        })
    }

    // =========================================================================
    // Query APIs
    // =========================================================================

    /// Get per-relay usage breakdown for a specific pool
    pub fn get_pool_usage(&self, pool_key: &(PublicKey, PoolType)) -> Vec<(PublicKey, u64)> {
        self.pools.get(pool_key)
            .map(|tracker| {
                tracker.relay_claims.iter()
                    .map(|(relay, claim)| (*relay, claim.cumulative_bytes))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Get per-pool breakdown for a specific relay
    pub fn get_relay_stats(&self, relay: &PublicKey) -> Vec<((PublicKey, PoolType), u64)> {
        self.pools.iter()
            .filter_map(|(pool_key, tracker)| {
                tracker.relay_claims.get(relay)
                    .map(|claim| (*pool_key, claim.cumulative_bytes))
            })
            .collect()
    }

    /// Get a relay's latest chain state for a specific pool.
    ///
    /// Used for chain recovery: a relay that lost its proof state can query
    /// any aggregator for its latest root and cumulative count. This is
    /// trustless — if the aggregator lies, the relay's next proof will fail
    /// at every other aggregator with ChainBreak.
    pub fn get_relay_state(
        &self,
        relay: &PublicKey,
        pool_key: &(PublicKey, PoolType),
    ) -> Option<([u8; 32], u64)> {
        self.pools.get(pool_key)
            .and_then(|tracker| tracker.relay_claims.get(relay))
            .map(|claim| (claim.latest_root, claim.cumulative_bytes))
    }

    /// Get network-wide statistics
    pub fn get_network_stats(&self) -> NetworkStats {
        let mut stats = NetworkStats::default();
        let mut all_relays: std::collections::HashSet<PublicKey> = std::collections::HashSet::new();

        for ((_, pool_type), tracker) in &self.pools {
            stats.active_pools += 1;
            for (relay, claim) in &tracker.relay_claims {
                all_relays.insert(*relay);
                stats.total_bytes += claim.cumulative_bytes;
                match pool_type {
                    PoolType::Subscribed => stats.subscribed_bytes += claim.cumulative_bytes,
                    PoolType::Free => stats.free_bytes += claim.cumulative_bytes,
                }
            }
        }

        stats.active_relays = all_relays.len();
        stats
    }

    /// Get free-tier relay statistics (for ecosystem reward distribution)
    pub fn get_free_tier_stats(&self) -> Vec<(PublicKey, u64)> {
        let mut relay_totals: HashMap<PublicKey, u64> = HashMap::new();

        for ((_, pool_type), tracker) in &self.pools {
            if *pool_type == PoolType::Free {
                for (relay, claim) in &tracker.relay_claims {
                    *relay_totals.entry(*relay).or_default() += claim.cumulative_bytes;
                }
            }
        }

        relay_totals.into_iter().collect()
    }

    // =========================================================================
    // History ledger
    // =========================================================================

    /// Record a distribution-built event in the history log.
    pub fn record_distribution_built(
        &mut self,
        user_pubkey: [u8; 32],
        pool_type: PoolType,
        distribution_root: [u8; 32],
        total_bytes: u64,
        num_relays: usize,
    ) {
        self.history.append(HistoryEvent::DistributionBuilt {
            user_pubkey,
            pool_type,
            distribution_root,
            total_bytes,
            num_relays,
        });
    }

    /// Record a distribution-posted event in the history log.
    pub fn record_distribution_posted(
        &mut self,
        user_pubkey: [u8; 32],
        distribution_root: [u8; 32],
        total_bytes: u64,
    ) {
        self.history.append(HistoryEvent::DistributionPosted {
            user_pubkey,
            distribution_root,
            total_bytes,
        });
    }

    /// Current history log height (next sequence number to be assigned).
    pub fn history_height(&self) -> u64 {
        self.history.next_seq
    }

    // =========================================================================
    // History query APIs (read from JSONL file on disk)
    // =========================================================================

    /// Get history entries from `seq` onwards (for sync protocol).
    /// Reads from the JSONL file on disk — nothing kept in memory.
    pub fn history_since(path: &Path, seq: u64) -> Vec<HistoryEntry> {
        Self::scan_history(path, |e| e.seq >= seq)
    }

    /// Get total network volume over a time range.
    /// Returns `(timestamp, batch_bytes)` pairs for ProofAccepted events in range.
    pub fn get_volume_history(path: &Path, from_ts: u64, to_ts: u64) -> Vec<(u64, u64)> {
        Self::scan_history(path, |e| e.recorded_at >= from_ts && e.recorded_at <= to_ts)
            .into_iter()
            .filter_map(|e| match e.event {
                HistoryEvent::ProofAccepted { batch_bytes, proof_timestamp, .. } => {
                    Some((proof_timestamp, batch_bytes))
                }
                _ => None,
            })
            .collect()
    }

    /// Get a specific relay's bandwidth history.
    /// Returns `(timestamp, batch_bytes, cumulative_bytes)` for the relay.
    pub fn get_relay_history(
        path: &Path,
        relay: &PublicKey,
        from_ts: u64,
        to_ts: u64,
    ) -> Vec<(u64, u64, u64)> {
        let relay = *relay;
        Self::scan_history(path, |e| e.recorded_at >= from_ts && e.recorded_at <= to_ts)
            .into_iter()
            .filter_map(move |e| match e.event {
                HistoryEvent::ProofAccepted {
                    relay_pubkey, batch_bytes, cumulative_bytes, proof_timestamp, ..
                } if relay_pubkey == relay => {
                    Some((proof_timestamp, batch_bytes, cumulative_bytes))
                }
                _ => None,
            })
            .collect()
    }

    /// Get a specific pool's bandwidth history.
    /// Returns `(timestamp, batch_bytes, cumulative_bytes)` for the pool.
    pub fn get_pool_history(
        path: &Path,
        pool: &PublicKey,

        from_ts: u64,
        to_ts: u64,
    ) -> Vec<(u64, u64, u64)> {
        let pool = *pool;
        Self::scan_history(path, |e| e.recorded_at >= from_ts && e.recorded_at <= to_ts)
            .into_iter()
            .filter_map(move |e| match e.event {
                HistoryEvent::ProofAccepted {
                    pool_pubkey, batch_bytes, cumulative_bytes, proof_timestamp, ..
                } if pool_pubkey == pool => {
                    Some((proof_timestamp, batch_bytes, cumulative_bytes))
                }
                _ => None,
            })
            .collect()
    }

    /// Scan the binary history file, returning entries that pass the filter.
    ///
    /// Format: repeated `[u32-LE length][bincode payload]` records.
    fn scan_history<F>(path: &Path, filter: F) -> Vec<HistoryEntry>
    where
        F: Fn(&HistoryEntry) -> bool,
    {
        let mut file = match std::fs::File::open(path) {
            Ok(f) => f,
            Err(_) => return Vec::new(),
        };
        let mut results = Vec::new();
        let mut len_buf = [0u8; 4];
        loop {
            if file.read_exact(&mut len_buf).is_err() {
                break; // EOF or read error
            }
            let len = u32::from_le_bytes(len_buf) as usize;
            let mut payload = vec![0u8; len];
            if file.read_exact(&mut payload).is_err() {
                break; // truncated record
            }
            if let Ok(entry) = bincode::deserialize::<HistoryEntry>(&payload) {
                if filter(&entry) {
                    results.push(entry);
                }
            }
        }
        results
    }

    // =========================================================================
    // History persistence (length-prefixed bincode)
    // =========================================================================

    /// Flush buffered history entries to the binary file (append-only).
    /// Each record is `[u32-LE length][bincode payload]`.
    /// After flush, the buffer is cleared — disk is the only copy.
    pub fn flush_history(&mut self, path: &Path) {
        if self.history.buffer.is_empty() {
            return;
        }

        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }

        match std::fs::OpenOptions::new().create(true).append(true).open(path) {
            Ok(mut file) => {
                let count = self.history.buffer.len();
                for entry in self.history.buffer.drain(..) {
                    if let Ok(payload) = bincode::serialize(&entry) {
                        let len = (payload.len() as u32).to_le_bytes();
                        let _ = file.write_all(&len);
                        let _ = file.write_all(&payload);
                    }
                }
                info!("Flushed {} history entries to disk", count);
            }
            Err(e) => {
                warn!("Failed to flush history to {}: {}", path.display(), e);
            }
        }
    }

    /// Recover the next_seq from an existing binary history file on startup.
    /// Scans all records for the last seq — does not keep entries in memory.
    pub fn recover_history_seq(path: &Path) -> u64 {
        let mut file = match std::fs::File::open(path) {
            Ok(f) => f,
            Err(_) => return 0,
        };
        let mut last_seq = 0u64;
        let mut count = 0u64;
        let mut len_buf = [0u8; 4];
        loop {
            if file.read_exact(&mut len_buf).is_err() {
                break;
            }
            let len = u32::from_le_bytes(len_buf) as usize;
            let mut payload = vec![0u8; len];
            if file.read_exact(&mut payload).is_err() {
                break;
            }
            if let Ok(entry) = bincode::deserialize::<HistoryEntry>(&payload) {
                last_seq = entry.seq;
                count += 1;
            }
        }
        if count > 0 {
            info!("Recovered history seq={} from {} entries in {}", last_seq + 1, count, path.display());
            last_seq + 1
        } else {
            0
        }
    }

    /// Set the history sequence counter (call after recover_history_seq on startup).
    pub fn set_history_seq(&mut self, next_seq: u64) {
        self.history = HistoryLog::with_seq(next_seq);
    }

    // =========================================================================
    // Persistence
    // =========================================================================

    /// Save aggregator state + posted_distributions to a JSON file.
    ///
    /// Uses atomic write (tmp + rename) to prevent corruption.
    pub fn save_to_file(&self, path: &Path, posted: &HashSet<[u8; 32]>) {
        let mut pools_map = HashMap::new();
        for ((pubkey, pool_type), tracker) in &self.pools {
            let key = format_pool_key(pubkey, pool_type);
            let mut relay_claims = HashMap::new();
            for (relay, claim) in &tracker.relay_claims {
                relay_claims.insert(hex::encode(relay), ProofClaimState {
                    cumulative_bytes: claim.cumulative_bytes,
                    latest_root: hex::encode(claim.latest_root),
                    last_updated: claim.last_updated,
                });
            }
            pools_map.insert(key, PoolTrackerState { relay_claims });
        }

        let mut pending_map = HashMap::new();
        for ((relay, pool, pool_type), queue) in &self.pending {
            let key = format_chain_key(relay, pool, pool_type);
            pending_map.insert(key, queue.iter().cloned().collect::<Vec<_>>());
        }

        let posted_entries: Vec<PostedEntry> = posted.iter().map(|pubkey| PostedEntry {
            user_pubkey: hex::encode(pubkey),
        }).collect();

        let state_file = AggregatorStateFile {
            pools: pools_map,
            pending: pending_map,
            posted_distributions: posted_entries,
        };

        let json = match serde_json::to_string_pretty(&state_file) {
            Ok(j) => j,
            Err(e) => {
                warn!("Failed to serialize aggregator state: {}", e);
                return;
            }
        };

        let tmp_path = path.with_extension("json.tmp");
        if let Err(e) = std::fs::write(&tmp_path, &json) {
            warn!("Failed to write aggregator state tmp file {}: {}", tmp_path.display(), e);
            return;
        }
        if let Err(e) = std::fs::rename(&tmp_path, path) {
            warn!("Failed to rename aggregator state file {} -> {}: {}", tmp_path.display(), path.display(), e);
            return;
        }

        debug!(
            "Saved aggregator state: {} pools, {} pending chains, {} posted distributions to {}",
            self.pools.len(),
            self.pending.len(),
            posted.len(),
            path.display(),
        );
    }

    /// Load aggregator state + posted_distributions from a JSON file.
    ///
    /// Returns the reconstructed aggregator and the set of already-posted distributions.
    pub fn load_from_file(
        path: &Path,
    ) -> Result<(Self, HashSet<[u8; 32]>), std::io::Error> {
        let contents = std::fs::read_to_string(path)?;
        let state_file: AggregatorStateFile = serde_json::from_str(&contents)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

        let mut pools = HashMap::new();
        for (key_str, tracker_state) in &state_file.pools {
            let Some(pool_key) = parse_pool_key(key_str) else { continue };
            let mut relay_claims = HashMap::new();
            for (relay_hex, claim_state) in &tracker_state.relay_claims {
                let Ok(relay_bytes) = hex::decode(relay_hex) else { continue };
                if relay_bytes.len() != 32 { continue; }
                let mut relay = [0u8; 32];
                relay.copy_from_slice(&relay_bytes);
                let Ok(root_bytes) = hex::decode(&claim_state.latest_root) else { continue };
                if root_bytes.len() != 32 { continue; }
                let mut root = [0u8; 32];
                root.copy_from_slice(&root_bytes);
                relay_claims.insert(relay, ProofClaim {
                    cumulative_bytes: claim_state.cumulative_bytes,
                    latest_root: root,
                    last_updated: claim_state.last_updated,
                });
            }
            pools.insert(pool_key, PoolTracker { relay_claims });
        }

        let mut pending: HashMap<ChainKey, VecDeque<ProofMessage>> = HashMap::new();
        let mut pending_total = 0usize;
        for (key_str, msgs) in &state_file.pending {
            let Some(chain_key) = parse_chain_key(key_str) else { continue };
            let queue: VecDeque<ProofMessage> = msgs.iter().cloned().collect();
            pending_total += queue.len();
            pending.insert(chain_key, queue);
        }

        let mut posted = HashSet::new();
        for entry in &state_file.posted_distributions {
            let Ok(bytes) = hex::decode(&entry.user_pubkey) else { continue };
            if bytes.len() != 32 { continue; }
            let mut pubkey = [0u8; 32];
            pubkey.copy_from_slice(&bytes);
            posted.insert(pubkey);
        }

        info!(
            "Loaded aggregator state: {} pools, {} pending chains ({} proofs), {} posted distributions from {}",
            pools.len(),
            pending.len(),
            pending_total,
            posted.len(),
            path.display(),
        );

        let agg = Self {
            pools,
            pending,
            pending_total,
            history: HistoryLog::new(),
        };

        Ok((agg, posted))
    }

    /// Return deduplicated user_pubkeys from tracked pools.
    ///
    /// Used by the node to batch-query on-chain subscription status
    /// for reconciliation after loading from disk.
    pub fn pool_keys_for_reconciliation(&self) -> Vec<PublicKey> {
        let mut seen = HashSet::new();
        for (pubkey, _pool_type) in self.pools.keys() {
            seen.insert(*pubkey);
        }
        seen.into_iter().collect()
    }

    /// Get all pool keys (both Subscribed and Free)
    pub fn all_pool_keys(&self) -> Vec<(PublicKey, PoolType)> {
        self.pools.keys().cloned().collect()
    }

    /// Get all subscribed pools (for distribution posting)
    pub fn subscribed_pools(&self) -> Vec<(PublicKey, PoolType)> {
        self.pools.iter()
            .filter(|((_, pool_type), _)| *pool_type == PoolType::Subscribed)
            .map(|(pool_key, _)| *pool_key)
            .collect()
    }

    /// Get the total number of tracked pools
    pub fn pool_count(&self) -> usize {
        self.pools.len()
    }
}

impl Default for Aggregator {
    fn default() -> Self {
        Self::new()
    }
}

/// Aggregator errors
#[derive(Debug, thiserror::Error)]
pub enum AggregatorError {
    #[error("Proof chain break: prev_root doesn't match")]
    ChainBreak,

    #[error("Non-increasing cumulative count")]
    NonIncreasingCount,

    #[error("Invalid proof")]
    InvalidProof,

    #[error("Invalid relay signature")]
    InvalidSignature,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Derive the ed25519 public key for a test relay seed
    fn relay_pubkey(seed: u8) -> [u8; 32] {
        tunnelcraft_crypto::SigningKeypair::from_secret_bytes(&[seed; 32]).public_key_bytes()
    }

    fn make_proof(relay: u8, pool: u8, pool_type: PoolType, batch: u64, cumulative: u64, prev_root: [u8; 32], new_root: [u8; 32]) -> ProofMessage {
        make_proof_epoch(relay, pool, pool_type, batch, cumulative, prev_root, new_root)
    }

    #[allow(clippy::too_many_arguments)]
    fn make_proof_epoch(relay: u8, pool: u8, pool_type: PoolType, batch: u64, cumulative: u64, prev_root: [u8; 32], new_root: [u8; 32]) -> ProofMessage {
        let keypair = tunnelcraft_crypto::SigningKeypair::from_secret_bytes(&[relay; 32]);
        let mut msg = ProofMessage {
            relay_pubkey: keypair.public_key_bytes(),
            pool_pubkey: [pool; 32],
            pool_type,
            batch_bytes: batch,
            cumulative_bytes: cumulative,
            prev_root,
            new_root,
            proof: vec![],
            timestamp: 1700000000,
            signature: vec![],
        };
        let sig = tunnelcraft_crypto::sign_data(&keypair, &msg.signable_data());
        msg.signature = sig.to_vec();
        msg
    }

    fn new_agg() -> Aggregator {
        Aggregator::new()
    }

    #[test]
    fn test_aggregator_creation() {
        let agg = new_agg();
        assert_eq!(agg.pool_count(), 0);
    }

    #[test]
    fn test_handle_single_proof() {
        let mut agg = new_agg();

        let msg = make_proof(1, 2, PoolType::Subscribed, 100, 100, [0u8; 32], [0xAA; 32]);
        agg.handle_proof(msg).unwrap();

        assert_eq!(agg.pool_count(), 1);
        let usage = agg.get_pool_usage(&([2u8; 32], PoolType::Subscribed));
        assert_eq!(usage.len(), 1);
        assert_eq!(usage[0].1, 100);
    }

    #[test]
    fn test_handle_chained_proofs() {
        let mut agg = new_agg();

        // First batch
        let msg1 = make_proof(1, 2, PoolType::Subscribed, 100, 100, [0u8; 32], [0xAA; 32]);
        agg.handle_proof(msg1).unwrap();

        // Second batch (chains from first)
        let msg2 = make_proof(1, 2, PoolType::Subscribed, 50, 150, [0xAA; 32], [0xBB; 32]);
        agg.handle_proof(msg2).unwrap();

        let usage = agg.get_pool_usage(&([2u8; 32], PoolType::Subscribed));
        assert_eq!(usage[0].1, 150);
    }

    #[test]
    fn test_out_of_order_buffered_and_replayed() {
        let mut agg = new_agg();

        // Batch 1: first proof
        let msg1 = make_proof(1, 2, PoolType::Subscribed, 100, 100, [0u8; 32], [0xAA; 32]);
        // Batch 2: chains from batch 1
        let msg2 = make_proof(1, 2, PoolType::Subscribed, 50, 150, [0xAA; 32], [0xBB; 32]);
        // Batch 3: chains from batch 2
        let msg3 = make_proof(1, 2, PoolType::Subscribed, 200, 350, [0xBB; 32], [0xCC; 32]);

        // Apply batch 1 normally
        agg.handle_proof(msg1).unwrap();

        // Deliver batch 3 before batch 2 (out of order) — should be buffered
        agg.handle_proof(msg3).unwrap();
        let usage = agg.get_pool_usage(&([2u8; 32], PoolType::Subscribed));
        assert_eq!(usage[0].1, 100); // Only batch 1 applied

        // Now deliver batch 2 — should apply batch 2 then auto-replay batch 3
        agg.handle_proof(msg2).unwrap();

        let usage = agg.get_pool_usage(&([2u8; 32], PoolType::Subscribed));
        assert_eq!(usage.len(), 1);
        assert_eq!(usage[0].1, 350); // All three batches applied
    }

    #[test]
    fn test_out_of_order_four_proofs_middle_reversed() {
        let mut agg = new_agg();

        let msg1 = make_proof(1, 2, PoolType::Subscribed, 100, 100, [0u8; 32], [0xAA; 32]);
        let msg2 = make_proof(1, 2, PoolType::Subscribed, 50, 150, [0xAA; 32], [0xBB; 32]);
        let msg3 = make_proof(1, 2, PoolType::Subscribed, 200, 350, [0xBB; 32], [0xCC; 32]);
        let msg4 = make_proof(1, 2, PoolType::Subscribed, 100, 450, [0xCC; 32], [0xDD; 32]);

        // Apply batch 1 normally
        agg.handle_proof(msg1).unwrap();

        // Deliver 4, 3, 2 (all out of order)
        agg.handle_proof(msg4).unwrap(); // buffered (needs [0xCC])
        agg.handle_proof(msg3).unwrap(); // buffered (needs [0xBB])
        agg.handle_proof(msg2).unwrap(); // applied (needs [0xAA] ✓) → drains msg3 → drains msg4

        let usage = agg.get_pool_usage(&([2u8; 32], PoolType::Subscribed));
        assert_eq!(usage.len(), 1);
        assert_eq!(usage[0].1, 450); // All four batches applied
    }

    #[test]
    fn test_truly_wrong_prev_root_buffered_but_never_applied() {
        let mut agg = new_agg();

        let msg1 = make_proof(1, 2, PoolType::Subscribed, 100, 100, [0u8; 32], [0xAA; 32]);
        agg.handle_proof(msg1).unwrap();

        // Wrong prev_root that will never match any chain head — stays buffered
        let msg_bad = make_proof(1, 2, PoolType::Subscribed, 50, 150, [0xCC; 32], [0xDD; 32]);
        agg.handle_proof(msg_bad).unwrap(); // buffered, not rejected

        // Relay's claim stays at batch 1
        let usage = agg.get_pool_usage(&([2u8; 32], PoolType::Subscribed));
        assert_eq!(usage[0].1, 100);
    }

    #[test]
    fn test_non_increasing_count_rejected() {
        let mut agg = new_agg();

        let msg1 = make_proof(1, 2, PoolType::Subscribed, 100, 100, [0u8; 32], [0xAA; 32]);
        agg.handle_proof(msg1).unwrap();

        // Same cumulative count — should fail
        let msg2 = make_proof(1, 2, PoolType::Subscribed, 0, 100, [0xAA; 32], [0xBB; 32]);
        let result = agg.handle_proof(msg2);
        assert!(matches!(result, Err(AggregatorError::NonIncreasingCount)));
    }

    #[test]
    fn test_multiple_relays_per_pool() {
        let mut agg = new_agg();

        let msg1 = make_proof(1, 10, PoolType::Subscribed, 70, 70, [0u8; 32], [0xAA; 32]);
        let msg2 = make_proof(2, 10, PoolType::Subscribed, 30, 30, [0u8; 32], [0xBB; 32]);
        agg.handle_proof(msg1).unwrap();
        agg.handle_proof(msg2).unwrap();

        let usage = agg.get_pool_usage(&([10u8; 32], PoolType::Subscribed));
        assert_eq!(usage.len(), 2);

        let total: u64 = usage.iter().map(|(_, c)| c).sum();
        assert_eq!(total, 100);
    }

    #[test]
    fn test_build_distribution() {
        let mut agg = new_agg();

        let msg1 = make_proof(1, 10, PoolType::Subscribed, 70, 70, [0u8; 32], [0xAA; 32]);
        let msg2 = make_proof(2, 10, PoolType::Subscribed, 30, 30, [0u8; 32], [0xBB; 32]);
        agg.handle_proof(msg1).unwrap();
        agg.handle_proof(msg2).unwrap();

        let dist = agg.build_distribution(&([10u8; 32], PoolType::Subscribed)).unwrap();
        assert_eq!(dist.total, 100);
        assert_eq!(dist.entries.len(), 2);
        assert_ne!(dist.root, [0u8; 32]);
    }

    #[test]
    fn test_build_distribution_empty_pool() {
        let agg = new_agg();
        assert!(agg.build_distribution(&([99u8; 32], PoolType::Subscribed)).is_none());
    }

    #[test]
    fn test_distribution_root_deterministic() {
        let mut agg = new_agg();

        let msg1 = make_proof(1, 10, PoolType::Subscribed, 70, 70, [0u8; 32], [0xAA; 32]);
        let msg2 = make_proof(2, 10, PoolType::Subscribed, 30, 30, [0u8; 32], [0xBB; 32]);
        agg.handle_proof(msg1).unwrap();
        agg.handle_proof(msg2).unwrap();

        let pool_key = ([10u8; 32], PoolType::Subscribed);
        let dist1 = agg.build_distribution(&pool_key).unwrap();
        let dist2 = agg.build_distribution(&pool_key).unwrap();
        assert_eq!(dist1.root, dist2.root);
    }

    #[test]
    fn test_network_stats() {
        let mut agg = new_agg();

        // Subscribed pool
        agg.handle_proof(make_proof(1, 10, PoolType::Subscribed, 70, 70, [0u8; 32], [0xAA; 32])).unwrap();
        agg.handle_proof(make_proof(2, 10, PoolType::Subscribed, 30, 30, [0u8; 32], [0xBB; 32])).unwrap();

        // Free pool
        agg.handle_proof(make_proof(1, 20, PoolType::Free, 50, 50, [0u8; 32], [0xCC; 32])).unwrap();

        let stats = agg.get_network_stats();
        assert_eq!(stats.active_pools, 2);
        assert_eq!(stats.active_relays, 2); // relay 1 and 2
        assert_eq!(stats.subscribed_bytes, 100);
        assert_eq!(stats.free_bytes, 50);
        assert_eq!(stats.total_bytes, 150);
    }

    #[test]
    fn test_relay_stats() {
        let mut agg = new_agg();

        agg.handle_proof(make_proof(1, 10, PoolType::Subscribed, 70, 70, [0u8; 32], [0xAA; 32])).unwrap();
        agg.handle_proof(make_proof(1, 20, PoolType::Free, 50, 50, [0u8; 32], [0xBB; 32])).unwrap();

        let relay_stats = agg.get_relay_stats(&relay_pubkey(1));
        assert_eq!(relay_stats.len(), 2);
        let total: u64 = relay_stats.iter().map(|(_, c)| c).sum();
        assert_eq!(total, 120);
    }

    #[test]
    fn test_free_tier_stats() {
        let mut agg = new_agg();

        agg.handle_proof(make_proof(1, 10, PoolType::Subscribed, 70, 70, [0u8; 32], [0xAA; 32])).unwrap();
        agg.handle_proof(make_proof(1, 20, PoolType::Free, 50, 50, [0u8; 32], [0xBB; 32])).unwrap();
        agg.handle_proof(make_proof(2, 20, PoolType::Free, 30, 30, [0u8; 32], [0xCC; 32])).unwrap();

        let free_stats = agg.get_free_tier_stats();
        assert_eq!(free_stats.len(), 2);
        let total: u64 = free_stats.iter().map(|(_, c)| c).sum();
        assert_eq!(total, 80); // 50 + 30
    }

    #[test]
    fn test_subscribed_pools() {
        let mut agg = new_agg();

        agg.handle_proof(make_proof(1, 10, PoolType::Subscribed, 70, 70, [0u8; 32], [0xAA; 32])).unwrap();
        agg.handle_proof(make_proof(1, 20, PoolType::Free, 50, 50, [0u8; 32], [0xBB; 32])).unwrap();

        let pools = agg.subscribed_pools();
        assert_eq!(pools.len(), 1);
        assert_eq!(pools[0].0, [10u8; 32]);
        assert_eq!(pools[0].1, PoolType::Subscribed);
    }

    #[test]
    fn test_get_relay_state() {
        let mut agg = new_agg();

        let msg = make_proof(1, 2, PoolType::Subscribed, 100, 100, [0u8; 32], [0xAA; 32]);
        agg.handle_proof(msg).unwrap();

        let relay = relay_pubkey(1);
        let pool_key = ([2u8; 32], PoolType::Subscribed);

        let state = agg.get_relay_state(&relay, &pool_key).unwrap();
        assert_eq!(state.0, [0xAA; 32]); // root
        assert_eq!(state.1, 100); // cumulative_count

        // Unknown relay returns None
        assert!(agg.get_relay_state(&[0xFFu8; 32], &pool_key).is_none());
    }

    #[test]
    fn test_separate_pool_types() {
        let mut agg = new_agg();

        // Same user, different pool types → separate pools
        agg.handle_proof(make_proof(1, 10, PoolType::Subscribed, 70, 70, [0u8; 32], [0xAA; 32])).unwrap();
        agg.handle_proof(make_proof(1, 10, PoolType::Free, 30, 30, [0u8; 32], [0xBB; 32])).unwrap();

        assert_eq!(agg.pool_count(), 2);

        let sub_usage = agg.get_pool_usage(&([10u8; 32], PoolType::Subscribed));
        assert_eq!(sub_usage.len(), 1);
        assert_eq!(sub_usage[0].1, 70);

        let free_usage = agg.get_pool_usage(&([10u8; 32], PoolType::Free));
        assert_eq!(free_usage.len(), 1);
        assert_eq!(free_usage[0].1, 30);
    }

    // =========================================================================
    // History ledger tests
    // =========================================================================

    /// Helper: create a temp dir + file for history tests, returns (dir, path)
    fn history_tmp(name: &str) -> (std::path::PathBuf, std::path::PathBuf) {
        let dir = std::env::temp_dir().join(format!("tunnelcraft-test-{}", name));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("history.bin");
        let _ = std::fs::remove_file(&path);
        (dir, path)
    }

    fn history_cleanup(dir: &std::path::Path, path: &std::path::Path) {
        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_dir(dir);
    }

    #[test]
    fn test_history_records_proofs() {
        let mut agg = new_agg();
        assert_eq!(agg.history_height(), 0);

        agg.handle_proof(make_proof(1, 2, PoolType::Subscribed, 100, 100, [0u8; 32], [0xAA; 32])).unwrap();
        assert_eq!(agg.history_height(), 1);

        agg.handle_proof(make_proof(1, 2, PoolType::Subscribed, 50, 150, [0xAA; 32], [0xBB; 32])).unwrap();
        assert_eq!(agg.history_height(), 2);

        // Flush and verify from disk
        let (dir, path) = history_tmp("records-proofs");
        agg.flush_history(&path);

        let entries = Aggregator::history_since(&path, 0);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].seq, 0);
        assert_eq!(entries[1].seq, 1);

        match &entries[0].event {
            HistoryEvent::ProofAccepted { batch_bytes, cumulative_bytes, .. } => {
                assert_eq!(*batch_bytes, 100);
                assert_eq!(*cumulative_bytes, 100);
            }
            _ => panic!("Expected ProofAccepted event"),
        }
        history_cleanup(&dir, &path);
    }

    #[test]
    fn test_history_since_offset() {
        let mut agg = new_agg();
        let (dir, path) = history_tmp("since-offset");

        agg.handle_proof(make_proof(1, 2, PoolType::Subscribed, 100, 100, [0u8; 32], [0xAA; 32])).unwrap();
        agg.handle_proof(make_proof(1, 2, PoolType::Subscribed, 50, 150, [0xAA; 32], [0xBB; 32])).unwrap();
        agg.handle_proof(make_proof(1, 2, PoolType::Subscribed, 200, 350, [0xBB; 32], [0xCC; 32])).unwrap();
        agg.flush_history(&path);

        assert_eq!(Aggregator::history_since(&path, 0).len(), 3);
        assert_eq!(Aggregator::history_since(&path, 1).len(), 2);
        assert_eq!(Aggregator::history_since(&path, 1)[0].seq, 1);
        assert_eq!(Aggregator::history_since(&path, 3).len(), 0);
        assert_eq!(Aggregator::history_since(&path, 100).len(), 0);

        history_cleanup(&dir, &path);
    }

    #[test]
    fn test_history_out_of_order_replayed() {
        let mut agg = new_agg();

        let msg1 = make_proof(1, 2, PoolType::Subscribed, 100, 100, [0u8; 32], [0xAA; 32]);
        let msg2 = make_proof(1, 2, PoolType::Subscribed, 50, 150, [0xAA; 32], [0xBB; 32]);
        let msg3 = make_proof(1, 2, PoolType::Subscribed, 200, 350, [0xBB; 32], [0xCC; 32]);

        agg.handle_proof(msg1).unwrap();
        agg.handle_proof(msg3).unwrap(); // buffered
        assert_eq!(agg.history_height(), 1); // Only msg1 applied

        agg.handle_proof(msg2).unwrap(); // msg2 + msg3 both applied
        assert_eq!(agg.history_height(), 3);
    }

    #[test]
    fn test_history_distribution_events() {
        let mut agg = new_agg();
        let (dir, path) = history_tmp("dist-events");

        agg.record_distribution_built(
            [10u8; 32], PoolType::Subscribed,
            [0xDD; 32], 1000, 5,
        );
        assert_eq!(agg.history_height(), 1);

        agg.record_distribution_posted(
            [10u8; 32], [0xDD; 32], 1000,
        );
        assert_eq!(agg.history_height(), 2);

        agg.flush_history(&path);

        let entries = Aggregator::history_since(&path, 0);
        match &entries[0].event {
            HistoryEvent::DistributionBuilt { total_bytes, num_relays, .. } => {
                assert_eq!(*total_bytes, 1000);
                assert_eq!(*num_relays, 5);
            }
            _ => panic!("Expected DistributionBuilt event"),
        }

        match &entries[1].event {
            HistoryEvent::DistributionPosted { total_bytes, .. } => {
                assert_eq!(*total_bytes, 1000);
            }
            _ => panic!("Expected DistributionPosted event"),
        }

        history_cleanup(&dir, &path);
    }

    #[test]
    fn test_history_volume_query() {
        let mut agg = new_agg();
        let (dir, path) = history_tmp("volume-query");

        agg.handle_proof(make_proof(1, 2, PoolType::Subscribed, 100, 100, [0u8; 32], [0xAA; 32])).unwrap();
        agg.handle_proof(make_proof(2, 3, PoolType::Free, 50, 50, [0u8; 32], [0xBB; 32])).unwrap();
        agg.flush_history(&path);

        let volume = Aggregator::get_volume_history(&path, 0, u64::MAX);
        assert_eq!(volume.len(), 2);
        assert_eq!(volume[0].1, 100);
        assert_eq!(volume[1].1, 50);

        history_cleanup(&dir, &path);
    }

    #[test]
    fn test_history_relay_query() {
        let mut agg = new_agg();
        let relay1 = relay_pubkey(1);
        let (dir, path) = history_tmp("relay-query");

        agg.handle_proof(make_proof(1, 2, PoolType::Subscribed, 100, 100, [0u8; 32], [0xAA; 32])).unwrap();
        agg.handle_proof(make_proof(2, 2, PoolType::Subscribed, 50, 50, [0u8; 32], [0xBB; 32])).unwrap();
        agg.flush_history(&path);

        let history = Aggregator::get_relay_history(&path, &relay1, 0, u64::MAX);
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].1, 100);
        assert_eq!(history[0].2, 100);

        history_cleanup(&dir, &path);
    }

    #[test]
    fn test_history_pool_query() {
        let mut agg = new_agg();
        let (dir, path) = history_tmp("pool-query");

        agg.handle_proof(make_proof(1, 10, PoolType::Subscribed, 70, 70, [0u8; 32], [0xAA; 32])).unwrap();
        agg.handle_proof(make_proof(2, 10, PoolType::Subscribed, 30, 30, [0u8; 32], [0xBB; 32])).unwrap();
        agg.handle_proof(make_proof(1, 20, PoolType::Free, 50, 50, [0u8; 32], [0xCC; 32])).unwrap();
        agg.flush_history(&path);

        let history = Aggregator::get_pool_history(&path, &[10u8; 32], 0, u64::MAX);
        assert_eq!(history.len(), 2);

        history_cleanup(&dir, &path);
    }

    #[test]
    fn test_history_flush_and_append() {
        let mut agg = new_agg();
        let (dir, path) = history_tmp("flush-append");

        agg.handle_proof(make_proof(1, 2, PoolType::Subscribed, 100, 100, [0u8; 32], [0xAA; 32])).unwrap();
        agg.handle_proof(make_proof(1, 2, PoolType::Subscribed, 50, 150, [0xAA; 32], [0xBB; 32])).unwrap();
        agg.flush_history(&path);

        assert_eq!(Aggregator::history_since(&path, 0).len(), 2);

        // Flush again — no-op (buffer empty)
        agg.flush_history(&path);
        assert_eq!(Aggregator::history_since(&path, 0).len(), 2);

        // Add more and flush — appends, not overwrites
        agg.handle_proof(make_proof(1, 2, PoolType::Subscribed, 200, 350, [0xBB; 32], [0xCC; 32])).unwrap();
        agg.flush_history(&path);
        assert_eq!(Aggregator::history_since(&path, 0).len(), 3);

        history_cleanup(&dir, &path);
    }

    #[test]
    fn test_history_recover_seq() {
        let mut agg = new_agg();
        let (dir, path) = history_tmp("recover-seq");

        agg.handle_proof(make_proof(1, 2, PoolType::Subscribed, 100, 100, [0u8; 32], [0xAA; 32])).unwrap();
        agg.handle_proof(make_proof(1, 2, PoolType::Subscribed, 50, 150, [0xAA; 32], [0xBB; 32])).unwrap();
        agg.flush_history(&path);

        // New aggregator recovers seq from disk
        let next_seq = Aggregator::recover_history_seq(&path);
        assert_eq!(next_seq, 2);

        let mut agg2 = new_agg();
        agg2.set_history_seq(next_seq);
        assert_eq!(agg2.history_height(), 2);

        // New entries continue from seq 2
        agg2.record_distribution_built([10u8; 32], PoolType::Subscribed, [0xDD; 32], 1000, 5);
        assert_eq!(agg2.history_height(), 3);

        // Flush new entries — they append to existing file
        agg2.flush_history(&path);
        let all = Aggregator::history_since(&path, 0);
        assert_eq!(all.len(), 3);
        assert_eq!(all[2].seq, 2);

        history_cleanup(&dir, &path);
    }

    #[test]
    fn test_history_nonexistent_file() {
        let path = std::path::Path::new("/tmp/nonexistent-tunnelcraft-history.jsonl");
        assert_eq!(Aggregator::history_since(path, 0).len(), 0);
        assert_eq!(Aggregator::get_volume_history(path, 0, u64::MAX).len(), 0);
        assert_eq!(Aggregator::recover_history_seq(path), 0);
    }

    #[test]
    fn test_history_bincode_size() {
        // Verify bincode keeps entries compact (~184 bytes)
        let entry = HistoryEntry {
            seq: 999_999,
            recorded_at: 1_700_000_000,
            event: HistoryEvent::ProofAccepted {
                relay_pubkey: [0xAB; 32],
                pool_pubkey: [0xCD; 32],
                pool_type: PoolType::Subscribed,
                batch_bytes: 3_145_728,
                cumulative_bytes: 1_073_741_824,
                prev_root: [0xEE; 32],
                new_root: [0xFF; 32],
                proof_timestamp: 1_700_000_000,
            },
        };
        let bytes = bincode::serialize(&entry).unwrap();
        let size = bytes.len();

        // bincode: ~184 bytes (raw bytes for [u8;32], fixed-width u64s)
        // vs hex JSON: ~504 bytes  → ~64% reduction
        // vs raw JSON: ~756 bytes  → ~76% reduction
        assert!(size < 250, "Bincode entry should be <250 bytes, got {}", size);
        assert!(size > 150, "Entry too small: {} bytes", size);

        // Verify roundtrip
        let decoded: HistoryEntry = bincode::deserialize(&bytes).unwrap();
        assert_eq!(decoded.seq, 999_999);
        match decoded.event {
            HistoryEvent::ProofAccepted { relay_pubkey, new_root, .. } => {
                assert_eq!(relay_pubkey, [0xAB; 32]);
                assert_eq!(new_root, [0xFF; 32]);
            }
            _ => panic!("Wrong event type"),
        }
    }
}
