//! TunnelCraft Aggregator
//!
//! Standalone service that any node can run. Subscribes to the proof
//! gossipsub topic, collects ZK-proven summaries from relays, builds
//! per-pool Merkle distributions, and posts them on-chain.
//!
//! Tracks both subscribed and free-tier traffic — free-tier stats feed
//! a future ecosystem reward pool.

use std::collections::HashMap;

use tracing::{debug, warn};

use tunnelcraft_core::PublicKey;
use tunnelcraft_network::{ProofMessage, PoolType};
use tunnelcraft_prover::{MerkleProof, MerkleTree, Prover, StubProver};

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

/// The aggregator service
///
/// Collects ZK-proven summaries from relays via gossipsub, builds
/// Merkle distributions per pool per epoch, and provides query APIs.
pub struct Aggregator {
    /// Per (user, pool_type, epoch): relay → latest cumulative proof
    pools: HashMap<(PublicKey, PoolType, u64), PoolTracker>,
    /// Pluggable prover for ZK proof verification
    prover: Box<dyn Prover>,
}

impl Aggregator {
    /// Create a new aggregator with a specific prover
    pub fn new(prover: Box<dyn Prover>) -> Self {
        Self {
            pools: HashMap::new(),
            prover,
        }
    }

    /// Handle an incoming proof message from gossipsub.
    ///
    /// Verifies the relay signature, ZK proof (if present), and proof chain
    /// (prev_root matches last known root), then updates the pool tracker.
    pub fn handle_proof(&mut self, msg: ProofMessage) -> Result<(), AggregatorError> {
        // 1. Verify relay's ed25519 signature
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

        // 2. Verify ZK proof if present
        if !msg.proof.is_empty() {
            match self.prover.verify(&msg.new_root, &msg.proof, msg.batch_bytes) {
                Ok(true) => {}
                Ok(false) => {
                    warn!(
                        "Invalid ZK proof from relay {} on pool {}",
                        hex::encode(&msg.relay_pubkey[..8]),
                        hex::encode(&msg.pool_pubkey[..8]),
                    );
                    return Err(AggregatorError::InvalidProof);
                }
                Err(e) => {
                    warn!(
                        "ZK proof verification error from relay {}: {:?}",
                        hex::encode(&msg.relay_pubkey[..8]),
                        e,
                    );
                    return Err(AggregatorError::InvalidProof);
                }
            }
        }

        // 3. Verify chain continuity
        let pool_key = (msg.pool_pubkey, msg.pool_type, msg.epoch);
        let pool = self.pools.entry(pool_key).or_insert_with(|| PoolTracker {
            relay_claims: HashMap::new(),
        });

        if let Some(existing) = pool.relay_claims.get(&msg.relay_pubkey) {
            if existing.latest_root != msg.prev_root {
                warn!(
                    "Proof chain break for relay {} on pool {} ({:?}): expected root {:?}, got prev_root {:?}",
                    hex::encode(&msg.relay_pubkey[..8]),
                    hex::encode(&msg.pool_pubkey[..8]),
                    msg.pool_type,
                    &existing.latest_root[..8],
                    &msg.prev_root[..8],
                );
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

        debug!(
            "Updated proof for relay {} on pool {} ({:?}): cumulative={}",
            hex::encode(&msg.relay_pubkey[..8]),
            hex::encode(&msg.pool_pubkey[..8]),
            msg.pool_type,
            msg.cumulative_bytes,
        );

        Ok(())
    }

    /// Build a Merkle distribution for a pool+epoch.
    ///
    /// Returns the distribution root and entries that can be posted
    /// on-chain via `post_distribution()`.
    pub fn build_distribution(&self, pool_key: &(PublicKey, PoolType, u64)) -> Option<Distribution> {
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

    /// Get per-relay usage breakdown for a specific pool+epoch
    pub fn get_pool_usage(&self, pool_key: &(PublicKey, PoolType, u64)) -> Vec<(PublicKey, u64)> {
        self.pools.get(pool_key)
            .map(|tracker| {
                tracker.relay_claims.iter()
                    .map(|(relay, claim)| (*relay, claim.cumulative_bytes))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Get per-pool breakdown for a specific relay
    pub fn get_relay_stats(&self, relay: &PublicKey) -> Vec<((PublicKey, PoolType, u64), u64)> {
        self.pools.iter()
            .filter_map(|(pool_key, tracker)| {
                tracker.relay_claims.get(relay)
                    .map(|claim| (*pool_key, claim.cumulative_bytes))
            })
            .collect()
    }

    /// Get a relay's latest chain state for a specific pool+epoch.
    ///
    /// Used for chain recovery: a relay that lost its proof state can query
    /// any aggregator for its latest root and cumulative count. This is
    /// trustless — if the aggregator lies, the relay's next proof will fail
    /// at every other aggregator with ChainBreak.
    pub fn get_relay_state(
        &self,
        relay: &PublicKey,
        pool_key: &(PublicKey, PoolType, u64),
    ) -> Option<([u8; 32], u64)> {
        self.pools.get(pool_key)
            .and_then(|tracker| tracker.relay_claims.get(relay))
            .map(|claim| (claim.latest_root, claim.cumulative_bytes))
    }

    /// Get network-wide statistics
    pub fn get_network_stats(&self) -> NetworkStats {
        let mut stats = NetworkStats::default();
        let mut all_relays: std::collections::HashSet<PublicKey> = std::collections::HashSet::new();

        for ((_, pool_type, _), tracker) in &self.pools {
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

        for ((_, pool_type, _), tracker) in &self.pools {
            if *pool_type == PoolType::Free {
                for (relay, claim) in &tracker.relay_claims {
                    *relay_totals.entry(*relay).or_default() += claim.cumulative_bytes;
                }
            }
        }

        relay_totals.into_iter().collect()
    }

    /// Get all subscribed pools (for epoch-end distribution posting)
    pub fn subscribed_pools(&self) -> Vec<(PublicKey, PoolType, u64)> {
        self.pools.iter()
            .filter(|((_, pool_type, _), _)| *pool_type == PoolType::Subscribed)
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
        Self::new(Box::new(StubProver::new()))
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
        make_proof_epoch(relay, pool, pool_type, 0, batch, cumulative, prev_root, new_root)
    }

    fn make_proof_epoch(relay: u8, pool: u8, pool_type: PoolType, epoch: u64, batch: u64, cumulative: u64, prev_root: [u8; 32], new_root: [u8; 32]) -> ProofMessage {
        let keypair = tunnelcraft_crypto::SigningKeypair::from_secret_bytes(&[relay; 32]);
        let mut msg = ProofMessage {
            relay_pubkey: keypair.public_key_bytes(),
            pool_pubkey: [pool; 32],
            pool_type,
            epoch,
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
        Aggregator::new(Box::new(StubProver::new()))
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
        let usage = agg.get_pool_usage(&([2u8; 32], PoolType::Subscribed, 0));
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

        let usage = agg.get_pool_usage(&([2u8; 32], PoolType::Subscribed, 0));
        assert_eq!(usage[0].1, 150);
    }

    #[test]
    fn test_chain_break_rejected() {
        let mut agg = new_agg();

        let msg1 = make_proof(1, 2, PoolType::Subscribed, 100, 100, [0u8; 32], [0xAA; 32]);
        agg.handle_proof(msg1).unwrap();

        // Wrong prev_root — should fail
        let msg2 = make_proof(1, 2, PoolType::Subscribed, 50, 150, [0xCC; 32], [0xDD; 32]);
        let result = agg.handle_proof(msg2);
        assert!(matches!(result, Err(AggregatorError::ChainBreak)));
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

        let usage = agg.get_pool_usage(&([10u8; 32], PoolType::Subscribed, 0));
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

        let dist = agg.build_distribution(&([10u8; 32], PoolType::Subscribed, 0)).unwrap();
        assert_eq!(dist.total, 100);
        assert_eq!(dist.entries.len(), 2);
        assert_ne!(dist.root, [0u8; 32]);
    }

    #[test]
    fn test_build_distribution_empty_pool() {
        let agg = new_agg();
        assert!(agg.build_distribution(&([99u8; 32], PoolType::Subscribed, 0)).is_none());
    }

    #[test]
    fn test_distribution_root_deterministic() {
        let mut agg = new_agg();

        let msg1 = make_proof(1, 10, PoolType::Subscribed, 70, 70, [0u8; 32], [0xAA; 32]);
        let msg2 = make_proof(2, 10, PoolType::Subscribed, 30, 30, [0u8; 32], [0xBB; 32]);
        agg.handle_proof(msg1).unwrap();
        agg.handle_proof(msg2).unwrap();

        let pool_key = ([10u8; 32], PoolType::Subscribed, 0);
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
        assert_eq!(pools[0].2, 0);
    }

    #[test]
    fn test_get_relay_state() {
        let mut agg = new_agg();

        let msg = make_proof(1, 2, PoolType::Subscribed, 100, 100, [0u8; 32], [0xAA; 32]);
        agg.handle_proof(msg).unwrap();

        let relay = relay_pubkey(1);
        let pool_key = ([2u8; 32], PoolType::Subscribed, 0);

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

        let sub_usage = agg.get_pool_usage(&([10u8; 32], PoolType::Subscribed, 0));
        assert_eq!(sub_usage.len(), 1);
        assert_eq!(sub_usage[0].1, 70);

        let free_usage = agg.get_pool_usage(&([10u8; 32], PoolType::Free, 0));
        assert_eq!(free_usage.len(), 1);
        assert_eq!(free_usage[0].1, 30);
    }
}
