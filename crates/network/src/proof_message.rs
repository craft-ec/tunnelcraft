//! Proof gossipsub message types
//!
//! Relays gossip ZK-proven summaries (not individual receipts) via
//! the `tunnelcraft/proofs/1.0.0` gossipsub topic. An aggregator
//! collects these and builds per-pool Merkle distributions for on-chain
//! settlement.

use serde::{Deserialize, Serialize};

/// Whether the user has an active subscription or is free-tier
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PoolType {
    /// User has an active SubscriptionAccount — claimable on-chain
    Subscribed,
    /// No subscription — tracked for stats + ecosystem rewards
    Free,
}

/// A ZK-proven summary of receipts for a single (relay, pool, epoch) triple.
///
/// Relays generate these locally by batching ForwardReceipts into
/// Merkle trees and producing ZK proofs. Each message extends a
/// running chain of proofs (prev_root → new_root) so the aggregator
/// can verify no receipts are double-counted.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofMessage {
    /// Relay that generated this proof
    pub relay_pubkey: [u8; 32],
    /// User whose pool these receipts belong to
    pub pool_pubkey: [u8; 32],
    /// Whether the user is subscribed or free-tier
    pub pool_type: PoolType,
    /// Subscription epoch these receipts belong to (prevents cross-epoch replay)
    pub epoch: u64,
    /// Total payload bytes in this batch of receipts
    pub batch_bytes: u64,
    /// Running total of payload bytes for this (relay, pool, epoch) triple
    pub cumulative_bytes: u64,
    /// Previous Merkle root (chained — verifies continuity)
    pub prev_root: [u8; 32],
    /// New Merkle root after adding this batch
    pub new_root: [u8; 32],
    /// ZK proof bytes (stub initially — mock proof)
    pub proof: Vec<u8>,
    /// Unix timestamp when this proof was generated
    pub timestamp: u64,
    /// Relay's ed25519 signature over the message (64 bytes)
    pub signature: Vec<u8>,
}

impl ProofMessage {
    /// Serialize to bytes (bincode)
    pub fn to_bytes(&self) -> Vec<u8> {
        bincode::serialize(self).expect("ProofMessage serialization should not fail")
    }

    /// Deserialize from bytes (bincode)
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, bincode::Error> {
        bincode::deserialize(bytes)
    }

    /// Data that gets signed by the relay (everything except signature)
    pub fn signable_data(&self) -> Vec<u8> {
        let mut data = Vec::with_capacity(32 + 32 + 1 + 8 + 8 + 8 + 32 + 32 + 8);
        data.extend_from_slice(&self.relay_pubkey);
        data.extend_from_slice(&self.pool_pubkey);
        data.push(match self.pool_type {
            PoolType::Subscribed => 0,
            PoolType::Free => 1,
        });
        data.extend_from_slice(&self.epoch.to_le_bytes());
        data.extend_from_slice(&self.batch_bytes.to_le_bytes());
        data.extend_from_slice(&self.cumulative_bytes.to_le_bytes());
        data.extend_from_slice(&self.prev_root);
        data.extend_from_slice(&self.new_root);
        data.extend_from_slice(&self.timestamp.to_le_bytes());
        // proof bytes are covered by the ZK proof itself, not the signature
        data
    }
}

/// Query a relay's latest proof chain state from an aggregator.
///
/// Sent by relays that lost their proof state (e.g., disk corruption) and
/// need to recover their chain. The aggregator responds with the latest
/// root and cumulative count for the given (relay, pool, pool_type, epoch) quad.
///
/// This is **trustless**: if the aggregator lies (wrong root), the relay's
/// next ProofMessage will fail at every other aggregator with `ChainBreak`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofStateQuery {
    /// Relay requesting its own chain state
    pub relay_pubkey: [u8; 32],
    /// User pool to query
    pub pool_pubkey: [u8; 32],
    /// Pool type (Subscribed or Free)
    pub pool_type: PoolType,
    /// Subscription epoch
    pub epoch: u64,
}

impl ProofStateQuery {
    pub fn to_bytes(&self) -> Vec<u8> {
        bincode::serialize(self).expect("ProofStateQuery serialization should not fail")
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, bincode::Error> {
        bincode::deserialize(bytes)
    }
}

/// Response to a ProofStateQuery.
///
/// Contains the latest known root and cumulative count for the relay on the
/// given pool. If the aggregator has no record, `found` is false.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofStateResponse {
    /// Whether the aggregator found state for this relay/pool
    pub found: bool,
    /// Relay's latest Merkle root for this pool
    pub root: [u8; 32],
    /// Relay's cumulative payload bytes for this pool
    pub cumulative_bytes: u64,
}

impl ProofStateResponse {
    pub fn to_bytes(&self) -> Vec<u8> {
        bincode::serialize(self).expect("ProofStateResponse serialization should not fail")
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, bincode::Error> {
        bincode::deserialize(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pool_type_serialization() {
        let subscribed = PoolType::Subscribed;
        let free = PoolType::Free;

        let bytes_sub = bincode::serialize(&subscribed).unwrap();
        let bytes_free = bincode::serialize(&free).unwrap();

        assert_eq!(bincode::deserialize::<PoolType>(&bytes_sub).unwrap(), PoolType::Subscribed);
        assert_eq!(bincode::deserialize::<PoolType>(&bytes_free).unwrap(), PoolType::Free);
    }

    #[test]
    fn test_proof_message_roundtrip() {
        let msg = ProofMessage {
            relay_pubkey: [1u8; 32],
            pool_pubkey: [2u8; 32],
            pool_type: PoolType::Subscribed,
            epoch: 0,
            batch_bytes: 10_000,
            cumulative_bytes: 50_000,
            prev_root: [0xAA; 32],
            new_root: [0xBB; 32],
            proof: vec![0xCC; 128],
            timestamp: 1700000000,
            signature: vec![0xDD; 64],
        };

        let bytes = msg.to_bytes();
        let decoded = ProofMessage::from_bytes(&bytes).unwrap();

        assert_eq!(decoded.relay_pubkey, msg.relay_pubkey);
        assert_eq!(decoded.pool_pubkey, msg.pool_pubkey);
        assert_eq!(decoded.pool_type, msg.pool_type);
        assert_eq!(decoded.batch_bytes, msg.batch_bytes);
        assert_eq!(decoded.cumulative_bytes, msg.cumulative_bytes);
        assert_eq!(decoded.prev_root, msg.prev_root);
        assert_eq!(decoded.new_root, msg.new_root);
        assert_eq!(decoded.proof, msg.proof);
        assert_eq!(decoded.timestamp, msg.timestamp);
        assert_eq!(decoded.signature, msg.signature);
    }

    #[test]
    fn test_proof_message_free_tier() {
        let msg = ProofMessage {
            relay_pubkey: [1u8; 32],
            pool_pubkey: [3u8; 32],
            pool_type: PoolType::Free,
            epoch: 0,
            batch_bytes: 5_000,
            cumulative_bytes: 5_000,
            prev_root: [0u8; 32], // First batch — zero root
            new_root: [0xEE; 32],
            proof: vec![],
            timestamp: 1700000000,
            signature: vec![0u8; 64],
        };

        let bytes = msg.to_bytes();
        let decoded = ProofMessage::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.pool_type, PoolType::Free);
        assert_eq!(decoded.prev_root, [0u8; 32]);
    }

    #[test]
    fn test_signable_data_deterministic() {
        let msg = ProofMessage {
            relay_pubkey: [1u8; 32],
            pool_pubkey: [2u8; 32],
            pool_type: PoolType::Subscribed,
            epoch: 0,
            batch_bytes: 100,
            cumulative_bytes: 200,
            prev_root: [0xAA; 32],
            new_root: [0xBB; 32],
            proof: vec![0xCC; 64],
            timestamp: 1700000000,
            signature: vec![0xFF; 64], // Signature should NOT affect signable_data
        };

        let data1 = msg.signable_data();
        let data2 = msg.signable_data();
        assert_eq!(data1, data2);

        // Changing signature should not change signable_data
        let mut msg2 = msg.clone();
        msg2.signature = vec![0x00; 64];
        assert_eq!(msg.signable_data(), msg2.signable_data());
    }

    #[test]
    fn test_signable_data_differs_for_different_messages() {
        let msg1 = ProofMessage {
            relay_pubkey: [1u8; 32],
            pool_pubkey: [2u8; 32],
            pool_type: PoolType::Subscribed,
            epoch: 0,
            batch_bytes: 100,
            cumulative_bytes: 200,
            prev_root: [0xAA; 32],
            new_root: [0xBB; 32],
            proof: vec![],
            timestamp: 1700000000,
            signature: vec![0u8; 64],
        };

        let mut msg2 = msg1.clone();
        msg2.batch_bytes = 200;

        assert_ne!(msg1.signable_data(), msg2.signable_data());
    }

    #[test]
    fn test_invalid_bytes_fails() {
        let result = ProofMessage::from_bytes(&[0u8; 10]);
        assert!(result.is_err());
    }

    #[test]
    fn test_proof_state_query_roundtrip() {
        let query = ProofStateQuery {
            relay_pubkey: [1u8; 32],
            pool_pubkey: [2u8; 32],
            pool_type: PoolType::Subscribed,
            epoch: 0,
        };
        let bytes = query.to_bytes();
        let decoded = ProofStateQuery::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.relay_pubkey, query.relay_pubkey);
        assert_eq!(decoded.pool_pubkey, query.pool_pubkey);
        assert_eq!(decoded.pool_type, query.pool_type);
    }

    #[test]
    fn test_proof_state_response_roundtrip() {
        let resp = ProofStateResponse {
            found: true,
            root: [0xAA; 32],
            cumulative_bytes: 12345,
        };
        let bytes = resp.to_bytes();
        let decoded = ProofStateResponse::from_bytes(&bytes).unwrap();
        assert!(decoded.found);
        assert_eq!(decoded.root, [0xAA; 32]);
        assert_eq!(decoded.cumulative_bytes, 12345);
    }

    #[test]
    fn test_proof_state_response_not_found() {
        let resp = ProofStateResponse {
            found: false,
            root: [0u8; 32],
            cumulative_bytes: 0,
        };
        let bytes = resp.to_bytes();
        let decoded = ProofStateResponse::from_bytes(&bytes).unwrap();
        assert!(!decoded.found);
    }
}
