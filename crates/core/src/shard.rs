use serde::{Deserialize, Serialize};

use crate::types::{ChainEntry, Id, PublicKey};

/// Shard type indicator
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ShardType {
    Request,
    Response,
}

/// A shard is a fragment of a request or response that travels through the network
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Shard {
    /// Unique identifier for this shard
    pub shard_id: Id,

    /// Request this shard belongs to
    pub request_id: Id,

    /// Public key of the user who originated the request
    pub user_pubkey: PublicKey,

    /// Destination: exit pubkey for requests, user pubkey for responses
    pub destination: PublicKey,

    /// Number of hops remaining before reaching destination
    pub hops_remaining: u8,

    /// Signature chain accumulated as shard travels through relays
    pub chain: Vec<ChainEntry>,

    /// Encrypted payload
    pub payload: Vec<u8>,

    /// Type of shard
    pub shard_type: ShardType,

    /// Shard index for erasure coding reconstruction
    pub shard_index: u8,

    /// Total number of shards in this set
    pub total_shards: u8,
}

impl Shard {
    /// Create a new request shard
    pub fn new_request(
        shard_id: Id,
        request_id: Id,
        user_pubkey: PublicKey,
        destination: PublicKey,
        hops_remaining: u8,
        payload: Vec<u8>,
        shard_index: u8,
        total_shards: u8,
    ) -> Self {
        Self {
            shard_id,
            request_id,
            user_pubkey,
            destination,
            hops_remaining,
            chain: Vec::new(),
            payload,
            shard_type: ShardType::Request,
            shard_index,
            total_shards,
        }
    }

    /// Create a new response shard
    ///
    /// The exit_entry should be created with the hops_remaining value at the time of signing.
    pub fn new_response(
        shard_id: Id,
        request_id: Id,
        user_pubkey: PublicKey,
        exit_entry: ChainEntry,
        hops_remaining: u8,
        payload: Vec<u8>,
        shard_index: u8,
        total_shards: u8,
    ) -> Self {
        Self {
            shard_id,
            request_id,
            user_pubkey,
            destination: user_pubkey, // Response goes back to user
            hops_remaining,
            chain: vec![exit_entry], // Chain starts with exit signature
            payload,
            shard_type: ShardType::Response,
            shard_index,
            total_shards,
        }
    }

    /// Add a signature to the chain (records current hops_remaining for verification)
    pub fn add_signature(&mut self, pubkey: PublicKey, signature: [u8; 64]) {
        self.chain.push(ChainEntry::new(pubkey, signature, self.hops_remaining));
    }

    /// Decrement hops and return whether we've reached zero
    pub fn decrement_hops(&mut self) -> bool {
        if self.hops_remaining > 0 {
            self.hops_remaining -= 1;
        }
        self.hops_remaining == 0
    }

    /// Check if this is a request shard
    pub fn is_request(&self) -> bool {
        self.shard_type == ShardType::Request
    }

    /// Check if this is a response shard
    pub fn is_response(&self) -> bool {
        self.shard_type == ShardType::Response
    }

    /// Get the data that should be signed by a relay (uses current hops_remaining)
    pub fn signable_data(&self) -> Vec<u8> {
        self.signable_data_with_hops(self.hops_remaining)
    }

    /// Get signable data with a specific hops value (for verification of past signatures)
    pub fn signable_data_with_hops(&self, hops: u8) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&self.shard_id);
        data.extend_from_slice(&self.request_id);
        data.extend_from_slice(&self.destination);
        data.push(hops);
        data
    }

    /// Serialize to bytes
    pub fn to_bytes(&self) -> Result<Vec<u8>, bincode::Error> {
        bincode::serialize(self)
    }

    /// Deserialize from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, bincode::Error> {
        bincode::deserialize(bytes)
    }
}

/// Wire format header magic bytes
pub const SHARD_MAGIC: [u8; 4] = [0x54, 0x43, 0x53, 0x48]; // "TCSH"

/// Current wire format version
pub const SHARD_VERSION: u8 = 1;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_request_shard() {
        let user_pubkey = [4u8; 32];
        let shard = Shard::new_request(
            [1u8; 32],  // shard_id
            [2u8; 32],  // request_id
            user_pubkey,  // user_pubkey
            [5u8; 32],  // destination
            3,          // hops_remaining
            vec![0u8; 100],  // payload
            0,          // shard_index
            5,          // total_shards
        );

        assert_eq!(shard.shard_id, [1u8; 32]);
        assert_eq!(shard.request_id, [2u8; 32]);
        assert_eq!(shard.user_pubkey, user_pubkey);
        assert_eq!(shard.destination, [5u8; 32]);
        assert_eq!(shard.hops_remaining, 3);
        assert_eq!(shard.shard_type, ShardType::Request);
        assert!(shard.chain.is_empty());
    }

    #[test]
    fn test_new_response_shard() {
        let exit_entry = ChainEntry::new([10u8; 32], [0u8; 64], 3);
        let shard = Shard::new_response(
            [1u8; 32],  // shard_id
            [2u8; 32],  // request_id
            [4u8; 32],  // user_pubkey
            exit_entry,
            3,          // hops_remaining
            vec![0u8; 100],  // payload
            0,          // shard_index
            5,          // total_shards
        );

        assert_eq!(shard.shard_type, ShardType::Response);
        assert_eq!(shard.destination, [4u8; 32]);
        assert_eq!(shard.chain.len(), 1);
        assert_eq!(shard.chain[0].pubkey, [10u8; 32]);
    }

    #[test]
    fn test_is_request() {
        let shard = Shard::new_request(
            [1u8; 32], [2u8; 32], [4u8; 32], [5u8; 32],
            3, vec![], 0, 5,
        );

        assert!(shard.is_request());
        assert!(!shard.is_response());
    }

    #[test]
    fn test_is_response() {
        let exit_entry = ChainEntry::new([10u8; 32], [0u8; 64], 3);
        let shard = Shard::new_response(
            [1u8; 32], [2u8; 32], [4u8; 32],
            exit_entry, 3, vec![], 0, 5,
        );

        assert!(shard.is_response());
        assert!(!shard.is_request());
    }

    #[test]
    fn test_decrement_hops() {
        let mut shard = Shard::new_request(
            [1u8; 32], [2u8; 32], [4u8; 32], [5u8; 32],
            3, vec![], 0, 5,
        );

        assert_eq!(shard.hops_remaining, 3);

        assert!(!shard.decrement_hops());
        assert_eq!(shard.hops_remaining, 2);

        assert!(!shard.decrement_hops());
        assert_eq!(shard.hops_remaining, 1);

        assert!(shard.decrement_hops());  // Returns true at zero
        assert_eq!(shard.hops_remaining, 0);
    }

    #[test]
    fn test_decrement_hops_at_zero() {
        let mut shard = Shard::new_request(
            [1u8; 32], [2u8; 32], [4u8; 32], [5u8; 32],
            0, vec![], 0, 5,
        );

        assert!(shard.decrement_hops());  // Already at zero
        assert_eq!(shard.hops_remaining, 0);

        // Decrementing at zero stays at zero
        assert!(shard.decrement_hops());
        assert_eq!(shard.hops_remaining, 0);
    }

    #[test]
    fn test_add_signature() {
        let mut shard = Shard::new_request(
            [1u8; 32], [2u8; 32], [4u8; 32], [5u8; 32],
            3, vec![], 0, 5,
        );

        assert!(shard.chain.is_empty());

        shard.add_signature([10u8; 32], [1u8; 64]);
        assert_eq!(shard.chain.len(), 1);
        assert_eq!(shard.chain[0].pubkey, [10u8; 32]);
        assert_eq!(shard.chain[0].hops_at_sign, 3);

        shard.decrement_hops();
        shard.add_signature([11u8; 32], [2u8; 64]);
        assert_eq!(shard.chain.len(), 2);
        assert_eq!(shard.chain[1].hops_at_sign, 2);
    }

    #[test]
    fn test_signable_data() {
        let shard = Shard::new_request(
            [1u8; 32], [2u8; 32], [4u8; 32], [5u8; 32],
            3, vec![], 0, 5,
        );

        let data = shard.signable_data();

        // Should contain shard_id (32) + request_id (32) + destination (32) + hops (1) = 97 bytes
        assert_eq!(data.len(), 97);
        assert_eq!(&data[0..32], &[1u8; 32]);  // shard_id
        assert_eq!(&data[32..64], &[2u8; 32]); // request_id
        assert_eq!(&data[64..96], &[5u8; 32]); // destination
        assert_eq!(data[96], 3);  // hops_remaining
    }

    #[test]
    fn test_signable_data_with_hops() {
        let shard = Shard::new_request(
            [1u8; 32], [2u8; 32], [4u8; 32], [5u8; 32],
            3, vec![], 0, 5,
        );

        let data_at_3 = shard.signable_data_with_hops(3);
        let data_at_2 = shard.signable_data_with_hops(2);

        // Same data except for hops
        assert_eq!(&data_at_3[0..96], &data_at_2[0..96]);
        assert_eq!(data_at_3[96], 3);
        assert_eq!(data_at_2[96], 2);
    }

    #[test]
    fn test_serialization_roundtrip() {
        let shard = Shard::new_request(
            [1u8; 32], [2u8; 32], [4u8; 32], [5u8; 32],
            3, vec![0xAB, 0xCD, 0xEF], 2, 5,
        );

        let bytes = shard.to_bytes().unwrap();
        let restored = Shard::from_bytes(&bytes).unwrap();

        assert_eq!(restored.shard_id, shard.shard_id);
        assert_eq!(restored.request_id, shard.request_id);
        assert_eq!(restored.user_pubkey, shard.user_pubkey);
        assert_eq!(restored.destination, shard.destination);
        assert_eq!(restored.hops_remaining, shard.hops_remaining);
        assert_eq!(restored.payload, shard.payload);
        assert_eq!(restored.shard_type, shard.shard_type);
        assert_eq!(restored.shard_index, shard.shard_index);
        assert_eq!(restored.total_shards, shard.total_shards);
    }

    #[test]
    fn test_serialization_with_chain() {
        let mut shard = Shard::new_request(
            [1u8; 32], [2u8; 32], [4u8; 32], [5u8; 32],
            3, vec![0x11, 0x22], 0, 5,
        );

        shard.add_signature([10u8; 32], [1u8; 64]);
        shard.add_signature([11u8; 32], [2u8; 64]);

        let bytes = shard.to_bytes().unwrap();
        let restored = Shard::from_bytes(&bytes).unwrap();

        assert_eq!(restored.chain.len(), 2);
        assert_eq!(restored.chain[0].pubkey, [10u8; 32]);
        assert_eq!(restored.chain[1].pubkey, [11u8; 32]);
    }

    #[test]
    fn test_deserialization_invalid_data() {
        let invalid_bytes = vec![0xFF, 0xFE, 0xFD];
        let result = Shard::from_bytes(&invalid_bytes);
        assert!(result.is_err());
    }

    #[test]
    fn test_deserialization_empty() {
        let result = Shard::from_bytes(&[]);
        assert!(result.is_err());
    }

    #[test]
    fn test_shard_type_equality() {
        assert_eq!(ShardType::Request, ShardType::Request);
        assert_eq!(ShardType::Response, ShardType::Response);
        assert_ne!(ShardType::Request, ShardType::Response);
    }

    #[test]
    fn test_magic_bytes() {
        assert_eq!(SHARD_MAGIC, [0x54, 0x43, 0x53, 0x48]);
        assert_eq!(SHARD_MAGIC[0], b'T');
        assert_eq!(SHARD_MAGIC[1], b'C');
        assert_eq!(SHARD_MAGIC[2], b'S');
        assert_eq!(SHARD_MAGIC[3], b'H');
    }

    #[test]
    fn test_shard_version() {
        assert_eq!(SHARD_VERSION, 1);
    }

    #[test]
    fn test_empty_payload() {
        let shard = Shard::new_request(
            [1u8; 32], [2u8; 32], [4u8; 32], [5u8; 32],
            3, vec![], 0, 5,
        );

        assert!(shard.payload.is_empty());

        let bytes = shard.to_bytes().unwrap();
        let restored = Shard::from_bytes(&bytes).unwrap();
        assert!(restored.payload.is_empty());
    }

    #[test]
    fn test_large_payload() {
        let large_payload = vec![0xAB; 1024 * 1024];  // 1MB
        let shard = Shard::new_request(
            [1u8; 32], [2u8; 32], [4u8; 32], [5u8; 32],
            3, large_payload.clone(), 0, 5,
        );

        assert_eq!(shard.payload.len(), 1024 * 1024);

        let bytes = shard.to_bytes().unwrap();
        let restored = Shard::from_bytes(&bytes).unwrap();
        assert_eq!(restored.payload, large_payload);
    }

    #[test]
    fn test_zero_hops_request() {
        let mut shard = Shard::new_request(
            [1u8; 32], [2u8; 32], [4u8; 32], [5u8; 32],
            0, vec![], 0, 5,
        );

        assert_eq!(shard.hops_remaining, 0);
        assert!(shard.decrement_hops());  // Already at destination
    }

    #[test]
    fn test_max_shard_index() {
        let shard = Shard::new_request(
            [1u8; 32], [2u8; 32], [4u8; 32], [5u8; 32],
            3, vec![], 255, 255,
        );

        assert_eq!(shard.shard_index, 255);
        assert_eq!(shard.total_shards, 255);
    }
}
