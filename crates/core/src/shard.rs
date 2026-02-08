use serde::{Deserialize, Serialize};

use sha2::{Sha256, Digest};

use crate::types::{Id, PublicKey};

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

    /// Binding proof tying this shard to the originating user for settlement.
    /// SHA256(request_id || user_pubkey || user_signature_on_request)
    /// Relays copy this into ForwardReceipts to bind receipts to the user's pool.
    pub user_proof: Id,

    /// Number of hops remaining before reaching destination
    pub hops_remaining: u8,

    /// Public key of the last relay that forwarded this shard.
    /// Relays stamp their identity here before forwarding.
    /// Used for ForwardReceipt sender binding.
    pub sender_pubkey: PublicKey,

    /// Total number of relay hops for this request (set by client, never decremented).
    /// Exit reads this to set hops_remaining on response shards.
    pub total_hops: u8,

    /// Encrypted payload
    pub payload: Vec<u8>,

    /// Type of shard
    pub shard_type: ShardType,

    /// Shard index for erasure coding reconstruction
    pub shard_index: u8,

    /// Total number of shards in this set
    pub total_shards: u8,

    /// Which chunk this shard belongs to (0-indexed).
    /// Data is split into 3KB chunks before erasure coding.
    pub chunk_index: u16,

    /// Total number of chunks in this request/response.
    pub total_chunks: u16,
}

impl Shard {
    /// Compute user_proof: SHA256(request_id || user_pubkey || user_signature_on_request)
    ///
    /// This binds receipts to the originating user so colluding relays can't
    /// create fake receipts for other users' pools.
    pub fn compute_user_proof(request_id: &Id, user_pubkey: &PublicKey, user_signature: &[u8; 64]) -> Id {
        let mut hasher = Sha256::new();
        hasher.update(request_id);
        hasher.update(user_pubkey);
        hasher.update(user_signature);
        let result = hasher.finalize();
        let mut proof = [0u8; 32];
        proof.copy_from_slice(&result);
        proof
    }

    /// Create a new request shard
    #[allow(clippy::too_many_arguments)]
    pub fn new_request(
        shard_id: Id,
        request_id: Id,
        user_pubkey: PublicKey,
        destination: PublicKey,
        hops_remaining: u8,
        payload: Vec<u8>,
        shard_index: u8,
        total_shards: u8,
        total_hops: u8,
        chunk_index: u16,
        total_chunks: u16,
    ) -> Self {
        Self {
            shard_id,
            request_id,
            user_pubkey,
            destination,
            user_proof: [0u8; 32], // Set by caller via set_user_proof() after signing
            hops_remaining,
            sender_pubkey: [0u8; 32], // Stamped by relays before forwarding
            total_hops,
            payload,
            shard_type: ShardType::Request,
            shard_index,
            total_shards,
            chunk_index,
            total_chunks,
        }
    }

    /// Create a new response shard
    ///
    /// Response shards inherit user_proof from the original request shard.
    /// `exit_pubkey` is the exit node's public key (set as initial sender_pubkey).
    /// `total_hops` is copied from the request shard.
    #[allow(clippy::too_many_arguments)]
    pub fn new_response(
        shard_id: Id,
        request_id: Id,
        user_pubkey: PublicKey,
        user_proof: Id,
        exit_pubkey: PublicKey,
        hops_remaining: u8,
        payload: Vec<u8>,
        shard_index: u8,
        total_shards: u8,
        total_hops: u8,
        chunk_index: u16,
        total_chunks: u16,
    ) -> Self {
        Self {
            shard_id,
            request_id,
            user_pubkey,
            destination: user_pubkey, // Response goes back to user
            user_proof,
            hops_remaining,
            sender_pubkey: exit_pubkey, // Exit stamps itself as the initial sender
            total_hops,
            payload,
            shard_type: ShardType::Response,
            shard_index,
            total_shards,
            chunk_index,
            total_chunks,
        }
    }

    /// Set the user_proof after computing it from the user's request signature
    pub fn set_user_proof(&mut self, user_proof: Id) {
        self.user_proof = user_proof;
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
            3,          // total_hops
            0,          // chunk_index
            1,          // total_chunks
        );

        assert_eq!(shard.shard_id, [1u8; 32]);
        assert_eq!(shard.request_id, [2u8; 32]);
        assert_eq!(shard.user_pubkey, user_pubkey);
        assert_eq!(shard.destination, [5u8; 32]);
        assert_eq!(shard.hops_remaining, 3);
        assert_eq!(shard.total_hops, 3);
        assert_eq!(shard.sender_pubkey, [0u8; 32]);
        assert_eq!(shard.shard_type, ShardType::Request);
    }

    #[test]
    fn test_new_response_shard() {
        let shard = Shard::new_response(
            [1u8; 32],  // shard_id
            [2u8; 32],  // request_id
            [4u8; 32],  // user_pubkey
            [0u8; 32],  // user_proof
            [10u8; 32], // exit_pubkey
            3,          // hops_remaining
            vec![0u8; 100],  // payload
            0,          // shard_index
            5,          // total_shards
            3,          // total_hops
            0,          // chunk_index
            1,          // total_chunks
        );

        assert_eq!(shard.shard_type, ShardType::Response);
        assert_eq!(shard.destination, [4u8; 32]);
        assert_eq!(shard.sender_pubkey, [10u8; 32]);
        assert_eq!(shard.total_hops, 3);
    }

    #[test]
    fn test_is_request() {
        let shard = Shard::new_request(
            [1u8; 32], [2u8; 32], [4u8; 32], [5u8; 32],
            3, vec![], 0, 5, 3, 0, 1,
        );

        assert!(shard.is_request());
        assert!(!shard.is_response());
    }

    #[test]
    fn test_is_response() {
        let shard = Shard::new_response(
            [1u8; 32], [2u8; 32], [4u8; 32], [0u8; 32],
            [10u8; 32], 3, vec![], 0, 5, 3, 0, 1,
        );

        assert!(shard.is_response());
        assert!(!shard.is_request());
    }

    #[test]
    fn test_decrement_hops() {
        let mut shard = Shard::new_request(
            [1u8; 32], [2u8; 32], [4u8; 32], [5u8; 32],
            3, vec![], 0, 5, 3, 0, 1,
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
            0, vec![], 0, 5, 0, 0, 1,
        );

        assert!(shard.decrement_hops());  // Already at zero
        assert_eq!(shard.hops_remaining, 0);

        // Decrementing at zero stays at zero
        assert!(shard.decrement_hops());
        assert_eq!(shard.hops_remaining, 0);
    }

    #[test]
    fn test_sender_pubkey_stamped() {
        let mut shard = Shard::new_request(
            [1u8; 32], [2u8; 32], [4u8; 32], [5u8; 32],
            3, vec![], 0, 5, 3, 0, 1,
        );

        assert_eq!(shard.sender_pubkey, [0u8; 32]);

        shard.sender_pubkey = [10u8; 32];
        assert_eq!(shard.sender_pubkey, [10u8; 32]);

        shard.sender_pubkey = [11u8; 32];
        assert_eq!(shard.sender_pubkey, [11u8; 32]);
    }

    #[test]
    fn test_serialization_roundtrip() {
        let shard = Shard::new_request(
            [1u8; 32], [2u8; 32], [4u8; 32], [5u8; 32],
            3, vec![0xAB, 0xCD, 0xEF], 2, 5, 3, 0, 1,
        );

        let bytes = shard.to_bytes().unwrap();
        let restored = Shard::from_bytes(&bytes).unwrap();

        assert_eq!(restored.shard_id, shard.shard_id);
        assert_eq!(restored.request_id, shard.request_id);
        assert_eq!(restored.user_pubkey, shard.user_pubkey);
        assert_eq!(restored.destination, shard.destination);
        assert_eq!(restored.hops_remaining, shard.hops_remaining);
        assert_eq!(restored.sender_pubkey, shard.sender_pubkey);
        assert_eq!(restored.total_hops, shard.total_hops);
        assert_eq!(restored.payload, shard.payload);
        assert_eq!(restored.shard_type, shard.shard_type);
        assert_eq!(restored.shard_index, shard.shard_index);
        assert_eq!(restored.total_shards, shard.total_shards);
    }

    #[test]
    fn test_serialization_with_sender_pubkey() {
        let mut shard = Shard::new_request(
            [1u8; 32], [2u8; 32], [4u8; 32], [5u8; 32],
            3, vec![0x11, 0x22], 0, 5, 3, 0, 1,
        );

        shard.sender_pubkey = [10u8; 32];

        let bytes = shard.to_bytes().unwrap();
        let restored = Shard::from_bytes(&bytes).unwrap();

        assert_eq!(restored.sender_pubkey, [10u8; 32]);
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
            3, vec![], 0, 5, 3, 0, 1,
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
            3, large_payload.clone(), 0, 5, 3, 0, 1,
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
            0, vec![], 0, 5, 0, 0, 1,
        );

        assert_eq!(shard.hops_remaining, 0);
        assert!(shard.decrement_hops());  // Already at destination
    }

    #[test]
    fn test_max_shard_index() {
        let shard = Shard::new_request(
            [1u8; 32], [2u8; 32], [4u8; 32], [5u8; 32],
            3, vec![], 255, 255, 3, 0, 1,
        );

        assert_eq!(shard.shard_index, 255);
        assert_eq!(shard.total_shards, 255);
    }
}
