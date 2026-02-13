//! Receipt compressor — hashes receipts into a Merkle tree.
//!
//! This is the default compression backend. It builds a binary Merkle
//! tree from receipt hashes and returns the root. The Merkle root serves
//! as a compact summary for gossip messaging (one root instead of
//! thousands of receipts).

use sha2::{Digest, Sha256};
use tunnelcraft_core::ForwardReceipt;

use crate::merkle::MerkleTree;
use crate::traits::{CompressedBatch, ReceiptCompression, CompressionError};

/// Receipt compressor that builds a Merkle tree from receipt hashes.
pub struct ReceiptCompressor;

impl ReceiptCompressor {
    pub fn new() -> Self {
        Self
    }

    /// Hash a receipt into a leaf: SHA256(shard_id || sender_pubkey || receiver_pubkey || pool_pubkey || payload_size_le || timestamp_le)
    fn receipt_leaf(receipt: &ForwardReceipt) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(receipt.shard_id);
        hasher.update(receipt.sender_pubkey);
        hasher.update(receipt.receiver_pubkey);
        hasher.update(receipt.pool_pubkey);
        hasher.update(receipt.payload_size.to_le_bytes());
        hasher.update(receipt.timestamp.to_le_bytes());
        let result = hasher.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&result);
        out
    }
}

impl Default for ReceiptCompressor {
    fn default() -> Self {
        Self::new()
    }
}

impl ReceiptCompression for ReceiptCompressor {
    fn compress(&self, batch: &[ForwardReceipt]) -> Result<CompressedBatch, CompressionError> {
        if batch.is_empty() {
            return Err(CompressionError::EmptyBatch);
        }

        let leaves: Vec<[u8; 32]> = batch.iter().map(Self::receipt_leaf).collect();
        let tree = MerkleTree::from_leaves(leaves);

        Ok(CompressedBatch {
            root: tree.root(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_receipt(shard_id: u8, receiver: u8) -> ForwardReceipt {
        ForwardReceipt {
            shard_id: [shard_id; 32],
            sender_pubkey: [0xFFu8; 32],
            receiver_pubkey: [receiver; 32],
            pool_pubkey: [0u8; 32],
            payload_size: 1024,
            timestamp: 1700000000,
            signature: [0u8; 64],
        }
    }

    #[test]
    fn test_compressor_compress() {
        let compressor = ReceiptCompressor::new();

        let batch = vec![
            make_receipt(10, 2),
            make_receipt(11, 3),
            make_receipt(12, 4),
        ];

        let output = compressor.compress(&batch).unwrap();
        assert_ne!(output.root, [0u8; 32]);
    }

    #[test]
    fn test_compressor_empty_batch() {
        let compressor = ReceiptCompressor::new();
        let result = compressor.compress(&[]);
        assert!(matches!(result, Err(CompressionError::EmptyBatch)));
    }

    #[test]
    fn test_compressor_deterministic() {
        let compressor = ReceiptCompressor::new();
        let batch = vec![make_receipt(10, 2), make_receipt(11, 3)];

        let out1 = compressor.compress(&batch).unwrap();
        let out2 = compressor.compress(&batch).unwrap();
        assert_eq!(out1.root, out2.root);
    }

    #[test]
    fn test_compressor_different_batches() {
        let compressor = ReceiptCompressor::new();
        let batch1 = vec![make_receipt(10, 2)];
        let batch2 = vec![make_receipt(20, 2)];

        let out1 = compressor.compress(&batch1).unwrap();
        let out2 = compressor.compress(&batch2).unwrap();
        assert_ne!(out1.root, out2.root);
    }
}
