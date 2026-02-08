//! Stub prover — hashes receipts into a Merkle tree, no ZK proof.
//!
//! This is the default prover used during development. It builds a
//! proper binary Merkle tree from receipt hashes but generates an
//! empty proof blob (no ZK).

use sha2::{Digest, Sha256};
use tunnelcraft_core::ForwardReceipt;

use crate::merkle::MerkleTree;
use crate::traits::{ProofOutput, Prover, ProverError};

/// Stub prover that builds a Merkle tree without ZK proofs.
pub struct StubProver;

impl StubProver {
    pub fn new() -> Self {
        Self
    }

    /// Hash a receipt into a leaf: SHA256(request_id || shard_id || sender_pubkey || receiver_pubkey || user_proof || epoch || timestamp)
    fn receipt_leaf(receipt: &ForwardReceipt) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(&receipt.request_id);
        hasher.update(&receipt.shard_id);
        hasher.update(&receipt.sender_pubkey);
        hasher.update(&receipt.receiver_pubkey);
        hasher.update(&receipt.user_proof);
        hasher.update(&receipt.epoch.to_le_bytes());
        hasher.update(&receipt.timestamp.to_le_bytes());
        let result = hasher.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&result);
        out
    }
}

impl Default for StubProver {
    fn default() -> Self {
        Self::new()
    }
}

impl Prover for StubProver {
    fn prove(&self, batch: &[ForwardReceipt]) -> Result<ProofOutput, ProverError> {
        if batch.is_empty() {
            return Err(ProverError::EmptyBatch);
        }

        let leaves: Vec<[u8; 32]> = batch.iter().map(Self::receipt_leaf).collect();
        let tree = MerkleTree::from_leaves(leaves);

        Ok(ProofOutput {
            new_root: tree.root(),
            proof: vec![], // No ZK proof in stub mode
        })
    }

    fn verify(&self, _root: &[u8; 32], _proof: &[u8], _batch_size: u64) -> Result<bool, ProverError> {
        // Stub prover: no proof to verify, always accept
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_receipt(request_id: u8, shard_id: u8, receiver: u8) -> ForwardReceipt {
        ForwardReceipt {
            request_id: [request_id; 32],
            shard_id: [shard_id; 32],
            sender_pubkey: [0xFFu8; 32],
            receiver_pubkey: [receiver; 32],
            user_proof: [0u8; 32],
            epoch: 0,
            timestamp: 1700000000,
            signature: [0u8; 64],
        }
    }

    #[test]
    fn test_stub_prover_prove_verify() {
        let prover = StubProver::new();

        let batch = vec![
            make_receipt(1, 10, 2),
            make_receipt(1, 11, 3),
            make_receipt(1, 12, 4),
        ];

        let output = prover.prove(&batch).unwrap();
        assert_ne!(output.new_root, [0u8; 32]);
        assert!(output.proof.is_empty()); // Stub has no proof

        // Verify always passes for stub
        assert!(prover.verify(&output.new_root, &output.proof, 3).unwrap());
    }

    #[test]
    fn test_stub_prover_empty_batch() {
        let prover = StubProver::new();
        let result = prover.prove(&[]);
        assert!(matches!(result, Err(ProverError::EmptyBatch)));
    }

    #[test]
    fn test_stub_prover_deterministic() {
        let prover = StubProver::new();
        let batch = vec![make_receipt(1, 10, 2), make_receipt(1, 11, 3)];

        let out1 = prover.prove(&batch).unwrap();
        let out2 = prover.prove(&batch).unwrap();
        assert_eq!(out1.new_root, out2.new_root);
    }

    #[test]
    fn test_stub_prover_different_batches() {
        let prover = StubProver::new();
        let batch1 = vec![make_receipt(1, 10, 2)];
        let batch2 = vec![make_receipt(2, 10, 2)];

        let out1 = prover.prove(&batch1).unwrap();
        let out2 = prover.prove(&batch2).unwrap();
        assert_ne!(out1.new_root, out2.new_root);
    }
}
