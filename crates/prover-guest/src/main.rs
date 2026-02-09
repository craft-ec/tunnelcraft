//! risc0 guest program for TunnelCraft receipt proving.
//!
//! Runs inside the risc0 RISC-V VM. Given a batch of ForwardReceipts:
//! 1. Verifies all receipts have the same sender_pubkey (anti-Sybil)
//! 2. Verifies ed25519 signatures on each receipt
//! 3. Hashes each receipt into a Merkle leaf (identical to StubProver::receipt_leaf)
//! 4. Builds a binary Merkle tree from the leaves
//! 5. Commits (root, batch_count, sender_pubkey) to the journal
//!
//! The verifier checks that the committed sender_pubkey matches the relay
//! that gossiped the ProofMessage, proving the relay actually forwarded
//! those shards.

#![no_main]
#![no_std]

extern crate alloc;
use alloc::vec::Vec;

use ed25519_dalek::{Signature, VerifyingKey};
use risc0_zkvm::guest::env;
use sha2::{Digest, Sha256};

use tunnelcraft_prover_guest_types::{GuestInput, GuestOutput, GuestReceipt};

risc0_zkvm::guest::entry!(main);

fn main() {
    let input: GuestInput = env::read();

    assert!(!input.receipts.is_empty(), "empty batch");

    // 1. All receipts must have the same sender (anti-Sybil) and same epoch (anti-replay)
    let sender = input.receipts[0].sender_pubkey;
    let epoch = input.receipts[0].epoch;
    for r in &input.receipts {
        assert_eq!(
            r.sender_pubkey, sender,
            "all receipts must have the same sender_pubkey"
        );
        assert_eq!(
            r.epoch, epoch,
            "all receipts must have the same epoch"
        );
    }

    // 2 + 3. Verify signatures and build leaves
    let mut leaves: Vec<[u8; 32]> = Vec::with_capacity(input.receipts.len());

    for receipt in &input.receipts {
        // Reconstruct signable data (must match ForwardReceipt::signable_data)
        let signable = signable_data(receipt);

        // Verify ed25519 signature (uses risc0's ed25519 precompile)
        let verifying_key = VerifyingKey::from_bytes(&receipt.receiver_pubkey)
            .expect("invalid receiver public key");
        let signature = Signature::from_bytes(&receipt.signature);
        verifying_key
            .verify_strict(&signable, &signature)
            .expect("invalid receipt signature");

        // Hash into leaf (must match StubProver::receipt_leaf)
        let leaf = receipt_leaf(receipt);
        leaves.push(leaf);
    }

    // 4. Build Merkle root (must match MerkleTree::from_leaves)
    let root = merkle_root(&leaves);

    // 5. Commit output
    let output = GuestOutput {
        root,
        batch_count: input.receipts.len() as u64,
        sender_pubkey: sender,
        epoch,
    };
    env::commit(&output);
}

/// Reconstruct signable data matching ForwardReceipt::signable_data().
///
/// Layout (180 bytes):
///   request_id (32) || shard_id (32) || sender_pubkey (32) ||
///   receiver_pubkey (32) || blind_token (32) || payload_size_le (4) || epoch_le (8) || timestamp_le (8)
fn signable_data(receipt: &GuestReceipt) -> Vec<u8> {
    let mut data = Vec::with_capacity(180);
    data.extend_from_slice(&receipt.request_id);
    data.extend_from_slice(&receipt.shard_id);
    data.extend_from_slice(&receipt.sender_pubkey);
    data.extend_from_slice(&receipt.receiver_pubkey);
    data.extend_from_slice(&receipt.blind_token);
    data.extend_from_slice(&receipt.payload_size.to_le_bytes());
    data.extend_from_slice(&receipt.epoch.to_le_bytes());
    data.extend_from_slice(&receipt.timestamp.to_le_bytes());
    data
}

/// Hash a receipt into a Merkle leaf matching StubProver::receipt_leaf().
///
/// SHA256(request_id || shard_id || sender_pubkey || receiver_pubkey || blind_token || payload_size_le || epoch_le || timestamp_le)
fn receipt_leaf(receipt: &GuestReceipt) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(&receipt.request_id);
    hasher.update(&receipt.shard_id);
    hasher.update(&receipt.sender_pubkey);
    hasher.update(&receipt.receiver_pubkey);
    hasher.update(&receipt.blind_token);
    hasher.update(&receipt.payload_size.to_le_bytes());
    hasher.update(&receipt.epoch.to_le_bytes());
    hasher.update(&receipt.timestamp.to_le_bytes());
    let result = hasher.finalize();
    let mut leaf = [0u8; 32];
    leaf.copy_from_slice(&result);
    leaf
}

/// Build Merkle root matching MerkleTree::from_leaves().
///
/// Pad to next power of 2 with [0u8; 32], then bottom-up:
///   parent = SHA256(left || right)
fn merkle_root(leaves: &[[u8; 32]]) -> [u8; 32] {
    if leaves.is_empty() {
        return [0u8; 32];
    }
    if leaves.len() == 1 {
        return leaves[0];
    }

    // Pad to next power of 2
    let n = leaves.len().next_power_of_two();
    let mut nodes: Vec<[u8; 32]> = Vec::with_capacity(n);
    nodes.extend_from_slice(leaves);
    while nodes.len() < n {
        nodes.push([0u8; 32]);
    }

    // Bottom-up merge
    while nodes.len() > 1 {
        let mut next = Vec::with_capacity(nodes.len() / 2);
        for i in (0..nodes.len()).step_by(2) {
            let mut hasher = Sha256::new();
            hasher.update(&nodes[i]);
            hasher.update(&nodes[i + 1]);
            let result = hasher.finalize();
            let mut parent = [0u8; 32];
            parent.copy_from_slice(&result);
            next.push(parent);
        }
        nodes = next;
    }

    nodes[0]
}
