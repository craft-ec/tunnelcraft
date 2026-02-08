//! Shared types between the risc0 guest program and the host prover.
//!
//! These types are `no_std`-compatible so they can be used inside the
//! risc0 RISC-V VM guest as well as by the host-side `Risc0Prover`.

#![no_std]

extern crate alloc;
use alloc::vec::Vec;

use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;

/// A single forward receipt as seen by the guest program.
///
/// Contains the receipt fields needed for signature verification and
/// Merkle leaf hashing. The guest verifies ed25519 signatures and
/// builds a Merkle tree from these receipts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuestReceipt {
    pub request_id: [u8; 32],
    pub shard_id: [u8; 32],
    /// Relay that forwarded the shard (bound to prevent Sybil re-proving)
    pub sender_pubkey: [u8; 32],
    pub receiver_pubkey: [u8; 32],
    pub user_proof: [u8; 32],
    /// Subscription epoch (prevents cross-epoch replay)
    pub epoch: u64,
    pub timestamp: u64,
    /// ed25519 signature from the receiver over all fields
    #[serde(with = "BigArray")]
    pub signature: [u8; 64],
}

/// Input to the guest program: a batch of receipts to prove.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuestInput {
    pub receipts: Vec<GuestReceipt>,
}

/// Output committed by the guest program.
///
/// The verifier checks:
/// - `root` matches `ProofMessage.new_root`
/// - `batch_count` matches `ProofMessage.batch_count`
/// - `sender_pubkey` matches `ProofMessage.relay_pubkey` (anti-Sybil)
/// - `epoch` matches `ProofMessage.epoch` (anti-replay)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuestOutput {
    /// Merkle root of the receipt batch
    pub root: [u8; 32],
    /// Number of receipts in this batch
    pub batch_count: u64,
    /// The sender (relay) pubkey — all receipts must have the same sender
    pub sender_pubkey: [u8; 32],
    /// Subscription epoch — all receipts must have the same epoch
    pub epoch: u64,
}
