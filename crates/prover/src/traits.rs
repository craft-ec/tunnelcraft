//! Receipt compression trait for pluggable batch compression backends.
//!
//! The default compressor builds a Merkle tree and returns the root.
//! This is a compression format for efficient gossip messaging — one
//! root + cumulative bytes instead of thousands of individual receipts.

use tunnelcraft_core::ForwardReceipt;

/// Output of receipt batch compression.
#[derive(Debug, Clone)]
pub struct CompressedBatch {
    /// Merkle root of the compressed receipt batch.
    pub root: [u8; 32],
}

/// Errors from receipt compression.
#[derive(Debug, thiserror::Error)]
pub enum CompressionError {
    #[error("Empty batch")]
    EmptyBatch,

    #[error("Compression failed: {0}")]
    CompressionFailed(String),
}

/// Pluggable receipt compression trait.
///
/// Implementations compress a batch of `ForwardReceipt`s into a single
/// Merkle root for efficient gossip dissemination. Receipts are already
/// unforgeable (signed by the next-hop relay), so no ZK proof is needed.
pub trait ReceiptCompression: Send + Sync {
    /// Compress a batch of receipts into a Merkle root.
    fn compress(&self, batch: &[ForwardReceipt]) -> Result<CompressedBatch, CompressionError>;
}
