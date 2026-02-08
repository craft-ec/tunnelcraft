//! TunnelCraft Settlement
//!
//! Solana client for on-chain settlement and subscription management.
//!
//! ## Settlement Flow (Per-Epoch Subscription + ZK-Proven Settlement)
//!
//! 1. **Subscribe**: User purchases a subscription tier (Basic/Standard/Premium).
//!    Payment goes into a per-epoch pool PDA. UserMeta tracks next_epoch.
//! 2. **Receipts stay local**: Relays collect ForwardReceipts locally and generate
//!    ZK proofs per pool. Proven summaries are gossiped via libp2p.
//! 3. **Post Distribution**: After epoch + grace period, an aggregator posts a
//!    Merkle distribution root on-chain from collected ZK-proven summaries.
//! 4. **Claim Rewards**: Each relay claims proportional share using Merkle proof.
//!    Payout transfers directly from pool PDA to relay wallet (no NodeAccount).
//!    Double-claim prevented by Light Protocol compressed ClaimReceipt.

mod client;
pub mod light;
mod types;

pub use client::{SettlementClient, SettlementConfig, SettlementMode};
pub use types::*;

use thiserror::Error;

#[derive(Error, Debug)]
pub enum SettlementError {
    #[error("RPC error: {0}")]
    RpcError(String),

    #[error("Transaction failed: {0}")]
    TransactionFailed(String),

    #[error("Insufficient credits")]
    InsufficientCredits,

    #[error("Subscription not found: {0}")]
    SubscriptionNotFound(String),

    #[error("Not authorized")]
    NotAuthorized,

    #[error("Epoch not complete")]
    EpochNotComplete,

    #[error("Distribution not posted")]
    DistributionNotPosted,

    #[error("Already claimed")]
    AlreadyClaimed,

    #[error("Distribution already posted for this pool")]
    DistributionAlreadyPosted,

    #[error("Invalid Merkle proof")]
    InvalidMerkleProof,

    #[error("Serialization error: {0}")]
    SerializationError(String),
}

pub type Result<T> = std::result::Result<T, SettlementError>;
