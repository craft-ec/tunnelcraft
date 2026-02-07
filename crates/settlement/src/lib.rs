//! TunnelCraft Settlement
//!
//! Solana client for on-chain settlement and subscription management.
//!
//! ## Settlement Flow (Per-User Pool Model)
//!
//! 1. **Subscribe**: User purchases a subscription tier (Basic/Standard/Premium).
//!    Payment goes into the user's pool PDA.
//! 2. **Submit Receipts**: Relays batch ForwardReceipts and submit them on-chain.
//!    Each receipt is deduped by `PDA(["receipt", pool_pda, SHA256(request_id || shard_id || receiver_pubkey)])`.
//! 3. **Claim Rewards**: End of cycle, relays claim proportional share:
//!    `relay_payout = (relay_receipts / total_receipts) * pool_balance`
//! 4. **Withdraw**: Nodes withdraw accumulated rewards to their wallet.

mod client;
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

    #[error("Serialization error: {0}")]
    SerializationError(String),
}

pub type Result<T> = std::result::Result<T, SettlementError>;
