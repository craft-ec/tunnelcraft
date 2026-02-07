//! Settlement types for on-chain operations
//!
//! New model: Subscription + Per-User Pool + ForwardReceipt proof of work

use tunnelcraft_core::{PublicKey, ForwardReceipt, SubscriptionTier};

/// Subscribe instruction data
#[derive(Debug, Clone)]
pub struct Subscribe {
    /// User's public key
    pub user_pubkey: PublicKey,
    /// Subscription tier
    pub tier: SubscriptionTier,
    /// Payment amount in lamports (USDC in production)
    pub payment_amount: u64,
}

/// Submit receipts for a user's pool
///
/// Relays batch their ForwardReceipts and submit them on-chain.
/// Each receipt is deduped by PDA(["receipt", pool_pda, SHA256(request_id || shard_index || receiver_pubkey)]).
#[derive(Debug, Clone)]
pub struct SubmitReceipts {
    /// User whose pool these receipts draw from
    pub user_pubkey: PublicKey,
    /// ForwardReceipts proving work done
    pub receipts: Vec<ForwardReceipt>,
}

/// Claim rewards from a user's pool
///
/// End of cycle: relay_payout = (relay_receipts / total_receipts) * pool_balance.
/// Proportional distribution based on verified ForwardReceipts.
#[derive(Debug, Clone)]
pub struct ClaimRewards {
    /// User pool to claim from
    pub user_pubkey: PublicKey,
    /// Node claiming rewards
    pub node_pubkey: PublicKey,
    /// Cycle/epoch to claim from
    pub epoch: u64,
}

/// Withdraw accumulated rewards to wallet
#[derive(Debug, Clone)]
pub struct Withdraw {
    /// Epoch to withdraw from
    pub epoch: u64,
    /// Amount to withdraw (0 = all available)
    pub amount: u64,
}

/// On-chain subscription state for a user
#[derive(Debug, Clone)]
pub struct SubscriptionState {
    /// User's public key
    pub user_pubkey: PublicKey,
    /// Active subscription tier
    pub tier: SubscriptionTier,
    /// Subscription expiry timestamp (unix seconds)
    pub expires_at: u64,
    /// Pool balance (payment minus claimed rewards)
    pub pool_balance: u64,
    /// Total receipts submitted against this pool
    pub total_receipts: u64,
}

/// Node's on-chain account tracking receipts and rewards
#[derive(Debug, Clone)]
pub struct NodeAccount {
    /// Node's public key
    pub node_pubkey: PublicKey,
    /// Receipts submitted in current epoch
    pub current_epoch_receipts: u64,
    /// Total receipts ever submitted
    pub lifetime_receipts: u64,
    /// Unclaimed reward balance (lamports)
    pub unclaimed_rewards: u64,
    /// Last withdrawal epoch
    pub last_withdrawal_epoch: u64,
}

/// Transaction signature (Solana format)
pub type TransactionSignature = [u8; 64];

/// On-chain account address
pub type AccountAddress = [u8; 32];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_subscribe_creation() {
        let sub = Subscribe {
            user_pubkey: [1u8; 32],
            tier: SubscriptionTier::Standard,
            payment_amount: 15_000_000, // 15 USDC in micro-units
        };

        assert_eq!(sub.user_pubkey, [1u8; 32]);
        assert_eq!(sub.tier, SubscriptionTier::Standard);
        assert_eq!(sub.payment_amount, 15_000_000);
    }

    #[test]
    fn test_submit_receipts_empty() {
        let submit = SubmitReceipts {
            user_pubkey: [1u8; 32],
            receipts: vec![],
        };

        assert!(submit.receipts.is_empty());
    }

    #[test]
    fn test_submit_receipts_with_data() {
        let receipt = ForwardReceipt {
            request_id: [1u8; 32],
            shard_index: 0,
            receiver_pubkey: [2u8; 32],
            timestamp: 1000,
            signature: [0u8; 64],
        };

        let submit = SubmitReceipts {
            user_pubkey: [3u8; 32],
            receipts: vec![receipt],
        };

        assert_eq!(submit.receipts.len(), 1);
        assert_eq!(submit.receipts[0].shard_index, 0);
    }

    #[test]
    fn test_claim_rewards_creation() {
        let claim = ClaimRewards {
            user_pubkey: [1u8; 32],
            node_pubkey: [2u8; 32],
            epoch: 42,
        };

        assert_eq!(claim.user_pubkey, [1u8; 32]);
        assert_eq!(claim.node_pubkey, [2u8; 32]);
        assert_eq!(claim.epoch, 42);
    }

    #[test]
    fn test_withdraw_all() {
        let withdraw = Withdraw {
            epoch: 42,
            amount: 0, // 0 = withdraw all
        };

        assert_eq!(withdraw.epoch, 42);
        assert_eq!(withdraw.amount, 0);
    }

    #[test]
    fn test_withdraw_partial() {
        let withdraw = Withdraw {
            epoch: 100,
            amount: 500,
        };

        assert_eq!(withdraw.epoch, 100);
        assert_eq!(withdraw.amount, 500);
    }

    #[test]
    fn test_subscription_state_creation() {
        let state = SubscriptionState {
            user_pubkey: [1u8; 32],
            tier: SubscriptionTier::Premium,
            expires_at: 1700000000,
            pool_balance: 40_000_000,
            total_receipts: 0,
        };

        assert_eq!(state.tier, SubscriptionTier::Premium);
        assert_eq!(state.pool_balance, 40_000_000);
    }

    #[test]
    fn test_node_account_creation() {
        let node = NodeAccount {
            node_pubkey: [1u8; 32],
            current_epoch_receipts: 500,
            lifetime_receipts: 10000,
            unclaimed_rewards: 1_000_000,
            last_withdrawal_epoch: 5,
        };

        assert_eq!(node.current_epoch_receipts, 500);
        assert_eq!(node.lifetime_receipts, 10000);
        assert_eq!(node.unclaimed_rewards, 1_000_000);
    }

    #[test]
    fn test_node_account_zero_state() {
        let node = NodeAccount {
            node_pubkey: [0u8; 32],
            current_epoch_receipts: 0,
            lifetime_receipts: 0,
            unclaimed_rewards: 0,
            last_withdrawal_epoch: 0,
        };

        assert_eq!(node.current_epoch_receipts, 0);
        assert_eq!(node.unclaimed_rewards, 0);
    }
}
