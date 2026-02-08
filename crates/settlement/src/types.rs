//! Settlement types for on-chain operations
//!
//! New model: Per-epoch subscription + ZK-proven settlement
//!
//! Each subscribe() creates a new epoch (monotonic counter per user).
//! Receipts stay local on the relay. Relays generate ZK proofs per pool,
//! gossip proven summaries, and an aggregator posts distributions on-chain.
//! Claims pay directly from pool PDA to relay wallet (no NodeAccount).

use tunnelcraft_core::{PublicKey, SubscriptionTier};

/// USDC mint address on Solana devnet (`4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU`)
pub const USDC_MINT_DEVNET: [u8; 32] = [
    59, 68, 44, 179, 145, 33, 87, 241, 58, 147, 61, 1, 52, 40, 45, 3,
    43, 95, 254, 205, 1, 162, 219, 241, 183, 121, 6, 8, 223, 0, 46, 167,
];

/// USDC mint address on Solana mainnet (`EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v`)
pub const USDC_MINT_MAINNET: [u8; 32] = [
    198, 250, 122, 243, 190, 219, 173, 58, 61, 101, 243, 106, 171, 201, 116, 49,
    177, 187, 228, 194, 210, 246, 224, 228, 124, 166, 2, 3, 69, 47, 93, 97,
];

/// Grace period after subscription expires before claims open (1 day)
pub const GRACE_PERIOD_SECS: u64 = 86_400;

/// Subscription epoch duration (30 days)
pub const EPOCH_DURATION_SECS: u64 = 30 * 24 * 3600;

/// Epoch phase for a subscription
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EpochPhase {
    /// Subscription is active — relays earning receipts
    Active,
    /// Subscription expired, grace period for final proofs (1 day)
    Grace,
    /// Grace period ended — distribution can be posted, claims open
    Claimable,
    /// Pool fully claimed or expired beyond recovery
    Closed,
}

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

/// Post a Merkle distribution root for a user's pool epoch.
///
/// Called by the aggregator after the grace period ends. Sets the
/// distribution root that relays use to claim their share.
#[derive(Debug, Clone)]
pub struct PostDistribution {
    /// User whose pool this distribution covers
    pub user_pubkey: PublicKey,
    /// Epoch this distribution covers
    pub epoch: u64,
    /// Merkle root of (relay, bytes) distribution
    pub distribution_root: [u8; 32],
    /// Total payload bytes across all relays for this pool
    pub total_bytes: u64,
}

/// Light Protocol parameters for on-chain claim (non-inclusion proof + address tree info).
/// Only needed in live mode — mock mode ignores these.
#[derive(Debug, Clone)]
pub struct ClaimLightParams {
    pub proof_a: [u8; 32],
    pub proof_b: [u8; 64],
    pub proof_c: [u8; 32],
    pub address_merkle_tree_pubkey_index: u8,
    pub address_queue_pubkey_index: u8,
    pub root_index: u16,
    pub output_tree_index: u8,
}

/// Claim rewards from a user's pool using a Merkle proof.
///
/// After distribution is posted, each relay claims its share.
/// Payout transfers directly from pool PDA to relay wallet.
/// Double-claim prevented by compressed ClaimReceipt (Light Protocol).
///
/// payout = (relay_bytes / total_bytes) * pool_balance
#[derive(Debug, Clone)]
pub struct ClaimRewards {
    /// User pool to claim from
    pub user_pubkey: PublicKey,
    /// Epoch to claim from
    pub epoch: u64,
    /// Node claiming rewards
    pub node_pubkey: PublicKey,
    /// Total payload bytes this relay has forwarded (proven by Merkle proof)
    pub relay_bytes: u64,
    /// Index of this relay's leaf in the Merkle tree
    pub leaf_index: u32,
    /// Merkle proof that (node_pubkey, relay_bytes) is in distribution_root
    pub merkle_proof: Vec<[u8; 32]>,
    /// Light Protocol params for compressed ClaimReceipt (None in mock mode)
    pub light_params: Option<ClaimLightParams>,
}

/// On-chain subscription state for a user epoch
#[derive(Debug, Clone)]
pub struct SubscriptionState {
    /// User's public key
    pub user_pubkey: PublicKey,
    /// Subscription epoch (monotonic per user)
    pub epoch: u64,
    /// Active subscription tier
    pub tier: SubscriptionTier,
    /// When the subscription was created (unix seconds)
    pub created_at: u64,
    /// Subscription expiry timestamp (unix seconds)
    pub expires_at: u64,
    /// Pool balance (payment minus claimed rewards)
    pub pool_balance: u64,
    /// Original pool balance at distribution time (for proportional claim calculation)
    pub original_pool_balance: u64,
    /// Total payload bytes across all relays (set by post_distribution)
    pub total_bytes: u64,
    /// Whether distribution has been posted
    pub distribution_posted: bool,
    /// Merkle root of the distribution (set by post_distribution)
    pub distribution_root: [u8; 32],
}

impl SubscriptionState {
    /// Determine the current epoch phase
    pub fn phase(&self, now: u64) -> EpochPhase {
        if now < self.expires_at {
            EpochPhase::Active
        } else if now < self.expires_at + GRACE_PERIOD_SECS {
            EpochPhase::Grace
        } else if self.pool_balance > 0 {
            EpochPhase::Claimable
        } else {
            EpochPhase::Closed
        }
    }
}

/// Light Protocol tree configuration for compressed accounts.
///
/// Specifies which address tree and output queue to use for
/// ClaimReceipt compressed account creation.
#[derive(Debug, Clone)]
pub struct LightTreeConfig {
    /// Address Merkle tree pubkey (32 bytes)
    pub address_tree: [u8; 32],
    /// Output queue pubkey (32 bytes)
    pub output_queue: [u8; 32],
}

impl LightTreeConfig {
    /// Devnet v2 tree configuration (default for devnet).
    ///
    /// Uses the standard Light Protocol devnet v2 trees:
    /// - Address tree: `amt2kaJA14v3urZbZvnc5v2np8jqvc4Z8zDep5wbtzx`
    /// - Output queue: `oq1na8gojfdUhsfCpyjNt6h4JaDWtHf1yQj4koBWfto`
    pub fn devnet_v2() -> Self {
        use crate::light::{ADDRESS_TREE_V2, OUTPUT_QUEUE_V2};
        Self {
            address_tree: ADDRESS_TREE_V2,
            output_queue: OUTPUT_QUEUE_V2,
        }
    }
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
            payment_amount: 15_000_000,
        };

        assert_eq!(sub.user_pubkey, [1u8; 32]);
        assert_eq!(sub.tier, SubscriptionTier::Standard);
        assert_eq!(sub.payment_amount, 15_000_000);
    }

    #[test]
    fn test_post_distribution_creation() {
        let dist = PostDistribution {
            user_pubkey: [1u8; 32],
            epoch: 0,
            distribution_root: [0xAA; 32],
            total_bytes: 1000,
        };

        assert_eq!(dist.user_pubkey, [1u8; 32]);
        assert_eq!(dist.epoch, 0);
        assert_eq!(dist.distribution_root, [0xAA; 32]);
        assert_eq!(dist.total_bytes, 1000);
    }

    #[test]
    fn test_claim_rewards_creation() {
        let claim = ClaimRewards {
            user_pubkey: [1u8; 32],
            epoch: 0,
            node_pubkey: [2u8; 32],
            relay_bytes: 500,
            leaf_index: 0,
            merkle_proof: vec![[0xBB; 32], [0xCC; 32]],
            light_params: None,
        };

        assert_eq!(claim.user_pubkey, [1u8; 32]);
        assert_eq!(claim.epoch, 0);
        assert_eq!(claim.node_pubkey, [2u8; 32]);
        assert_eq!(claim.relay_bytes, 500);
        assert_eq!(claim.merkle_proof.len(), 2);
    }

    #[test]
    fn test_subscription_state_creation() {
        let state = SubscriptionState {
            user_pubkey: [1u8; 32],
            epoch: 0,
            tier: SubscriptionTier::Premium,
            created_at: 1700000000,
            expires_at: 1700000000 + EPOCH_DURATION_SECS,
            pool_balance: 40_000_000,
            original_pool_balance: 40_000_000,
            total_bytes: 0,
            distribution_posted: false,
            distribution_root: [0u8; 32],
        };

        assert_eq!(state.tier, SubscriptionTier::Premium);
        assert_eq!(state.pool_balance, 40_000_000);
        assert!(!state.distribution_posted);
    }

    #[test]
    fn test_epoch_phase_active() {
        let now = 1700000000;
        let state = SubscriptionState {
            user_pubkey: [1u8; 32],
            epoch: 0,
            tier: SubscriptionTier::Standard,
            created_at: now,
            expires_at: now + EPOCH_DURATION_SECS,
            pool_balance: 1_000_000,
            original_pool_balance: 1_000_000,
            total_bytes: 0,
            distribution_posted: false,
            distribution_root: [0u8; 32],
        };

        assert_eq!(state.phase(now + 100), EpochPhase::Active);
    }

    #[test]
    fn test_epoch_phase_grace() {
        let now = 1700000000;
        let expires_at = now + EPOCH_DURATION_SECS;
        let state = SubscriptionState {
            user_pubkey: [1u8; 32],
            epoch: 0,
            tier: SubscriptionTier::Standard,
            created_at: now,
            expires_at,
            pool_balance: 1_000_000,
            original_pool_balance: 1_000_000,
            total_bytes: 0,
            distribution_posted: false,
            distribution_root: [0u8; 32],
        };

        // Just after expiry — should be Grace
        assert_eq!(state.phase(expires_at + 1), EpochPhase::Grace);
        // Just before grace ends
        assert_eq!(state.phase(expires_at + GRACE_PERIOD_SECS - 1), EpochPhase::Grace);
    }

    #[test]
    fn test_epoch_phase_claimable() {
        let now = 1700000000;
        let expires_at = now + EPOCH_DURATION_SECS;
        let state = SubscriptionState {
            user_pubkey: [1u8; 32],
            epoch: 0,
            tier: SubscriptionTier::Standard,
            created_at: now,
            expires_at,
            pool_balance: 1_000_000,
            original_pool_balance: 1_000_000,
            total_bytes: 0,
            distribution_posted: false,
            distribution_root: [0u8; 32],
        };

        // After grace period, with balance remaining
        assert_eq!(state.phase(expires_at + GRACE_PERIOD_SECS + 1), EpochPhase::Claimable);
    }

    #[test]
    fn test_epoch_phase_closed() {
        let now = 1700000000;
        let expires_at = now + EPOCH_DURATION_SECS;
        let state = SubscriptionState {
            user_pubkey: [1u8; 32],
            epoch: 0,
            tier: SubscriptionTier::Standard,
            created_at: now,
            expires_at,
            pool_balance: 0, // Fully drained
            original_pool_balance: 1_000_000,
            total_bytes: 100,
            distribution_posted: true,
            distribution_root: [0xAA; 32],
        };

        // After grace, pool drained → Closed
        assert_eq!(state.phase(expires_at + GRACE_PERIOD_SECS + 1), EpochPhase::Closed);
    }

    #[test]
    fn test_grace_period_constant() {
        assert_eq!(GRACE_PERIOD_SECS, 86_400); // 1 day
    }

    #[test]
    fn test_epoch_duration_constant() {
        assert_eq!(EPOCH_DURATION_SECS, 30 * 24 * 3600); // 30 days
    }
}
