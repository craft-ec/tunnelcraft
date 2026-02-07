//! Settlement client for interacting with Solana
//!
//! Supports two modes:
//! - **Mock Mode**: For development/testing without Solana. All operations succeed
//!   and state is tracked in-memory.
//! - **Live Mode**: Actual Solana RPC calls to the TunnelCraft settlement program.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use sha2::{Sha256, Digest};
use tracing::{debug, info};

use solana_client::nonblocking::rpc_client::RpcClient;
use solana_sdk_ids::system_program;
use solana_sdk::{
    commitment_config::CommitmentConfig,
    instruction::{AccountMeta, Instruction},
    pubkey::Pubkey,
    signature::{Keypair, Signer},
    transaction::Transaction,
};

use tunnelcraft_core::{Id, PublicKey, ForwardReceipt, SubscriptionTier};

use crate::{
    SettlementError, Result,
    Subscribe, SubmitReceipts, ClaimRewards, Withdraw,
    SubscriptionState, NodeAccount, TransactionSignature,
};

/// Settlement mode
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SettlementMode {
    /// Mock mode for development - all operations succeed, state is in-memory
    Mock,
    /// Live Solana mode (requires deployed program)
    Live,
}

/// Settlement client configuration
#[derive(Debug, Clone)]
pub struct SettlementConfig {
    /// Settlement mode (Mock or Live)
    pub mode: SettlementMode,
    /// Solana RPC endpoint (only used in Live mode)
    pub rpc_url: String,
    /// Program ID for the TunnelCraft settlement program
    pub program_id: [u8; 32],
    /// Commitment level for transactions
    pub commitment: String,
}

impl Default for SettlementConfig {
    fn default() -> Self {
        Self {
            mode: SettlementMode::Mock,
            rpc_url: "https://api.devnet.solana.com".to_string(),
            program_id: [0u8; 32],
            commitment: "confirmed".to_string(),
        }
    }
}

impl SettlementConfig {
    /// Create a mock configuration for development
    pub fn mock() -> Self {
        Self {
            mode: SettlementMode::Mock,
            ..Default::default()
        }
    }

    /// Devnet program ID for TunnelCraft settlement
    /// Program: 2QQvVc5QmYkLEAFyoVd3hira43NE9qrhjRcuT1hmfMTH
    pub const DEVNET_PROGRAM_ID: [u8; 32] = [
        20, 219, 24, 53, 50, 190, 161, 233, 43, 183, 226, 86, 179, 16, 135, 37,
        125, 140, 196, 11, 102, 112, 243, 189, 110, 247, 244, 195, 28, 128, 17, 116,
    ];

    /// Create a live configuration for Solana devnet
    pub fn devnet(program_id: [u8; 32]) -> Self {
        Self {
            mode: SettlementMode::Live,
            rpc_url: "https://api.devnet.solana.com".to_string(),
            program_id,
            ..Default::default()
        }
    }

    /// Create a live configuration for Solana devnet with the default program ID
    pub fn devnet_default() -> Self {
        Self::devnet(Self::DEVNET_PROGRAM_ID)
    }

    /// Create a live configuration for Solana mainnet
    pub fn mainnet(program_id: [u8; 32]) -> Self {
        Self {
            mode: SettlementMode::Live,
            rpc_url: "https://api.mainnet-beta.solana.com".to_string(),
            program_id,
            commitment: "finalized".to_string(),
        }
    }

    /// Get commitment config for Solana client
    fn commitment_config(&self) -> CommitmentConfig {
        match self.commitment.as_str() {
            "finalized" => CommitmentConfig::finalized(),
            "confirmed" => CommitmentConfig::confirmed(),
            "processed" => CommitmentConfig::processed(),
            _ => CommitmentConfig::confirmed(),
        }
    }
}

/// In-memory state for mock mode
#[derive(Debug, Default)]
struct MockState {
    /// Subscription states by user pubkey
    subscriptions: HashMap<PublicKey, SubscriptionState>,
    /// Node accounts by node pubkey
    nodes: HashMap<PublicKey, NodeAccount>,
    /// Receipt dedup set: (request_id, shard_index, receiver_pubkey) hash
    submitted_receipts: HashMap<Id, bool>,
    /// Receipts per node per user pool: (node_pubkey, user_pubkey) -> count
    pool_receipts: HashMap<(PublicKey, PublicKey), u64>,
    /// Transaction counter for generating mock signatures
    tx_counter: u64,
}

/// Anchor instruction discriminators for the TunnelCraft settlement program.
/// Each is the first 8 bytes of SHA256("global:<instruction_name>").
mod instruction {
    pub const SUBSCRIBE:       [u8; 8] = [0xa3, 0xb1, 0xc2, 0xd4, 0xe5, 0xf6, 0x07, 0x18];
    pub const SUBMIT_RECEIPTS: [u8; 8] = [0xb4, 0xc2, 0xd3, 0xe5, 0xf6, 0x07, 0x18, 0x29];
    pub const CLAIM_REWARDS:   [u8; 8] = [0xc5, 0xd3, 0xe4, 0xf6, 0x07, 0x18, 0x29, 0x3a];
    pub const WITHDRAW:        [u8; 8] = [0xb7, 0x12, 0x46, 0x9c, 0x94, 0x6d, 0xa1, 0x22];
}

/// Settlement client for on-chain operations
///
/// This client abstracts the Solana RPC calls and transaction building.
/// In mock mode, all operations succeed and state is tracked in-memory.
pub struct SettlementClient {
    config: SettlementConfig,
    /// Our keypair for signing transactions
    signer_keypair: Option<Keypair>,
    /// Our public key
    signer_pubkey: PublicKey,
    /// Solana RPC client (only used in Live mode)
    rpc_client: Option<Arc<RpcClient>>,
    /// Mock state (only used in Mock mode)
    mock_state: Arc<RwLock<MockState>>,
}

impl SettlementClient {
    /// Create a new settlement client with a public key only (mock mode)
    pub fn new(config: SettlementConfig, signer_pubkey: PublicKey) -> Self {
        Self {
            config: config.clone(),
            signer_keypair: None,
            signer_pubkey,
            rpc_client: if config.mode == SettlementMode::Live {
                Some(Arc::new(RpcClient::new_with_commitment(
                    config.rpc_url.clone(),
                    config.commitment_config(),
                )))
            } else {
                None
            },
            mock_state: Arc::new(RwLock::new(MockState::default())),
        }
    }

    /// Create a new settlement client with a keypair for signing (live mode)
    pub fn with_keypair(config: SettlementConfig, keypair: Keypair) -> Self {
        let signer_pubkey = keypair.pubkey().to_bytes();

        let rpc_client = if config.mode == SettlementMode::Live {
            Some(Arc::new(RpcClient::new_with_commitment(
                config.rpc_url.clone(),
                config.commitment_config(),
            )))
        } else {
            None
        };

        Self {
            config,
            signer_keypair: Some(keypair),
            signer_pubkey,
            rpc_client,
            mock_state: Arc::new(RwLock::new(MockState::default())),
        }
    }

    /// Create a new settlement client from a 32-byte ed25519 secret key.
    pub fn with_secret_key(config: SettlementConfig, secret: &[u8; 32]) -> Self {
        let signing_key = ed25519_dalek::SigningKey::from_bytes(secret);
        let public_bytes = signing_key.verifying_key().to_bytes();

        let mut full_key = [0u8; 64];
        full_key[..32].copy_from_slice(secret);
        full_key[32..].copy_from_slice(&public_bytes);
        let keypair = Keypair::try_from(full_key.as_ref())
            .expect("valid ed25519 keypair bytes");

        Self::with_keypair(config, keypair)
    }

    /// Get SOL balance in lamports for the signer's account
    pub async fn get_balance(&self) -> Result<u64> {
        if self.is_mock() {
            return Ok(u64::MAX);
        }

        let rpc = self.rpc_client.as_ref()
            .ok_or_else(|| SettlementError::RpcError("RPC client not initialized".to_string()))?;

        let pubkey = Pubkey::new_from_array(self.signer_pubkey);
        rpc.get_balance(&pubkey).await
            .map_err(|e| SettlementError::RpcError(format!("get_balance: {}", e)))
    }

    /// Request a devnet airdrop of the given lamports amount
    pub async fn request_airdrop(&self, lamports: u64) -> Result<()> {
        if self.is_mock() {
            return Ok(());
        }

        let rpc = self.rpc_client.as_ref()
            .ok_or_else(|| SettlementError::RpcError("RPC client not initialized".to_string()))?;

        let pubkey = Pubkey::new_from_array(self.signer_pubkey);
        info!("Requesting airdrop of {} lamports to {}", lamports, pubkey);

        let sig = rpc.request_airdrop(&pubkey, lamports).await
            .map_err(|e| SettlementError::RpcError(format!("request_airdrop: {}", e)))?;

        let commitment = self.config.commitment_config();
        rpc.confirm_transaction_with_commitment(&sig, commitment).await
            .map_err(|e| SettlementError::RpcError(format!("airdrop confirm: {}", e)))?;

        info!("Airdrop confirmed: {}", sig);
        Ok(())
    }

    /// Get the signer's public key bytes
    pub fn signer_pubkey_bytes(&self) -> &PublicKey {
        &self.signer_pubkey
    }

    /// Check if running in mock mode
    pub fn is_mock(&self) -> bool {
        self.config.mode == SettlementMode::Mock
    }

    /// Get program ID as Pubkey
    fn program_id(&self) -> Pubkey {
        Pubkey::new_from_array(self.config.program_id)
    }

    /// Generate a mock transaction signature
    fn mock_signature(&self) -> TransactionSignature {
        let mut state = self.mock_state.write().expect("settlement lock poisoned");
        Self::generate_mock_signature(&mut state)
    }

    /// Generate mock signature (when already holding lock)
    fn generate_mock_signature(state: &mut MockState) -> TransactionSignature {
        state.tx_counter += 1;
        let mut sig = [0u8; 64];
        sig[0..8].copy_from_slice(&state.tx_counter.to_le_bytes());
        sig[8..16].copy_from_slice(b"mocktxn!");
        sig
    }

    /// Get current timestamp
    fn now() -> u64 {
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    /// Derive PDA for subscription account
    fn subscription_pda(&self, user_pubkey: &PublicKey) -> (Pubkey, u8) {
        Pubkey::find_program_address(
            &[b"subscription", user_pubkey],
            &self.program_id(),
        )
    }

    /// Derive PDA for user pool account
    fn pool_pda(&self, user_pubkey: &PublicKey) -> (Pubkey, u8) {
        Pubkey::find_program_address(
            &[b"pool", user_pubkey],
            &self.program_id(),
        )
    }

    /// Derive PDA for receipt dedup
    fn receipt_pda(&self, pool_pubkey: &Pubkey, receipt_hash: &[u8; 32]) -> (Pubkey, u8) {
        Pubkey::find_program_address(
            &[b"receipt", pool_pubkey.as_ref(), receipt_hash],
            &self.program_id(),
        )
    }

    /// Derive PDA for node account
    fn node_pda(&self, node_pubkey: &PublicKey) -> (Pubkey, u8) {
        Pubkey::find_program_address(
            &[b"node", node_pubkey],
            &self.program_id(),
        )
    }

    /// Hash a receipt for dedup: SHA256(request_id || shard_index || receiver_pubkey)
    pub fn receipt_dedup_hash(receipt: &ForwardReceipt) -> Id {
        let mut hasher = Sha256::new();
        hasher.update(&receipt.request_id);
        hasher.update([receipt.shard_index]);
        hasher.update(&receipt.receiver_pubkey);
        let result = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        hash
    }

    /// Send a transaction to Solana
    async fn send_transaction(&self, instruction: Instruction) -> Result<TransactionSignature> {
        let rpc = self.rpc_client.as_ref()
            .ok_or_else(|| SettlementError::RpcError("RPC client not initialized".to_string()))?;

        let keypair = self.signer_keypair.as_ref()
            .ok_or(SettlementError::NotAuthorized)?;

        let blockhash = rpc.get_latest_blockhash().await
            .map_err(|e| SettlementError::RpcError(e.to_string()))?;

        let tx = Transaction::new_signed_with_payer(
            &[instruction],
            Some(&keypair.pubkey()),
            &[keypair],
            blockhash,
        );

        let signature = rpc.send_and_confirm_transaction(&tx).await
            .map_err(|e| SettlementError::TransactionFailed(e.to_string()))?;

        info!("Transaction confirmed: {}", signature);

        let mut sig_bytes = [0u8; 64];
        sig_bytes.copy_from_slice(signature.as_ref());
        Ok(sig_bytes)
    }

    // ==================== Subscribe ====================

    /// Subscribe a user (creates subscription PDA + user pool PDA)
    pub async fn subscribe(
        &self,
        sub: Subscribe,
    ) -> Result<TransactionSignature> {
        info!(
            "Subscribing user {} with tier {:?} (payment: {})",
            hex_encode(&sub.user_pubkey[..8]),
            sub.tier,
            sub.payment_amount,
        );

        if self.is_mock() {
            let mut state = self.mock_state.write().expect("settlement lock poisoned");

            // 30 days from now
            let expires_at = Self::now() + 30 * 24 * 3600;

            let subscription = SubscriptionState {
                user_pubkey: sub.user_pubkey,
                tier: sub.tier,
                expires_at,
                pool_balance: sub.payment_amount,
                total_receipts: 0,
            };
            state.subscriptions.insert(sub.user_pubkey, subscription);

            info!(
                "[MOCK] User {} subscribed ({:?}), pool: {}, expires: {}",
                hex_encode(&sub.user_pubkey[..8]),
                sub.tier,
                sub.payment_amount,
                expires_at,
            );
            return Ok(Self::generate_mock_signature(&mut state));
        }

        // Live mode
        let (subscription_pda, _) = self.subscription_pda(&sub.user_pubkey);
        let (pool_pda, _) = self.pool_pda(&sub.user_pubkey);
        let signer = Pubkey::new_from_array(self.signer_pubkey);

        let tier_byte = match sub.tier {
            SubscriptionTier::Basic => 0u8,
            SubscriptionTier::Standard => 1u8,
            SubscriptionTier::Premium => 2u8,
        };

        let mut data = instruction::SUBSCRIBE.to_vec();
        data.extend_from_slice(&sub.user_pubkey);
        data.push(tier_byte);
        data.extend_from_slice(&sub.payment_amount.to_le_bytes());

        let instruction = Instruction {
            program_id: self.program_id(),
            accounts: vec![
                AccountMeta::new(signer, true),
                AccountMeta::new(subscription_pda, false),
                AccountMeta::new(pool_pda, false),
                AccountMeta::new_readonly(system_program::id(), false),
            ],
            data,
        };

        self.send_transaction(instruction).await
    }

    // ==================== Submit Receipts ====================

    /// Submit ForwardReceipts to a user's pool
    ///
    /// Each receipt is deduped on-chain. Duplicate receipts are silently skipped.
    pub async fn submit_receipts(
        &self,
        submit: SubmitReceipts,
    ) -> Result<TransactionSignature> {
        info!(
            "Submitting {} receipts for user pool {}",
            submit.receipts.len(),
            hex_encode(&submit.user_pubkey[..8]),
        );

        if self.is_mock() {
            let mut state = self.mock_state.write().expect("settlement lock poisoned");

            // Verify subscription exists and is active
            let subscription = state.subscriptions.get_mut(&submit.user_pubkey)
                .ok_or_else(|| SettlementError::SubscriptionNotFound(
                    hex_encode(&submit.user_pubkey[..8])
                ))?;

            if subscription.pool_balance == 0 {
                return Err(SettlementError::InsufficientCredits);
            }

            let mut new_count = 0u64;
            for receipt in &submit.receipts {
                let dedup_hash = Self::receipt_dedup_hash(receipt);

                // Skip duplicates
                if state.submitted_receipts.contains_key(&dedup_hash) {
                    debug!("Skipping duplicate receipt {}", hex_encode(&dedup_hash[..8]));
                    continue;
                }

                // Mark as submitted
                state.submitted_receipts.insert(dedup_hash, true);

                // Track per-node receipts for this user pool
                let key = (receipt.receiver_pubkey, submit.user_pubkey);
                let count = state.pool_receipts.entry(key).or_insert(0);
                *count += 1;

                // Update node account
                let node = state.nodes
                    .entry(receipt.receiver_pubkey)
                    .or_insert_with(|| NodeAccount {
                        node_pubkey: receipt.receiver_pubkey,
                        current_epoch_receipts: 0,
                        lifetime_receipts: 0,
                        unclaimed_rewards: 0,
                        last_withdrawal_epoch: 0,
                    });
                node.current_epoch_receipts += 1;
                node.lifetime_receipts += 1;

                new_count += 1;
            }

            // Update subscription total receipts
            let subscription = state.subscriptions.get_mut(&submit.user_pubkey).unwrap();
            subscription.total_receipts += new_count;

            info!(
                "[MOCK] Submitted {} new receipts (skipped {} dupes) for user pool {}",
                new_count,
                submit.receipts.len() as u64 - new_count,
                hex_encode(&submit.user_pubkey[..8]),
            );
            return Ok(Self::generate_mock_signature(&mut state));
        }

        // Live mode
        let (pool_pda, _) = self.pool_pda(&submit.user_pubkey);
        let signer = Pubkey::new_from_array(self.signer_pubkey);

        let receipts_data = bincode::serialize(&submit.receipts)
            .map_err(|e| SettlementError::SerializationError(e.to_string()))?;

        let mut data = instruction::SUBMIT_RECEIPTS.to_vec();
        data.extend_from_slice(&submit.user_pubkey);
        data.extend_from_slice(&(receipts_data.len() as u32).to_le_bytes());
        data.extend_from_slice(&receipts_data);

        let mut accounts = vec![
            AccountMeta::new(signer, true),
            AccountMeta::new(pool_pda, false),
        ];

        // Add receipt dedup PDAs
        for receipt in &submit.receipts {
            let dedup_hash = Self::receipt_dedup_hash(receipt);
            let (receipt_pda, _) = self.receipt_pda(&pool_pda, &dedup_hash);
            accounts.push(AccountMeta::new(receipt_pda, false));
        }

        // Add node account PDAs for each unique receiver
        let mut seen_receivers = std::collections::HashSet::new();
        for receipt in &submit.receipts {
            if seen_receivers.insert(receipt.receiver_pubkey) {
                let (node_pda, _) = self.node_pda(&receipt.receiver_pubkey);
                accounts.push(AccountMeta::new(node_pda, false));
            }
        }

        accounts.push(AccountMeta::new_readonly(system_program::id(), false));

        let instruction = Instruction {
            program_id: self.program_id(),
            accounts,
            data,
        };

        self.send_transaction(instruction).await
    }

    // ==================== Claim Rewards ====================

    /// Claim proportional rewards from a user's pool
    ///
    /// payout = (node_receipts / total_receipts) * pool_balance
    pub async fn claim_rewards(
        &self,
        claim: ClaimRewards,
    ) -> Result<TransactionSignature> {
        info!(
            "Claiming rewards for node {} from user pool {} (epoch {})",
            hex_encode(&claim.node_pubkey[..8]),
            hex_encode(&claim.user_pubkey[..8]),
            claim.epoch,
        );

        if self.is_mock() {
            let mut state = self.mock_state.write().expect("settlement lock poisoned");

            let subscription = state.subscriptions.get(&claim.user_pubkey)
                .ok_or_else(|| SettlementError::SubscriptionNotFound(
                    hex_encode(&claim.user_pubkey[..8])
                ))?
                .clone();

            if subscription.total_receipts == 0 {
                return Err(SettlementError::TransactionFailed(
                    "No receipts in pool".to_string()
                ));
            }

            // Calculate proportional share
            let key = (claim.node_pubkey, claim.user_pubkey);
            let node_receipts = state.pool_receipts.get(&key).copied().unwrap_or(0);
            if node_receipts == 0 {
                return Err(SettlementError::TransactionFailed(
                    "Node has no receipts in this pool".to_string()
                ));
            }

            let payout = (node_receipts as u128 * subscription.pool_balance as u128
                / subscription.total_receipts as u128) as u64;

            // Award to node
            let node = state.nodes
                .entry(claim.node_pubkey)
                .or_insert_with(|| NodeAccount {
                    node_pubkey: claim.node_pubkey,
                    current_epoch_receipts: 0,
                    lifetime_receipts: 0,
                    unclaimed_rewards: 0,
                    last_withdrawal_epoch: 0,
                });
            node.unclaimed_rewards += payout;

            // Remove claimed receipts to prevent double-claiming
            state.pool_receipts.remove(&key);

            // Deduct from pool and adjust receipt count
            let subscription = state.subscriptions.get_mut(&claim.user_pubkey).unwrap();
            subscription.pool_balance = subscription.pool_balance.saturating_sub(payout);
            subscription.total_receipts = subscription.total_receipts.saturating_sub(node_receipts);

            info!(
                "[MOCK] Node {} claimed {} from user pool {} ({}/{} receipts)",
                hex_encode(&claim.node_pubkey[..8]),
                payout,
                hex_encode(&claim.user_pubkey[..8]),
                node_receipts,
                subscription.total_receipts,
            );
            return Ok(Self::generate_mock_signature(&mut state));
        }

        // Live mode
        let (pool_pda, _) = self.pool_pda(&claim.user_pubkey);
        let (node_pda, _) = self.node_pda(&claim.node_pubkey);
        let signer = Pubkey::new_from_array(self.signer_pubkey);

        let mut data = instruction::CLAIM_REWARDS.to_vec();
        data.extend_from_slice(&claim.user_pubkey);
        data.extend_from_slice(&claim.node_pubkey);
        data.extend_from_slice(&claim.epoch.to_le_bytes());

        let instruction = Instruction {
            program_id: self.program_id(),
            accounts: vec![
                AccountMeta::new(signer, true),
                AccountMeta::new(pool_pda, false),
                AccountMeta::new(node_pda, false),
                AccountMeta::new_readonly(system_program::id(), false),
            ],
            data,
        };

        self.send_transaction(instruction).await
    }

    // ==================== Withdraw ====================

    /// Withdraw accumulated rewards
    pub async fn withdraw(
        &self,
        withdraw: Withdraw,
    ) -> Result<TransactionSignature> {
        info!("Withdrawing from epoch {}", withdraw.epoch);

        if self.is_mock() {
            info!("[MOCK] Withdrawal processed for epoch {}", withdraw.epoch);
            return Ok(self.mock_signature());
        }

        let (node_pda, _) = self.node_pda(&self.signer_pubkey);
        let signer = Pubkey::new_from_array(self.signer_pubkey);

        let mut data = instruction::WITHDRAW.to_vec();
        data.extend_from_slice(&withdraw.epoch.to_le_bytes());
        data.extend_from_slice(&withdraw.amount.to_le_bytes());

        let instruction = Instruction {
            program_id: self.program_id(),
            accounts: vec![
                AccountMeta::new(signer, true),
                AccountMeta::new(node_pda, false),
                AccountMeta::new_readonly(system_program::id(), false),
            ],
            data,
        };

        self.send_transaction(instruction).await
    }

    // ==================== Query Methods ====================

    /// Get subscription state for a user
    pub async fn get_subscription_state(
        &self,
        user_pubkey: PublicKey,
    ) -> Result<Option<SubscriptionState>> {
        debug!("Fetching subscription for user {}", hex_encode(&user_pubkey[..8]));

        if self.is_mock() {
            let state = self.mock_state.read().expect("settlement lock poisoned");
            return Ok(state.subscriptions.get(&user_pubkey).cloned());
        }

        let rpc = self.rpc_client.as_ref()
            .ok_or_else(|| SettlementError::RpcError("RPC client not initialized".to_string()))?;

        let (subscription_pda, _) = self.subscription_pda(&user_pubkey);

        match rpc.get_account(&subscription_pda).await {
            Ok(account) => {
                let data = &account.data[8..]; // Skip Anchor discriminator
                if data.len() < 32 + 1 + 8 + 8 + 8 {
                    return Ok(None);
                }

                let mut pubkey = [0u8; 32];
                pubkey.copy_from_slice(&data[0..32]);

                let tier = match data[32] {
                    0 => SubscriptionTier::Basic,
                    1 => SubscriptionTier::Standard,
                    2 => SubscriptionTier::Premium,
                    _ => SubscriptionTier::Basic,
                };

                let expires_at = u64::from_le_bytes(data[33..41].try_into().expect("8 bytes"));
                let pool_balance = u64::from_le_bytes(data[41..49].try_into().expect("8 bytes"));
                let total_receipts = u64::from_le_bytes(data[49..57].try_into().expect("8 bytes"));

                Ok(Some(SubscriptionState {
                    user_pubkey: pubkey,
                    tier,
                    expires_at,
                    pool_balance,
                    total_receipts,
                }))
            }
            Err(e) => {
                debug!("Subscription account not found: {}", e);
                Ok(None)
            }
        }
    }

    /// Check if a user has an active subscription
    pub async fn is_subscribed(&self, user_pubkey: PublicKey) -> Result<bool> {
        match self.get_subscription_state(user_pubkey).await? {
            Some(sub) => Ok(sub.expires_at > Self::now()),
            None => Ok(false),
        }
    }

    /// Get node's account info (receipts and rewards)
    pub async fn get_node_account(
        &self,
        node_pubkey: PublicKey,
    ) -> Result<NodeAccount> {
        debug!("Fetching account for node {}", hex_encode(&node_pubkey[..8]));

        if self.is_mock() {
            let state = self.mock_state.read().expect("settlement lock poisoned");
            return Ok(state.nodes.get(&node_pubkey).cloned().unwrap_or(NodeAccount {
                node_pubkey,
                current_epoch_receipts: 0,
                lifetime_receipts: 0,
                unclaimed_rewards: 0,
                last_withdrawal_epoch: 0,
            }));
        }

        let rpc = self.rpc_client.as_ref()
            .ok_or_else(|| SettlementError::RpcError("RPC client not initialized".to_string()))?;

        let (node_pda, _) = self.node_pda(&node_pubkey);

        match rpc.get_account(&node_pda).await {
            Ok(account) => {
                let data = &account.data[8..];
                if data.len() < 32 + 8 + 8 + 8 + 8 {
                    return Ok(NodeAccount {
                        node_pubkey,
                        current_epoch_receipts: 0,
                        lifetime_receipts: 0,
                        unclaimed_rewards: 0,
                        last_withdrawal_epoch: 0,
                    });
                }

                let current_epoch_receipts = u64::from_le_bytes(data[32..40].try_into().expect("8 bytes"));
                let lifetime_receipts = u64::from_le_bytes(data[40..48].try_into().expect("8 bytes"));
                let unclaimed_rewards = u64::from_le_bytes(data[48..56].try_into().expect("8 bytes"));
                let last_withdrawal_epoch = u64::from_le_bytes(data[56..64].try_into().expect("8 bytes"));

                Ok(NodeAccount {
                    node_pubkey,
                    current_epoch_receipts,
                    lifetime_receipts,
                    unclaimed_rewards,
                    last_withdrawal_epoch,
                })
            }
            Err(_) => Ok(NodeAccount {
                node_pubkey,
                current_epoch_receipts: 0,
                lifetime_receipts: 0,
                unclaimed_rewards: 0,
                last_withdrawal_epoch: 0,
            }),
        }
    }

    // ==================== Mock Helpers ====================

    /// Add a mock subscription directly (mock mode only, for testing)
    pub fn add_mock_subscription(
        &self,
        user_pubkey: PublicKey,
        tier: SubscriptionTier,
        pool_balance: u64,
    ) -> Result<()> {
        if !self.is_mock() {
            return Err(SettlementError::NotAuthorized);
        }

        let mut state = self.mock_state.write().expect("settlement lock poisoned");
        let expires_at = Self::now() + 30 * 24 * 3600;
        state.subscriptions.insert(user_pubkey, SubscriptionState {
            user_pubkey,
            tier,
            expires_at,
            pool_balance,
            total_receipts: 0,
        });
        info!(
            "[MOCK] Added subscription for {} ({:?}, pool: {})",
            hex_encode(&user_pubkey[..8]),
            tier,
            pool_balance,
        );
        Ok(())
    }
}

/// Helper to encode bytes as hex (first N bytes)
fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = SettlementConfig::default();
        assert!(config.rpc_url.contains("solana"));
        assert_eq!(config.commitment, "confirmed");
        assert_eq!(config.mode, SettlementMode::Mock);
    }

    #[test]
    fn test_mock_config() {
        let config = SettlementConfig::mock();
        assert_eq!(config.mode, SettlementMode::Mock);
    }

    #[test]
    fn test_devnet_config() {
        let program_id = [42u8; 32];
        let config = SettlementConfig::devnet(program_id);
        assert_eq!(config.mode, SettlementMode::Live);
        assert_eq!(config.program_id, program_id);
    }

    #[test]
    fn test_receipt_dedup_hash() {
        let receipt = ForwardReceipt {
            request_id: [1u8; 32],
            shard_index: 0,
            receiver_pubkey: [2u8; 32],
            timestamp: 1000,
            signature: [0u8; 64],
        };

        let hash1 = SettlementClient::receipt_dedup_hash(&receipt);
        let hash2 = SettlementClient::receipt_dedup_hash(&receipt);
        assert_eq!(hash1, hash2); // Deterministic

        // Different shard_index = different hash
        let receipt2 = ForwardReceipt {
            shard_index: 1,
            ..receipt.clone()
        };
        let hash3 = SettlementClient::receipt_dedup_hash(&receipt2);
        assert_ne!(hash1, hash3);
    }

    #[test]
    fn test_receipt_dedup_ignores_timestamp() {
        let receipt1 = ForwardReceipt {
            request_id: [1u8; 32],
            shard_index: 0,
            receiver_pubkey: [2u8; 32],
            timestamp: 1000,
            signature: [0u8; 64],
        };

        let receipt2 = ForwardReceipt {
            timestamp: 2000, // Different timestamp
            ..receipt1.clone()
        };

        // Same dedup hash (timestamp not included in dedup)
        assert_eq!(
            SettlementClient::receipt_dedup_hash(&receipt1),
            SettlementClient::receipt_dedup_hash(&receipt2),
        );
    }

    #[tokio::test]
    async fn test_client_creation() {
        let config = SettlementConfig::mock();
        let client = SettlementClient::new(config, [0u8; 32]);
        assert!(client.is_mock());
    }

    #[tokio::test]
    async fn test_mock_subscribe() {
        let config = SettlementConfig::mock();
        let client = SettlementClient::new(config, [0u8; 32]);

        let user_pubkey = [1u8; 32];
        let sub = Subscribe {
            user_pubkey,
            tier: SubscriptionTier::Standard,
            payment_amount: 15_000_000,
        };

        let sig = client.subscribe(sub).await.unwrap();
        assert_ne!(sig, [0u8; 64]);

        // Verify subscription was created
        let state = client.get_subscription_state(user_pubkey).await.unwrap();
        assert!(state.is_some());
        let state = state.unwrap();
        assert_eq!(state.tier, SubscriptionTier::Standard);
        assert_eq!(state.pool_balance, 15_000_000);

        // Verify is_subscribed
        assert!(client.is_subscribed(user_pubkey).await.unwrap());
    }

    #[tokio::test]
    async fn test_mock_submit_receipts() {
        let config = SettlementConfig::mock();
        let client = SettlementClient::new(config, [0u8; 32]);

        let user_pubkey = [1u8; 32];
        client.add_mock_subscription(user_pubkey, SubscriptionTier::Basic, 5_000_000).unwrap();

        let receipt = ForwardReceipt {
            request_id: [10u8; 32],
            shard_index: 0,
            receiver_pubkey: [2u8; 32],
            timestamp: 1000,
            signature: [0u8; 64],
        };

        let submit = SubmitReceipts {
            user_pubkey,
            receipts: vec![receipt.clone()],
        };

        client.submit_receipts(submit).await.unwrap();

        // Check node got credit
        let node = client.get_node_account([2u8; 32]).await.unwrap();
        assert_eq!(node.current_epoch_receipts, 1);
        assert_eq!(node.lifetime_receipts, 1);

        // Check subscription total_receipts
        let sub = client.get_subscription_state(user_pubkey).await.unwrap().unwrap();
        assert_eq!(sub.total_receipts, 1);
    }

    #[tokio::test]
    async fn test_mock_receipt_dedup() {
        let config = SettlementConfig::mock();
        let client = SettlementClient::new(config, [0u8; 32]);

        let user_pubkey = [1u8; 32];
        client.add_mock_subscription(user_pubkey, SubscriptionTier::Basic, 5_000_000).unwrap();

        let receipt = ForwardReceipt {
            request_id: [10u8; 32],
            shard_index: 0,
            receiver_pubkey: [2u8; 32],
            timestamp: 1000,
            signature: [0u8; 64],
        };

        // Submit same receipt twice
        let submit1 = SubmitReceipts {
            user_pubkey,
            receipts: vec![receipt.clone()],
        };
        client.submit_receipts(submit1).await.unwrap();

        let submit2 = SubmitReceipts {
            user_pubkey,
            receipts: vec![receipt],
        };
        client.submit_receipts(submit2).await.unwrap();

        // Should only count once
        let node = client.get_node_account([2u8; 32]).await.unwrap();
        assert_eq!(node.current_epoch_receipts, 1);
    }

    #[tokio::test]
    async fn test_mock_claim_rewards() {
        let config = SettlementConfig::mock();
        let client = SettlementClient::new(config, [0u8; 32]);

        let user_pubkey = [1u8; 32];
        let node1 = [2u8; 32];
        let node2 = [3u8; 32];

        client.add_mock_subscription(user_pubkey, SubscriptionTier::Standard, 1_000_000).unwrap();

        // Submit 3 receipts for node1, 1 for node2
        let receipts: Vec<ForwardReceipt> = (0..4).map(|i| ForwardReceipt {
            request_id: [10u8; 32],
            shard_index: i,
            receiver_pubkey: if i < 3 { node1 } else { node2 },
            timestamp: 1000,
            signature: [0u8; 64],
        }).collect();

        let submit = SubmitReceipts {
            user_pubkey,
            receipts,
        };
        client.submit_receipts(submit).await.unwrap();

        // Node1 claims: 3/4 * 1_000_000 = 750_000
        let claim1 = ClaimRewards {
            user_pubkey,
            node_pubkey: node1,
            epoch: 1,
        };
        client.claim_rewards(claim1).await.unwrap();

        let acct1 = client.get_node_account(node1).await.unwrap();
        assert_eq!(acct1.unclaimed_rewards, 750_000);

        // Node2 claims: 1/4 * 1_000_000 = 250_000
        let claim2 = ClaimRewards {
            user_pubkey,
            node_pubkey: node2,
            epoch: 1,
        };
        client.claim_rewards(claim2).await.unwrap();

        let acct2 = client.get_node_account(node2).await.unwrap();
        assert_eq!(acct2.unclaimed_rewards, 250_000);

        // Pool should be drained
        let sub = client.get_subscription_state(user_pubkey).await.unwrap().unwrap();
        assert_eq!(sub.pool_balance, 0);
    }

    #[tokio::test]
    async fn test_mock_no_subscription() {
        let config = SettlementConfig::mock();
        let client = SettlementClient::new(config, [0u8; 32]);

        let submit = SubmitReceipts {
            user_pubkey: [99u8; 32],
            receipts: vec![],
        };

        let result = client.submit_receipts(submit).await;
        assert!(matches!(result, Err(SettlementError::SubscriptionNotFound(_))));
    }

    #[tokio::test]
    async fn test_not_subscribed() {
        let config = SettlementConfig::mock();
        let client = SettlementClient::new(config, [0u8; 32]);

        assert!(!client.is_subscribed([99u8; 32]).await.unwrap());
    }

    #[test]
    fn test_config_custom_rpc() {
        let config = SettlementConfig {
            mode: SettlementMode::Live,
            rpc_url: "http://localhost:8899".to_string(),
            program_id: [1u8; 32],
            commitment: "finalized".to_string(),
        };

        assert_eq!(config.rpc_url, "http://localhost:8899");
        assert_eq!(config.program_id, [1u8; 32]);
        assert_eq!(config.commitment, "finalized");
        assert_eq!(config.mode, SettlementMode::Live);
    }

    #[test]
    fn test_hex_encode() {
        assert_eq!(hex_encode(&[0x00, 0xFF, 0xAB]), "00ffab");
        assert_eq!(hex_encode(&[]), "");
        assert_eq!(hex_encode(&[0x12, 0x34, 0x56, 0x78]), "12345678");
    }
}
